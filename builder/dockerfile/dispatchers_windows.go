package dockerfile // import "github.com/docker/docker/builder/dockerfile"

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/pkg/system"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
)

var pattern = regexp.MustCompile(`^[a-zA-Z]:\.$`)

// normalizeWorkdir normalizes a user requested working directory in a
// platform semantically consistent way.
func normalizeWorkdir(platform string, current string, requested string) (string, error) {
	if platform == "" {
		platform = "windows"
	}
	if platform == "windows" {
		return normalizeWorkdirWindows(current, requested)
	}
	return normalizeWorkdirUnix(current, requested)
}

// normalizeWorkdirUnix normalizes a user requested working directory in a
// platform semantically consistent way.
func normalizeWorkdirUnix(current string, requested string) (string, error) {
	if requested == "" {
		return "", errors.New("cannot normalize nothing")
	}
	current = strings.Replace(current, string(os.PathSeparator), "/", -1)
	requested = strings.Replace(requested, string(os.PathSeparator), "/", -1)
	if !path.IsAbs(requested) {
		return path.Join(`/`, current, requested), nil
	}
	return requested, nil
}

// normalizeWorkdirWindows normalizes a user requested working directory in a
// platform semantically consistent way.
func normalizeWorkdirWindows(current string, requested string) (string, error) {
	if requested == "" {
		return "", errors.New("cannot normalize nothing")
	}

	// `filepath.Clean` will replace "" with "." so skip in that case
	if current != "" {
		current = filepath.Clean(current)
	}
	if requested != "" {
		requested = filepath.Clean(requested)
	}

	// If either current or requested in Windows is:
	// C:
	// C:.
	// then an error will be thrown as the definition for the above
	// refers to `current directory on drive C:`
	// Since filepath.Clean() will automatically normalize the above
	// to `C:.`, we only need to check the last format
	if pattern.MatchString(current) {
		return "", fmt.Errorf("%s is not a directory. If you are specifying a drive letter, please add a trailing '\\'", current)
	}
	if pattern.MatchString(requested) {
		return "", fmt.Errorf("%s is not a directory. If you are specifying a drive letter, please add a trailing '\\'", requested)
	}

	// Target semantics is C:\somefolder, specifically in the format:
	// UPPERCASEDriveLetter-Colon-Backslash-FolderName. We are already
	// guaranteed that `current`, if set, is consistent. This allows us to
	// cope correctly with any of the following in a Dockerfile:
	//	WORKDIR a                       --> C:\a
	//	WORKDIR c:\\foo                 --> C:\foo
	//	WORKDIR \\foo                   --> C:\foo
	//	WORKDIR /foo                    --> C:\foo
	//	WORKDIR c:\\foo \ WORKDIR bar   --> C:\foo --> C:\foo\bar
	//	WORKDIR C:/foo \ WORKDIR bar    --> C:\foo --> C:\foo\bar
	//	WORKDIR C:/foo \ WORKDIR \\bar  --> C:\foo --> C:\bar
	//	WORKDIR /foo \ WORKDIR c:/bar   --> C:\foo --> C:\bar
	if len(current) == 0 || system.IsAbs(requested) {
		if (requested[0] == os.PathSeparator) ||
			(len(requested) > 1 && string(requested[1]) != ":") ||
			(len(requested) == 1) {
			requested = filepath.Join(`C:\`, requested)
		}
	} else {
		requested = filepath.Join(current, requested)
	}
	// Upper-case drive letter
	return (strings.ToUpper(string(requested[0])) + requested[1:]), nil
}

// resolveCmdLine takes a command line arg set and optionally prepends a platform-specific
// shell in front of it. If the target operating system is Windows, it will also
// do Windows-specific argv-style reparsing of the command line.
func resolveCmdLine(cmd instructions.ShellDependantCmdLine, runConfig *container.Config, os, command, original string) []string {
	result := cmd.CmdLine

	// We need to reparse in Windows argv-style handling here if the target
	// OS is Windows, and the command line is not in JSON (exec) format.
	// This takes quite some explaining, hence the verbose comment below.
	//
	// This reparsing comes as a result of the integration of containerd as the
	// runtime execution engine on Windows. Previously, by somewhat bad design,
	// the Config structure used a field `ArgsEscaped` to indicate to the runtime
	// whether or not the arguments had been escaped.
	//
	// This was set to true when invoking a container from the builder, and
	// false when invoking a container through the CLI (docker run/exec).
	//
	// Without this change, the builder (both on Windows and Linux) would
	// parse the following RUN statement in a docker file as four elements
	// (assuming the default shell of `cmd /S /C`.
	//
	// Statement: `RUN mkdir "a b"
	// Elements:
	//   cmd
	//   /S
	//   /C
	//   mkdir "a b"
	//
	// Where-as from Powershell or cmd doing a docker run of the same such as
	// `docker run --rm microsoft/nanoserver cmd /S /C mkdir "a b"`, the
	// invoking shell will parse the command into FIVE (not four) elements through
	// the Win32 call `CommandLineToArgvW` - see
	// https://docs.microsoft.com/en-us/windows/desktop/api/shellapi/nf-shellapi-commandlinetoargvw
	// for more information.
	//
	// Statement: `cmd /S /C mkdir "a b"`
	// Elements:
	//   cmd
	//   /S
	//   /C
	//   mkdir
	//   a b
	//
	// While this difference in parsing in the two scenarios is consistent
	// between Windows and Linux, on Windows this is actually incorrect. To
	// clarify - on Windows, the builders four-element parsing is incorrect.
	// The reason it is wrong on Windows is that prior to calling `CreateProcess`,
	// it is necessary to call `EscapeArg` (in golang) on each argument.
	//
	// If calling `EscapeArg` on `mkdir "a b"` and calling `CreateProcess`, the
	// call would fail. However, if calling `EscapeArg` twice with two arguments.
	// the `CreateProcess` call would work exactly as expected. Using the above
	// example, the first call to `EscapeArg` would be on `mkdir`, and the
	// second call would be on `a b`. As there's a space in `a b`, it would be
	// escaped correctly to be enclosed in double-quotes.
	//
	// So why is this a problem when moving the runtime part of moby across to
	// ContainerD on Windows? Previously, Windows called HCS directly in-process
	// from docker (in the libcontainerd package). That package had context
	// of the caller (ie builder or run/exec) via the `ArgsEscaped` parameter
	// in the `Config` structure, and would conditionally call `EscapeArg`
	// accordingly - not from the builder, and yes from run/exec.
	//
	// With the containerd runtime execution, the interface between the docker
	// and containerd is the OCI spec which is in essence "thrown over the wall".
	// The OCI spec (rightly) doesn't have any concept of whether or not
	// arguments are escaped. The spec should always be written (again rightly)
	// as if the arguments are NOT escaped. When it comes to invocation of the
	// process through runhcs (runc equivalent on Windows), that's where the
	// calls to `EscapeArg` are made.
	//
	// Putting all the above another way, on Windows, we should be parsing the
	// RUN statement in the builder as if it were Windows-style argv parameters,
	// and always populate the OCI spec with un-escaped args. Only at the point
	// of invoking `CreateProcess` should the args be escaped.
	//
	// Note that this applies only to WCOW, not LCOW.
	//
	// Note also, to do the reparsing, we re-use some golang code present in
	// the Windows part of the repo to do Argv processing. Unfortunately, golang
	// does export these functions, so they are copied here.
	//
	// Phew :)

	if os == "windows" && cmd.PrependShell {
		original = original[len(command):] // strip off the relevant command such as run etc.
		result = commandLineToArgv(original)
	}

	if cmd.PrependShell && result != nil {
		result = append(getShell(runConfig, os), result...)
	}
	return result
}

// The following three functions are copied from the unexported functions in the
// Windows golang implementation of commandLineToArgv.

// appendBSBytes appends n '\\' bytes to b and returns the resulting slice.
func appendBSBytes(b []byte, n int) []byte {
	for ; n > 0; n-- {
		b = append(b, '\\')
	}
	return b
}

// readNextArg splits command line string cmd into next
// argument and command line remainder.
func readNextArg(cmd string) (arg []byte, rest string) {
	var b []byte
	var inquote bool
	var nslash int
	for ; len(cmd) > 0; cmd = cmd[1:] {
		c := cmd[0]
		switch c {
		case ' ', '\t':
			if !inquote {
				return appendBSBytes(b, nslash), cmd[1:]
			}
		case '"':
			b = appendBSBytes(b, nslash/2)
			if nslash%2 == 0 {
				// use "Prior to 2008" rule from
				// http://daviddeley.com/autohotkey/parameters/parameters.htm
				// section 5.2 to deal with double double quotes
				if inquote && len(cmd) > 1 && cmd[1] == '"' {
					b = append(b, c)
					cmd = cmd[1:]
				}
				inquote = !inquote
			} else {
				b = append(b, c)
			}
			nslash = 0
			continue
		case '\\':
			nslash++
			continue
		}
		b = appendBSBytes(b, nslash)
		nslash = 0
		b = append(b, c)
	}
	return appendBSBytes(b, nslash), ""
}

// commandLineToArgv splits a command line into individual argument
// strings, following the Windows conventions documented
// at http://daviddeley.com/autohotkey/parameters/parameters.htm#WINARGV
func commandLineToArgv(cmd string) []string {
	var args []string
	for len(cmd) > 0 {
		if cmd[0] == ' ' || cmd[0] == '\t' {
			cmd = cmd[1:]
			continue
		}
		var arg []byte
		arg, cmd = readNextArg(cmd)
		args = append(args, string(arg))
	}
	return args
}
