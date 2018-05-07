package hcsshim

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"syscall"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

// CreateProcessExParams is the structure used for calling CreateProcessEx
type CreateProcessEx struct {
	OCISpecification  *specs.Spec // Required to be fully populated for LCOW as passed to GCS if not in the utility VM.
	CreateInUtilityVm bool        // Whether the process is created in the utility VM or the container
	Stdin             io.Reader   // Optional reader for sending on to the processes stdin stream
	Stdout            io.Writer   // Optional writer for returning the processes stdout stream
	Stderr            io.Writer   // Optional writer for returning the processes stderr stream
	ByteCounts        ByteCounts  // How much data to copy on each stream if they are supplied. 0 means to io.EOF.
}

// ByteCounts are the number of bytes copied to/from standard handles. Note
// this is int64 rather than uint64 to match the golang io.Copy() signature.
type ByteCounts struct {
	In  int64
	Out int64
	Err int64
}

// CreateProcessEx is a wrapper for CreateProcess that creates an arbirary process
// (most usefully inside a utility VM) and optionally performs IO copies
// with timeout between the pipes provided as input, and the pipes in the process.
// In the parameter structure, if byte-counts are non-zero, a maximum of those
// bytes are copied to the appropriate standard IO reader/writer. When zero,
// it copies until EOF. It also returns byte-counts indicating how much data
// was sent/received from the process. It is the responsibility of the caller
// to call Close() on the process returned.
func (container *container) CreateProcessEx(opts *CreateProcessEx) (Process, *ByteCounts, error) {
	if opts.OCISpecification == nil {
		return nil, nil, fmt.Errorf("no OCISpecification passed to CreateProcessEx")
	}
	if opts.OCISpecification.Process == nil {
		return nil, nil, fmt.Errorf("no Process in OCISpecification passed to CreateProcessEx")
	}

	copiedByteCounts := &ByteCounts{}
	commandLine := strings.Join(opts.OCISpecification.Process.Args, " ")
	environment := make(map[string]string)
	for _, v := range opts.OCISpecification.Process.Env {
		s := strings.SplitN(v, "=", 2)
		if len(s) == 2 && len(s[1]) > 0 {
			environment[s[0]] = s[1]
		}
	}

	targetOperatingSystem := "windows"
	if opts.OCISpecification.Linux != nil {
		targetOperatingSystem = "linux"
	}

	if targetOperatingSystem == "linux" {
		if _, ok := environment["PATH"]; !ok {
			environment["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:"
		}
	}

	// TODO WIndows defaults... This function won't currently work...

	processConfig := &ProcessConfig{
		EmulateConsole:    false,
		CreateStdInPipe:   (opts.Stdin != nil),
		CreateStdOutPipe:  (opts.Stdout != nil),
		CreateStdErrPipe:  (opts.Stderr != nil),
		CreateInUtilityVm: opts.CreateInUtilityVm,
		WorkingDirectory:  opts.OCISpecification.Process.Cwd,
		Environment:       environment,
		CommandLine:       commandLine,
	}

	if targetOperatingSystem == "linux" {
		// LCOW requires the raw OCI spec passed through HCS and onwards to
		// GCS for the utility VM.
		ociBuf, err := json.Marshal(opts.OCISpecification)
		if err != nil {
			return nil, nil, err
		}
		ociRaw := json.RawMessage(ociBuf)
		processConfig.OCISpecification = &ociRaw
	}

	proc, err := container.CreateProcess(processConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create process (%+v): %s", processConfig, err)
	}

	processStdin, processStdout, processStderr, err := proc.Stdio()
	if err != nil {
		proc.Kill() // Should this have a timeout?
		proc.Close()
		return nil, nil, fmt.Errorf("failed to get stdio pipes for process %+v: %s", processConfig, err)
	}

	// Send the data into the process's stdin
	if opts.Stdin != nil {
		if copiedByteCounts.In, err = copyWithTimeout(processStdin,
			opts.Stdin,
			opts.ByteCounts.In,
			fmt.Sprintf("CreateProcessEx: to stdin of %q", commandLine)); err != nil {
			return nil, nil, err
		}

		// Don't need stdin now we've sent everything. This signals GCS that we are finished sending data.
		if err := proc.CloseStdin(); err != nil && !IsNotExist(err) && !IsAlreadyClosed(err) {
			// This error will occur if the compute system is currently shutting down
			if perr, ok := err.(*ProcessError); ok && perr.Err != ErrVmcomputeOperationInvalidState {
				return nil, nil, err
			}
		}
	}

	// Copy the data back from stdout
	if opts.Stdout != nil {
		// Copy the data over to the writer.
		if copiedByteCounts.Out, err = copyWithTimeout(opts.Stdout,
			processStdout,
			opts.ByteCounts.Out,
			fmt.Sprintf("CreateProcessEx: from stdout from %q", commandLine)); err != nil {
			return nil, nil, err
		}
	}

	// Copy the data back from stderr
	if opts.Stderr != nil {
		// Copy the data over to the writer.
		if copiedByteCounts.Err, err = copyWithTimeout(opts.Stderr,
			processStderr,
			opts.ByteCounts.Err,
			fmt.Sprintf("CreateProcessEx: from stderr of %s", commandLine)); err != nil {
			return nil, nil, err
		}
	}

	logrus.Debugf("hcsshim: CreateProcessEx success: %q", commandLine)
	return proc, copiedByteCounts, nil
}

// copyWithTimeout is a wrapper for io.Copy using a timeout duration
func copyWithTimeout(dst io.Writer, src io.Reader, size int64, context string) (int64, error) {
	log := "to EOF"
	if size > 0 {
		log = fmt.Sprintf("%d bytes", size)
	}
	logrus.Debugf(fmt.Sprintf("hcsshim::copywithtimeout (%s) %s", context, log))

	type resultType struct {
		err   error
		bytes int64
	}

	done := make(chan resultType, 1)
	go func() {
		result := resultType{}
		if logrus.GetLevel() < logrus.DebugLevel || logDataByteCount == 0 {
			result.bytes, result.err = io.Copy(dst, src)
		} else {
			// In advanced debug mode where we log (hexdump format) what is copied
			// up to the number of bytes defined by environment variable
			// HCSSHIM_LOG_DATA_BYTE_COUNT
			var buf bytes.Buffer
			tee := io.TeeReader(src, &buf)
			result.bytes, result.err = io.Copy(dst, tee)
			if result.err == nil {
				size := result.bytes
				if size > logDataByteCount {
					size = logDataByteCount
				}
				if size > 0 {
					bytes := make([]byte, size)
					if _, err := buf.Read(bytes); err == nil {
						logrus.Debugf(fmt.Sprintf("hcsshim: copyWithTimeout\n%s", hex.Dump(bytes)))
					}
				}
			}
		}
		done <- result
	}()

	var result resultType
	timedout := time.After(defaultTimeoutSeconds)

	select {
	case <-timedout:
		return 0, fmt.Errorf("hcsshim::copyWithTimeout: timed out (%s)", context)
	case result = <-done:
		if result.err != nil && result.err != io.EOF {
			// See https://github.com/golang/go/blob/f3f29d1dea525f48995c1693c609f5e67c046893/src/os/exec/exec_windows.go for a clue as to why we are doing this :)
			if se, ok := result.err.(syscall.Errno); ok {
				const (
					errNoData     = syscall.Errno(232)
					errBrokenPipe = syscall.Errno(109)
				)
				if se == errNoData || se == errBrokenPipe {
					logrus.Debugf("hcsshim::copyWithTimeout: hit NoData or BrokenPipe: %d: %s", se, context)
					return result.bytes, nil
				}
			}
			return 0, fmt.Errorf("hcsshim::copyWithTimeout: error reading: '%s' after %d bytes (%s)", result.err, result.bytes, context)
		}
	}
	logrus.Debugf("hcsshim::copyWithTimeout: success - copied %d bytes (%s)", result.bytes, context)
	return result.bytes, nil
}
