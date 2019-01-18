package system // import "github.com/docker/docker/pkg/system"

import "golang.org/x/sys/windows"

// EscapeArgs is a no-op on non-Windows platforms. On Windows, it
// escapes a set of process arguments
func EscapeArgs(args []string) []string {
	escapedArgs := make([]string, len(args))
	for i, a := range args {
		escapedArgs[i] = windows.EscapeArg(a)
	}
	return escapedArgs
}
