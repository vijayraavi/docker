// +build !windows

package system // import "github.com/docker/docker/pkg/system"

// EscapeArgs is a no-op on non-Windows platforms. On Windows, it
// escapes a set of process arguments
func EscapeArgs(args []string) []string {
	return args
}
