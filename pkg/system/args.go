package system // import "github.com/docker/docker/pkg/system"

import "strings"

// CommandLineFromArgSet builds a command line (such as used for image
// history) from a set of command line arguments.
func CommandLineFromArgSet(args []string, os string) string {
	if os == "windows" {
		return strings.Join(EscapeArgs(args), " ")
	}
	return strings.Join(args, " ")
}
