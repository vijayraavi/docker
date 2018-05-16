// +build !windows

package schemaversion

func init() {
	panic(`hcsshim\schemaversion is not supported on non-Windows platforms and should not be imported`)
}
