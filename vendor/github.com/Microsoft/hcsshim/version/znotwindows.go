// +build !windows

package version

func init() {
	panic(`hcsshim\version is not supported on non-Windows platforms and should not be imported`)
}
