// +build !windows

package hcsshim

func init() {
	panic("hcsshim is not supported on non-Windows platforms and should not be imported")
}
