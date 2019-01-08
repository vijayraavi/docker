// +build !windows

package system // import "github.com/docker/docker/pkg/system"

// InitLCOW does nothing since LCOW is a windows only feature
func InitLCOW(experimental bool) {
}

// InitContainerdOnWindows does nothing since using containerd for
// Windows runtime is Windows-specific
func InitContainerdOnWindows(experimental bool, cdPath string) {
}

// ContainerdSupported returns true if the use of ContainerD is supported.
func ContainerdSupported(experimental bool, cdPath string) bool {
	return true
}
