package system // import "github.com/docker/docker/pkg/system"

import "os"

var (
	// lcowSupported determines if Linux Containers on Windows are supported.
	lcowSupported = false

	// containerdSupported determines if Windows should use ContainerD as the runtime.
	containerdSupported = false
)

// InitLCOW sets whether LCOW is supported or not
func InitLCOW(experimental bool) {
	v := GetOSVersion()
	if experimental && v.Build >= 16299 {
		lcowSupported = true
	}
}

// InitContainerdOnWindows sets whether to use ContainerD for runtime
// on Windows. This is an experimental feature still in development, and
// also requires an environment variable to be set (so as not to turn the
// feature on from simply experimental which would also mean LCOW.
func InitContainerd(experimental bool, cdPath string) {
	v := GetOSVersion()
	if experimental && v.Build >= 17763 && len(cdPath) > 0 && len(os.Getenv("DOCKER_WINDOWS_CONTAINERD")) > 0 {
		containerdSupported = true
	}
}

// ContainerdSupported returns true if the use of ContainerD is supported.
func ContainerdSupported() bool {
	return containerdSupported
}
