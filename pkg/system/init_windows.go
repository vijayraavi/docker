package system

import "os"

// LCOWSupported determines if Linux Containers on Windows are supported.
var lcowSupported = false

func init() {
	// TODO @jhowardmsft.
	// 1. Replace with RS3 RTM build number.
	// 2. Remove the getenv check when image-store is coalesced as shouldn't be needed anymore.
	v := GetOSVersion()
	if v.Build > 16270 && os.Getenv("LCOW_SUPPORTED") != "" {
		lcowSupported = true
	}

}
