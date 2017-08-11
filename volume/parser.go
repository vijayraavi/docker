package volume

import (
	"runtime"

	"github.com/docker/docker/api/types/mount"
)

const (
	// PlatformLinux is the same as runtime.GOOS on linux
	PlatformLinux = "linux"
	// PlatformWindows is the same as runtime.GOOS on windows
	PlatformWindows = "windows"
)

// Parser represents a platform specific parser for mount expressions
type Parser interface {
	ParseMountRaw(raw, volumeDriver string) (*MountPoint, error)
	ParseMountSpec(cfg mount.Mount) (*MountPoint, error)
	ParseVolumesFrom(spec string) (string, string, error)
	DefaultPropagationMode() mount.Propagation
	ConvertTmpfsOptions(opt *mount.TmpfsOptions, readOnly bool) (string, error)
	DefaultCopyMode() bool
	ValidateVolumeName(name string) error
	ReadWrite(mode string) bool
	IsBackwardCompatible(m *MountPoint) bool
	HasResource(m *MountPoint, absPath string) bool
	ValidateTmpfsMountDestination(dest string) error

	validateMountConfig(mt *mount.Mount) error
}

// NewParser creates a parser for a given container platform, depending on the current host OS (linux on a windows host will resolve to an lcowParser)
func NewParser(containerPlatform string) Parser {
	switch containerPlatform {
	case PlatformWindows:
		return &windowsParser{}
	}
	if runtime.GOOS == PlatformWindows {
		return &lcowParser{}
	}
	return &linuxParser{}
}
