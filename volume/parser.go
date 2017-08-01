package volume

import (
	"runtime"

	"github.com/docker/docker/api/types/mount"
)

const (
	PlatformLinux   = "linux"
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
	IsVolumeNameValid(name string) (bool, error)
	ReadWrite(mode string) bool
	IsBackwardCompatible(m *MountPoint) bool
	HasResource(m *MountPoint, absPath string) bool
	ValidateTmpfsMountDestination(dest string) error

	validateMountConfig(mt *mount.Mount) error
}

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
