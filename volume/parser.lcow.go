package volume

import (
	"fmt"
	"path"

	"github.com/docker/docker/api/types/mount"
)

type lcowParser struct {
	windowsParser
}

func (p *lcowParser) validateMountConfig(mnt *mount.Mount) error {
	return p.validateMountConfigReg(mnt, rxLCOWDestination, func(m *mount.Mount) error {
		if path.Clean(m.Target) == "/" {
			return fmt.Errorf("invalid specification: destination can't be '/'")
		}
		return nil
	})
}

func (p *lcowParser) ParseMountRaw(raw, volumeDriver string) (*MountPoint, error) {
	return p.parseMountRaw(raw, volumeDriver, rxLCOWDestination, false, func(m *mount.Mount) error {
		if path.Clean(m.Target) == "/" {
			return fmt.Errorf("invalid specification: destination can't be '/'")
		}
		return nil
	})
}

func (p *lcowParser) ParseMountSpec(cfg mount.Mount) (*MountPoint, error) {
	return p.parseMountSpec(cfg, rxLCOWDestination, false, func(m *mount.Mount) error {
		if path.Clean(m.Target) == "/" {
			return fmt.Errorf("invalid specification: destination can't be '/'")
		}
		return nil
	})
}
