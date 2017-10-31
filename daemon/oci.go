package daemon

import (
	"regexp"
	"runtime"
	"strings"

	containertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/container"
	"github.com/docker/docker/daemon/caps"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// nolint: gosimple
var (
	deviceCgroupRuleRegex = regexp.MustCompile("^([acb]) ([0-9]+|\\*):([0-9]+|\\*) ([rwm]{1,3})$")
)

// Note setLinuxCPUMemoryPidsResources is shared between LCOL and LCOW
func setLinuxCPUMemoryPidsResources(s *specs.Spec, r containertypes.Resources) error {
	if s.Linux.Resources == nil {
		s.Linux.Resources = &specs.LinuxResources{}
	}
	cpuRes, err := getLinuxCPUResources(r)
	if err != nil {
		return err
	}
	s.Linux.Resources.Memory = getLinuxMemoryResources(r)
	s.Linux.Resources.CPU = cpuRes
	s.Linux.Resources.Pids = &specs.LinuxPids{Limit: r.PidsLimit}

	return nil
}

func (daemon *Daemon) setRlimits(s *specs.Spec, c *container.Container) error {
	var rlimits []specs.POSIXRlimit

	// We want to leave the original HostConfig alone so make a copy here
	hostConfig := *c.HostConfig
	// Merge with the daemon defaults
	daemon.mergeUlimits(&hostConfig)
	for _, ul := range hostConfig.Ulimits {
		rlimits = append(rlimits, specs.POSIXRlimit{
			Type: "RLIMIT_" + strings.ToUpper(ul.Name),
			Soft: uint64(ul.Soft),
			Hard: uint64(ul.Hard),
		})
	}

	s.Process.Rlimits = rlimits
	return nil
}

// mergeUlimits merge the Ulimits from HostConfig with daemon defaults, and update HostConfig
func (daemon *Daemon) mergeUlimits(c *containertypes.HostConfig) {
	// No-op for Windows containers on Windows.
	// TODO @jhowardmsft - extend to make this operational for LCOW.
	if runtime.GOOS == "windows" {
		return
	}
	ulimits := c.Ulimits
	// Merge ulimits with daemon defaults
	ulIdx := make(map[string]struct{})
	for _, ul := range ulimits {
		ulIdx[ul.Name] = struct{}{}
	}
	for name, ul := range daemon.configStore.Ulimits {
		if _, exists := ulIdx[name]; !exists {
			ulimits = append(ulimits, ul)
		}
	}
	c.Ulimits = ulimits
}

func setNamespace(s *specs.Spec, ns specs.LinuxNamespace) {
	for i, n := range s.Linux.Namespaces {
		if n.Type == ns.Type {
			s.Linux.Namespaces[i] = ns
			return
		}
	}
	s.Linux.Namespaces = append(s.Linux.Namespaces, ns)
}

func setCapabilities(s *specs.Spec, c *container.Container) error {
	var caplist []string
	var err error
	if c.HostConfig.Privileged {
		caplist = caps.GetAllCapabilities()
	} else {
		caplist, err = caps.TweakCapabilities(s.Process.Capabilities.Effective, c.HostConfig.CapAdd, c.HostConfig.CapDrop)
		if err != nil {
			return err
		}
	}
	s.Process.Capabilities.Effective = caplist
	s.Process.Capabilities.Bounding = caplist
	s.Process.Capabilities.Permitted = caplist
	s.Process.Capabilities.Inheritable = caplist
	return nil
}

func IsLCOWSpec(s *specs.Spec) bool {
	if runtime.GOOS == "windows" && s.Linux != nil {
		return true
	}
	return false
}

func clearReadOnly(m *specs.Mount) {
	var opt []string
	for _, o := range m.Options {
		if o != "ro" {
			opt = append(opt, o)
		}
	}
	m.Options = opt
}
