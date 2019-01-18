package daemon // import "github.com/docker/docker/daemon"

// Note: Eventually this file will replace oci_windows.go.
// For now, rather than having lots of "if containerd <foo> else <bar>", the
// files are largely duplicated.

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/docker/docker/container"
	"github.com/docker/docker/oci"
	"github.com/docker/docker/pkg/sysinfo"
	"github.com/docker/docker/pkg/system"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func (daemon *Daemon) createSpecContainerd(c *container.Container) (*specs.Spec, error) {

	// @jhowardmsft TODO: revisit this - can re-use much of the containerd oci package.
	// See containerd/containerd/ctr/commands/run/run_windows.go as an example.

	img, err := daemon.imageService.GetImage(string(c.ImageID))
	if err != nil {
		return nil, err
	}

	s := oci.DefaultOSSpec(img.OS)

	linkedEnv, err := daemon.setupLinkedContainers(c)
	if err != nil {
		return nil, err
	}

	// Note, unlike Unix, we do NOT call into SetupWorkingDirectory as
	// this is done in VMCompute. Further, we couldn't do it for Hyper-V
	// containers anyway.

	// In base spec
	s.Hostname = c.FullHostname()

	if err := daemon.setupSecretDir(c); err != nil {
		return nil, err
	}

	if err := daemon.setupConfigDir(c); err != nil {
		return nil, err
	}

	// In s.Mounts
	mounts, err := daemon.setupMounts(c)
	if err != nil {
		return nil, err
	}

	var isHyperV bool
	if c.HostConfig.Isolation.IsDefault() {
		// Container using default isolation, so take the default from the daemon configuration
		isHyperV = daemon.defaultIsolation.IsHyperV()
	} else {
		// Container may be requesting an explicit isolation mode.
		isHyperV = c.HostConfig.Isolation.IsHyperV()
	}

	if isHyperV {
		s.Windows.HyperV = &specs.WindowsHyperV{}
	}

	// If the container has not been started, and has configs or secrets
	// secrets, create symlinks to each config and secret. If it has been
	// started before, the symlinks should have already been created. Also, it
	// is important to not mount a Hyper-V  container that has been started
	// before, to protect the host from the container; for example, from
	// malicious mutation of NTFS data structures.
	if !c.HasBeenStartedBefore && (len(c.SecretReferences) > 0 || len(c.ConfigReferences) > 0) {
		// The container file system is mounted before this function is called,
		// except for Hyper-V containers, so mount it here in that case.
		if isHyperV {
			if err := daemon.Mount(c); err != nil {
				return nil, err
			}
			defer daemon.Unmount(c)
		}
		if err := c.CreateSecretSymlinks(); err != nil {
			return nil, err
		}
		if err := c.CreateConfigSymlinks(); err != nil {
			return nil, err
		}
	}

	secretMounts, err := c.SecretMounts()
	if err != nil {
		return nil, err
	}
	if secretMounts != nil {
		mounts = append(mounts, secretMounts...)
	}

	configMounts := c.ConfigMounts()
	if configMounts != nil {
		mounts = append(mounts, configMounts...)
	}

	for _, mount := range mounts {
		m := specs.Mount{
			Source:      mount.Source,
			Destination: mount.Destination,
		}
		if !mount.Writable {
			m.Options = append(m.Options, "ro")
		}
		if img.OS != runtime.GOOS {
			m.Type = "bind"
			m.Options = append(m.Options, "rbind")
			m.Options = append(m.Options, fmt.Sprintf("uvmpath=/tmp/gcs/%s/binds", c.ID))
		}
		s.Mounts = append(s.Mounts, m)
	}

	// In s.Process
	s.Process.Args = append([]string{c.Path}, c.Args...)
	s.Process.Cwd = c.Config.WorkingDir
	s.Process.Env = c.CreateDaemonEnvironment(c.Config.Tty, linkedEnv)
	if c.Config.Tty {
		s.Process.Terminal = c.Config.Tty
		s.Process.ConsoleSize = &specs.Box{
			Height: c.HostConfig.ConsoleSize[0],
			Width:  c.HostConfig.ConsoleSize[1],
		}
	}
	s.Process.User.Username = c.Config.User
	s.Windows.LayerFolders, err = daemon.imageService.GetLayerFolders(img, c.RWLayer)
	if err != nil {
		return nil, errors.Wrapf(err, "container %s", c.ID)
	}

	dnsSearch := daemon.getDNSSearchSettings(c)

	// Get endpoints for the libnetwork allocated networks to the container
	var epList []string
	AllowUnqualifiedDNSQuery := false
	gwHNSID := ""
	if c.NetworkSettings != nil {
		for n := range c.NetworkSettings.Networks {
			sn, err := daemon.FindNetwork(n)
			if err != nil {
				continue
			}

			ep, err := getEndpointInNetwork(c.Name, sn)
			if err != nil {
				continue
			}

			data, err := ep.DriverInfo()
			if err != nil {
				continue
			}

			if data["GW_INFO"] != nil {
				gwInfo := data["GW_INFO"].(map[string]interface{})
				if gwInfo["hnsid"] != nil {
					gwHNSID = gwInfo["hnsid"].(string)
				}
			}

			if data["hnsid"] != nil {
				epList = append(epList, data["hnsid"].(string))
			}

			if data["AllowUnqualifiedDNSQuery"] != nil {
				AllowUnqualifiedDNSQuery = true
			}
		}
	}

	var networkSharedContainerID string
	if c.HostConfig.NetworkMode.IsContainer() {
		networkSharedContainerID = c.NetworkSharedContainerID
		for _, ep := range c.SharedEndpointList {
			epList = append(epList, ep)
		}
	}

	if gwHNSID != "" {
		epList = append(epList, gwHNSID)
	}

	s.Windows.Network = &specs.WindowsNetwork{
		AllowUnqualifiedDNSQuery:   AllowUnqualifiedDNSQuery,
		DNSSearchList:              dnsSearch,
		EndpointList:               epList,
		NetworkSharedContainerName: networkSharedContainerID,
	}

	switch img.OS {
	case "windows":
		if err := daemon.createSpecContainerdWindowsFields(c, &s, isHyperV); err != nil {
			return nil, err
		}
	case "linux":
		if !system.LCOWSupported() {
			return nil, fmt.Errorf("Linux containers on Windows are not supported")
		}
		if err := daemon.createSpecContainerdLinuxFields(c, &s); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("Unsupported platform %q", img.OS)
	}

	if b, err := json.Marshal(&s); err == nil {
		logrus.Debugf("Generated spec: %s", string(b))
	}

	return (*specs.Spec)(&s), nil
}

// Sets the Windows-specific fields of the OCI spec
func (daemon *Daemon) createSpecContainerdWindowsFields(c *container.Container, s *specs.Spec, isHyperV bool) error {

	if len(s.Process.Cwd) == 0 {
		// We default to C:\ to workaround the oddity of the case that the
		// default directory for cmd running as LocalSystem (or
		// ContainerAdministrator) is c:\windows\system32. Hence docker run
		// <image> cmd will by default end in c:\windows\system32, rather
		// than 'root' (/) on Linux. The oddity is that if you have a dockerfile
		// which has no WORKDIR and has a COPY file ., . will be interpreted
		// as c:\. Hence, setting it to default of c:\ makes for consistency.
		s.Process.Cwd = `C:\`
	}

	s.Root.Readonly = false // Windows does not support a read-only root filesystem
	if !isHyperV {
		if c.BaseFS == nil {
			return errors.New("createSpecWindowsFields: BaseFS of container " + c.ID + " is unexpectedly nil")
		}

		s.Root.Path = c.BaseFS.Path() // This is not set for Hyper-V containers
		if !strings.HasSuffix(s.Root.Path, `\`) {
			s.Root.Path = s.Root.Path + `\` // Ensure a correctly formatted volume GUID path \\?\Volume{GUID}\
		}
	}

	// First boot optimization
	s.Windows.IgnoreFlushesDuringBoot = !c.HasBeenStartedBefore

	// In s.Windows.Resources
	cpuShares := uint16(c.HostConfig.CPUShares)
	cpuMaximum := uint16(c.HostConfig.CPUPercent) * 100
	cpuCount := uint64(c.HostConfig.CPUCount)
	if c.HostConfig.NanoCPUs > 0 {
		if isHyperV {
			cpuCount = uint64(c.HostConfig.NanoCPUs / 1e9)
			leftoverNanoCPUs := c.HostConfig.NanoCPUs % 1e9
			if leftoverNanoCPUs != 0 {
				cpuCount++
				cpuMaximum = uint16(c.HostConfig.NanoCPUs / int64(cpuCount) / (1e9 / 10000))
				if cpuMaximum < 1 {
					// The requested NanoCPUs is so small that we rounded to 0, use 1 instead
					cpuMaximum = 1
				}
			}
		} else {
			cpuMaximum = uint16(c.HostConfig.NanoCPUs / int64(sysinfo.NumCPU()) / (1e9 / 10000))
			if cpuMaximum < 1 {
				// The requested NanoCPUs is so small that we rounded to 0, use 1 instead
				cpuMaximum = 1
			}
		}
	}

	if cpuMaximum != 0 || cpuShares != 0 || cpuCount != 0 {
		if s.Windows.Resources == nil {
			s.Windows.Resources = &specs.WindowsResources{}
		}
		s.Windows.Resources.CPU = &specs.WindowsCPUResources{
			Maximum: &cpuMaximum,
			Shares:  &cpuShares,
			Count:   &cpuCount,
		}
	}

	memoryLimit := uint64(c.HostConfig.Memory)
	if memoryLimit != 0 {
		if s.Windows.Resources == nil {
			s.Windows.Resources = &specs.WindowsResources{}
		}
		s.Windows.Resources.Memory = &specs.WindowsMemoryResources{
			Limit: &memoryLimit,
		}
	}

	if c.HostConfig.IOMaximumBandwidth != 0 || c.HostConfig.IOMaximumIOps != 0 {
		if s.Windows.Resources == nil {
			s.Windows.Resources = &specs.WindowsResources{}
		}
		s.Windows.Resources.Storage = &specs.WindowsStorageResources{
			Bps:  &c.HostConfig.IOMaximumBandwidth,
			Iops: &c.HostConfig.IOMaximumIOps,
		}
	}

	// Read and add credentials from the security options if a credential spec has been provided.
	if c.HostConfig.SecurityOpt != nil {
		cs := ""
		for _, sOpt := range c.HostConfig.SecurityOpt {
			sOpt = strings.ToLower(sOpt)
			if !strings.Contains(sOpt, "=") {
				return fmt.Errorf("invalid security option: no equals sign in supplied value %s", sOpt)
			}
			var splitsOpt []string
			splitsOpt = strings.SplitN(sOpt, "=", 2)
			if len(splitsOpt) != 2 {
				return fmt.Errorf("invalid security option: %s", sOpt)
			}
			if splitsOpt[0] != "credentialspec" {
				return fmt.Errorf("security option not supported: %s", splitsOpt[0])
			}

			var (
				match   bool
				csValue string
				err     error
			)
			if match, csValue = getCredentialSpec("file://", splitsOpt[1]); match {
				if csValue == "" {
					return fmt.Errorf("no value supplied for file:// credential spec security option")
				}
				if cs, err = readCredentialSpecFile(c.ID, daemon.root, filepath.Clean(csValue)); err != nil {
					return err
				}
			} else if match, csValue = getCredentialSpec("registry://", splitsOpt[1]); match {
				if csValue == "" {
					return fmt.Errorf("no value supplied for registry:// credential spec security option")
				}
				if cs, err = readCredentialSpecRegistry(c.ID, csValue); err != nil {
					return err
				}
			} else {
				return fmt.Errorf("invalid credential spec security option - value must be prefixed file:// or registry:// followed by a value")
			}
		}
		s.Windows.CredentialSpec = cs
	}

	// Do we have any assigned devices?
	if len(c.HostConfig.Devices) > 0 {
		if isHyperV {
			return errors.New("device assignment is not supported for HyperV containers")
		}
		if system.GetOSVersion().Build < 17763 {
			return errors.New("device assignment requires Windows builds RS5 (17763+) or later")
		}
		for _, deviceMapping := range c.HostConfig.Devices {
			srcParts := strings.SplitN(deviceMapping.PathOnHost, "/", 2)
			if len(srcParts) != 2 {
				return errors.New("invalid device assignment path")
			}
			if srcParts[0] != "class" {
				return errors.Errorf("invalid device assignment type: '%s' should be 'class'", srcParts[0])
			}
			wd := specs.WindowsDevice{
				ID:     srcParts[1],
				IDType: srcParts[0],
			}
			s.Windows.Devices = append(s.Windows.Devices, wd)
		}
	}

	return nil
}

// Sets the Linux-specific fields of the OCI spec
// TODO: @jhowardmsft LCOW Support. We need to do a lot more pulling in what can
// be pulled in from oci_linux.go.
func (daemon *Daemon) createSpecContainerdLinuxFields(c *container.Container, s *specs.Spec) error {
	if len(s.Process.Cwd) == 0 {
		s.Process.Cwd = `/`
	}
	s.Root.Path = "rootfs"
	s.Root.Readonly = c.HostConfig.ReadonlyRootfs
	if err := oci.SetCapabilities(s, c.HostConfig.CapAdd, c.HostConfig.CapDrop, c.HostConfig.Privileged); err != nil {
		return fmt.Errorf("linux spec capabilities: %v", err)
	}
	devPermissions, err := oci.AppendDevicePermissionsFromCgroupRules(nil, c.HostConfig.DeviceCgroupRules)
	if err != nil {
		return fmt.Errorf("linux runtime spec devices: %v", err)
	}
	s.Linux.Resources.Devices = devPermissions
	return nil
}
