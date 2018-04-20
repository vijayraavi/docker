package hcsshim

import (
	"fmt"
	//	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
)

// createWCOWv1 creates a Windows (WCOW) container using the V1 schema.
// This supports both Argon and Xenon. We are guaranteed that the top-level
// fields in the createOptions are populated at this point.

// TODO: COmbined in specToHCSContainerDocument for both v1 and v2
func createWCOWv1(createOptions *CreateOptions) (Container, error) {

	logrus.Debugf("createWCOWv1")

	configuration := &ContainerConfig{
		SystemType: "Container",
		Name:       createOptions.id,
		Owner:      createOptions.owner,
		IgnoreFlushesDuringBoot: createOptions.spec.Windows.IgnoreFlushesDuringBoot,
		HostName:                createOptions.spec.Hostname,
		HvPartition:             false,
	}

	if createOptions.spec.Windows.Resources != nil {
		if createOptions.spec.Windows.Resources.CPU != nil {
			if createOptions.spec.Windows.Resources.CPU.Count != nil {
				cpuCount := *createOptions.spec.Windows.Resources.CPU.Count
				hostCPUCount := uint64(numCPU())
				if cpuCount > hostCPUCount {
					createOptions.logger.Warnf("Changing requested CPUCount of %d to current number of processors, %d", cpuCount, hostCPUCount)
					cpuCount = hostCPUCount
				}
				configuration.ProcessorCount = uint32(cpuCount)
			}
			if createOptions.spec.Windows.Resources.CPU.Shares != nil {
				configuration.ProcessorWeight = uint64(*createOptions.spec.Windows.Resources.CPU.Shares)
			}
			if createOptions.spec.Windows.Resources.CPU.Maximum != nil {
				configuration.ProcessorMaximum = int64(*createOptions.spec.Windows.Resources.CPU.Maximum)
			}
		}
		if createOptions.spec.Windows.Resources.Memory != nil {
			if createOptions.spec.Windows.Resources.Memory.Limit != nil {
				configuration.MemoryMaximumInMB = int64(*createOptions.spec.Windows.Resources.Memory.Limit) / 1024 / 1024
			}
		}
		if createOptions.spec.Windows.Resources.Storage != nil {
			if createOptions.spec.Windows.Resources.Storage.Bps != nil {
				configuration.StorageBandwidthMaximum = *createOptions.spec.Windows.Resources.Storage.Bps

			}
			if createOptions.spec.Windows.Resources.Storage.Iops != nil {
				configuration.StorageIOPSMaximum = *createOptions.spec.Windows.Resources.Storage.Iops
			}
		}
	}

	if createOptions.spec.Windows.Network != nil {
		configuration.EndpointList = createOptions.spec.Windows.Network.EndpointList
		configuration.AllowUnqualifiedDNSQuery = createOptions.spec.Windows.Network.AllowUnqualifiedDNSQuery
		if createOptions.spec.Windows.Network.DNSSearchList != nil {
			configuration.DNSSearchList = strings.Join(createOptions.spec.Windows.Network.DNSSearchList, ",")
		}
		configuration.NetworkSharedContainerName = createOptions.spec.Windows.Network.NetworkSharedContainerName
	}

	if cs, ok := createOptions.spec.Windows.CredentialSpec.(string); ok {
		configuration.Credentials = cs
	}

	// We must have least two layers in the spec, the bottom one being a
	// base image, the top one being the RW layer.
	if createOptions.spec.Windows.LayerFolders == nil || len(createOptions.spec.Windows.LayerFolders) < 2 {
		return nil, fmt.Errorf("invalid spec - not enough layer folders supplied")
	}

	// Strip off the top-most RW layer as that's passed in separately to HCS
	configuration.LayerFolderPath = createOptions.spec.Windows.LayerFolders[len(createOptions.spec.Windows.LayerFolders)-1]

	if createOptions.spec.Windows.HyperV != nil {
		configuration.HvPartition = true
		if createOptions.spec.Windows.HyperV.UtilityVMPath == "" {
			return nil, fmt.Errorf("no utility VM path for Hyper-V containers was supplied to the runtime")
		}
		configuration.HvRuntime = &HvRuntime{ImagePath: createOptions.spec.Windows.HyperV.UtilityVMPath}

		if createOptions.spec.Root != nil && createOptions.spec.Root.Path != "" {
			return nil, fmt.Errorf("invalid container spec - Root.Path must be omitted for a Hyper-V container")
		}
	} else {

		if createOptions.spec.Root == nil {
			return nil, fmt.Errorf("invalid container spec - Root must be set")
		}
		const volumeGUIDRegex = `^\\\\\?\\(Volume)\{{0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}\}\\$`
		if _, err := regexp.MatchString(volumeGUIDRegex, createOptions.spec.Root.Path); err != nil {
			return nil, fmt.Errorf(`invalid container spec - Root.Path '%s' must be a volume GUID path in the format '\\?\Volume{GUID}\'`, createOptions.spec.Root.Path)
		}
		// HCS API requires the trailing backslash to be removed
		if createOptions.spec.Root.Path[:len(createOptions.spec.Root.Path)] == `\` {
			createOptions.spec.Root.Path = createOptions.spec.Root.Path[:len(createOptions.spec.Root.Path)-1]
		}
		configuration.VolumePath = createOptions.spec.Root.Path
	}

	if createOptions.spec.Root != nil && createOptions.spec.Root.Readonly {
		return nil, fmt.Errorf(`invalid container spec - readonly is not supported`)
	}

	for _, layerPath := range createOptions.spec.Windows.LayerFolders[:len(createOptions.spec.Windows.LayerFolders)-1] {
		_, filename := filepath.Split(layerPath)
		g, err := NameToGuid(filename)
		if err != nil {
			return nil, err
		}
		configuration.Layers = append(configuration.Layers, Layer{ID: g.ToString(), Path: layerPath})
	}

	// Add the mounts (volumes, bind mounts etc) to the structure
	var mds []MappedDir
	var mps []MappedPipe
	for _, mount := range createOptions.spec.Mounts {
		const pipePrefix = `\\.\pipe\`
		if mount.Type != "" {
			return nil, fmt.Errorf("invalid container spec - Mount.Type '%s' must not be set", mount.Type)
		}
		if strings.HasPrefix(mount.Destination, pipePrefix) {
			mp := MappedPipe{HostPath: mount.Source, ContainerPipeName: mount.Destination[len(pipePrefix):]}
			mps = append(mps, mp)
		} else {
			md := MappedDir{
				HostPath:      mount.Source,
				ContainerPath: mount.Destination,
				ReadOnly:      false,
			}
			for _, o := range mount.Options {
				if strings.ToLower(o) == "ro" {
					md.ReadOnly = true
				}
			}
			mds = append(mds, md)
		}
	}
	configuration.MappedDirectories = mds
	if len(mps) > 0 && GetOSVersion().Build < 16299 { // RS3
		return nil, fmt.Errorf("named pipe mounts are not supported on this version of Windows")
	}
	configuration.MappedPipes = mps

	logrus.Debugf("wcowv1 configuration: %+v", configuration)
	container, err := CreateContainer(createOptions.id, configuration)
	if err != nil {
		return nil, err
	}

	createOptions.logger.Debugf("createWCOWv1() completed successfully")
	return container, nil
}
