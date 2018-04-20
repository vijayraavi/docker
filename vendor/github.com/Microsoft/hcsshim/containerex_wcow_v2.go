package hcsshim

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

func createWCOWv2(createOptions *CreateOptions) (Container, error) {
	if createOptions.lcowOptions != nil {
		return nil, fmt.Errorf("lcowOptions must not be supplied for a v2 schema Windows container request")
	}
	if createOptions.spec.Windows != nil && createOptions.spec.Windows.HyperV != nil {
		return createWCOWv2UVM(createOptions)
	}
	return createWCOWv2Argon(createOptions)
}

func createWCOWv2UVM(createOptions *CreateOptions) (Container, error) {
	logrus.Debugf("HCSShim: Creating utility VM id=%s", createOptions.id)

	iocis := "invalid OCI spec:"
	if len(createOptions.spec.Windows.LayerFolders) != 1 {
		return nil, fmt.Errorf("%s Windows.LayerFolders must have length 1 for a hosting system pointing to a folder containing sandbox.vhdx", iocis)
	}
	if len(createOptions.spec.Hostname) > 0 {
		return nil, fmt.Errorf("%s Hostname cannot be set for a hosting system", iocis)
	}
	if createOptions.spec.Windows.Resources != nil && createOptions.spec.Windows.Resources.CPU != nil && createOptions.spec.Windows.Resources.CPU.Shares != nil {
		return nil, fmt.Errorf("%s Windows.Resources.CPU.Shares must not be set for a hosting system", iocis)
	}
	if createOptions.spec.Windows.Resources != nil && createOptions.spec.Windows.Resources.CPU != nil && createOptions.spec.Windows.Resources.CPU.Maximum != nil {
		return nil, fmt.Errorf("%s Windows.Resources.CPU.Maximum must not be set for a hosting system", iocis)
	}
	if createOptions.spec.Root != nil {
		return nil, fmt.Errorf("%s Root must not be set for a hosting system", iocis)
	}
	if createOptions.spec.Windows.Resources != nil && createOptions.spec.Windows.Resources.Storage != nil {
		return nil, fmt.Errorf("%s Windows.Resources.Storage must not be set for a hosting system", iocis)
	}
	if createOptions.spec.Windows.CredentialSpec != nil {
		return nil, fmt.Errorf("%s Windows.CredentialSpec must not be set for a hosting system", iocis)
	}
	if createOptions.spec.Windows.Network != nil {
		return nil, fmt.Errorf("%s Windows.Network must not be set for a hosting system", iocis) // Need to revisit, but blocking everything currently not hooked up
	}
	if 0 != len(createOptions.spec.Mounts) {
		return nil, fmt.Errorf("%s Mounts must not be set for a hosting system", iocis)
	}

	// TODO:  Default the utilty VMpath under HyperV in spec if not supplied

	attachments := make(map[string]VirtualMachinesResourcesStorageAttachmentV2)
	attachments["0"] = VirtualMachinesResourcesStorageAttachmentV2{
		Path: filepath.Join(createOptions.spec.Windows.LayerFolders[0], "sandbox.vhdx"),
		Type: "VirtualDisk",
	}
	scsi := make(map[string]VirtualMachinesResourcesStorageScsiV2)
	scsi["0"] = VirtualMachinesResourcesStorageScsiV2{Attachments: attachments}
	memory := int32(2048)
	processors := int32(1)
	if createOptions.spec.Windows.Resources != nil {
		if createOptions.spec.Windows.Resources.Memory != nil && createOptions.spec.Windows.Resources.Memory.Limit != nil {
			memory = int32(*createOptions.spec.Windows.Resources.Memory.Limit / 1024 / 1024) // OCI spec is in bytes. HCS takes MB
		}
		if createOptions.spec.Windows.Resources.CPU != nil && createOptions.spec.Windows.Resources.CPU.Count != nil {
			processors = int32(*createOptions.spec.Windows.Resources.CPU.Count)
		}
	}
	uvm := &ComputeSystemV2{
		Owner:         createOptions.owner,
		SchemaVersion: &createOptions.schemaVersion,
		VirtualMachine: &VirtualMachineV2{
			Chipset: &VirtualMachinesResourcesChipsetV2{
				UEFI: &VirtualMachinesResourcesUefiV2{
					BootThis: &VirtualMachinesResourcesUefiBootEntryV2{
						DevicePath: `\EFI\Microsoft\Boot\bootmgfw.efi`,
						DiskNumber: 0,
						UefiDevice: "VMBFS",
					},
				},
			},
			ComputeTopology: &VirtualMachinesResourcesComputeTopologyV2{
				Memory: &VirtualMachinesResourcesComputeMemoryV2{
					Backing:             "Virtual",
					Startup:             memory,
					DirectFileMappingMB: 1024, // Sensible default, but could be a tuning parameter somewhere
				},
				Processor: &VirtualMachinesResourcesComputeProcessorV2{
					Count: processors,
				},
			},

			Devices: &VirtualMachinesDevicesV2{
				// Add networking here.... TODO
				SCSI: scsi,
				VirtualSMBShares: []VirtualMachinesResourcesStorageVSmbShareV2{VirtualMachinesResourcesStorageVSmbShareV2{
					Flags: VsmbFlagPseudoOplocks | VsmbFlagNoDirnotify | VsmbFlagNoLocks | VsmbFlagTakeBackupPrivilege | VsmbFlagReadOnly,
					Name:  "os",
					Path:  createOptions.spec.Windows.HyperV.UtilityVMPath,
				}},
				GuestInterface: &VirtualMachinesResourcesGuestInterfaceV2{ConnectToBridge: true},
			},
		},
	}

	uvmb, err := json.Marshal(uvm)
	if err != nil {
		return nil, err
	}
	logrus.Debugf("HCSShim: UVM definition: %s", string(uvmb))
	uvmContainer, err := createContainer(createOptions.id, string(uvmb), SchemaV20())
	if err != nil {
		return nil, err
	}
	uvmContainer.(*container).scsiLocations.used[0][0] = true
	return uvmContainer, nil
}

// removeVSMB removes a VSMB share from a utility VM. The mutex must be
// held when calling this function
func removeVSMB(c Container, id string) error {
	logrus.Debugf("HCSShim: Removing vsmb %s", id)
	if _, ok := c.(*container).vsmbShares.guids[id]; !ok {
		return fmt.Errorf("failed to remove vsmbShare %s as it is not in utility VM %s", id, c.(*container).id)
	} else {
		logrus.Debugf("VSMB: %s refcount: %d", id, c.(*container).vsmbShares.guids[id])
		c.(*container).vsmbShares.guids[id]--
		if c.(*container).vsmbShares.guids[id] == 0 {
			delete(c.(*container).vsmbShares.guids, id)
			modification := &ModifySettingsRequestV2{
				ResourceType: ResourceTypeVSmbShare,
				RequestType:  RequestTypeRemove,
				// TODO: https://microsoft.visualstudio.com/OS/_queries?_a=edit&id=17031676&triage=true. Settings should not be required, just ResourceUri
				Settings:    VirtualMachinesResourcesStorageVSmbShareV2{Name: id},
				ResourceUri: fmt.Sprintf("virtualmachine/devices/virtualsmbshares/%s", id),
			}
			if err := c.Modify(modification); err != nil {
				return fmt.Errorf("failed to remove vsmbShare %s from utility VM %s after refcount dropped to zero: %s", id, c.(*container).id, err)
			}
		}
	}
	return nil
}

// removeVSMBOnFailure is a helper to roll-back any VSMB shares added to a utility VM on a failure path
func removeVSMBOnFailure(c Container, toRemove []string) {
	if len(toRemove) == 0 {
		return
	}
	c.(*container).vsmbShares.Lock()
	defer c.(*container).vsmbShares.Unlock()
	for _, vsmbShare := range toRemove {
		if err := removeVSMB(c, vsmbShare); err != nil {
			logrus.Warnf("Possibly leaked vsmbshare on error removal path: %s", err)
		}
	}
}

// removeSCSI removes a mapped virtual disk from a containers SCSI controller. The mutex
// must be held when calling this function
func removeSCSI(c Container, controller int, lun int) error {
	scsiModification := &ModifySettingsRequestV2{
		ResourceType: ResourceTypeMappedVirtualDisk,
		RequestType:  RequestTypeRemove,
		ResourceUri:  fmt.Sprintf("VirtualMachine/Devices/SCSI/%d/%d", controller, lun),
	}
	if err := c.Modify(scsiModification); err != nil {
		return err
	}
	c.(*container).scsiLocations.used[controller][lun] = false
	return nil
}

// removeSCSIOnFailure is a helper to roll-back a SCSI disk added to a utility VM on a failure path
func removeSCSIOnFailure(c Container, controller int, lun int) {
	c.(*container).scsiLocations.Lock()
	defer c.(*container).scsiLocations.Unlock()
	if err := removeSCSI(c, controller, lun); err != nil {
		logrus.Warnf("Possibly leaked SCSI disk on error removal path: %s", err)
	}
}

func createWCOWv2Argon(createOptions *CreateOptions) (Container, error) {

	hostedSystem := &HostedSystemV2{
		SchemaVersion: SchemaV20(),
		Container:     &ContainerV2{Storage: createOptions.mountedLayers},
	}

	computeSystemV2 := &ComputeSystemV2{
		Owner:                             createOptions.owner,
		SchemaVersion:                     SchemaV20(),
		HostingSystemId:                   createOptions.hostingSystem.(*container).id,
		HostedSystem:                      hostedSystem,
		ShouldTerminateOnLastHandleClosed: true,
	}

	computeSystemV2b, err := json.Marshal(computeSystemV2)
	if err != nil {
		// TODO:
		//removeVSMBOnFailure(createOptions.hostingSystem, vsmbAdded)
		//removeSCSIOnFailure(createOptions.hostingSystem, controller, lun)
		return nil, err
	}
	logrus.Debugf("HCSShim: definition: %s", string(computeSystemV2b))
	hostedContainer, err := createContainer(createOptions.id, string(computeSystemV2b), SchemaV20())
	if err != nil {
		// TODO
		//removeVSMBOnFailure(createOptions.hostingSystem, vsmbAdded)
		//removeSCSIOnFailure(createOptions.hostingSystem, controller, lun)
		return nil, err
	}
	return hostedContainer, nil
}

// specToHCSContainerDocument creates a document suitable for calling HCS to create
// a container, both hosted and process isolated. It can create both v1 and v2
// schema.
func specToHCSContainerDocument(createOptions *CreateOptions) (interface{}, error) {
	logrus.Debugf("createWCOWv1")

	v1 := &ContainerConfig{
		SystemType: "Container",
		Name:       createOptions.id,
		Owner:      createOptions.owner,
		IgnoreFlushesDuringBoot: createOptions.spec.Windows.IgnoreFlushesDuringBoot,
		HostName:                createOptions.spec.Hostname,
		HvPartition:             false,
	}

	// TODO: Fill in HostingSystemId and HostedSystem outside
	// IgnoreFlushesDuringBoot is a property of the SCSI attachment for the sandbox. Set when it's hot-added to the utility VM
	// ID is a property on the create call in V2 rather than part of the schema.
	v2 := &ComputeSystemV2{
		Owner:                             createOptions.owner,
		SchemaVersion:                     SchemaV20(),
		ShouldTerminateOnLastHandleClosed: true,
		Container:                         &ContainerV2{Storage: &ContainersResourcesStorageV2{}},
	}
	if createOptions.spec.Hostname != "" {
		v2.Container.GuestOS = &GuestOsV2{HostName: createOptions.spec.Hostname}
	}

	if createOptions.spec.Windows.Resources != nil {
		if createOptions.spec.Windows.Resources.CPU != nil {
			if createOptions.spec.Windows.Resources.CPU.Count != nil ||
				createOptions.spec.Windows.Resources.CPU.Shares != nil ||
				createOptions.spec.Windows.Resources.CPU.Maximum != nil {
				v2.Container.Processor = &ContainersResourcesProcessorV2{}
			}
			if createOptions.spec.Windows.Resources.CPU.Count != nil {
				cpuCount := *createOptions.spec.Windows.Resources.CPU.Count
				hostCPUCount := uint64(numCPU())
				if cpuCount > hostCPUCount {
					createOptions.logger.Warnf("Changing requested CPUCount of %d to current number of processors, %d", cpuCount, hostCPUCount)
					cpuCount = hostCPUCount
				}
				v1.ProcessorCount = uint32(cpuCount)
				v2.Container.Processor.Count = v1.ProcessorCount
			}
			if createOptions.spec.Windows.Resources.CPU.Shares != nil {
				v1.ProcessorWeight = uint64(*createOptions.spec.Windows.Resources.CPU.Shares)
				v2.Container.Processor.Weight = v1.ProcessorWeight
			}
			if createOptions.spec.Windows.Resources.CPU.Maximum != nil {
				v1.ProcessorMaximum = int64(*createOptions.spec.Windows.Resources.CPU.Maximum)
				v2.Container.Processor.Maximum = uint64(v1.ProcessorMaximum)
			}
		}
		if createOptions.spec.Windows.Resources.Memory != nil {
			if createOptions.spec.Windows.Resources.Memory.Limit != nil {
				v1.MemoryMaximumInMB = int64(*createOptions.spec.Windows.Resources.Memory.Limit) / 1024 / 1024
				v2.Container.Memory = &ContainersResourcesMemoryV2{Maximum: uint64(v1.MemoryMaximumInMB)}

			}
		}
		if createOptions.spec.Windows.Resources.Storage != nil {
			if createOptions.spec.Windows.Resources.Storage.Bps != nil || createOptions.spec.Windows.Resources.Storage.Iops != nil {
				v2.Container.Storage.StorageQoS = &ContainersResourcesStorageQoSV2{}
			}
			if createOptions.spec.Windows.Resources.Storage.Bps != nil {
				v1.StorageBandwidthMaximum = *createOptions.spec.Windows.Resources.Storage.Bps
				v2.Container.Storage.StorageQoS.BandwidthMaximum = *createOptions.spec.Windows.Resources.Storage.Bps
			}
			if createOptions.spec.Windows.Resources.Storage.Iops != nil {
				v1.StorageIOPSMaximum = *createOptions.spec.Windows.Resources.Storage.Iops
				v2.Container.Storage.StorageQoS.IOPSMaximum = *createOptions.spec.Windows.Resources.Storage.Iops
			}
		}
	}

	// TODO V2 networking. Only partial at the moment. v2.Container.Networking.Namespace specifically
	if createOptions.spec.Windows.Network != nil {
		v2.Container.Networking = &ContainersResourcesNetworkingV2{}

		v1.EndpointList = createOptions.spec.Windows.Network.EndpointList
		v2.Container.Networking.NetworkAdapters = v1.EndpointList

		v1.AllowUnqualifiedDNSQuery = createOptions.spec.Windows.Network.AllowUnqualifiedDNSQuery
		v2.Container.Networking.AllowUnqualifiedDnsQuery = v1.AllowUnqualifiedDNSQuery

		if createOptions.spec.Windows.Network.DNSSearchList != nil {
			v1.DNSSearchList = strings.Join(createOptions.spec.Windows.Network.DNSSearchList, ",")
			v2.Container.Networking.DNSSearchList = v1.DNSSearchList
		}

		v1.NetworkSharedContainerName = createOptions.spec.Windows.Network.NetworkSharedContainerName
		v2.Container.Networking.NetworkSharedContainerName = v1.NetworkSharedContainerName
	}

	//	// TODO V2 Credentials not in the schema yet.
	if cs, ok := createOptions.spec.Windows.CredentialSpec.(string); ok {
		v1.Credentials = cs
	}

	//	// We must have least two layers in the spec, the bottom one being a
	//	// base image, the top one being the RW layer.
	//	if createOptions.spec.Windows.LayerFolders == nil || len(createOptions.spec.Windows.LayerFolders) < 2 {
	//		return "", fmt.Errorf("invalid spec - not enough layer folders supplied")
	//	}

	//	// Strip off the top-most RW layer as that's passed in separately to HCS
	//	configuration.LayerFolderPath = createOptions.spec.Windows.LayerFolders[len(createOptions.spec.Windows.LayerFolders)-1]

	//	if createOptions.spec.Windows.HyperV != nil {
	//		configuration.HvPartition = true
	//		if createOptions.spec.Windows.HyperV.UtilityVMPath == "" {
	//			return nil, fmt.Errorf("no utility VM path for Hyper-V containers was supplied to the runtime")
	//		}
	//		configuration.HvRuntime = &HvRuntime{ImagePath: createOptions.spec.Windows.HyperV.UtilityVMPath}

	//		if createOptions.spec.Root != nil && createOptions.spec.Root.Path != "" {
	//			return nil, fmt.Errorf("invalid container spec - Root.Path must be omitted for a Hyper-V container")
	//		}
	//	} else {

	//		if createOptions.spec.Root == nil {
	//			return nil, fmt.Errorf("invalid container spec - Root must be set")
	//		}
	//		const volumeGUIDRegex = `^\\\\\?\\(Volume)\{{0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}\}\\$`
	//		if _, err := regexp.MatchString(volumeGUIDRegex, createOptions.spec.Root.Path); err != nil {
	//			return nil, fmt.Errorf(`invalid container spec - Root.Path '%s' must be a volume GUID path in the format '\\?\Volume{GUID}\'`, createOptions.spec.Root.Path)
	//		}
	//		// HCS API requires the trailing backslash to be removed
	//		if createOptions.spec.Root.Path[:len(createOptions.spec.Root.Path)] == `\` {
	//			createOptions.spec.Root.Path = createOptions.spec.Root.Path[:len(createOptions.spec.Root.Path)-1]
	//		}
	//		configuration.VolumePath = createOptions.spec.Root.Path
	//	}

	//	if createOptions.spec.Root != nil && createOptions.spec.Root.Readonly {
	//		return nil, fmt.Errorf(`invalid container spec - readonly is not supported`)
	//	}

	//	for _, layerPath := range createOptions.spec.Windows.LayerFolders[:len(createOptions.spec.Windows.LayerFolders)-1] {
	//		_, filename := filepath.Split(layerPath)
	//		g, err := NameToGuid(filename)
	//		if err != nil {
	//			return nil, err
	//		}
	//		configuration.Layers = append(configuration.Layers, Layer{ID: g.ToString(), Path: layerPath})
	//	}

	// Add the mounts as mapped directories or mapped pipes
	var (
		mdsv1 []MappedDir
		mpsv1 []MappedPipe
		mdsv2 []ContainersResourcesMappedDirectoryV2
		mpsv2 []ContainersResourcesMappedPipeV2
	)
	for _, mount := range createOptions.spec.Mounts {
		const pipePrefix = `\\.\pipe\`
		if mount.Type != "" {
			return "", fmt.Errorf("invalid container spec - Mount.Type '%s' must not be set", mount.Type)
		}
		if strings.HasPrefix(mount.Destination, pipePrefix) {
			mpsv1 = append(mpsv1, MappedPipe{HostPath: mount.Source, ContainerPipeName: mount.Destination[len(pipePrefix):]})
			mpsv2 = append(mpsv2, ContainersResourcesMappedPipeV2{HostPath: mount.Source, ContainerPipeName: mount.Destination[len(pipePrefix):]})
		} else {
			mdv1 := MappedDir{HostPath: mount.Source, ContainerPath: mount.Destination, ReadOnly: false}
			mdv2 := ContainersResourcesMappedDirectoryV2{HostPath: mount.Source, ContainerPath: mount.Destination, ReadOnly: false}
			for _, o := range mount.Options {
				if strings.ToLower(o) == "ro" {
					mdv1.ReadOnly = true
					mdv2.ReadOnly = true
				}
			}
			mdsv1 = append(mdsv1, mdv1)
			mdsv2 = append(mdsv2, mdv2)
		}
	}
	v1.MappedDirectories = mdsv1
	v2.Container.MappedDirectories = mdsv2
	if len(mpsv1) > 0 && GetOSVersion().Build < 16299 { // RS3
		return "", fmt.Errorf("named pipe mounts are not supported on this version of Windows")
	}
	v1.MappedPipes = mpsv1
	v2.Container.MappedPipes = mpsv2

	logrus.Debugf("wcowv1 configuration: %+v", v1)
	return "", nil
}

// MountLayers is a helper for clients to hide all the complexity of layer mounting
// Layer folder are in order: base, [rolayer1..rolayern,] sandbox
// TODO: Extend for LCOW?
//
// v1: Returns the mount path on the host as a volume GUID. It's pointless doing this for Xenon.
func MountContainerStorage(layerFolders []string, hostingSystem Container, sv *SchemaVersion) (interface{}, error) {
	if err := sv.isSupported(); err != nil {
		return nil, err
	}
	if sv.isV10() {
		if len(layerFolders) < 2 {
			return nil, fmt.Errorf("need at least two layers - base and sandbox")
		}
		id := filepath.Base(layerFolders[len(layerFolders)-1])
		homeDir := filepath.Dir(layerFolders[len(layerFolders)-1])
		di := DriverInfo{HomeDir: homeDir}

		if err := ActivateLayer(di, id); err != nil {
			return nil, err
		}
		if err := PrepareLayer(di, id, layerFolders[:len(layerFolders)-1]); err != nil {
			if err2 := DeactivateLayer(di, id); err2 != nil {
				logrus.Warnf("Failed to Deactivate %s: %s", id, err)
			}
			return nil, err
		}

		mountPath, err := GetLayerMountPath(di, id)
		if err != nil {
			if err := UnprepareLayer(di, id); err != nil {
				logrus.Warnf("Failed to Unprepare %s: %s", id, err)
			}
			if err2 := DeactivateLayer(di, id); err2 != nil {
				logrus.Warnf("Failed to Deactivate %s: %s", id, err)
			}
			return nil, err
		}
		return mountPath, nil
	}

	// v2 schema.

	if hostingSystem == nil {
		return nil, fmt.Errorf("Not implemented v2 mounting argon-style")
	}

	// 	Add each read-only layers as a VSMB share. In each case, the ResourceUri will end in a GUID based on the folder path.
	//  Each VSMB share is ref-counted so that multiple containers in the same utility VM can share them.
	c := hostingSystem.(*container)
	c.vsmbShares.Lock()
	if c.vsmbShares.guids == nil {
		c.vsmbShares.guids = make(map[string]int)
	}
	var vsmbAdded []string
	for _, layerPath := range layerFolders[:len(layerFolders)-1] {
		logrus.Debugf("Processing layerPath %s as read-only VSMB share", layerPath)
		_, filename := filepath.Split(layerPath)
		guid, err := NameToGuid(filename)
		if err != nil {
			removeVSMBOnFailure(hostingSystem, vsmbAdded)
			c.vsmbShares.Unlock()
			return nil, err
		}
		if _, ok := c.vsmbShares.guids[guid.ToString()]; !ok {
			logrus.Debugf("Processing layerPath %s: Perfoming modify to add VSMB share", layerPath)
			modification := &ModifySettingsRequestV2{
				ResourceType: ResourceTypeVSmbShare,
				RequestType:  RequestTypeAdd,
				Settings: VirtualMachinesResourcesStorageVSmbShareV2{
					Name:  guid.ToString(),
					Flags: VsmbFlagReadOnly | VsmbFlagPseudoOplocks | VsmbFlagTakeBackupPrivilege,
					Path:  layerPath,
				},
				ResourceUri: fmt.Sprintf("virtualmachine/devices/virtualsmbshares/%s", guid.ToString()),
			}
			if err := hostingSystem.Modify(modification); err != nil {
				c.vsmbShares.Unlock()
				removeVSMBOnFailure(hostingSystem, vsmbAdded)
				return nil, err
			}
			c.vsmbShares.guids[guid.ToString()] = 1
		} else {
			c.vsmbShares.guids[guid.ToString()]++
			logrus.Debugf("Processing layerPath %s: Incremented refcount to: %d", layerPath, c.vsmbShares.guids[guid.ToString()])
		}
		vsmbAdded = append(vsmbAdded, guid.ToString())
	}
	c.vsmbShares.Unlock()

	// 	Add the sandbox at an unused SCSI location. The container path inside the utility VM will be C:\<GUID> where
	// 	GUID is based on the folder in which the sandbox is located. Therefore, it is critical that if two containers
	// 	are created in the same utility VM, they have unique sandbox directories.

	controller, lun, err := allocateSCSI(c)
	if err != nil {
		removeVSMBOnFailure(hostingSystem, vsmbAdded)
		return nil, err
	}

	// TODO: Currently GCS doesn't support more than one SCSI controller. @jhowardmsft/@swernli. This will hopefully be fixed in GCS for RS5.
	// It will also require the HostedSettings to be extended in the call below to include the controller as well as the LUN.
	if controller > 0 {
		return nil, fmt.Errorf("too many SCSI attachments for a single controller")
	}

	_, sandboxPath := filepath.Split(layerFolders[len(layerFolders)-1])
	containerPathGUID, err := NameToGuid(sandboxPath)
	if err != nil {
		removeVSMBOnFailure(hostingSystem, vsmbAdded)
		return nil, err
	}
	sandboxModification := &ModifySettingsRequestV2{
		ResourceType: ResourceTypeMappedVirtualDisk,
		RequestType:  RequestTypeAdd,
		Settings: VirtualMachinesResourcesStorageAttachmentV2{
			Path: filepath.Join(layerFolders[len(layerFolders)-1], "sandbox.vhdx"),
			Type: "VirtualDisk",
			// TODO Hmmm....  Where do we do this now????  IgnoreFlushes: createOptions.spec.Windows.IgnoreFlushesDuringBoot,
		},
		ResourceUri: fmt.Sprintf("VirtualMachine/Devices/SCSI/%d/%d", controller, lun),
		HostedSettings: ContainersResourcesMappedDirectoryV2{
			ContainerPath: fmt.Sprintf(`C:\%s`, containerPathGUID.ToString()),
			Lun:           uint8(lun),
		},
	}
	if err := hostingSystem.Modify(sandboxModification); err != nil {
		removeVSMBOnFailure(hostingSystem, vsmbAdded)
		return nil, err
	}

	// 	Load the filter at the C:\<GUID> location calculated above. We pass into this request each of the
	// 	read-only layer folders.

	layers := []ContainersResourcesLayerV2{}
	for _, vsmb := range vsmbAdded {
		layers = append(layers, ContainersResourcesLayerV2{
			Id:   vsmb,
			Path: fmt.Sprintf(`\\?\VMSMB\VSMB-{dcc079ae-60ba-4d07-847c-3493609c0870}\%s`, vsmb),
		})
	}
	combinedLayers := CombinedLayersV2{
		ContainerRootPath: fmt.Sprintf(`C:\%s`, containerPathGUID.ToString()),
		Layers:            layers,
	}
	combinedLayersModification := &ModifySettingsRequestV2{
		ResourceType:   ResourceTypeCombinedLayers,
		RequestType:    RequestTypeAdd,
		HostedSettings: combinedLayers,
	}
	if err := hostingSystem.Modify(combinedLayersModification); err != nil {
		removeVSMBOnFailure(hostingSystem, vsmbAdded)
		removeSCSIOnFailure(hostingSystem, controller, lun)
		return nil, err
	}

	return combinedLayers, nil
}

// TODO UnmountContainerStorage()

func UnmountContainerStorage(layerFolders []string, hostingSystem Container, sv *SchemaVersion) error {
	//	if err := sv.isSupported(); err != nil {
	//		return nil, err
	//	}
	//	if sv.isV10() {
	//		if len(layerFolders) < 2 {
	//			return nil, fmt.Errorf("need at least two layers - base and sandbox")
	//		}
	//		id := filepath.Base(layerFolders[len(layerFolders)-1])
	//		homeDir := filepath.Dir(layerFolders[len(layerFolders)-1])
	//		di := DriverInfo{HomeDir: homeDir}

	//		if err := ActivateLayer(di, id); err != nil {
	//			return nil, err
	//		}
	//		if err := PrepareLayer(di, id, layerFolders[:len(layerFolders)-1]); err != nil {
	//			if err2 := DeactivateLayer(di, id); err2 != nil {
	//				logrus.Warnf("Failed to Deactivate %s: %s", id, err)
	//			}
	//			return nil, err
	//		}

	//		mountPath, err := GetLayerMountPath(di, id)
	//		if err != nil {
	//			if err := UnprepareLayer(di, id); err != nil {
	//				logrus.Warnf("Failed to Unprepare %s: %s", id, err)
	//			}
	//			if err2 := DeactivateLayer(di, id); err2 != nil {
	//				logrus.Warnf("Failed to Deactivate %s: %s", id, err)
	//			}
	//			return nil, err
	//		}
	//		return mountPath, nil
	//	}
	return nil
}
