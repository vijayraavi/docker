package hcsshim

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/sirupsen/logrus"
)

func createWCOWv2(createOptions *CreateOptions) (Container, error) {
	if createOptions.lcowOptions != nil {
		return nil, fmt.Errorf("lcowOptions must not be supplied for a v2 schema Windows container request")
	}
	if createOptions.spec.Windows.HyperV != nil {
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
	if createOptions.spec.Windows.Resources.CPU != nil && createOptions.spec.Windows.Resources.CPU.Shares != nil {
		return nil, fmt.Errorf("%s Windows.Resources.CPU.Shares must not be set for a hosting system", iocis)
	}
	if createOptions.spec.Windows.Resources.CPU != nil && createOptions.spec.Windows.Resources.CPU.Maximum != nil {
		return nil, fmt.Errorf("%s Windows.Resources.CPU.Maximum must not be set for a hosting system", iocis)
	}
	if createOptions.spec.Root != nil {
		return nil, fmt.Errorf("%s Root must not be set for a hosting system", iocis)
	}
	if createOptions.spec.Windows.Resources.Storage != nil {
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
					Backing: "Virtual",
					Startup: memory,
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
	//
	// High-level steps:
	// 	1. Add each read-only layers as a VSMB share. In each case, the ResourceUri will end in a GUID based on the folder path.
	//     Each VSMB share is ref-counted so that multiple containers in the same utility VM can share them.
	//
	// 	2. Add the sandbox at an unused SCSI location. The container path inside the utility VM will be C:\<GUID> where
	// 	   GUID is based on the folder in which the sandbox is located. Therefore, it is critical that if two containers
	// 	   are created in the same utility VM, they have unique sandbox directories.
	//
	// 	3. Load the filter at the C:\<GUID> location calculated in step 2. We pass into this request each of the
	// 	   read-only layer folders which were mounted in step 1.
	//
	//  4. Create a compute system

	createOptions.hostingSystem.(*container).vsmbShares.Lock()
	if createOptions.hostingSystem.(*container).vsmbShares.guids == nil {
		createOptions.hostingSystem.(*container).vsmbShares.guids = make(map[string]int)
	}
	var vsmbAdded []string
	for _, layerPath := range createOptions.spec.Windows.LayerFolders[:len(createOptions.spec.Windows.LayerFolders)-1] {
		logrus.Debugf("Processing layerPath %s as read-only VSMB share", layerPath)
		_, filename := filepath.Split(layerPath)
		guid, err := NameToGuid(filename)
		if err != nil {
			removeVSMBOnFailure(createOptions.hostingSystem, vsmbAdded)
			createOptions.hostingSystem.(*container).vsmbShares.Unlock()
			return nil, err
		}
		if _, ok := createOptions.hostingSystem.(*container).vsmbShares.guids[guid.ToString()]; !ok {
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
			if err := createOptions.hostingSystem.Modify(modification); err != nil {
				createOptions.hostingSystem.(*container).vsmbShares.Unlock()
				removeVSMBOnFailure(createOptions.hostingSystem, vsmbAdded)
				return nil, err
			}
			createOptions.hostingSystem.(*container).vsmbShares.guids[guid.ToString()] = 1
		} else {
			createOptions.hostingSystem.(*container).vsmbShares.guids[guid.ToString()]++
			logrus.Debugf("Processing layerPath %s: Incremented refcount to: %d", layerPath, createOptions.hostingSystem.(*container).vsmbShares.guids[guid.ToString()])
		}
		vsmbAdded = append(vsmbAdded, guid.ToString())
	}
	createOptions.hostingSystem.(*container).vsmbShares.Unlock()

	//
	// Add the sandbox to the SCSI controller
	//

	controller, lun, err := allocateSCSI(createOptions.hostingSystem.(*container))
	if err != nil {
		removeVSMBOnFailure(createOptions.hostingSystem, vsmbAdded)
		return nil, err
	}

	// TODO: Currently GCS doesn't support more than one SCSI controller. @jhowardmsft/@swernli. This will hopefully be fixed in GCS for RS5.
	// It will also require the HostedSettings to be extended in the call below to include the controller as well as the LUN.
	if controller > 0 {
		return nil, fmt.Errorf("too many SCSI attachments for a single controller")
	}

	_, sandboxPath := filepath.Split(createOptions.spec.Windows.LayerFolders[len(createOptions.spec.Windows.LayerFolders)-1])
	containerPathGUID, err := NameToGuid(sandboxPath)
	if err != nil {
		removeVSMBOnFailure(createOptions.hostingSystem, vsmbAdded)
		return nil, err
	}
	sandboxModification := &ModifySettingsRequestV2{
		ResourceType: ResourceTypeMappedVirtualDisk,
		RequestType:  RequestTypeAdd,
		Settings: VirtualMachinesResourcesStorageAttachmentV2{
			Path: filepath.Join(createOptions.spec.Windows.LayerFolders[len(createOptions.spec.Windows.LayerFolders)-1], "sandbox.vhdx"),
			Type: "VirtualDisk",
		},
		ResourceUri: fmt.Sprintf("VirtualMachine/Devices/SCSI/%d/%d", controller, lun),
		HostedSettings: ContainersResourcesMappedDirectoryV2{
			ContainerPath: fmt.Sprintf(`C:\%s`, containerPathGUID.ToString()),
			Lun:           uint8(lun),
		},
	}
	if err := createOptions.hostingSystem.Modify(sandboxModification); err != nil {
		removeVSMBOnFailure(createOptions.hostingSystem, vsmbAdded)
		return nil, err
	}

	//
	// Setup the storage filter in the utility VM
	//

	layers := []ContainersResourcesLayerV2{}
	for _, vsmb := range vsmbAdded {
		layers = append(layers, ContainersResourcesLayerV2{
			Id:   vsmb,
			Path: fmt.Sprintf(`\\?\VMSMB\VSMB-{dcc079ae-60ba-4d07-847c-3493609c0870}\%s`, vsmb),
		})
	}
	combinedLayersModification := &ModifySettingsRequestV2{
		ResourceType: ResourceTypeCombinedLayers,
		RequestType:  RequestTypeAdd,
		HostedSettings: CombinedLayersV2{
			ContainerRootPath: fmt.Sprintf(`C:\%s`, containerPathGUID.ToString()),
			Layers:            layers,
		},
	}
	if err := createOptions.hostingSystem.Modify(combinedLayersModification); err != nil {
		removeVSMBOnFailure(createOptions.hostingSystem, vsmbAdded)
		removeSCSIOnFailure(createOptions.hostingSystem, controller, lun)
		return nil, err
	}

	// Create the container

	hostedSystem := &HostedSystemV2{
		SchemaVersion: SchemaV20(),
		Container: &ContainerV2{
			Storage: &ContainersResourcesStorageV2{
				// TODO Open query with @swernli. Only the path should in theory be needed where the union FS is exposed. However, layers are also required currently.
				// It's used for the registry filter. IMO, there should probably be a call similar to CombinedLayers to load the registry filter.
				Layers: layers,
				Path:   fmt.Sprintf(`C:\%s`, containerPathGUID.ToString()),
			},
		},
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
		removeVSMBOnFailure(createOptions.hostingSystem, vsmbAdded)
		removeSCSIOnFailure(createOptions.hostingSystem, controller, lun)
		return nil, err
	}
	logrus.Debugf("HCSShim: definition: %s", string(computeSystemV2b))
	hostedContainer, err := createContainer(createOptions.id, string(computeSystemV2b), SchemaV20())
	if err != nil {
		removeVSMBOnFailure(createOptions.hostingSystem, vsmbAdded)
		removeSCSIOnFailure(createOptions.hostingSystem, controller, lun)
		return nil, err
	}
	return hostedContainer, nil
}
