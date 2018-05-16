// +build windows

package hcsshim

// Containers functions relating to an LCOW utility VM (implying v2)

import (
	"encoding/json"
	"fmt"
	//"os"
	//	"path/filepath"

	//specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/Microsoft/hcsshim/schemaversion"
	"github.com/sirupsen/logrus"
)

func createLCOWv2UVM(coi *createOptionsExInternal) (Container, error) {
	logrus.Debugf("hcsshim::createLCOWv2UVM Creating utility VM id=%s", coi.actualId)

	iocis := "invalid OCI spec:"
	if len(coi.Spec.Windows.LayerFolders) < 2 {
		return nil, fmt.Errorf("%s Windows.LayerFolders must have length of at least 2 for a hosting system", iocis)
	}
	if len(coi.Spec.Hostname) > 0 {
		return nil, fmt.Errorf("%s Hostname cannot be set for a hosting system", iocis)
	}
	if coi.Spec.Windows.Resources != nil && coi.Spec.Windows.Resources.CPU != nil && coi.Spec.Windows.Resources.CPU.Shares != nil {
		return nil, fmt.Errorf("%s Windows.Resources.CPU.Shares must not be set for a hosting system", iocis)
	}
	if coi.Spec.Windows.Resources != nil && coi.Spec.Windows.Resources.CPU != nil && coi.Spec.Windows.Resources.CPU.Maximum != nil {
		return nil, fmt.Errorf("%s Windows.Resources.CPU.Maximum must not be set for a hosting system", iocis)
	}
	// LCOW Only when combine.
	//	if coi.Spec.Root != nil {
	//		return nil, fmt.Errorf("%s Root must not be set for a hosting system", iocis)
	//	}
	if coi.Spec.Windows.Resources != nil && coi.Spec.Windows.Resources.Storage != nil {
		return nil, fmt.Errorf("%s Windows.Resources.Storage must not be set for a hosting system", iocis)
	}
	if coi.Spec.Windows.CredentialSpec != nil {
		return nil, fmt.Errorf("%s Windows.CredentialSpec must not be set for a hosting system", iocis)
	}
	if coi.Spec.Windows.Network != nil {
		return nil, fmt.Errorf("%s Windows.Network must not be set for a hosting system", iocis) // Need to revisit, but blocking everything currently not hooked up
	}
	//	if 0 != len(coi.Spec.Mounts) {
	//		return nil, fmt.Errorf("%s Mounts must not be set for a hosting system", iocis)
	//	}

	//	uvmFolder, err := LocateWCOWUVMFolderFromLayerFolders(coi.Spec.Windows.LayerFolders)
	//	if err != nil {
	//		return nil, fmt.Errorf("failed to locate utility VM folder from layer folders: %s", err)
	//	}
	//	// Create the sandbox in the top-most layer folder, creating the folder if it doesn't already exist.
	sandboxFolder := coi.Spec.Windows.LayerFolders[len(coi.Spec.Windows.LayerFolders)-1]
	logrus.Debugf("hcsshim::createWCOWv2UVM Sandbox folder: %s", sandboxFolder)

	//	// Create the directory if it doesn't exist
	//	if _, err := os.Stat(sandboxFolder); os.IsNotExist(err) {
	//		logrus.Debugf("hcsshim::createWCOWv2UVM Creating folder: %s ", sandboxFolder)
	//		if err := os.MkdirAll(sandboxFolder, 0777); err != nil {
	//			return nil, fmt.Errorf("failed to create utility VM sandbox folder: %s", err)
	//		}
	//	}

	//	// Create sandbox.vhdx in the sandbox folder based on the template, granting the correct permissions to it
	//	if err := CreateWCOWUVMSandbox(uvmFolder, sandboxFolder, coi.actualId); err != nil {
	//		return nil, fmt.Errorf("failed to create UVM sandbox: %s", err)
	//	}

	//	attachments := make(map[string]VirtualMachinesResourcesStorageAttachmentV2)
	//	attachments["0"] = VirtualMachinesResourcesStorageAttachmentV2{
	//		Path: filepath.Join(sandboxFolder, "sandbox.vhdx"),
	//		Type: "VirtualDisk",
	//	}
	scsi := make(map[string]VirtualMachinesResourcesStorageScsiV2)

	//	scsi["0"] = VirtualMachinesResourcesStorageScsiV2{Attachments: attachments}
	memory := int32(1024)
	processors := int32(2)
	if numCPU() == 1 {
		processors = 1
	}
	if coi.Spec.Windows.Resources != nil {
		if coi.Spec.Windows.Resources.Memory != nil && coi.Spec.Windows.Resources.Memory.Limit != nil {
			memory = int32(*coi.Spec.Windows.Resources.Memory.Limit / 1024 / 1024) // OCI spec is in bytes. HCS takes MB
		}
		if coi.Spec.Windows.Resources.CPU != nil && coi.Spec.Windows.Resources.CPU.Count != nil {
			processors = int32(*coi.Spec.Windows.Resources.CPU.Count)
		}
	}

	//baseLayerFolder := coi.Spec.Windows.LayerFolders[len(coi.Spec.Windows.LayerFolders)-2]

	uvm := &ComputeSystemV2{
		Owner:         coi.actualOwner,
		SchemaVersion: coi.actualSchemaVersion,
		VirtualMachine: &VirtualMachineV2{
			Chipset: &VirtualMachinesResourcesChipsetV2{
				UEFI: &VirtualMachinesResourcesUefiV2{
					BootThis: &VirtualMachinesResourcesUefiBootEntryV2{
						DevicePath:   `\` + coi.actualKernelFile,
						DiskNumber:   0,
						UefiDevice:   "VMBFS",
						OptionalData: `\` + coi.actualInitrdFile,
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
				VPMem: &VirtualMachinesResourcesStorageVpmemControllerV2{
					MaximumCount: 16, // TODO Why? From R's example
				},
				SCSI: scsi,
				VirtualSMBShares: []VirtualMachinesResourcesStorageVSmbShareV2{VirtualMachinesResourcesStorageVSmbShareV2{
					Flags: VsmbFlagReadOnly | VsmbFlagShareRead | VsmbFlagCacheIO | VsmbFlagTakeBackupPrivilege, // 0x17 (23 dec)
					Name:  "os",
					Path:  coi.actualKirdPath,
				}},
				GuestInterface: &VirtualMachinesResourcesGuestInterfaceV2{
					ConnectToBridge: true,
					BridgeFlags:     3, // TODO What are these??
				},
			},
		},
	}

	uvmb, err := json.Marshal(uvm)
	if err != nil {
		return nil, err
	}
	uvmContainer, err := createContainer(coi.actualId, string(uvmb), schemaversion.SchemaV20())
	if err != nil {
		logrus.Debugln("failed to create UVM: ", err)
		return nil, err
	}
	//uvmContainer.(*container).scsiLocations.hostPath[0][0] = attachments["0"].Path
	return uvmContainer, nil
}
