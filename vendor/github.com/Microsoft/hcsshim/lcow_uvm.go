// +build windows

package hcsshim

// Containers functions relating to an LCOW utility VM (implying v2)

import (
	"encoding/json"
	"fmt"

	//specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/Microsoft/hcsshim/schema/v2"
	"github.com/Microsoft/hcsshim/schemaversion"
	"github.com/sirupsen/logrus"
)

func createLCOWv2UVM(coi *createOptionsExInternal) (Container, error) {
	logrus.Debugf("hcsshim::createLCOWv2UVM Creating utility VM id=%s", coi.actualId)

	iocis := "invalid OCI spec:"
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

	//	// See if there's a sandbox folder at the end of the layer folders. If it is, then we attach this to SCSI.
	//	// We look for a .vhdx in that folder as the key. RO layers are .vhd.
	//	possibleSandboxFolder := coi.Spec.Windows.LayerFolders[len(coi.Spec.Windows.LayerFolders)-1]
	//	sandboxFile := ""

	//	err := filepath.Walk(possibleSandboxFolder, func(path string, info os.FileInfo, err error) error {
	//		if info.IsDir() {
	//			return nil
	//		}
	//		if filepath.Ext(path) == ".vhdx" {
	//			sandboxFile = path
	//			return io.EOF // Trick to break out early.
	//		}
	//		return nil
	//	})
	//	if err == io.EOF {
	//		err = nil
	//	}

	scsi := make(map[string]hcsschemav2.VirtualMachinesResourcesStorageScsiV2)
	scsi["0"] = hcsschemav2.VirtualMachinesResourcesStorageScsiV2{Attachments: make(map[string]hcsschemav2.VirtualMachinesResourcesStorageAttachmentV2)}
	//	if sandboxFile != "" {
	//		if err := GrantVmAccess(coi.actualId, sandboxFile); err != nil {
	//			return nil, err
	//		}
	//	}

	c := container{}
	uvm := &hcsschemav2.ComputeSystemV2{
		Owner:         coi.actualOwner,
		SchemaVersion: coi.actualSchemaVersion,
		VirtualMachine: &hcsschemav2.VirtualMachineV2{
			Chipset: &hcsschemav2.VirtualMachinesResourcesChipsetV2{
				UEFI: &hcsschemav2.VirtualMachinesResourcesUefiV2{
					BootThis: &hcsschemav2.VirtualMachinesResourcesUefiBootEntryV2{
						DevicePath:   `\` + coi.actualKernelFile,
						DiskNumber:   0,
						UefiDevice:   "VMBFS",
						OptionalData: `initrd=\` + coi.actualInitrdFile,
					},
				},
			},
			ComputeTopology: &hcsschemav2.VirtualMachinesResourcesComputeTopologyV2{
				Memory: &hcsschemav2.VirtualMachinesResourcesComputeMemoryV2{
					Backing: "Virtual",
					Startup: memory,
				},
				Processor: &hcsschemav2.VirtualMachinesResourcesComputeProcessorV2{
					Count: processors,
				},
			},

			Devices: &hcsschemav2.VirtualMachinesDevicesV2{
				// Add networking here.... TODO
				VPMem: &hcsschemav2.VirtualMachinesResourcesStorageVpmemControllerV2{
					MaximumCount: int32(len(c.vpmemLocations.hostPath)), //16, // TODO Why? From R's example
				},
				SCSI: scsi,
				VirtualSMBShares: []hcsschemav2.VirtualMachinesResourcesStorageVSmbShareV2{hcsschemav2.VirtualMachinesResourcesStorageVSmbShareV2{
					Flags: hcsschemav2.VsmbFlagReadOnly | hcsschemav2.VsmbFlagShareRead | hcsschemav2.VsmbFlagCacheIO | hcsschemav2.VsmbFlagTakeBackupPrivilege, // 0x17 (23 dec)
					Name:  "os",
					Path:  coi.actualKirdPath,
				}},
				GuestInterface: &hcsschemav2.VirtualMachinesResourcesGuestInterfaceV2{
					ConnectToBridge: true,
					BridgeFlags:     3, // TODO What are these??
				},
			},
		},
	}

	// Additional JSON for debugging
	//{
	//    "VirtualMachine": {
	//        "Chipset": {
	//            "UEFI": {
	//                "BootThis": {
	//                    "optional_data": "initrd=\\initrd.img console=ttyS0,115200",
	//                }
	//            }
	//        },
	//        "Devices": {
	//            "COMPorts": {
	//                "Port1": "\\\\.\\pipe\\vmpipe"
	//            },
	//            "Keyboard": {},
	//            "Rdp": {},
	//            "VideoMonitor": {},
	//        }
	//    }
	//}

	if coi.KernelBootOptions != "" {
		uvm.VirtualMachine.Chipset.UEFI.BootThis.OptionalData = uvm.VirtualMachine.Chipset.UEFI.BootThis.OptionalData + fmt.Sprintf(" %s", coi.KernelBootOptions)
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
	//	if sandboxFile != "" {
	//		_, _, err := AddSCSI(uvmContainer, sandboxFile, "/tmp/scratch")
	//		if err != nil {
	//			uvmContainer.Terminate()
	//			return nil, err
	//		}

	//	}
	return uvmContainer, nil
}
