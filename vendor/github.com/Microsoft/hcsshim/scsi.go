package hcsshim

import (
	"fmt"

	"github.com/sirupsen/logrus"
)

// allocateSCSI finds the next available slot on the
// SCSI controllers associated with a utility VM to use.
func allocateSCSI(container *container, hostPath string) (int, int, error) {
	if container == nil {
		return -1, -1, fmt.Errorf("allocateSCSI was not passed a container object")
	}
	container.scsiLocations.Lock()
	defer container.scsiLocations.Unlock()
	for controller, luns := range container.scsiLocations.hostPath {
		for lun, hp := range luns {
			if hp == "" {
				container.scsiLocations.hostPath[controller][lun] = hostPath
				logrus.Debugf("hcsshim::allocateSCSI %d:%d %q", controller, lun, hostPath)
				return controller, lun, nil

			}
		}
	}
	return -1, -1, fmt.Errorf("no free SCSI locations")
}

func deallocateSCSI(container *container, controller int, lun int) error {
	if container == nil {
		return fmt.Errorf("allocateSCSI was not passed a container object")
	}
	container.scsiLocations.Lock()
	defer container.scsiLocations.Unlock()
	container.scsiLocations.hostPath[controller][lun] = ""
	return nil
}

// Lock must be held when calling this function
func findSCSIAttachment(container *container, findThisHostPath string) (int, int, error) {
	if container == nil {
		return -1, -1, fmt.Errorf("findSCSIAttachment was not passed a container object")
	}
	for controller, slots := range container.scsiLocations.hostPath {
		for slot, hostPath := range slots {
			if hostPath == findThisHostPath {
				logrus.Debugf("hcsshim::findSCSIAttachment %d:%d %s", controller, slot, hostPath)
				return controller, slot, nil
			}
		}
	}
	return -1, -1, fmt.Errorf("%s is not attached to SCSI", findThisHostPath)
}

// AddSCSI adds a SCSI disk to a utility VM at the next available location.
//
// In the v1 world, we do the modify call, HCS allocates a place on the SCSI bus,
// and we have to query back to HCS to determine where it landed.
//
// In the v2 world, we are in control of everything ourselves. Hence we have ref-
// counting and so-on tracking what SCSI locations are available or used.
//
// hostPath is required
// containerPath is optional.
//
// Returns the controller ID (0..3) and LUN (0..63) where the disk is attached.
//
// TODO: Consider a structure here so that we can extend for future functionality without
//       breaking the API surface.
func AddSCSI(uvm Container, hostPath string, containerPath string) (int, int, error) {
	controller := -1
	lun := -1
	if uvm == nil {
		return -1, -1, fmt.Errorf("no utility VM passed to AddSCSI")
	}
	uvmc := uvm.(*container)
	logrus.Debugf("hcsshim::AddSCSI id:%s hostPath:%s containerPath:%s sv:%s", uvmc.id, hostPath, containerPath, uvmc.schemaVersion.String())

	if uvmc.schemaVersion.IsV10() {
		modification := &ResourceModificationRequestResponse{
			Resource: "MappedVirtualDisk",
			Data: MappedVirtualDisk{
				HostPath:          hostPath,
				ContainerPath:     containerPath,
				CreateInUtilityVM: true,
				AttachOnly:        (containerPath == ""),
			},
			Request: "Add",
		}
		if err := uvmc.Modify(modification); err != nil {
			return -1, -1, fmt.Errorf("hcsshim::AddSCSI: failed to modify utility VM configuration: %s", err)
		}

		// Get the list of mapped virtual disks to find the controller and LUN IDs
		logrus.Debugf("hcsshim::AddSCSI: %s querying mapped virtual disks", hostPath)
		mvdControllers, err := uvmc.MappedVirtualDisks()
		if err != nil {
			return -1, -1, fmt.Errorf("failed to get mapped virtual disks: %s", err)
		}

		// Find our mapped disk from the list of all currently added.
		for controllerNumber, controllerElement := range mvdControllers {
			for diskNumber, diskElement := range controllerElement.MappedVirtualDisks {
				if diskElement.HostPath == hostPath {
					controller = controllerNumber
					lun = diskNumber
					break
				}
			}
		}
		if controller == -1 || lun == -1 {
			// We're somewhat stuffed here. Can't remove it as we don't know the controller/lun
			return -1, -1, fmt.Errorf("failed to find %s in mapped virtual disks after hot-adding", hostPath)
		}

		uvmc.scsiLocations.Lock()
		defer uvmc.scsiLocations.Unlock()
		if uvmc.scsiLocations.hostPath[controller][lun] != "" {
			removeSCSI(uvm, hostPath, controller, lun)
			return -1, -1, fmt.Errorf("internal consistency error - %d:%d is in use by %s", controller, lun, hostPath)
		}
		uvmc.scsiLocations.hostPath[controller][lun] = hostPath

		logrus.Debugf("hcsshim::AddSCSI success id:%s hostPath:%s added at %d:%d sv:%s", uvmc.id, hostPath, controller, lun, uvmc.schemaVersion.String())
		return controller, lun, nil
	}

	// V2 Schema
	var err error
	controller, lun, err = allocateSCSI(uvmc, hostPath)
	if err != nil {
		return -1, -1, err
	}

	// TODO: Currently GCS doesn't support more than one SCSI controller. @jhowardmsft/@swernli. This will hopefully be fixed in GCS for RS5.
	// It will also require the HostedSettings to be extended in the call below to include the controller as well as the LUN.
	if controller > 0 {
		return -1, -1, fmt.Errorf("too many SCSI attachments")
	}

	SCSIModification := &ModifySettingsRequestV2{
		ResourceType: ResourceTypeMappedVirtualDisk,
		RequestType:  RequestTypeAdd,
		Settings: VirtualMachinesResourcesStorageAttachmentV2{
			Path: hostPath,
			Type: "VirtualDisk",
		},
		ResourceUri: fmt.Sprintf("VirtualMachine/Devices/SCSI/%d/%d", controller, lun),
		HostedSettings: ContainersResourcesMappedDirectoryV2{
			ContainerPath: containerPath,
			Lun:           uint8(lun),
			AttachOnly:    (containerPath == ""),
			// TODO: Controller: uint8(controller), // TODO NOT IN HCS API CURRENTLY
		},
	}
	if err := uvm.Modify(SCSIModification); err != nil {
		deallocateSCSI(uvmc, controller, lun)
		return -1, -1, fmt.Errorf("hcsshim::AddSCSI: failed to modify utility VM configuration: %s", err)
	}
	logrus.Debugf("hcsshim::AddSCSI id:%s hostPath:%s added at %d:%d sv:%s", uvmc.id, hostPath, controller, lun, uvmc.schemaVersion.String())
	return controller, lun, nil

}

// RemoveSCSI removes a SCSI disk from a utility VM. As an external API, it
// is "safe". Internal use can call removeSCSI.
func RemoveSCSI(uvm Container, hostPath string) error {
	if uvm == nil {
		return fmt.Errorf("no utility VM passed to RemoveSCSI")
	}
	uvmc := uvm.(*container)
	uvmc.scsiLocations.Lock()
	defer uvmc.scsiLocations.Unlock()

	// Make sure is actually attached
	controller, lun, err := findSCSIAttachment(uvmc, hostPath)
	if err != nil {
		return fmt.Errorf("cannot remove SCSI disk %s as it is not attached to container %s: %s", hostPath, uvmc.id, err)
	}

	if err := removeSCSI(uvm, hostPath, controller, lun); err != nil {
		return fmt.Errorf("failed to remove SCSI disk %s from container %s: %s", hostPath, uvmc.id, err)

	}
	return nil
}

// removeSCSI is the internally callable "unsafe" version of RemoveSCSI. The mutex
// MUST be held when calling this function.
func removeSCSI(uvm Container, hostPath string, controller int, lun int) error {
	var scsiModification interface{}
	logrus.Debugf("hcsshim::RemoveSCSI id:%s hostPath:%s sv:%s", uvm.(*container).id, hostPath, uvm.(*container).schemaVersion.String())
	if uvm.(*container).schemaVersion.IsV10() {
		scsiModification = &ResourceModificationRequestResponse{
			Resource: "MappedVirtualDisk",
			Data: MappedVirtualDisk{
				HostPath:          hostPath,
				CreateInUtilityVM: true,
			},
			Request: "Remove",
		}
	} else {
		scsiModification = &ModifySettingsRequestV2{
			ResourceType: ResourceTypeMappedVirtualDisk,
			RequestType:  RequestTypeRemove,
			ResourceUri:  fmt.Sprintf("VirtualMachine/Devices/SCSI/%d/%d", controller, lun),
		}
	}
	if err := uvm.Modify(scsiModification); err != nil {
		return err
	}
	uvm.(*container).scsiLocations.hostPath[controller][lun] = ""
	logrus.Debugf("hcsshim::RemoveSCSI: Success %s removed from %s %d:%d", hostPath, uvm.(*container).id, controller, lun)
	return nil
}
