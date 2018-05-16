package hcsshim

import (
	"fmt"
	"strconv"

	"github.com/sirupsen/logrus"
)

// allocateVPMEM finds the next available slot on the
// VPMEM controllers associated with a utility VM to use.
func allocateVPMEM(container *container, hostPath string) (int, uint8, error) {
	if container == nil {
		return -1, 0, fmt.Errorf("allocateVPMEM was not passed a container object")
	}
	container.vpmemLocations.Lock()
	defer container.vpmemLocations.Unlock()
	for controller, locations := range container.vpmemLocations.hostPath {
		for location, hp := range locations {
			if hp == "" {
				container.vpmemLocations.hostPath[controller][location] = hostPath
				logrus.Debugf("hcsshim::allocateVPMEM %d:%d %q", controller, location, hostPath)
				return controller, uint8(location), nil

			}
		}
	}
	return -1, 0, fmt.Errorf("no free VPMEM locations")
}

func deallocateVPMEM(container *container, controller int, location uint8) error {
	if container == nil {
		return fmt.Errorf("allocateVPMEM was not passed a container object")
	}
	container.vpmemLocations.Lock()
	defer container.vpmemLocations.Unlock()
	container.vpmemLocations.hostPath[controller][location] = ""
	return nil
}

// Lock must be held when calling this function
func findVPMEMAttachment(container *container, findThisHostPath string) (int, uint8, error) {
	if container == nil {
		return -1, 0, fmt.Errorf("findVPMEMAttachment was not passed a container object")
	}
	for controller, locations := range container.vpmemLocations.hostPath {
		for location, hostPath := range locations {
			if hostPath == findThisHostPath {
				logrus.Debugf("hcsshim::findVPMEMAttachment %d:%d %s", controller, location, hostPath)
				return controller, uint8(location), nil
			}
		}
	}
	return -1, 0, fmt.Errorf("%s is not attached to VPMEM", findThisHostPath)
}

// AddVPMEM adds a VPMEM disk to a utility VM at the next available location.
//
// This is only supported for v2 schema.
//
// Returns the controller ID (0..0) and location(0..255) where the disk is attached.
//
// TODO: Consider a structure here so that we can extend for future functionality without
//       breaking the API surface.
func AddVPMEM(uvm Container, hostPath string, containerPath string) (int, uint8, error) {
	controller := -1
	var location uint8
	if uvm == nil {
		return -1, 0, fmt.Errorf("no utility VM passed to AddVPMEM")
	}
	uvmc := uvm.(*container)
	logrus.Debugf("hcsshim::AddVPMEM id:%s hostPath:%s containerPath:%s sv:%s", uvmc.id, hostPath, containerPath, uvmc.schemaVersion.String())

	if uvmc.schemaVersion.IsV10() {
		return -1, 0, fmt.Errorf("AddVPMEM not supported on v1 schema utility VMs")
	}

	var err error
	controller, location, err = allocateVPMEM(uvmc, hostPath)
	if err != nil {
		return -1, 0, err
	}

	// TODO: Assuming max of one controller currently.
	if controller > 0 {
		return -1, 0, fmt.Errorf("too many VPMEM attachments")
	}

	devices := make(map[string]VirtualMachinesResourcesStorageVpmemDeviceV2)
	devices[strconv.Itoa(controller)] = VirtualMachinesResourcesStorageVpmemDeviceV2{
		HostPath:    hostPath,
		ReadOnly:    true,
		ImageFormat: "VHD1",
	}

	hostedSettings := MappedVPMemController{}
	hostedSettings.MappedDevices = make(map[uint8]string)
	hostedSettings.MappedDevices[location] = fmt.Sprintf("/tmp/vpmem%d/%d", controller, location)

	VPMEMModification := &ModifySettingsRequestV2{
		ResourceType:   ResourceTypeVPMemDevice,
		RequestType:    RequestTypeAdd,
		Settings:       devices,
		HostedSettings: hostedSettings,
	}
	if err := uvm.Modify(VPMEMModification); err != nil {
		deallocateVPMEM(uvmc, controller, location)
		return -1, 0, fmt.Errorf("hcsshim::AddVPMEM: failed to modify utility VM configuration: %s", err)
	}
	logrus.Debugf("hcsshim::AddVPMEM id:%s hostPath:%s added at %d:%d", uvmc.id, hostPath, controller, location)
	return controller, location, nil
}

// RemoveVPMEM removes a VPMEM disk from a utility VM. As an external API, it
// is "safe". Internal use can call removeVPMEM.
func RemoveVPMEM(uvm Container, hostPath string) error {
	if uvm == nil {
		return fmt.Errorf("no utility VM passed to RemoveVPMEM")
	}
	uvmc := uvm.(*container)
	uvmc.vpmemLocations.Lock()
	defer uvmc.vpmemLocations.Unlock()

	// Make sure is actually attached
	controller, location, err := findVPMEMAttachment(uvmc, hostPath)
	if err != nil {
		return fmt.Errorf("cannot remove VPMEM %s as it is not attached to container %s: %s", hostPath, uvmc.id, err)
	}

	if err := removeVPMEM(uvm, hostPath, controller, location); err != nil {
		return fmt.Errorf("failed to remove VPMEM %s from container %s: %s", hostPath, uvmc.id, err)
	}
	return nil
}

// removeVPMEM is the internally callable "unsafe" version of RemoveVPMEM. The mutex
// MUST be held when calling this function.
func removeVPMEM(uvm Container, hostPath string, controller int, location uint8) error {
	logrus.Debugf("hcsshim::RemoveVPMEM id:%s hostPath:%s", uvm.(*container).id, hostPath)
	if uvm.(*container).schemaVersion.IsV10() {
		return fmt.Errorf("RemoveVPMEM not supported on v1 schema utility VMs")
	}

	vpmemModification := &ModifySettingsRequestV2{
	//			ResourceType: ResourceTypeMappedVirtualDisk,
	//			RequestType:  RequestTypeRemove,
	//			ResourceUri:  fmt.Sprintf("VirtualMachine/Devices/SCSI/%d/%d", controller, lun),

	}

	panic("JJH not yet implemented")
	if err := uvm.Modify(vpmemModification); err != nil {
		return err
	}
	uvm.(*container).vpmemLocations.hostPath[controller][location] = ""
	logrus.Debugf("hcsshim::RemoveVPMEM: Success %s removed from %s %d:%d", hostPath, uvm.(*container).id, controller, location)
	return nil
}
