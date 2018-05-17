// +build windows

package hcsshim

import (
	"fmt"
	"strconv"

	"github.com/Microsoft/hcsshim/schema/v2"
	"github.com/sirupsen/logrus"
)

// allocateVPMEM finds the next available VPMem slot
func allocateVPMEM(container *container, hostPath string) (int, error) {
	if container == nil {
		return -1, fmt.Errorf("allocateVPMEM was not passed a container object")
	}
	container.vpmemLocations.Lock()
	defer container.vpmemLocations.Unlock()
	for index, currentValue := range container.vpmemLocations.hostPath {
		if currentValue == "" {
			container.vpmemLocations.hostPath[index] = hostPath
			logrus.Debugf("hcsshim::allocateVPMEM %d %q", index, hostPath)
			return index, nil

		}
	}
	return -1, fmt.Errorf("no free VPMEM locations")
}

func deallocateVPMEM(container *container, location int) error {
	if container == nil {
		return fmt.Errorf("allocateVPMEM was not passed a container object")
	}
	container.vpmemLocations.Lock()
	defer container.vpmemLocations.Unlock()
	container.vpmemLocations.hostPath[location] = ""
	return nil
}

// Lock must be held when calling this function
func findVPMEMAttachment(container *container, findThisHostPath string) (int, error) {
	if container == nil {
		return -1, fmt.Errorf("findVPMEMAttachment was not passed a container object")
	}
	for index, currentValue := range container.vpmemLocations.hostPath {
		if currentValue == findThisHostPath {
			logrus.Debugf("hcsshim::findVPMEMAttachment %d %s", index, findThisHostPath)
			return index, nil
		}

	}
	return -1, fmt.Errorf("%s is not attached to VPMEM", findThisHostPath)
}

// AddVPMEM adds a VPMEM disk to a utility VM at the next available location.
//
// This is only supported for v2 schema linux utility VMs
//
// Returns the location(0..255) where the device is attached, and if exposed,
// the container path which will be /tmp/vpmem<location>/ if no container path
// is supplied, or the user supplied one if it is.
//
// TODO: Consider a structure here so that we can extend for future functionality without
//       breaking the API surface.
func AddVPMEM(uvm Container, hostPath string, containerPath string, expose bool) (int, string, error) {
	location := -1
	if uvm == nil {
		return -1, "", fmt.Errorf("no utility VM passed to AddVPMEM")
	}
	uvmc := uvm.(*container)
	logrus.Debugf("hcsshim::AddVPMEM id:%s hostPath:%s containerPath:%s expose:%t sv:%s", uvmc.id, hostPath, containerPath, expose, uvmc.schemaVersion.String())

	if uvmc.schemaVersion.IsV10() {
		return -1, "", fmt.Errorf("AddVPMEM not supported on v1 schema utility VMs")
	}

	// BIG TODO: We need to store the hosted settings to so that on release we can tell GCS to flush.

	var err error
	location, err = allocateVPMEM(uvmc, hostPath)
	if err != nil {
		return -1, "", err
	}
	controller := hcsschemav2.VirtualMachinesResourcesStorageVpmemControllerV2{}
	controller.Devices = make(map[string]hcsschemav2.VirtualMachinesResourcesStorageVpmemDeviceV2)
	controller.Devices[strconv.Itoa(location)] = hcsschemav2.VirtualMachinesResourcesStorageVpmemDeviceV2{
		HostPath:    hostPath,
		ReadOnly:    true,
		ImageFormat: "VHD1",
	}

	modification := &hcsschemav2.ModifySettingsRequestV2{
		ResourceType: hcsschemav2.ResourceTypeVPMemDevice,
		RequestType:  hcsschemav2.RequestTypeAdd,
		Settings:     controller,
	}

	if expose {
		if containerPath == "" {
			containerPath = fmt.Sprintf("/tmp/vpmem%d", location)
		}
		hostedSettings := hcsschemav2.MappedVPMemController{}
		hostedSettings.MappedDevices = make(map[int]string)
		hostedSettings.MappedDevices[location] = containerPath
		modification.HostedSettings = hostedSettings
	}

	if err := uvm.Modify(modification); err != nil {
		deallocateVPMEM(uvmc, location)
		return -1, "", fmt.Errorf("hcsshim::AddVPMEM: failed to modify utility VM configuration: %s", err)
	}
	logrus.Debugf("hcsshim::AddVPMEM id:%s hostPath:%s added at %d", uvmc.id, hostPath, location)
	return location, containerPath, nil
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
	location, err := findVPMEMAttachment(uvmc, hostPath)
	if err != nil {
		return fmt.Errorf("cannot remove VPMEM %s as it is not attached to container %s: %s", hostPath, uvmc.id, err)
	}

	if err := removeVPMEM(uvm, hostPath, location); err != nil {
		return fmt.Errorf("failed to remove VPMEM %s from container %s: %s", hostPath, uvmc.id, err)
	}
	return nil
}

// removeVPMEM is the internally callable "unsafe" version of RemoveVPMEM. The mutex
// MUST be held when calling this function.
func removeVPMEM(uvm Container, hostPath string, location int) error {
	logrus.Debugf("hcsshim::RemoveVPMEM id:%s hostPath:%s", uvm.(*container).id, hostPath)
	if uvm.(*container).schemaVersion.IsV10() {
		return fmt.Errorf("RemoveVPMEM not supported on v1 schema utility VMs")
	}

	vpmemModification := &hcsschemav2.ModifySettingsRequestV2{
	//			ResourceType: hcsschemav2.ResourceTypeMappedVirtualDisk,
	//			RequestType:  hcsschemav2.RequestTypeRemove,
	//			ResourceUri:  fmt.Sprintf("VirtualMachine/Devices/SCSI/%d/%d", controller, lun),

	}

	panic("JJH not yet implemented")
	if err := uvm.Modify(vpmemModification); err != nil {
		return err
	}
	uvm.(*container).vpmemLocations.hostPath[location] = ""
	logrus.Debugf("hcsshim::RemoveVPMEM: Success %s removed from %s %d", hostPath, uvm.(*container).id, location)
	return nil
}
