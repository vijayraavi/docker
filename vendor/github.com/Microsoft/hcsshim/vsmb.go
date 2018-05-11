package hcsshim

import (
	"fmt"
	"path/filepath"

	"github.com/sirupsen/logrus"
)

// AddVSMB adds a VSMB share to a utility VM. Each VSMB share is ref-counted and
// only added if it isn't already.
func AddVSMB(uvm Container, path string, flags int32) (string, error) {
	if uvm == nil {
		return "", fmt.Errorf("no uvm passed to AddVSMB() for %s", path)
	}
	uvmc := uvm.(*container)
	if !uvmc.schemaVersion.IsV20() {
		return "", fmt.Errorf("can only add a VSMB share to a v2-schema utility VM")
	}
	logrus.Debugf("hcsshim::AddVSMB %s id:%s", path, uvmc.id)
	uvmc.vsmbShares.Lock()
	defer uvmc.vsmbShares.Unlock()
	if uvmc.vsmbShares.guids == nil {
		uvmc.vsmbShares.guids = make(map[string]int)
	}
	_, filename := filepath.Split(path)
	guid, err := NameToGuid(filename)
	if err != nil {
		return "", err
	}
	if _, ok := uvmc.vsmbShares.guids[guid.ToString()]; !ok {
		modification := &ModifySettingsRequestV2{
			ResourceType: ResourceTypeVSmbShare,
			RequestType:  RequestTypeAdd,
			Settings: VirtualMachinesResourcesStorageVSmbShareV2{
				Name:  guid.ToString(),
				Flags: flags,
				Path:  path,
			},
			ResourceUri: fmt.Sprintf("virtualmachine/devices/virtualsmbshares/%s", guid.ToString()),
		}
		if err := uvm.Modify(modification); err != nil {
			return "", err
		}
		uvmc.vsmbShares.guids[guid.ToString()] = 1
	} else {
		uvmc.vsmbShares.guids[guid.ToString()]++
	}
	logrus.Debugf("hcsshim::AddVSMB %s: refcount=%d GUID %s", path, uvmc.vsmbShares.guids[guid.ToString()], guid.ToString())
	return guid.ToString(), nil
}

// RemoveVSMB removes a VSMB share from a utility VM. Each VSMB share is ref-counted
// and only actually removed when the ref-count drops to zero.
func RemoveVSMB(uvm Container, path string) error {
	if uvm == nil {
		return fmt.Errorf("no uvm passed to RemoveVSMB() for %s", path)
	}
	uvmc := uvm.(*container)
	if !uvmc.schemaVersion.IsV20() {
		return fmt.Errorf("can only remove a VSMB share from a v2-schema utility VM")
	}
	logrus.Debugf("hcsshim::RemoveVSMB %s id:%s", path, uvmc.id)
	uvmc.vsmbShares.Lock()
	defer uvmc.vsmbShares.Unlock()

	_, filename := filepath.Split(path)
	guid, err := NameToGuid(filename)
	if err != nil {
		return fmt.Errorf("failed to call NameToGuid on %s while removing VSMB from %s: %s. It may be leaked.", path, uvmc.id, err)
	}
	if _, ok := uvmc.vsmbShares.guids[guid.ToString()]; !ok {
		return fmt.Errorf("%s is not present as a VSMB share in %s, cannot remove", path, uvmc.id)
	}
	uvmc.vsmbShares.guids[guid.ToString()]--
	if uvmc.vsmbShares.guids[guid.ToString()] > 0 {
		logrus.Debugf("hcsshim::RemoveVSMB %s id:%s Ref-count now %d. It is still present in the utility VM", path, uvmc.id, uvmc.vsmbShares.guids[guid.ToString()])
	}
	delete(uvmc.vsmbShares.guids, guid.ToString())
	modification := &ModifySettingsRequestV2{
		ResourceType: ResourceTypeVSmbShare,
		RequestType:  RequestTypeRemove,
		Settings:     VirtualMachinesResourcesStorageVSmbShareV2{Name: guid.ToString()},
		ResourceUri:  fmt.Sprintf("virtualmachine/devices/virtualsmbshares/%s", guid.ToString()),
	}
	if err := uvm.Modify(modification); err != nil {
		return fmt.Errorf("failed to remove vsmb share %s from %s: %s: %s", path, uvmc.id, modification, err)
	}
	return nil
}

// removeVSMB removes a VSMB share from a utility VM. The mutex must be
// held when calling this function
func removeVSMB(c Container, id string) error {
	if _, ok := c.(*container).vsmbShares.guids[id]; !ok {
		return fmt.Errorf("failed to remove vsmbShare %s as it is not in utility VM %s", id, c.(*container).id)
	} else {
		c.(*container).vsmbShares.guids[id]--
		logrus.Debugf("hcsshim::removeVSMB: %s refcount after decrement: %d", id, c.(*container).vsmbShares.guids[id])
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
