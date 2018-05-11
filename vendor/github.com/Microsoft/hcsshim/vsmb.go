package hcsshim

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

// AddVSMB adds a VSMB share to a utility VM. Each VSMB share is ref-counted and
// only added if it isn't already.
func AddVSMB(uvm Container, path string, flags int32) error {
	if uvm == nil {
		return fmt.Errorf("no uvm passed to AddVSMB() for %s", path)
	}
	path = strings.ToLower(path)
	uvmc := uvm.(*container)
	if !uvmc.schemaVersion.IsV20() {
		return fmt.Errorf("can only add a VSMB share to a v2-schema utility VM")
	}
	logrus.Debugf("hcsshim::AddVSMB %s id:%s", path, uvmc.id)
	uvmc.vsmbShares.Lock()
	defer uvmc.vsmbShares.Unlock()
	if uvmc.vsmbShares.shares == nil {
		uvmc.vsmbShares.shares = make(map[string]vsmbShare)
	}
	if _, ok := uvmc.vsmbShares.shares[path]; !ok {

		_, filename := filepath.Split(path)
		guid, err := NameToGuid(filename)
		if err != nil {
			return err
		}

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
			return err
		}
		uvmc.vsmbShares.shares[path] = vsmbShare{guid: guid.ToString(), refCount: 1}
	} else {
		s := vsmbShare{guid: uvmc.vsmbShares.shares[path].guid, refCount: uvmc.vsmbShares.shares[path].refCount + 1}
		uvmc.vsmbShares.shares[path] = s
	}
	logrus.Debugf("hcsshim::AddVSMB Success %s: refcount=%d GUID %s", path, uvmc.vsmbShares.shares[path].refCount, uvmc.vsmbShares.shares[path].guid)
	return nil
}

// RemoveVSMB removes a VSMB share from a utility VM. Each VSMB share is ref-counted
// and only actually removed when the ref-count drops to zero.
func RemoveVSMB(uvm Container, path string) error {
	if uvm == nil {
		return fmt.Errorf("no uvm passed to RemoveVSMB() for %s", path)
	}
	path = strings.ToLower(path)
	uvmc := uvm.(*container)
	if !uvmc.schemaVersion.IsV20() {
		return fmt.Errorf("can only remove a VSMB share from a v2-schema utility VM")
	}
	logrus.Debugf("hcsshim::RemoveVSMB %s id:%s", path, uvmc.id)
	uvmc.vsmbShares.Lock()
	defer uvmc.vsmbShares.Unlock()
	if _, ok := uvmc.vsmbShares.shares[path]; !ok {
		return fmt.Errorf("%s is not present as a VSMB share in %s, cannot remove", path, uvmc.id)
	}
	return removeVSMB(uvmc, path)
}

// removeVSMB is the internally callable "unsafe" version of RemoveVSMB. The mutex
// MUST be held when calling this function.
func removeVSMB(uvm Container, path string) error {
	path = strings.ToLower(path)
	uvmc := uvm.(*container)
	s := vsmbShare{guid: uvmc.vsmbShares.shares[path].guid, refCount: uvmc.vsmbShares.shares[path].refCount - 1}
	uvmc.vsmbShares.shares[path] = s
	if s.refCount > 0 {
		logrus.Debugf("hcsshim::RemoveVSMB Success %s id:%s Ref-count now %d. It is still present in the utility VM", path, uvmc.id, s.refCount)
		return nil
	}
	logrus.Debugf("hcsshim::RemoveVSMB Zero ref-count, removing. %s id:%s", path, uvmc.id)
	delete(uvmc.vsmbShares.shares, path)
	modification := &ModifySettingsRequestV2{
		ResourceType: ResourceTypeVSmbShare,
		RequestType:  RequestTypeRemove,
		Settings:     VirtualMachinesResourcesStorageVSmbShareV2{Name: s.guid},
		ResourceUri:  fmt.Sprintf("virtualmachine/devices/virtualsmbshares/%s", s.guid),
	}
	if err := uvm.Modify(modification); err != nil {
		return fmt.Errorf("failed to remove vsmb share %s from %s: %s: %s", path, uvmc.id, modification, err)
	}
	logrus.Debugf("hcsshim::RemoveVSMB Success %s id:%s successfully removed from utility VM", path, uvmc.id)
	return nil
}

// GetVSMBGUID returns the GUID used to mount a VSMB share in a utility VM
func GetVSMBGUID(uvm Container, path string) (string, error) {
	if uvm == nil {
		return "", fmt.Errorf("no utility VM passed to GetVSMBShareGUID")
	}
	uvmc := uvm.(*container)
	if uvmc.vsmbShares.shares == nil {
		return "", fmt.Errorf("no vsmbShares in utility VM!")
	}
	if path == "" {
		return "", fmt.Errorf("no path passed to GetVSMBShareGUID")
	}
	uvmc.vsmbShares.Lock()
	defer uvmc.vsmbShares.Unlock()
	path = strings.ToLower(path)
	if _, ok := uvmc.vsmbShares.shares[path]; !ok {
		return "", fmt.Errorf("%s not found as VSMB share in %s", path, uvmc.id)
	}
	logrus.Debugf("hcsshim::GetVSMBGUID Success %s id:%s guid:%s", path, uvmc.id, uvmc.vsmbShares.shares[path].guid)
	return uvmc.vsmbShares.shares[path].guid, nil
}
