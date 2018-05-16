// +build windows

package hcsshim

//import (
//	"fmt"
//	"path/filepath"
//	"strings"

//	"github.com/sirupsen/logrus"
//)

//// AddVPMEM adds a VPMEM share to a utility VM. Each VPMEM share is ref-counted and
//// only added if it isn't already.
//func AddVPMEM(uvm Container, path string, flags int32) error {
//	if uvm == nil {
//		return fmt.Errorf("no uvm passed to AddVPMEM() for %s", path)
//	}
//	path = strings.ToLower(path)
//	uvmc := uvm.(*container)
//	if !uvmc.schemaVersion.IsV20() {
//		return fmt.Errorf("can only add a VPMEM share to a v2-schema utility VM")
//	}
//	logrus.Debugf("hcsshim::AddVPMEM %s id:%s", path, uvmc.id)
//	uvmc.vpmemLocations.Lock()
//	defer uvmc.vpmemLocations.Unlock()
//	if uvmc.vpmemLocations.locations == nil {
//		uvmc.vpmemLocations.locations = make(map[string]vpmemLocation)
//	}
//	if _, ok := uvmc.vpmemLocations.locations[path]; !ok {
//		_, filename := filepath.Split(path)

//		modification := &ModifySettingsRequestV2{
//			ResourceType: ResourceTypeVSmbShare,
//			RequestType:  RequestTypeAdd,
//			Settings: VirtualMachinesResourcesStorageVSmbShareV2{
//				Name:  guid.ToString(),
//				Flags: flags,
//				Path:  path,
//			},
//			ResourceUri: fmt.Sprintf("virtualmachine/devices/virtualsmbshares/%s", guid.ToString()),
//		}
//		if err := uvm.Modify(modification); err != nil {
//			return err
//		}
//		uvmc.vpmemLocations.locations[path] = vpmemShare{refCount: 1}
//	} else {
//		s := vpmemShare{refCount: uvmc.vpmemLocations.locations[path].refCount + 1}
//		uvmc.vpmemLocations.locations[path] = s
//	}
//	logrus.Debugf("hcsshim::AddVPMEM Success %s: refcount=%d", path, uvmc.vpmemLocations.locations[path].refCount)
//	return nil
//}

//// RemoveVPMEM removes a VPMEM share from a utility VM. Each VPMEM share is ref-counted
//// and only actually removed when the ref-count drops to zero.
//func RemoveVPMEM(uvm Container, path string) error {
//	if uvm == nil {
//		return fmt.Errorf("no uvm passed to RemoveVPMEM() for %s", path)
//	}
//	path = strings.ToLower(path)
//	uvmc := uvm.(*container)
//	if !uvmc.schemaVersion.IsV20() {
//		return fmt.Errorf("can only remove a VPMEM share from a v2-schema utility VM")
//	}
//	logrus.Debugf("hcsshim::RemoveVPMEM %s id:%s", path, uvmc.id)
//	uvmc.vpmemLocations.Lock()
//	defer uvmc.vpmemLocations.Unlock()
//	if _, ok := uvmc.vpmemLocations.locations[path]; !ok {
//		return fmt.Errorf("%s is not present as a VPMEM share in %s, cannot remove", path, uvmc.id)
//	}
//	return removeVPMEM(uvmc, path)
//}

//// removeVPMEM is the internally callable "unsafe" version of RemoveVPMEM. The mutex
//// MUST be held when calling this function.
//func removeVPMEM(uvm Container, path string) error {
//	path = strings.ToLower(path)
//	uvmc := uvm.(*container)
//	s := vpmemShare{guid: uvmc.vpmemLocations.locations[path].guid, refCount: uvmc.vpmemLocations.locations[path].refCount - 1}
//	uvmc.vpmemLocations.locations[path] = s
//	if s.refCount > 0 {
//		logrus.Debugf("hcsshim::RemoveVPMEM Success %s id:%s Ref-count now %d. It is still present in the utility VM", path, uvmc.id, s.refCount)
//		return nil
//	}
//	logrus.Debugf("hcsshim::RemoveVPMEM Zero ref-count, removing. %s id:%s", path, uvmc.id)
//	delete(uvmc.vpmemLocations.locations, path)
//	modification := &ModifySettingsRequestV2{
//		ResourceType: ResourceTypeVSmbShare,
//		RequestType:  RequestTypeRemove,
//		Settings:     VirtualMachinesResourcesStorageVSmbShareV2{Name: s.guid},
//		ResourceUri:  fmt.Sprintf("virtualmachine/devices/virtualsmbshares/%s", s.guid),
//	}
//	if err := uvm.Modify(modification); err != nil {
//		return fmt.Errorf("failed to remove vpmem share %s from %s: %s: %s", path, uvmc.id, modification, err)
//	}
//	logrus.Debugf("hcsshim::RemoveVPMEM Success %s id:%s successfully removed from utility VM", path, uvmc.id)
//	return nil
//}
