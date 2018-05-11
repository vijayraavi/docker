package hcsshim

import (
	"fmt"
	"path/filepath"

	"github.com/sirupsen/logrus"
)

// AddVSMB adds a VSMB share to a utility VM
func AddVSMB(uvm Container, path string, flags int32) (string, error) {
	logrus.Debugf("hcsshim::AddVSMB %s", path)
	if uvm == nil {
		return "", fmt.Errorf("no uvm passed to AddVSMB() for %s", path)
	}
	uvmc := uvm.(*container)
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
