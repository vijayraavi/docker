package hcsshim

import (
	"os"
	"testing"

	"github.com/sirupsen/logrus"
)

// TestWCOWVSMB tests adding/removing VSMB from a v2 Windows utility VM
func TestWCOWVSMB(t *testing.T) {
	v2uvm, v2uvmScratchDir := createv2WCOWUVM(t, layersNanoserver, "", nil)
	defer os.RemoveAll(v2uvmScratchDir)
	defer v2uvm.Terminate()
	v2uvmc := v2uvm.(*container)

	dir := createTempDir(t)

	for i := 0; i < 3; i++ {
		guid, _ := AddVSMB(v2uvm, dir, VsmbFlagReadOnly|VsmbFlagPseudoOplocks|VsmbFlagTakeBackupPrivilege|VsmbFlagCacheIO|VsmbFlagShareRead)
		logrus.Debugln(guid, v2uvmc.vsmbShares)
	}
}
