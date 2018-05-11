package hcsshim

import (
	"os"
	"testing"

	//	"github.com/sirupsen/logrus"
)

// TestWCOWVSMB tests adding/removing VSMB from a v2 Windows utility VM
func TestWCOWVSMB(t *testing.T) {
	v2uvm, v2uvmScratchDir := createv2WCOWUVM(t, layersNanoserver, "", nil)
	defer os.RemoveAll(v2uvmScratchDir)
	startContainer(t, v2uvm)
	defer v2uvm.Terminate()
	//v2uvmc := v2uvm.(*container)

	dir := createTempDir(t)

	for i := 0; i < 1; i++ {
		AddVSMB(v2uvm, dir, VsmbFlagReadOnly|VsmbFlagPseudoOplocks|VsmbFlagTakeBackupPrivilege|VsmbFlagCacheIO|VsmbFlagShareRead)
		RemoveVSMB(v2uvm, dir)
	}
}
