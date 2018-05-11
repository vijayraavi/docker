package hcsshim

import (
	"os"
	"strings"
	"testing"

	//	"github.com/sirupsen/logrus"
)

// TestWCOWVSMB tests adding/removing VSMB from a v2 Windows utility VM
func TestWCOWVSMB(t *testing.T) {
	v2uvm, v2uvmScratchDir := createv2WCOWUVM(t, layersNanoserver, "", nil)
	defer os.RemoveAll(v2uvmScratchDir)
	startContainer(t, v2uvm)
	defer v2uvm.Terminate()
	v2uvmc := v2uvm.(*container)

	dir := strings.ToUpper(createTempDir(t)) // Force upper-case
	var iterations uint32 = 1000
	for i := 0; i < int(iterations); i++ {
		if err := AddVSMB(v2uvm, dir, VsmbFlagReadOnly|VsmbFlagPseudoOplocks|VsmbFlagTakeBackupPrivilege|VsmbFlagCacheIO|VsmbFlagShareRead); err != nil {
			t.Fatalf("AddVSMB failed: %s", err)
		}
	}
	if len(v2uvmc.vsmbShares.shares) != 1 {
		t.Fatalf("Should only be one VSMB entry")
	}
	if _, ok := v2uvmc.vsmbShares.shares[dir]; ok {
		t.Fatalf("should not found as upper case")
	}
	if _, ok := v2uvmc.vsmbShares.shares[strings.ToLower(dir)]; !ok {
		t.Fatalf("not found!")
	}
	if v2uvmc.vsmbShares.shares[strings.ToLower(dir)].refCount != iterations {
		t.Fatalf("iteration mismatch: %d %d", iterations, v2uvmc.vsmbShares.shares[strings.ToLower(dir)].refCount)
	}

	// Remove them all
	for i := 0; i < int(iterations); i++ {
		if err := RemoveVSMB(v2uvm, dir); err != nil {
			t.Fatalf("RemoveVSMB failed: %s", err)
		}
	}
	if len(v2uvmc.vsmbShares.shares) != 0 {
		t.Fatalf("Should not be any vsmb entries remaining")
	}

}
