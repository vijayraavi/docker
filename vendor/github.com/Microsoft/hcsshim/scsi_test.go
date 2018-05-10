// +build windows

//
// These unit tests must run on a system setup to run both Argons and Xenons,
// have docker installed, and have the nanoserver (WCOW) and alpine (LCOW)
// base images installed. The nanoserver image MUST match the build of the
// host.
//
// We rely on docker as the tools to extract a container image aren't
// open source. We use it to find the location of the base image on disk.
//

package hcsshim

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// TestAllocateSCSI tests allocateSCSI/deallocateSCSI/findSCSIAttachment
func TestAllocateSCSI(t *testing.T) {
	t.Skip("for now")
	v2uvm, v2uvmScratchDir := createv2WCOWUVM(t, layersNanoserver, "", nil)
	defer os.RemoveAll(v2uvmScratchDir)
	defer v2uvm.Terminate()
	v2uvmc := v2uvm.(*container)

	c, l, err := findSCSIAttachment(v2uvmc, filepath.Join(v2uvmScratchDir, `sandbox.vhdx`))
	if err != nil {
		t.Fatalf("failed to find sandbox %s", err)
	}
	if c != 0 && l != 0 {
		t.Fatalf("sandbox at %d:%d", c, l)
	}

	for i := 0; i <= (4*64)-2; i++ { // 4 controllers, each with 64 slots but 0:0 is the UVM scratch
		controller, lun, err := allocateSCSI(v2uvmc, `anything`)
		if err != nil {
			t.Fatalf("unexpected error %s", err)
		}
		if lun != (i+1)%64 {
			t.Fatalf("unexpected LUN:%d i=%d", lun, i)
		}
		if controller != (i+1)/64 {
			t.Fatalf("unexpected controller:%d i=%d", controller, i)
		}
	}
	_, _, err = allocateSCSI(v2uvmc, `shouldfail`)
	if err == nil {
		t.Fatalf("expected error")
	}
	if err.Error() != "no free SCSI locations" {
		t.Fatalf("expected to have run out of SCSI slots")
	}

	for c := 0; c < 4; c++ {
		for l := 0; l < 64; l++ {
			if !(c == 0 && l == 0) {
				deallocateSCSI(v2uvmc, c, l)
			}
		}
	}
	if v2uvmc.scsiLocations.hostPath[0][0] == "" {
		t.Fatalf("0:0 should still be taken")
	}
	c, l, err = findSCSIAttachment(v2uvmc, filepath.Join(v2uvmScratchDir, `sandbox.vhdx`))
	if err != nil {
		t.Fatalf("failed to find sandbox %s", err)
	}
	if c != 0 && l != 0 {
		t.Fatalf("sandbox at %d:%d", c, l)
	}
}

// TestAddRemoveSCSIDiskv2WCOW validates adding and removing SCSI disks
// from a utility VM in both attach-only and with a container path. Also does
// negative testing so that a disk can't be attached twice.
func TestAddRemoveSCSIDiskv2WCOW(t *testing.T) {
	t.Skip("for now")
	v2uvm, v2uvmScratchDir := createv2WCOWUVM(t, layersNanoserver, "", nil)
	defer os.RemoveAll(v2uvmScratchDir)
	startContainer(t, v2uvm)
	defer v2uvm.Terminate()

	testAddRemoveSCSIDisk(t, v2uvm, `c:\`, "windows")
}

// TestAddRemoveSCSIDiskv1LCOW validates adding and removing SCSI disks
// from a utility VM in both attach-only and with a container path. Also does
// negative testing so that a disk can't be attached twice.
func TestAddRemoveSCSIDiskv1LCOW(t *testing.T) {
	t.Skip("for now")
	spec := getDefaultLinuxSpec(t)
	uvm, err := CreateContainerEx(&CreateOptions{Spec: spec})
	if err != nil {
		t.Fatalf("Failed create: %s", err)
	}
	startContainer(t, uvm)
	defer uvm.Terminate()

	testAddRemoveSCSIDisk(t, uvm, "/", "linux")
}

func testAddRemoveSCSIDisk(t *testing.T, uvm Container, pathPrefix string, operatingSystem string) {
	numDisks := 63 // Windows: 63 as the UVM scratch is at 0:0
	if operatingSystem == "linux" {
		numDisks-- // HCS v1 for Linux has the UVM scratch at 0:0 and reserves 0:1 for the container scratch, even if it's not attached.
	}

	// Create a bunch of directories each containing sandbox.vhdx
	disks := make([]string, numDisks)
	for i := 0; i < numDisks; i++ {
		if operatingSystem == "windows" {
			disks[i] = createWCOWTempDirWithSandbox(t)
		} else {
			disks[i], _ = createLCOWTempDirWithSandbox(t)
		}
		defer os.RemoveAll(disks[i])
		disks[i] = filepath.Join(disks[i], `sandbox.vhdx`)
	}

	// Add each of the disks to the utility VM. Attach-only, no container path
	logrus.Debugln("First - adding in attach-only")
	for i := 0; i < numDisks; i++ {
		_, _, err := AddSCSIDisk(uvm, disks[i], "")
		if err != nil {
			t.Fatalf("failed to add scsi disk %d %s: %s", i, disks[i], err)
		}
	}

	// Try to re-add. These should all fail.
	logrus.Debugln("Next - trying to re-add")
	for i := 0; i < numDisks; i++ {
		_, _, err := AddSCSIDisk(uvm, disks[i], "")
		if err == nil {
			t.Fatalf("should not be able to re-add the same SCSI disk!")
		}
	}

	// Remove them all
	logrus.Debugln("Removing them all")
	for i := 0; i < numDisks; i++ {
		if err := RemoveSCSIDisk(uvm, disks[i]); err != nil {
			t.Fatalf("expected success: %s", err)
		}
	}

	// Now re-add but providing a container path
	logrus.Debugln("Next - re-adding with a container path")
	for i := 0; i < numDisks; i++ {
		_, _, err := AddSCSIDisk(uvm, disks[i], fmt.Sprintf(`%s%d`, pathPrefix, i))
		if err != nil {
			time.Sleep(10 * time.Minute)
			t.Fatalf("failed to add scsi disk %d %s: %s", i, disks[i], err)
		}
	}

	// Try to re-add. These should all fail.
	logrus.Debugln("Next - trying to re-add")
	for i := 0; i < numDisks; i++ {
		_, _, err := AddSCSIDisk(uvm, disks[i], fmt.Sprintf(`%s%d`, pathPrefix, i))
		if err == nil {
			t.Fatalf("should not be able to re-add the same SCSI disk!")
		}
	}

	// Remove them all
	logrus.Debugln("Next - Removing them")
	for i := 0; i < numDisks; i++ {
		if err := RemoveSCSIDisk(uvm, disks[i]); err != nil {
			t.Fatalf("expected success: %s", err)
		}
	}

	// TODO: Could extend to validate can't add a 64th disk (windows). 63rd (linux).
}
