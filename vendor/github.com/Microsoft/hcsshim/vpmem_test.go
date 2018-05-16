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

// TestAllocateVPMEM tests allocateVPMEM/deallocateVPMEM/findVPMEMAttachment
// TODO: Only half done
func TestAllocateVPMEM(t *testing.T) {
	t.Skip("for now")
	tempDir, _ := createLCOWTempDirWithSandbox(t)
	defer os.RemoveAll(tempDir)

	spec := getDefaultLinuxSpec(t)
	spec.Windows.LayerFolders = append(layersAlpine, tempDir)
	v2uvm, err := CreateContainerEx(&CreateOptionsEx{
		AsHostingSystem: true,
		SchemaVersion:   SchemaV20(),
		Spec:            spec,
	})
	if err != nil {
		t.Fatalf("Failed create: %s", err)
	}
	defer v2uvm.Terminate()
	v2uvmc := v2uvm.(*container)

	for i := 0; i <= (1 * 255); i++ { // 1 controller, each with 256 locations
		controller, location, err := allocateVPMEM(v2uvmc, `anything`)
		if err != nil {
			t.Fatalf("unexpected error %s", err)
		}
		if location != uint8(i%256) {
			t.Fatalf("unexpected location:%d i=%d", location, i)
		}
		if controller != i/256 {
			t.Fatalf("unexpected controller:%d i=%d", controller, i)
		}
	}
	_, _, err = allocateVPMEM(v2uvmc, `shouldfail`)
	if err == nil {
		t.Fatalf("expected error")
	}
	if err.Error() != "no free VPMEM locations" {
		t.Fatalf("expected to have run out of VPMEM slots")
	}

	for c := 0; c < 1; c++ {
		for l := 0; l < 256; l++ {
			if !(c == 0 && l == 0) {
				deallocateVPMEM(v2uvmc, c, uint8(l))
			}
		}
	}
	// TODO The other half. As the sandbox isn't attached in create.... this is a problem at the moment
	//	c, l, err := findVPMEMAttachment(v2uvmc, filepath.Join(tempDir, `sandbox.vhdx`))
	//	if err != nil {
	//		t.Fatalf("failed to find sandbox %s", err)
	//	}
	//	if c != 0 && l != 0 {
	//		t.Fatalf("sandbox at %d:%d", c, l)
	//	}
}

// TestAddRemoveVPMEMv2LCOW validates adding and removing VPMEM devices
// from a utility VM. Also does negative testing so that a device can't be
// attached twice.
func TestAddRemoveVPMEMv2LCOW(t *testing.T) {
	//	t.Skip("for now")

	tempDir, _ := createLCOWTempDirWithSandbox(t)
	defer os.RemoveAll(tempDir)

	spec := getDefaultLinuxSpec(t)
	spec.Windows.LayerFolders = append(layersAlpine, tempDir)
	v2uvm, err := CreateContainerEx(&CreateOptionsEx{
		AsHostingSystem: true,
		SchemaVersion:   SchemaV20(),
		Spec:            spec,
	})
	if err != nil {
		t.Fatalf("Failed create: %s", err)
	}
	defer v2uvm.Terminate()
	//v2uvmc := v2uvm.(*container)
	startContainer(t, v2uvm)

	numDisks := 2

	// Create a bunch of directories each containing sandbox.vhdx
	disks := make([]string, numDisks)
	for i := 0; i < numDisks; i++ {
		disks[i], _ = createLCOWTempDirWithSandbox(t)
		defer os.RemoveAll(disks[i])
		disks[i] = filepath.Join(disks[i], `sandbox.vhdx`)
	}

	// Add each of the disks to the utility VM. Attach-only, no container path
	logrus.Debugln("First - adding in attach-only")
	for i := 0; i < numDisks; i++ {
		_, _, err := AddVPMEM(v2uvm, disks[i], "")
		if err != nil {
			t.Fatalf("failed to add vpmem device %d %s: %s", i, disks[i], err)
		}
	}

	// Try to re-add. These should all fail.
	logrus.Debugln("Next - trying to re-add")
	for i := 0; i < numDisks; i++ {
		_, _, err := AddVPMEM(v2uvm, disks[i], "")
		if err == nil {
			t.Fatalf("should not be able to re-add the same vpmem device!")
		}
	}

	// Remove them all
	logrus.Debugln("Removing them all")
	for i := 0; i < numDisks; i++ {
		if err := RemoveVPMEM(v2uvm, disks[i]); err != nil {
			t.Fatalf("expected success: %s", err)
		}
	}

	// Now re-add but providing a container path
	logrus.Debugln("Next - re-adding with a container path")
	for i := 0; i < numDisks; i++ {
		_, _, err := AddVPMEM(v2uvm, disks[i], fmt.Sprintf(`/tmp/vpmem0/%d`, i))
		if err != nil {
			time.Sleep(10 * time.Minute)
			t.Fatalf("failed to add vpmem device %d %s: %s", i, disks[i], err)
		}
	}

	// Try to re-add. These should all fail.
	logrus.Debugln("Next - trying to re-add")
	for i := 0; i < numDisks; i++ {
		_, _, err := AddVPMEM(v2uvm, disks[i], fmt.Sprintf(`/tmp/vpmem0/%d`, i))
		if err == nil {
			t.Fatalf("should not be able to re-add the same SCSI disk!")
		}
	}

	// Remove them all
	logrus.Debugln("Next - Removing them")
	for i := 0; i < numDisks; i++ {
		if err := RemoveVPMEM(v2uvm, disks[i]); err != nil {
			t.Fatalf("expected success: %s", err)
		}
	}

	// TODO: Could extend to validate can't add a 257th device.

}
