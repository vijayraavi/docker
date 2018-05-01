package hcsshim

//func reverseLayers(layers []string) {
//	last := len(layers) - 1
//	for i := 0; i < len(layers)/2; i++ {
//		layers[i], layers[last-i] = layers[last-i], layers[i]
//	}
//}

import (
	"fmt"
	"path/filepath"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

// allocateSCSI finds the next available slot on the
// SCSI controllers associated with a utility VM to use.
func allocateSCSI(container *container, hostPath string, containerPath string) (int, int, error) {
	container.scsiLocations.Lock()
	defer container.scsiLocations.Unlock()
	for controller, luns := range container.scsiLocations.hostPath {
		for lun, hp := range luns {
			if hp == "" {
				container.scsiLocations.hostPath[controller][lun] = hostPath
				logrus.Debugf("Allocated SCSI %d:%d %q %q", controller, lun, hostPath, containerPath)
				return controller, lun, nil

			}
		}
	}
	return -1, -1, fmt.Errorf("no free SCSI locations")
}

// Lock must be taken externally when calling this function
func findSCSIAttachment(container *container, findThisHostPath string) (int, int, error) {
	for controller, slots := range container.scsiLocations.hostPath {
		for slot, hostPath := range slots {
			if hostPath == findThisHostPath {
				logrus.Debugf("Found SCSI %d:%d %s", controller, slot, hostPath)
				return controller, slot, nil
			}
		}
	}
	return 0, 0, fmt.Errorf("%s is not attached to SCSI", findThisHostPath)
}

// CreateOptions are the complete set of fields required to call any of the
// Create* APIs in HCSShim.
type CreateOptions struct {
	Id              string                        // Identifier for the container
	IsHostingSystem bool                          // If this is host (utility VM) for other containers
	HostingSystem   Container                     // Container object representing the utility VM
	Owner           string                        // Arbitrary string determining the owner
	SchemaVersion   *SchemaVersion                // Schema version of the create request
	Spec            *specs.Spec                   // Definition of the container or utility VM
	LCOWOptions     *LCOWOptions                  // Configuration of an LCOW utility VM. ??Should these be part of OCI?? // What about annotations to put these in?
	Logger          *logrus.Entry                 // For logging
	MountedLayers   *ContainersResourcesStorageV2 // For v2 Xenon - TODO for Argon too....
}

// CreateWindowsUVMSandbox is a helper to create a sandbox for a Windows utility VM
// with permissions to the specified VM ID in a specified directory
func CreateWindowsUVMSandbox(imagePath, destDirectory, vmID string) error {
	sourceSandbox := filepath.Join(imagePath, `UtilityVM\SystemTemplate.vhdx`)
	targetSandbox := filepath.Join(destDirectory, "sandbox.vhdx")
	if err := CopyFile(sourceSandbox, targetSandbox, true); err != nil {
		return err
	}
	if err := GrantVmAccess(vmID, targetSandbox); err != nil {
		// TODO: Delete the file?
		return err
	}
	return nil
}

// CreateContainerEx creates a container. It can cope with a  wide variety of
// scenarios, including v1 HCS schema calls, as well as more complex v2 HCS schema
// calls. The matrix of possibilities, and required fields is below:
//
// All calls:
//  - id		// Of the container or utility VM being created
//  - owner		// Of the container or utility VM being created
//  - logger    // For logging actions taken
//
//
// V1 calls
//	1. WCOW Argon 							// {id; containerSpec}
//	2. WCOW Xenon 							// {id; containerSpec}
//	3. LCOW Xenon 							// {id; containerSpec; lcowOptions}
//
// V2 calls (WCOW)
//  4. WCOW Xenon v2 UVM only					// {uvmId; uvmSpec}
//  5. WCOW Xenon v2 UVM + Argon-in-Xenon		// {uvmId; uvmSpec}; {id; containerSpec}
//  6. WCOW Argon v2							// {id, containerSpec}
//  7. WCOW Argon-in-Xenon v2, existing UVM		// {uvmId}; {id, containerSpec}
//
// V2 calls (LCOW)
// ... // TODO LCOW v2 Xenon
//
// Returns
// - Interface for the container that was created. Always returned in v1. Optional in V2.
// - Interface for the utility VM that was optionally created if a V2 schema call
// - Error indication

func CreateContainerEx(createOptions *CreateOptions) (Container, error) {
	if createOptions.SchemaVersion == nil {
		return nil, fmt.Errorf("SchemaVersion must be supplied")
	}
	if err := createOptions.SchemaVersion.isSupported(); err != nil {
		return nil, err
	}
	if createOptions.Id == "" {
		return nil, fmt.Errorf("Id must be supplied")
	}
	if createOptions.Owner == "" {
		return nil, fmt.Errorf("Owner must be supplied")
	}
	if createOptions.Logger == nil {
		return nil, fmt.Errorf("Logger must be supplied")
	}
	if createOptions.Spec == nil {
		return nil, fmt.Errorf("Spec must be supplied")
	}
	// TODO All this logger stuff
	//logger := createOptions.Logger.WithField("container", createOptions.Id)
	createOptions.Logger = createOptions.Logger.WithField("container", createOptions.Id)

	if createOptions.SchemaVersion.IsV10() {
		if createOptions.HostingSystem != nil {
			return nil, fmt.Errorf("HostingSystem must not be supplied for a v1 schema request")
		}
		if createOptions.LCOWOptions != nil {
			return nil, fmt.Errorf("lcowOptions must not be supplied for a v1 schema Windows container request")
		}
	}
	if createOptions.Spec.Linux != nil {
		if createOptions.Spec.Windows == nil {
			return nil, fmt.Errorf("containerSpec 'Windows' field must container layer folders for a Linux container")
		}
		if createOptions.SchemaVersion.IsV10() {
			return createLCOWv1(createOptions)
		} else {
			// TODO v2 LCOW
			panic("LCOW v2 not implemented")
		}
	}

	// Is a WCOW request.
	if createOptions.IsHostingSystem { // TODO Should be able to put this into CreateHCSContainerDocument
		return createWCOWv2UVM(createOptions)
	}

	hcsDocument, err := CreateHCSContainerDocument(createOptions)
	if err != nil {
		return nil, err
	}
	return createContainer(createOptions.Id, hcsDocument, createOptions.SchemaVersion)
}

// UVMResourcesFromContainerSpec takes a container spec and generates a
// resources structure suitable for creating a utility VM to host the container.
// This is really only relevant for a client that is running a single container
// in a utility VM using the v2 schema. It implements logic which for the v1 schema
// was implemented internally in HCS.
func UVMResourcesFromContainerSpec(spec *specs.Spec) (*specs.WindowsResources, error) {
	// TODO Move to a non-Windows file
	// TODO: Processors. File bug. V2 schema for VM doesn't allow weight/limit, just on compute system.

	if spec == nil && spec.Linux != nil { // TODO
		return nil, fmt.Errorf("UVMResourcesFromContainerSpec not supported for LCOW yet")
	}

	if spec == nil || spec.Windows == nil {
		return nil, fmt.Errorf("invalid spec")
	}
	var uvmCPUCount uint64 = 2
	var uvmMemoryMB uint64 = 512
	uvmResources := &specs.WindowsResources{
		Memory: &specs.WindowsMemoryResources{},
		CPU:    &specs.WindowsCPUResources{Count: &uvmCPUCount},
	}
	if numCPU() == 1 {
		uvmCPUCount = 1
	}
	if spec.Windows.Resources != nil {
		if spec.Windows.Resources.CPU != nil && spec.Windows.Resources.CPU.Count != nil {
			uvmCPUCount = *spec.Windows.Resources.CPU.Count
		}
		if spec.Windows.Resources.Memory.Limit != nil {
			uvmMemoryMB = (*spec.Windows.Resources.Memory.Limit) / 1024 / 1024
		}
	}

	// Add 256MB and round up to nearest 512MB
	uvmMemoryMB += 256
	if uvmMemoryMB%512 > 0 {
		uvmMemoryMB += (512 - (uvmMemoryMB % 512))
	}
	uvmMemoryBytes := uvmMemoryMB * 1024 * 1024
	uvmResources.Memory.Limit = &uvmMemoryBytes

	logrus.Debugf("hcsshim: uvmResources: Memory %d MB CPUs %d", uvmMemoryMB, *uvmResources.CPU.Count)

	return uvmResources, nil
}
