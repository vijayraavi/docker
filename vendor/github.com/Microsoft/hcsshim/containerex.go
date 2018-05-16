// +build windows

package hcsshim

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Microsoft/hcsshim/schemaversion"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

const (
// HCSOPTION_ constants are string values which can be added in the RuntimeOptions of a call to CreateContainerEx.
//HCSOPTION_ADDITIONAL_JSON_V1 = "hcs.additional.v1.json" // HCS:  Additional JSON to merge into Create calls in HCS for V1 schema. Default is none
//HCSOPTION_ADDITIONAL_JSON_V2 = "hcs.additional.v2.json" // HCS:  Additional JSON to merge into Create calls in HCS for V2.x schema. Default is none
//HCSOPTION_WCOW_V2_UVM_MEMORY_OVERHEAD = "hcs.wcow.v2.uvm.additional.memory" // WCOW: v2 schema MB of memory to add to WCOW UVM when calculating resources. Defaults to 256MB
//HCSOPTION_LCOW_GLOBALMODE     = "lcow.globalmode"     // LCOW: Utility VM lifetime. Presence of this causes global mode which is insecure, but more efficient. Default is non-global
//HCSOPTION_LCOW_SANDBOXSIZE_GB = "lcow.sandboxsize.gb" // LCOW: Size of sandbox in GB
//HCSOPTION_LCOW_TIMEOUT = "lcow.timeout" // LCOW: Timeout (seconds) waiting for utility VM operations to complete.

)

// CreateOptionsEx are the set of fields used to call CreateContainerEx().
// Note: In the spec, the LayerFolders must be arranged in the same way in which
// moby configures them: layern, layern-1,...,layer2,layer1,sandbox
// where layer1 is the base read-only layer, layern is the top-most read-only
// layer, and sandbox is the RW layer. This is for historical reasons only.
type CreateOptionsEx struct {

	// Common parameters
	Id              string                       // Identifier for the container
	Owner           string                       // Specifies the owner. Defaults to executable name.
	Spec            *specs.Spec                  // Definition of the container or utility VM being created
	SchemaVersion   *schemaversion.SchemaVersion // Requested Schema Version. Defaults to v2 for RS5, v1 for RS1..RS4
	HostingSystem   Container                    // Container object representing a utility or service VM in which the container is to be created.
	AsHostingSystem bool                         // This is a utility VM for hosting containers, or for use as a service VM

	// LCOW specific parameters
	KirdPath          string // Folder in which kernel and initrd reside. Defaults to \Program Files\Linux Containers
	KernelFile        string // Filename under KirdPath for the kernel. Defaults to bootx64.efi
	InitrdFile        string // Filename under KirdPath for the initrd image. Defaults to initrd.img
	KernelBootOptions string // Additional boot options for the kernel
}

// createOptionsInternal is the set of user-supplied create options, but includes internal
// fields for processing the request once user-supplied stuff has been validated.
type createOptionsExInternal struct {
	*CreateOptionsEx

	actualSchemaVersion *schemaversion.SchemaVersion // Calculated based on Windows build and optional caller-supplied override
	actualId            string                       // Identifier for the container
	actualOwner         string                       // Owner for the container
	actualKirdPath      string                       // LCOW kernel/initrd path
	actualKernelFile    string                       // LCOW kernel file
	actualInitrdFile    string                       // LCOW initrd file
}

// CreateContainerEx creates a container. It can cope with a  wide variety of
// scenarios, including v1 HCS schema calls, as well as more complex v2 HCS schema
// calls.
func CreateContainerEx(createOptions *CreateOptionsEx) (Container, error) {
	logrus.Debugf("hcsshim::CreateContainerEx options: %+v", createOptions)

	coi := &createOptionsExInternal{
		CreateOptionsEx:  createOptions,
		actualId:         createOptions.Id,
		actualOwner:      createOptions.Owner,
		actualKirdPath:   createOptions.KirdPath,
		actualKernelFile: createOptions.KernelFile,
		actualInitrdFile: createOptions.InitrdFile,
	}

	if coi.actualId == "" {
		g, err := GenerateGUID()
		if err != nil {
			return nil, fmt.Errorf("failed to generate GUID for container ID: %s", err)
		}
		coi.actualId = g.ToString()
	}
	if coi.actualOwner == "" {
		coi.actualOwner = filepath.Base(os.Args[0])
	}

	if coi.Spec == nil {
		return nil, fmt.Errorf("Spec must be supplied")
	}

	if coi.HostingSystem != nil {
		// By definition, a hosting system can only be supplied for a v2 Xenon.
		if !coi.HostingSystem.SchemaVersion().IsV20() {
			return nil, fmt.Errorf("supplied hosting system must be a v2 schema container")
		}
		coi.actualSchemaVersion = coi.HostingSystem.SchemaVersion()
	} else {
		coi.actualSchemaVersion = schemaversion.DetermineSchemaVersion(coi.SchemaVersion)
		logrus.Debugf("hcsshim::CreateContainerEx using schema %s", coi.actualSchemaVersion.String())
	}

	if coi.Spec.Linux != nil {
		if coi.Spec.Windows == nil {
			return nil, fmt.Errorf("containerSpec 'Windows' field must container layer folders for a Linux container")
		}
		if coi.actualKirdPath == "" {
			coi.actualKirdPath = filepath.Join(os.Getenv("ProgramFiles"), "Linux Containers")
		}
		if coi.actualKernelFile == "" {
			coi.actualKernelFile = "bootx64.efi"
		}
		if coi.actualInitrdFile == "" {
			coi.actualInitrdFile = "initrd.img"
		}
		if coi.actualSchemaVersion.IsV10() {
			logrus.Debugln("hcsshim::CreateContainerEx Calling createLCOWv1")
			return createLCOWv1(coi)
		} else {
			if coi.AsHostingSystem {
				return createLCOWv2UVM(coi)
			}
			// TODO v2 LCOW
			panic("LCOW v2 not implemented for container yet")
		}
	}

	//
	// Is a WCOW request.
	//

	// Is it a Utility VM?
	if coi.AsHostingSystem {
		return createWCOWv2UVM(coi)
	}

	// So it's a container.
	return createWCOWContainer(coi)
}
