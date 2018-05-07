package hcsshim

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

const (
	// HCSOPTION_ constants are string values which can be added in the RuntimeOptions of a call to CreateContainerEx.
	HCSOPTION_SCHEMA_VERSION              = "hcs.schema.version"                // HCS:  Request a schema version. Content is a SchemaVersion object. Defaults to v2 for RS5, v1 for RS1..RS4
	HCSOPTION_OWNER                       = "hcs.container.owner"               // HCS:  Specified the owner. Defaults to executable name
	HCSOPTION_ID                          = "hcs.container.id"                  // HCS:  Specifies the ID of a created container. Defaults to a GUID if not supplied
	HCSOPTION_ADDITIONAL_JSON_V1          = "hcs.additional.v1.json"            // HCS:  Additional JSON to merge into Create calls in HCS for V1 schema. Default is none
	HCSOPTION_ADDITIONAL_JSON_V2          = "hcs.additional.v2.json"            // HCS:  Additional JSON to merge into Create calls in HCS for V2.x schema. Default is none
	HCSOPTION_SPEC_DEFINES_UTILITY_VM     = "hcs.spec.defines.utility.vm"       // HCS:  If defined, the spec is for a utility VM. Default is a container.
	HCSOPTION_WCOW_V2_UVM_MEMORY_OVERHEAD = "hcs.wcow.v2.uvm.additional.memory" // WCOW: v2 schema MB of memory to add to WCOW UVM when calculating resources. Defaults to 256MB
	HCSOPTION_LCOW_KIRD_PATH              = "lcow.kirdpath"                     // LCOW: Folder in which kernel and initrd reside. Defaults to \Program Files\Linux Containers
	HCSOPTION_LCOW_KERNEL_FILE            = "lcow.kernel"                       // LCOW: Filename under kirdpath for the kernel. Defaults to bootx64.efi
	HCSOPTION_LCOW_INITRD_FILE            = "lcow.initrd"                       // LCOW: Filename under kirdpath for the initrd. Defaults to initrd.img
	HCSOPTION_LCOW_BOOT_PARAMETERS        = "lcow.bootparameters"               // LCOW: Additional boot parameters for starting the kernel. Default is no additional parameters
	HCSOPTION_LCOW_GLOBALMODE             = "lcow.globalmode"                   // LCOW: Utility VM lifetime. Presence of this causes global mode which is insecure, but more efficient. Default is non-global
	HCSOPTION_LCOW_SANDBOXSIZE_GB         = "lcow.sandboxsize.gb"               // LCOW: Size of sandbox in GB
	HCSOPTION_LCOW_TIMEOUT                = "lcow.timeout"                      // LCOW: Timeout (seconds) waiting for utility VM operations to complete.

	// WINDOWS_BUILD_ constants are hopefully self explanatory :) RS2 was a client-only release in case you're asking why it's not in the list.
	WINDOWS_BUILD_RS1 = 14393
	WINDOWS_BUILD_RS3 = 16299
	WINDOWS_BUILD_RS4 = 17134
	WINDOWS_BUILD_RS5 = 17659 // TODO Bump to final RS5 build

)

// CreateOptions are the set of fields used to call CreateContainerEx().
// Note: In the spec, the LayerFolders must be arranged in the same way in which
// moby configures them: layern, layern-1,...,layer2,layer1,sandbox
// where layer1 is the base read-only layer, layern is the top-most read-only
// layer, and sandbox is the RW layer. This is for historical reasons only.
type CreateOptions struct {
	Spec          *specs.Spec       // Definition of the container or utility VM being created
	Options       map[string]string // Runtime options. See HCSOPTION_ constants for possible values.
	HostingSystem Container         // Container object representing a utility or service VM
	Logger        *logrus.Entry     // For logging

	// Internal fields
	sv             *SchemaVersion // Calculated based on Windows build and optional caller-supplied override
	id             string         // Identifier for the container
	owner          string         // Owner for the container
	lcowkird       string         // LCOW kernel/initrd path
	lcowkernel     string         // LCOW kernel file
	lcowinitrd     string         // LCOW initrd file
	lcowbootparams string         // LCOW additional boot parameters
}

// valueFromStringMap scans a map[string]string such as runtime options or
// annotations in a spec for a value. Keys are case insensitive. Values are not.
func valueFromStringMap(m map[string]string, name string) string {
	if m == nil {
		return ""
	}
	for k, v := range m {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// CreateContainerEx creates a container. It can cope with a  wide variety of
// scenarios, including v1 HCS schema calls, as well as more complex v2 HCS schema
// calls.
func CreateContainerEx(createOptions *CreateOptions) (Container, error) {
	logrus.Debugf("hcsshim::CreateContainerEx options: %+v", createOptions.Options)

	createOptions.sv = determineSchemaVersion(createOptions.Options)
	logrus.Debugf("hcsshim::CreateContainerEx using schema %s", createOptions.sv.String())

	createOptions.id = valueFromStringMap(createOptions.Options, HCSOPTION_ID)
	if createOptions.id == "" {
		g, _ := GenerateGUID() // TODO Error handling
		createOptions.id = g.ToString()
	}
	createOptions.owner = valueFromStringMap(createOptions.Options, HCSOPTION_OWNER)
	if createOptions.owner == "" {
		createOptions.owner = filepath.Base(os.Args[0])
	}

	if createOptions.Logger == nil {
		return nil, fmt.Errorf("Logger must be supplied")
	}
	if createOptions.Spec == nil {
		return nil, fmt.Errorf("Spec must be supplied")
	}
	// TODO All this logger stuff
	//logger := createOptions.Logger.WithField("container", createOptions.Id)
	createOptions.Logger = createOptions.Logger.WithField("container", createOptions.id)

	if createOptions.sv.IsV10() {
		if createOptions.HostingSystem != nil {
			return nil, fmt.Errorf("HostingSystem must not be supplied for a v1 schema request")
		}
	}
	if createOptions.Spec.Linux != nil {
		if createOptions.Spec.Windows == nil {
			return nil, fmt.Errorf("containerSpec 'Windows' field must container layer folders for a Linux container")
		}
		getLCOWSettings(createOptions)
		if createOptions.sv.IsV10() {
			logrus.Debugln("hcsshim::CreateContainerEx Calling createLCOWv1")
			return createLCOWv1(createOptions)
		} else {
			// TODO v2 LCOW
			panic("LCOW v2 not implemented")
		}
	}

	// Is a WCOW request.

	if valueFromStringMap(createOptions.Options, HCSOPTION_SPEC_DEFINES_UTILITY_VM) != "" {
		// TODO Should be able to put this into CreateHCSContainerDocument
		return createWCOWv2UVM(createOptions)
	}

	hcsDocument, err := CreateHCSContainerDocument(createOptions)
	if err != nil {
		return nil, err
	}
	return createContainer(createOptions.id, hcsDocument, createOptions.sv)
}

// CreateWCOWUVMSandbox is a helper to create a sandbox for a Windows utility VM
// with permissions to the specified VM ID in a specified directory
func CreateWCOWUVMSandbox(imagePath, destDirectory, vmID string) error {
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
