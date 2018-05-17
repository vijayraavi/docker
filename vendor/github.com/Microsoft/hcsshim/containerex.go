// +build windows

package hcsshim

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Microsoft/hcsshim/schema/v2"
	"github.com/Microsoft/hcsshim/schemaversion"
	"github.com/Microsoft/hcsshim/version"
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
			return createLCOWContainer(coi)
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

// createHCSContainerDocument creates a document suitable for calling HCS to create
// a container, both hosted and process isolated. It can create both v1 and v2
// schema, WCOW and LCOW. The containers storage should have been mounted already.

func createHCSContainerDocument(coi *createOptionsExInternal, operatingSystem string) (string, error) {
	logrus.Debugf("hcsshim: CreateHCSContainerDocument")
	// TODO: Make this safe if exported so no null pointer dereferences.

	if operatingSystem != "windows" && operatingSystem != "linux" {
		return "", fmt.Errorf("cannot create HCS container document - operating system %q not recognised", operatingSystem)
	}

	if coi.Spec == nil {
		return "", fmt.Errorf("cannot create HCS container document - OCI spec is missing")
	}

	if coi.Spec.Windows == nil {
		return "", fmt.Errorf("cannot create HCS container document - OCI spec Windows section is missing ")
	}

	v1 := &ContainerConfig{
		SystemType:              "Container",
		Name:                    coi.actualId,
		Owner:                   coi.actualOwner,
		HvPartition:             false,
		IgnoreFlushesDuringBoot: coi.Spec.Windows.IgnoreFlushesDuringBoot,
	}

	// IgnoreFlushesDuringBoot is a property of the SCSI attachment for the sandbox. Set when it's hot-added to the utility VM
	// ID is a property on the create call in V2 rather than part of the schema.
	v2 := &hcsschemav2.ComputeSystemV2{
		Owner:                             coi.actualOwner,
		SchemaVersion:                     schemaversion.SchemaV20(),
		ShouldTerminateOnLastHandleClosed: true,
	}
	v2Container := &hcsschemav2.ContainerV2{Storage: &hcsschemav2.ContainersResourcesStorageV2{}}

	// TODO: Still want to revisit this.
	if coi.Spec.Windows.LayerFolders == nil || len(coi.Spec.Windows.LayerFolders) < 2 {
		return "", fmt.Errorf("invalid spec - not enough layer folders supplied")
	}

	if coi.Spec.Hostname != "" {
		v1.HostName = coi.Spec.Hostname
		v2Container.GuestOS = &hcsschemav2.GuestOsV2{HostName: coi.Spec.Hostname}
	}

	if coi.Spec.Windows.Resources != nil {
		if coi.Spec.Windows.Resources.CPU != nil {
			if coi.Spec.Windows.Resources.CPU.Count != nil ||
				coi.Spec.Windows.Resources.CPU.Shares != nil ||
				coi.Spec.Windows.Resources.CPU.Maximum != nil {
				v2Container.Processor = &hcsschemav2.ContainersResourcesProcessorV2{}
			}
			if coi.Spec.Windows.Resources.CPU.Count != nil {
				cpuCount := *coi.Spec.Windows.Resources.CPU.Count
				hostCPUCount := uint64(numCPU())
				if cpuCount > hostCPUCount {
					logrus.Warnf("Changing requested CPUCount of %d to current number of processors, %d", cpuCount, hostCPUCount)
					cpuCount = hostCPUCount
				}
				v1.ProcessorCount = uint32(cpuCount)
				v2Container.Processor.Count = v1.ProcessorCount
			}
			if coi.Spec.Windows.Resources.CPU.Shares != nil {
				v1.ProcessorWeight = uint64(*coi.Spec.Windows.Resources.CPU.Shares)
				v2Container.Processor.Weight = v1.ProcessorWeight
			}
			if coi.Spec.Windows.Resources.CPU.Maximum != nil {
				v1.ProcessorMaximum = int64(*coi.Spec.Windows.Resources.CPU.Maximum)
				v2Container.Processor.Maximum = uint64(v1.ProcessorMaximum)
			}
		}
		if coi.Spec.Windows.Resources.Memory != nil {
			if coi.Spec.Windows.Resources.Memory.Limit != nil {
				v1.MemoryMaximumInMB = int64(*coi.Spec.Windows.Resources.Memory.Limit) / 1024 / 1024
				v2Container.Memory = &hcsschemav2.ContainersResourcesMemoryV2{Maximum: uint64(v1.MemoryMaximumInMB)}

			}
		}
		if coi.Spec.Windows.Resources.Storage != nil {
			if coi.Spec.Windows.Resources.Storage.Bps != nil || coi.Spec.Windows.Resources.Storage.Iops != nil {
				v2Container.Storage.StorageQoS = &hcsschemav2.ContainersResourcesStorageQoSV2{}
			}
			if coi.Spec.Windows.Resources.Storage.Bps != nil {
				v1.StorageBandwidthMaximum = *coi.Spec.Windows.Resources.Storage.Bps
				v2Container.Storage.StorageQoS.BandwidthMaximum = *coi.Spec.Windows.Resources.Storage.Bps
			}
			if coi.Spec.Windows.Resources.Storage.Iops != nil {
				v1.StorageIOPSMaximum = *coi.Spec.Windows.Resources.Storage.Iops
				v2Container.Storage.StorageQoS.IOPSMaximum = *coi.Spec.Windows.Resources.Storage.Iops
			}
		}
	}

	// TODO V2 networking. Only partial at the moment. v2.Container.Networking.Namespace specifically
	if coi.Spec.Windows.Network != nil {
		v2Container.Networking = &hcsschemav2.ContainersResourcesNetworkingV2{}

		v1.EndpointList = coi.Spec.Windows.Network.EndpointList
		v2Container.Networking.NetworkAdapters = v1.EndpointList

		v1.AllowUnqualifiedDNSQuery = coi.Spec.Windows.Network.AllowUnqualifiedDNSQuery
		v2Container.Networking.AllowUnqualifiedDnsQuery = v1.AllowUnqualifiedDNSQuery

		if coi.Spec.Windows.Network.DNSSearchList != nil {
			v1.DNSSearchList = strings.Join(coi.Spec.Windows.Network.DNSSearchList, ",")
			v2Container.Networking.DNSSearchList = v1.DNSSearchList
		}

		v1.NetworkSharedContainerName = coi.Spec.Windows.Network.NetworkSharedContainerName
		v2Container.Networking.NetworkSharedContainerName = v1.NetworkSharedContainerName
	}

	//	// TODO V2 Credentials not in the schema yet.
	if operatingSystem == "windows" {
		if cs, ok := coi.Spec.Windows.CredentialSpec.(string); ok {
			v1.Credentials = cs
		}
	}

	if coi.Spec.Root == nil {
		return "", fmt.Errorf("spec is invalid - root isn't populated")
	}

	if operatingSystem == "windows" && coi.Spec.Root.Readonly {
		return "", fmt.Errorf(`invalid container spec - readonly is not supported for Windows containers`)
	}

	// Strip off the top-most RW/Sandbox layer as that's passed in separately to HCS for v1
	v1.LayerFolderPath = coi.Spec.Windows.LayerFolders[len(coi.Spec.Windows.LayerFolders)-1]

	if coi.HostingSystem == nil ||
		(coi.actualSchemaVersion.IsV10() && coi.Spec.Windows.HyperV == nil) {
		// Argon v1 or v2.
		const volumeGUIDRegex = `^\\\\\?\\(Volume)\{{0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}\}\\$`
		if _, err := regexp.MatchString(volumeGUIDRegex, coi.Spec.Root.Path); err != nil {
			return "", fmt.Errorf(`invalid container spec - Root.Path '%s' must be a volume GUID path in the format '\\?\Volume{GUID}\'`, coi.Spec.Root.Path)
		}
		if coi.Spec.Root.Path[len(coi.Spec.Root.Path)-1] != '\\' {
			coi.Spec.Root.Path = fmt.Sprintf(`%s\`, coi.Spec.Root.Path) // Be nice to clients and make sure well-formed for back-compat
		}
		v1.VolumePath = coi.Spec.Root.Path[:len(coi.Spec.Root.Path)-1] // Strip the trailing backslash. Required for v1.
		v2Container.Storage.Path = coi.Spec.Root.Path
	} else {
		// A hosting system was supplied, implying v2 Xenon; OR a v1 Xenon.
		if coi.actualSchemaVersion.IsV10() {
			// V1 Xenon
			v1.HvPartition = true
			if coi.Spec == nil || coi.Spec.Windows == nil || coi.Spec.Windows.HyperV == nil { // Be resilient to nil de-reference
				return "", fmt.Errorf(`invalid container spec - Spec.Windows.HyperV is nil`)
			}
			if coi.Spec.Windows.HyperV.UtilityVMPath != "" {
				// Client-supplied utility VM path
				v1.HvRuntime = &HvRuntime{ImagePath: coi.Spec.Windows.HyperV.UtilityVMPath}
			} else {
				// Client was lazy. Let's locate it from the layer folders instead.
				uvmImagePath, err := LocateWCOWUVMFolderFromLayerFolders(coi.Spec.Windows.LayerFolders)
				if err != nil {
					return "", err
				}
				v1.HvRuntime = &HvRuntime{ImagePath: filepath.Join(uvmImagePath, `UtilityVM`)}
			}
		} else {
			// Hosting system was supplied, so is v2 Xenon.
			v2Container.Storage.Path = coi.Spec.Root.Path
			// This is a little inefficient, but makes it MUCH easier for clients. Build the combinedLayers.Layers structure.
			for _, layerFolder := range coi.Spec.Windows.LayerFolders[:len(coi.Spec.Windows.LayerFolders)-1] {
				layerFolderVSMBGUID, err := GetVSMBGUID(coi.HostingSystem, layerFolder)
				if err != nil {
					return "", err
				}
				v2Container.Storage.Layers = append(v2Container.Storage.Layers,
					hcsschemav2.ContainersResourcesLayerV2{
						Id:   layerFolderVSMBGUID,
						Path: fmt.Sprintf(`\\?\VMSMB\VSMB-{dcc079ae-60ba-4d07-847c-3493609c0870}\%s`, layerFolderVSMBGUID),
					})
			}
		}
	}

	if coi.HostingSystem == nil { // Argon v1 or v2
		for _, layerPath := range coi.Spec.Windows.LayerFolders[:len(coi.Spec.Windows.LayerFolders)-1] {
			_, filename := filepath.Split(layerPath)
			g, err := NameToGuid(filename)
			if err != nil {
				return "", err
			}
			v1.Layers = append(v1.Layers, Layer{ID: g.ToString(), Path: layerPath})
			v2Container.Storage.Layers = append(v2Container.Storage.Layers, hcsschemav2.ContainersResourcesLayerV2{Id: g.ToString(), Path: layerPath})
		}
	}

	// Add the mounts as mapped directories or mapped pipes
	// TODO: Mapped pipes to add in v2 schema.
	var (
		mdsv1 []MappedDir
		mpsv1 []MappedPipe
		mdsv2 []hcsschemav2.ContainersResourcesMappedDirectoryV2
		mpsv2 []hcsschemav2.ContainersResourcesMappedPipeV2
	)
	if operatingSystem == "windows" {
		for _, mount := range coi.Spec.Mounts {
			const pipePrefix = `\\.\pipe\`
			if mount.Type != "" {
				return "", fmt.Errorf("invalid container spec - Mount.Type '%s' must not be set", mount.Type)
			}
			if strings.HasPrefix(mount.Destination, pipePrefix) {
				mpsv1 = append(mpsv1, MappedPipe{HostPath: mount.Source, ContainerPipeName: mount.Destination[len(pipePrefix):]})
				mpsv2 = append(mpsv2, hcsschemav2.ContainersResourcesMappedPipeV2{HostPath: mount.Source, ContainerPipeName: mount.Destination[len(pipePrefix):]})
			} else {
				mdv1 := MappedDir{HostPath: mount.Source, ContainerPath: mount.Destination, ReadOnly: false}
				var mdv2 hcsschemav2.ContainersResourcesMappedDirectoryV2
				if coi.HostingSystem == nil {
					mdv2 = hcsschemav2.ContainersResourcesMappedDirectoryV2{HostPath: mount.Source, ContainerPath: mount.Destination, ReadOnly: false}
				} else {
					mountSourceVSMBGUID, err := GetVSMBGUID(coi.HostingSystem, mount.Source)
					if err != nil {
						return "", err
					}
					mdv2 = hcsschemav2.ContainersResourcesMappedDirectoryV2{
						HostPath:      fmt.Sprintf(`\\?\VMSMB\VSMB-{dcc079ae-60ba-4d07-847c-3493609c0870}\%s`, mountSourceVSMBGUID),
						ContainerPath: mount.Destination,
						ReadOnly:      false}
				}
				for _, o := range mount.Options {
					if strings.ToLower(o) == "ro" {
						mdv1.ReadOnly = true
						mdv2.ReadOnly = true
					}
				}
				mdsv1 = append(mdsv1, mdv1)
				mdsv2 = append(mdsv2, mdv2)
			}
		}

		v1.MappedDirectories = mdsv1
		v2Container.MappedDirectories = mdsv2
		if len(mpsv1) > 0 && version.GetOSVersion().Build < version.WINDOWS_BUILD_RS3 {
			return "", fmt.Errorf("named pipe mounts are not supported on this version of Windows")
		}
		v1.MappedPipes = mpsv1
		v2Container.MappedPipes = mpsv2
	}

	// Put the v2Container object as a HostedSystem for a Xenon, or directly in the schema for an Argon.
	if coi.HostingSystem == nil {
		v2.Container = v2Container
	} else {
		v2.HostingSystemId = coi.HostingSystem.(*container).id
		v2.HostedSystem = &hcsschemav2.HostedSystemV2{
			SchemaVersion: schemaversion.SchemaV20(),
			Container:     v2Container,
		}
	}

	if coi.actualSchemaVersion.IsV10() {
		v1b, err := json.Marshal(v1)
		if err != nil {
			return "", err
		}
		logrus.Debugln("hcsshim: HCS Document:", string(v1b))
		return string(v1b), nil
	} else {
		v2b, err := json.Marshal(v2)
		if err != nil {
			return "", err
		}
		logrus.Debugln("hcsshim: HCS Document:", string(v2b))
		return string(v2b), nil
	}
}
