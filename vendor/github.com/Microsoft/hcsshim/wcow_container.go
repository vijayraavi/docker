package hcsshim

// Contains functions relating to a WCOW container, as opposed to a utility VM

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

// CreateWCOWHCSContainerDocument creates a document suitable for calling HCS to create
// a container, both hosted and process isolated. It can create both v1 and v2
// schema. This is exported just in case a client could find it useful, but
// not strictly necessary as it will be called by CreateContainerEx().
//
// The containers storage should have been mounted already.

func CreateWCOWHCSContainerDocument(createOptions *CreateOptions) (string, error) {
	logrus.Debugf("hcsshim: CreateWCOWHCSContainerDocument")

	// TODO: Make this safe if exported so no null pointer dereferences.
	// TODO: Should this be a Windows function explicitly in the name

	if createOptions.Spec == nil {
		return "", fmt.Errorf("cannot create HCS container document - OCI spec is missing")
	}

	if createOptions.Spec.Windows == nil {
		return "", fmt.Errorf("cannot create HCS container document - OCI spec Windows section is missing ")
	}

	v1 := &ContainerConfig{
		SystemType:              "Container",
		Name:                    createOptions.actualId,
		Owner:                   createOptions.actualOwner,
		HvPartition:             false,
		IgnoreFlushesDuringBoot: createOptions.Spec.Windows.IgnoreFlushesDuringBoot,
	}

	// IgnoreFlushesDuringBoot is a property of the SCSI attachment for the sandbox. Set when it's hot-added to the utility VM
	// ID is a property on the create call in V2 rather than part of the schema.
	v2 := &ComputeSystemV2{
		Owner:                             createOptions.actualOwner,
		SchemaVersion:                     SchemaV20(),
		ShouldTerminateOnLastHandleClosed: true,
	}
	v2Container := &ContainerV2{Storage: &ContainersResourcesStorageV2{}}

	// TODO: Still want to revisit this.
	if createOptions.Spec.Windows.LayerFolders == nil || len(createOptions.Spec.Windows.LayerFolders) < 2 {
		return "", fmt.Errorf("invalid spec - not enough layer folders supplied")
	}

	if createOptions.Spec.Hostname != "" {
		v1.HostName = createOptions.Spec.Hostname
		v2Container.GuestOS = &GuestOsV2{HostName: createOptions.Spec.Hostname}
	}

	if createOptions.Spec.Windows.Resources != nil {
		if createOptions.Spec.Windows.Resources.CPU != nil {
			if createOptions.Spec.Windows.Resources.CPU.Count != nil ||
				createOptions.Spec.Windows.Resources.CPU.Shares != nil ||
				createOptions.Spec.Windows.Resources.CPU.Maximum != nil {
				v2Container.Processor = &ContainersResourcesProcessorV2{}
			}
			if createOptions.Spec.Windows.Resources.CPU.Count != nil {
				cpuCount := *createOptions.Spec.Windows.Resources.CPU.Count
				hostCPUCount := uint64(numCPU())
				if cpuCount > hostCPUCount {
					logrus.Warnf("Changing requested CPUCount of %d to current number of processors, %d", cpuCount, hostCPUCount)
					cpuCount = hostCPUCount
				}
				v1.ProcessorCount = uint32(cpuCount)
				v2Container.Processor.Count = v1.ProcessorCount
			}
			if createOptions.Spec.Windows.Resources.CPU.Shares != nil {
				v1.ProcessorWeight = uint64(*createOptions.Spec.Windows.Resources.CPU.Shares)
				v2Container.Processor.Weight = v1.ProcessorWeight
			}
			if createOptions.Spec.Windows.Resources.CPU.Maximum != nil {
				v1.ProcessorMaximum = int64(*createOptions.Spec.Windows.Resources.CPU.Maximum)
				v2Container.Processor.Maximum = uint64(v1.ProcessorMaximum)
			}
		}
		if createOptions.Spec.Windows.Resources.Memory != nil {
			if createOptions.Spec.Windows.Resources.Memory.Limit != nil {
				v1.MemoryMaximumInMB = int64(*createOptions.Spec.Windows.Resources.Memory.Limit) / 1024 / 1024
				v2Container.Memory = &ContainersResourcesMemoryV2{Maximum: uint64(v1.MemoryMaximumInMB)}

			}
		}
		if createOptions.Spec.Windows.Resources.Storage != nil {
			if createOptions.Spec.Windows.Resources.Storage.Bps != nil || createOptions.Spec.Windows.Resources.Storage.Iops != nil {
				v2Container.Storage.StorageQoS = &ContainersResourcesStorageQoSV2{}
			}
			if createOptions.Spec.Windows.Resources.Storage.Bps != nil {
				v1.StorageBandwidthMaximum = *createOptions.Spec.Windows.Resources.Storage.Bps
				v2Container.Storage.StorageQoS.BandwidthMaximum = *createOptions.Spec.Windows.Resources.Storage.Bps
			}
			if createOptions.Spec.Windows.Resources.Storage.Iops != nil {
				v1.StorageIOPSMaximum = *createOptions.Spec.Windows.Resources.Storage.Iops
				v2Container.Storage.StorageQoS.IOPSMaximum = *createOptions.Spec.Windows.Resources.Storage.Iops
			}
		}
	}

	// TODO V2 networking. Only partial at the moment. v2.Container.Networking.Namespace specifically
	if createOptions.Spec.Windows.Network != nil {
		v2Container.Networking = &ContainersResourcesNetworkingV2{}

		v1.EndpointList = createOptions.Spec.Windows.Network.EndpointList
		v2Container.Networking.NetworkAdapters = v1.EndpointList

		v1.AllowUnqualifiedDNSQuery = createOptions.Spec.Windows.Network.AllowUnqualifiedDNSQuery
		v2Container.Networking.AllowUnqualifiedDnsQuery = v1.AllowUnqualifiedDNSQuery

		if createOptions.Spec.Windows.Network.DNSSearchList != nil {
			v1.DNSSearchList = strings.Join(createOptions.Spec.Windows.Network.DNSSearchList, ",")
			v2Container.Networking.DNSSearchList = v1.DNSSearchList
		}

		v1.NetworkSharedContainerName = createOptions.Spec.Windows.Network.NetworkSharedContainerName
		v2Container.Networking.NetworkSharedContainerName = v1.NetworkSharedContainerName
	}

	//	// TODO V2 Credentials not in the schema yet.
	if cs, ok := createOptions.Spec.Windows.CredentialSpec.(string); ok {
		v1.Credentials = cs
	}

	if createOptions.Spec.Root == nil {
		return "", fmt.Errorf("spec is invalid - root isn't populated")
	}

	if createOptions.Spec.Root.Readonly {
		return "", fmt.Errorf(`invalid container spec - readonly is not supported`)
	}

	// Strip off the top-most RW/Sandbox layer as that's passed in separately to HCS for v1
	// TODO Should this be inside the check below?
	v1.LayerFolderPath = createOptions.Spec.Windows.LayerFolders[len(createOptions.Spec.Windows.LayerFolders)-1]

	if createOptions.HostingSystem == nil ||
		(createOptions.actualSchemaVersion.IsV10() && createOptions.Spec.Windows.HyperV == nil) {
		// Argon v1 or v2.
		const volumeGUIDRegex = `^\\\\\?\\(Volume)\{{0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}\}\\$`
		if _, err := regexp.MatchString(volumeGUIDRegex, createOptions.Spec.Root.Path); err != nil {
			return "", fmt.Errorf(`invalid container spec - Root.Path '%s' must be a volume GUID path in the format '\\?\Volume{GUID}\'`, createOptions.Spec.Root.Path)
		}
		if createOptions.Spec.Root.Path[len(createOptions.Spec.Root.Path)-1] != '\\' {
			createOptions.Spec.Root.Path = fmt.Sprintf(`%s\`, createOptions.Spec.Root.Path) // Be nice to clients and make sure well-formed for back-compat
		}
		v1.VolumePath = createOptions.Spec.Root.Path[:len(createOptions.Spec.Root.Path)-1] // Strip the trailing backslash. Required for v1.
		v2Container.Storage.Path = createOptions.Spec.Root.Path
	} else {
		if createOptions.actualSchemaVersion.IsV10() {
			v1.HvPartition = true
			// TODO: Do we need a check for nil pointer here? Or done previously
			if createOptions.Spec.Windows.HyperV.UtilityVMPath != "" {
				v1.HvRuntime = &HvRuntime{ImagePath: createOptions.Spec.Windows.HyperV.UtilityVMPath}
			} else {
				uvmImagePath, err := LocateWCOWUVMFolderFromLayerFolders(createOptions.Spec.Windows.LayerFolders)
				if err != nil {
					return "", err
				}
				v1.HvRuntime = &HvRuntime{ImagePath: filepath.Join(uvmImagePath, `UtilityVM`)}
			}
		} else {
			v2Container.Storage.Path = createOptions.Spec.Root.Path
			// This is a little inefficient, but makes it MUCH easier for clients. Build the combinedLayers.Layers structure.
			for _, layerFolder := range createOptions.Spec.Windows.LayerFolders[:len(createOptions.Spec.Windows.LayerFolders)-1] {
				layerFolderVSMBGUID, err := GetVSMBGUID(createOptions.HostingSystem, layerFolder)
				if err != nil {
					return "", err
				}
				v2Container.Storage.Layers = append(v2Container.Storage.Layers,
					ContainersResourcesLayerV2{
						Id:   layerFolderVSMBGUID,
						Path: fmt.Sprintf(`\\?\VMSMB\VSMB-{dcc079ae-60ba-4d07-847c-3493609c0870}\%s`, layerFolderVSMBGUID),
					})
			}
		}
	}

	if createOptions.HostingSystem == nil { // ie Not a v2 xenon. As the mounted layers were passed in instead.
		for _, layerPath := range createOptions.Spec.Windows.LayerFolders[:len(createOptions.Spec.Windows.LayerFolders)-1] {
			_, filename := filepath.Split(layerPath)
			g, err := NameToGuid(filename)
			if err != nil {
				return "", err
			}
			v1.Layers = append(v1.Layers, Layer{ID: g.ToString(), Path: layerPath})
			v2Container.Storage.Layers = append(v2Container.Storage.Layers, ContainersResourcesLayerV2{Id: g.ToString(), Path: layerPath})
		}
	}

	// Add the mounts as mapped directories or mapped pipes
	var (
		mdsv1 []MappedDir
		mpsv1 []MappedPipe
		mdsv2 []ContainersResourcesMappedDirectoryV2
		mpsv2 []ContainersResourcesMappedPipeV2
	)
	for _, mount := range createOptions.Spec.Mounts {
		const pipePrefix = `\\.\pipe\`
		if mount.Type != "" {
			return "", fmt.Errorf("invalid container spec - Mount.Type '%s' must not be set", mount.Type)
		}
		if strings.HasPrefix(mount.Destination, pipePrefix) {
			mpsv1 = append(mpsv1, MappedPipe{HostPath: mount.Source, ContainerPipeName: mount.Destination[len(pipePrefix):]})
			mpsv2 = append(mpsv2, ContainersResourcesMappedPipeV2{HostPath: mount.Source, ContainerPipeName: mount.Destination[len(pipePrefix):]})
		} else {
			mdv1 := MappedDir{HostPath: mount.Source, ContainerPath: mount.Destination, ReadOnly: false}
			mdv2 := ContainersResourcesMappedDirectoryV2{HostPath: mount.Source, ContainerPath: mount.Destination, ReadOnly: false}
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
	if len(mpsv1) > 0 && GetOSVersion().Build < WINDOWS_BUILD_RS3 {
		return "", fmt.Errorf("named pipe mounts are not supported on this version of Windows")
	}
	v1.MappedPipes = mpsv1
	v2Container.MappedPipes = mpsv2

	// Put the v2Container object as a HostedSystem for a Xenon, or directly in the schema for an Argon.
	if createOptions.HostingSystem == nil {
		v2.Container = v2Container
	} else {
		v2.HostingSystemId = createOptions.HostingSystem.(*container).id
		v2.HostedSystem = &HostedSystemV2{
			SchemaVersion: SchemaV20(),
			Container:     v2Container,
		}
	}

	if createOptions.actualSchemaVersion.IsV10() {
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

func createWCOWContainer(createOptions *CreateOptions) (Container, error) {

	sandboxFolder := createOptions.Spec.Windows.LayerFolders[len(createOptions.Spec.Windows.LayerFolders)-1]
	logrus.Debugf("hcsshim::createWCOWContainer Sandbox folder: %s", sandboxFolder)

	// Create the directory for the RW sandbox layer if it doesn't exist
	if _, err := os.Stat(sandboxFolder); os.IsNotExist(err) {
		logrus.Debugf("hcsshim::createWCOWContainer container sandbox folder does not exist so creating: %s ", sandboxFolder)
		if err := os.MkdirAll(sandboxFolder, 0777); err != nil {
			return nil, fmt.Errorf("failed to auto-create container sandbox folder %s: %s", sandboxFolder, err)
		}
	}

	// Create sandbox.vhdx if it doesn't exist in the sandbox folder
	if _, err := os.Stat(filepath.Join(sandboxFolder, "sandbox.vhdx")); os.IsNotExist(err) {
		logrus.Debugf("hcsshim::createWCOWContainer container sandbox.vhdx does not exist so creating in %s ", sandboxFolder)
		di := DriverInfo{HomeDir: filepath.Dir(sandboxFolder)}
		if err := CreateSandboxLayer(di, filepath.Base(sandboxFolder), createOptions.Spec.Windows.LayerFolders[0], createOptions.Spec.Windows.LayerFolders[:len(createOptions.Spec.Windows.LayerFolders)-1]); err != nil {
			return nil, fmt.Errorf("failed to CreateSandboxLayer %s", err)
		}
	}

	// TODO: Move the regex to validate the root to here.

	// Do we need to auto-mount on behalf of the end user?
	weMountedStorage := false
	origSpecRoot := createOptions.Spec.Root
	if createOptions.Spec.Root == nil {
		createOptions.Spec.Root = &specs.Root{}
	}
	if createOptions.Spec.Root.Path == "" {
		logrus.Debugln("hcsshim::createWCOWContainer Auto-mounting storage")
		mcl, err := MountContainerLayers(createOptions.Spec.Windows.LayerFolders, createOptions.HostingSystem)
		if err != nil {
			return nil, fmt.Errorf("failed to auto-mount container storage: %s", err)
		}
		weMountedStorage = true
		if createOptions.HostingSystem == nil {
			createOptions.Spec.Root.Path = mcl.(string) // Argon v1 or v2
		} else {
			createOptions.Spec.Root.Path = mcl.(CombinedLayersV2).ContainerRootPath // v2 Xenon WCOW
		}
	}

	hcsDocument, err := CreateWCOWHCSContainerDocument(createOptions)
	if err != nil {
		if weMountedStorage {
			UnmountContainerLayers(createOptions.Spec.Windows.LayerFolders, createOptions.HostingSystem, UnmountOperationAll) // TODO Ignoring error for now
			createOptions.Spec.Root = origSpecRoot
		}
		return nil, err
	}

	return createContainer(createOptions.actualId, hcsDocument, createOptions.actualSchemaVersion)
}
