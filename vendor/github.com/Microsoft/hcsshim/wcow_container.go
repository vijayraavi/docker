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
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// createWCOWHCSContainerDocument creates a document suitable for calling HCS to create
// a container, both hosted and process isolated. It can create both v1 and v2
// schema. The containers storage should have been mounted already.

func createWCOWHCSContainerDocument(coi *createOptionsExInternal) (string, error) {
	logrus.Debugf("hcsshim: CreateWCOWHCSContainerDocument")

	// TODO: Make this safe if exported so no null pointer dereferences.
	// TODO: Should this be a Windows function explicitly in the name

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
	v2 := &ComputeSystemV2{
		Owner:                             coi.actualOwner,
		SchemaVersion:                     SchemaV20(),
		ShouldTerminateOnLastHandleClosed: true,
	}
	v2Container := &ContainerV2{Storage: &ContainersResourcesStorageV2{}}

	// TODO: Still want to revisit this.
	if coi.Spec.Windows.LayerFolders == nil || len(coi.Spec.Windows.LayerFolders) < 2 {
		return "", fmt.Errorf("invalid spec - not enough layer folders supplied")
	}

	if coi.Spec.Hostname != "" {
		v1.HostName = coi.Spec.Hostname
		v2Container.GuestOS = &GuestOsV2{HostName: coi.Spec.Hostname}
	}

	if coi.Spec.Windows.Resources != nil {
		if coi.Spec.Windows.Resources.CPU != nil {
			if coi.Spec.Windows.Resources.CPU.Count != nil ||
				coi.Spec.Windows.Resources.CPU.Shares != nil ||
				coi.Spec.Windows.Resources.CPU.Maximum != nil {
				v2Container.Processor = &ContainersResourcesProcessorV2{}
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
				v2Container.Memory = &ContainersResourcesMemoryV2{Maximum: uint64(v1.MemoryMaximumInMB)}

			}
		}
		if coi.Spec.Windows.Resources.Storage != nil {
			if coi.Spec.Windows.Resources.Storage.Bps != nil || coi.Spec.Windows.Resources.Storage.Iops != nil {
				v2Container.Storage.StorageQoS = &ContainersResourcesStorageQoSV2{}
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
		v2Container.Networking = &ContainersResourcesNetworkingV2{}

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
	if cs, ok := coi.Spec.Windows.CredentialSpec.(string); ok {
		v1.Credentials = cs
	}

	if coi.Spec.Root == nil {
		return "", fmt.Errorf("spec is invalid - root isn't populated")
	}

	if coi.Spec.Root.Readonly {
		return "", fmt.Errorf(`invalid container spec - readonly is not supported`)
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
					ContainersResourcesLayerV2{
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
	for _, mount := range coi.Spec.Mounts {
		const pipePrefix = `\\.\pipe\`
		if mount.Type != "" {
			return "", fmt.Errorf("invalid container spec - Mount.Type '%s' must not be set", mount.Type)
		}
		if strings.HasPrefix(mount.Destination, pipePrefix) {
			mpsv1 = append(mpsv1, MappedPipe{HostPath: mount.Source, ContainerPipeName: mount.Destination[len(pipePrefix):]})
			mpsv2 = append(mpsv2, ContainersResourcesMappedPipeV2{HostPath: mount.Source, ContainerPipeName: mount.Destination[len(pipePrefix):]})
		} else {
			mdv1 := MappedDir{HostPath: mount.Source, ContainerPath: mount.Destination, ReadOnly: false}
			var mdv2 ContainersResourcesMappedDirectoryV2
			if coi.HostingSystem == nil {
				mdv2 = ContainersResourcesMappedDirectoryV2{HostPath: mount.Source, ContainerPath: mount.Destination, ReadOnly: false}
			} else {
				mountSourceVSMBGUID, err := GetVSMBGUID(coi.HostingSystem, mount.Source)
				if err != nil {
					return "", err
				}
				mdv2 = ContainersResourcesMappedDirectoryV2{
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
	if len(mpsv1) > 0 && GetOSVersion().Build < WINDOWS_BUILD_RS3 {
		return "", fmt.Errorf("named pipe mounts are not supported on this version of Windows")
	}
	v1.MappedPipes = mpsv1
	v2Container.MappedPipes = mpsv2

	// Put the v2Container object as a HostedSystem for a Xenon, or directly in the schema for an Argon.
	if coi.HostingSystem == nil {
		v2.Container = v2Container
	} else {
		v2.HostingSystemId = coi.HostingSystem.(*container).id
		v2.HostedSystem = &HostedSystemV2{
			SchemaVersion: SchemaV20(),
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

func createWCOWContainer(coi *createOptionsExInternal) (Container, error) {

	sandboxFolder := coi.Spec.Windows.LayerFolders[len(coi.Spec.Windows.LayerFolders)-1]
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
		if err := CreateSandboxLayer(di, filepath.Base(sandboxFolder), coi.Spec.Windows.LayerFolders[0], coi.Spec.Windows.LayerFolders[:len(coi.Spec.Windows.LayerFolders)-1]); err != nil {
			return nil, fmt.Errorf("failed to CreateSandboxLayer %s", err)
		}
	}

	// Do we need to auto-mount on behalf of the end user?
	weMountedStorage := false
	origSpecRoot := coi.Spec.Root
	if coi.Spec.Root == nil {
		coi.Spec.Root = &specs.Root{}
	}
	if coi.Spec.Root.Path == "" {
		logrus.Debugln("hcsshim::createWCOWContainer Auto-mounting storage")
		mcl, err := MountContainerLayers(coi.Spec.Windows.LayerFolders, coi.HostingSystem)
		if err != nil {
			return nil, fmt.Errorf("failed to auto-mount container storage: %s", err)
		}
		weMountedStorage = true
		if coi.HostingSystem == nil {
			coi.Spec.Root.Path = mcl.(string) // Argon v1 or v2
		} else {
			coi.Spec.Root.Path = mcl.(CombinedLayersV2).ContainerRootPath // v2 Xenon WCOW
		}
	}

	// Auto-mount the mounts. There's only something to do for v2 xenons. In argons and v1 xenon,
	// it's done by the HCS directly.
	var vsmbMountsAddedByUs []string
	for _, mount := range coi.Spec.Mounts {
		if mount.Destination == "" || mount.Source == "" {
			thisError := fmt.Errorf("invalid OCI spec - a mount must have a source and a destination")
			thisError = undoMountOnFailure(coi, origSpecRoot, weMountedStorage, vsmbMountsAddedByUs, thisError)
			return nil, thisError
		}

		if coi.HostingSystem != nil {
			logrus.Debugf("hcsshim::createWCOWContainer Hot-adding VSMB share for OCI mount %+v", mount)
			// Hot-add the VSMB shares to the utility VM
			// TODO: What are the right flags. Asked swernli
			// TODO: Read-only
			err := AddVSMB(coi.HostingSystem, mount.Source, VsmbFlagReadOnly|VsmbFlagPseudoOplocks|VsmbFlagTakeBackupPrivilege|VsmbFlagCacheIO|VsmbFlagShareRead)
			if err != nil {
				thisError := fmt.Errorf("failed to add VSMB share to utility VM for mount %+v: %s", mount, err)
				thisError = undoMountOnFailure(coi, origSpecRoot, weMountedStorage, vsmbMountsAddedByUs, thisError)
				return nil, thisError
			} else {
				vsmbMountsAddedByUs = append(vsmbMountsAddedByUs, mount.Source)
			}
		}
	}

	hcsDocument, err := createWCOWHCSContainerDocument(coi)
	if err != nil {
		err = undoMountOnFailure(coi, origSpecRoot, weMountedStorage, vsmbMountsAddedByUs, err)
		return nil, err
	}

	return createContainer(coi.actualId, hcsDocument, coi.actualSchemaVersion)
}

func undoMountOnFailure(coi *createOptionsExInternal, origSpecRoot *specs.Root, weMountedStorage bool, vsmbMountsAddedByUs []string, currentError error) error {
	logrus.Debugf("hcsshim::undoMountOnFailure Unwinding container layers")
	retError := currentError
	if weMountedStorage {
		logrus.Debugf("hcsshim::undoMountOnFailure Unwinding container layers")
		if unmountError := UnmountContainerLayers(coi.Spec.Windows.LayerFolders, coi.HostingSystem, UnmountOperationAll); unmountError != nil {
			logrus.Warnf("may have leaked container layers storage on unwind: %s", unmountError)
			retError = errors.Wrapf(currentError, fmt.Sprintf("may have leaked some storage - hcsshim auto-mounted container storage, but was unable to complete the unmount: %s", unmountError))
		}
		coi.Spec.Root = origSpecRoot
	}

	// Unwind vsmb bind-mounts
	for _, vsmbMountAddedByUs := range vsmbMountsAddedByUs {
		logrus.Debugf("hcsshim::undoMountOnFailure Unwinding VSMB Mount %s", vsmbMountAddedByUs)
		if unmountError := RemoveVSMB(coi.HostingSystem, vsmbMountAddedByUs); unmountError != nil {
			logrus.Warnf("may have leaked vsmb for bind-mount on unwind: %s: %s", vsmbMountAddedByUs, unmountError)
			retError = errors.Wrapf(currentError, fmt.Sprintf("may have leaked some storage - hcsshim auto-mounted vsmb bind-mount, but was unable to complete the unmount: %s", unmountError))
		}
	}

	return retError
}
