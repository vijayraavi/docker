// +build windows

package hcsshim

// Containers functions relating to utility VMs. Currently v2 schema only.

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/Microsoft/hcsshim/schema/v2"
	"github.com/Microsoft/hcsshim/schemaversion"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

type vsmbShare struct {
	refCount uint32
	guid     string
}

type UtilityVM struct {
	Id                      string                  // Identifier for the uvm. Defaults to generated GUID.
	Owner                   string                  // Specifies the owner. Defaults to executable name.
	OperatingSystem         string                  // "windows" or "linux"
	Resources               *specs.WindowsResources // Optional resources for the utility VM. Supports Memory.limit and CPU.Count only currently. // TODO possibly?
	AdditionHCSDocumentJSON string                  // Optional additional JSON to merge into the HCS document prior to a Utility VMs creation call

	// WCOW specific parameters
	LayerFolders []string // Set of folders for base layers and sandbox. Ordered from top most read-only through base read-only layer, followed by sandbox

	// LCOW specific parameters
	KirdPath               string                       // Folder in which kernel and initrd reside. Defaults to \Program Files\Linux Containers
	KernelFile             string                       // Filename under KirdPath for the kernel. Defaults to bootx64.efi
	InitrdFile             string                       // Filename under KirdPath for the initrd image. Defaults to initrd.img
	KernelBootOptions      string                       // Additional boot options for the kernel
	KernelDebugMode        bool                         // Configures the kernel in debug mode using sane defaults
	KernelDebugComPortPipe string                       // If kernel is in debug mode, can override the pipe here.
	SchemaVersion          *schemaversion.SchemaVersion // For a v1 service VM (back-compatibility)

	// Internal fields
	hcsHandle      hcsSystem // TODO: This should really just be a syscall.Handle
	handleLock     sync.RWMutex
	callbackNumber uintptr
	vsmbShares     struct {
		sync.Mutex
		shares map[string]vsmbShare
	}
	vpmemLocations struct {
		sync.Mutex
		hostPath [128]string // Limited by ACPI size.
	}
	scsiLocations struct {
		sync.Mutex
		hostPath [4][64]string // Hyper-V supports 4 controllers, 64 slots per controller. Limited to 1 controller for now though.
	}
}

// TODO: Extend for the "serviceVM" concept for LCOW v1 schema (back-compat)
// Create() creates a utility VM.
//
// WCOW Notes:
//   - If the sandbox folder does not exist, it will be created
//   - If the sandbox folder does not contain `sandbox.vhdx` it will be created based on the system template located in the layer folders.
//   - The sandbox is always attached to SCSI 0:0
func (uvm *UtilityVM) Create() error {
	logrus.Debugf("uvm::Create option: %+v", uvm) // TODO Tidy this up whatis printed.

	if uvm.OperatingSystem != "linux" && uvm.OperatingSystem != "windows" {
		panic("JJH")
		logrus.Debugf("uvm::Create Unsupported OS")
		return fmt.Errorf("unsupported operating system %q", uvm.OperatingSystem)
	}

	// Defaults if omitted by caller.
	if uvm.Id == "" {
		g, err := GenerateGUID()
		if err != nil {
			return fmt.Errorf("failed to generate GUID for Id: %s", err)
		}
		uvm.Id = g.ToString()
	}
	if uvm.Owner == "" {
		uvm.Owner = filepath.Base(os.Args[0])
	}
	if uvm.OperatingSystem == "linux" {
		if uvm.KirdPath == "" {
			uvm.KirdPath = filepath.Join(os.Getenv("ProgramFiles"), "Linux Containers")
		}
		if uvm.KernelFile == "" {
			uvm.KernelFile = "bootx64.efi"
		}
		if uvm.InitrdFile == "" {
			uvm.InitrdFile = "initrd.img"
		}
		if uvm.KernelDebugComPortPipe == "" {
			uvm.KernelDebugComPortPipe = `\\.\pipe\vmpipe`
		}
		if _, err := os.Stat(filepath.Join(uvm.KirdPath, uvm.KernelFile)); os.IsNotExist(err) {
			return fmt.Errorf("kernel '%s' not found", filepath.Join(uvm.KirdPath, uvm.KernelFile))
		}
		if _, err := os.Stat(filepath.Join(uvm.KirdPath, uvm.InitrdFile)); os.IsNotExist(err) {
			return fmt.Errorf("initrd '%s' not found", filepath.Join(uvm.KirdPath, uvm.InitrdFile))
		}

		// MOVE THIS TO THE CONTAINER SIZE NOW TODO TODO TODO
		//		// Ensure all the MappedVirtualDisks exist on the host
		//		for _, mvd := range config.MappedVirtualDisks {
		//			if _, err := os.Stat(mvd.HostPath); err != nil {
		//				return fmt.Errorf("mapped virtual disk '%s' not found", mvd.HostPath)
		//			}
		//			if mvd.ContainerPath == "" {
		//				return fmt.Errorf("mapped virtual disk '%s' requested without a container path", mvd.HostPath)
		//			}
		//		}

	}
	if uvm.SchemaVersion == nil {
		uvm.SchemaVersion = schemaversion.SchemaV20()
	}

	if uvm.OperatingSystem == "windows" {
		logrus.Debugf("uvm::Create Windows utility VM")
		return uvm.createWCOW()
	}
	logrus.Debugf("uvm::Create Linux utility VM")
	return uvm.createLCOW()
}

func (uvm *UtilityVM) createLCOW() error {
	logrus.Debugf("uvm::createLCOW id=%s", uvm.Id)

	memory := int32(1024)
	processors := int32(2)
	if numCPU() == 1 {
		processors = 1
	}
	if uvm.Resources != nil {
		if uvm.Resources.Memory != nil && uvm.Resources.Memory.Limit != nil {
			memory = int32(*uvm.Resources.Memory.Limit / 1024 / 1024) // OCI spec is in bytes. HCS takes MB
		}
		if uvm.Resources.CPU != nil && uvm.Resources.CPU.Count != nil {
			processors = int32(*uvm.Resources.CPU.Count)
		}
	}

	//	// See if there's a sandbox folder at the end of the layer folders. If it is, then we attach this to SCSI.
	//	// We look for a .vhdx in that folder as the key. RO layers are .vhd.
	//	possibleSandboxFolder := coi.Spec.Windows.LayerFolders[len(coi.Spec.Windows.LayerFolders)-1]
	//	sandboxFile := ""

	//	err := filepath.Walk(possibleSandboxFolder, func(path string, info os.FileInfo, err error) error {
	//		if info.IsDir() {
	//			return nil
	//		}
	//		if filepath.Ext(path) == ".vhdx" {
	//			sandboxFile = path
	//			return io.EOF // Trick to break out early.
	//		}
	//		return nil
	//	})
	//	if err == io.EOF {
	//		err = nil
	//	}

	//
	// We need to build the v1 version here too.

	scsi := make(map[string]hcsschemav2.VirtualMachinesResourcesStorageScsiV2)
	scsi["0"] = hcsschemav2.VirtualMachinesResourcesStorageScsiV2{Attachments: make(map[string]hcsschemav2.VirtualMachinesResourcesStorageAttachmentV2)}
	hcsDocumentV2 := &hcsschemav2.ComputeSystemV2{
		Owner:         uvm.Owner,
		SchemaVersion: schemaversion.SchemaV20(),
		VirtualMachine: &hcsschemav2.VirtualMachineV2{
			Chipset: &hcsschemav2.VirtualMachinesResourcesChipsetV2{
				UEFI: &hcsschemav2.VirtualMachinesResourcesUefiV2{
					BootThis: &hcsschemav2.VirtualMachinesResourcesUefiBootEntryV2{
						DevicePath:   `\` + uvm.KernelFile,
						DiskNumber:   0,
						UefiDevice:   "VMBFS",
						OptionalData: `initrd=\` + uvm.InitrdFile,
					},
				},
			},
			ComputeTopology: &hcsschemav2.VirtualMachinesResourcesComputeTopologyV2{
				Memory: &hcsschemav2.VirtualMachinesResourcesComputeMemoryV2{
					Backing: "Virtual",
					Startup: memory,
				},
				Processor: &hcsschemav2.VirtualMachinesResourcesComputeProcessorV2{
					Count: processors,
				},
			},

			Devices: &hcsschemav2.VirtualMachinesDevicesV2{
				// Add networking here.... TODO
				VPMem: &hcsschemav2.VirtualMachinesResourcesStorageVpmemControllerV2{
					MaximumCount: 128, // TODO: Consider making this flexible. Effectively the number of unique read-only layers available in the UVM. LCOW max is 128 in the platform.
				},
				SCSI: scsi,
				VirtualSMBShares: []hcsschemav2.VirtualMachinesResourcesStorageVSmbShareV2{hcsschemav2.VirtualMachinesResourcesStorageVSmbShareV2{
					Flags: hcsschemav2.VsmbFlagReadOnly | hcsschemav2.VsmbFlagShareRead | hcsschemav2.VsmbFlagCacheIO | hcsschemav2.VsmbFlagTakeBackupPrivilege, // 0x17 (23 dec)
					Name:  "os",
					Path:  uvm.KirdPath,
				}},
				GuestInterface: &hcsschemav2.VirtualMachinesResourcesGuestInterfaceV2{
					ConnectToBridge: true,
					BridgeFlags:     3, // TODO What are these??
				},
			},
		},
	}

	if uvm.KernelDebugMode {
		hcsDocumentV2.VirtualMachine.Chipset.UEFI.BootThis.OptionalData += " console=ttyS0,115200"
		hcsDocumentV2.VirtualMachine.Devices.COMPorts = &hcsschemav2.VirtualMachinesResourcesComPortsV2{Port1: uvm.KernelDebugComPortPipe}
		hcsDocumentV2.VirtualMachine.Devices.Keyboard = &hcsschemav2.VirtualMachinesResourcesKeyboardV2{}
		hcsDocumentV2.VirtualMachine.Devices.Mouse = &hcsschemav2.VirtualMachinesResourcesMouseV2{}
		hcsDocumentV2.VirtualMachine.Devices.Rdp = &hcsschemav2.VirtualMachinesResourcesRdpV2{}
		hcsDocumentV2.VirtualMachine.Devices.VideoMonitor = &hcsschemav2.VirtualMachinesResourcesVideoMonitorV2{}
	}

	if uvm.KernelBootOptions != "" {
		hcsDocumentV2.VirtualMachine.Chipset.UEFI.BootThis.OptionalData = hcsDocumentV2.VirtualMachine.Chipset.UEFI.BootThis.OptionalData + fmt.Sprintf(" %s", uvm.KernelBootOptions)
	}

	hcsDocumentV2B, err := json.Marshal(hcsDocumentV2)
	if err != nil {
		return err
	}
	if err := uvm.createHCSComputeSystem(string(hcsDocumentV2B)); err != nil {
		logrus.Debugln("failed to create UVM: ", err)
		return err
	}

	return nil
}

func (uvm *UtilityVM) createWCOW() error {
	logrus.Debugf("uvm::createWCOW Creating utility VM id=%s", uvm.Id)

	if len(uvm.LayerFolders) < 2 {
		return fmt.Errorf("at least 2 LayerFolders must be supplied")
	}

	uvmFolder, err := LocateWCOWUVMFolderFromLayerFolders(uvm.LayerFolders)
	if err != nil {
		return fmt.Errorf("failed to locate utility VM folder from layer folders: %s", err)
	}

	// Create the sandbox in the top-most layer folder, creating the folder if it doesn't already exist.
	sandboxFolder := uvm.LayerFolders[len(uvm.LayerFolders)-1]
	logrus.Debugf("uvm::createWCOW Sandbox folder: %s", sandboxFolder)

	// Create the directory if it doesn't exist
	if _, err := os.Stat(sandboxFolder); os.IsNotExist(err) {
		logrus.Debugf("uvm::createWCOW Creating folder: %s ", sandboxFolder)
		if err := os.MkdirAll(sandboxFolder, 0777); err != nil {
			return fmt.Errorf("failed to create utility VM sandbox folder: %s", err)
		}
	}

	// Create sandbox.vhdx in the sandbox folder based on the template, granting the correct permissions to it
	if _, err := os.Stat(filepath.Join(sandboxFolder, `sandbox.vhdx`)); os.IsNotExist(err) {
		if err := CreateWCOWUVMSandbox(uvmFolder, sandboxFolder, uvm.Id); err != nil {
			return fmt.Errorf("failed to create sandbox: %s", err)
		}
	}

	// We attach the sandbox to SCSI 0:0
	attachments := make(map[string]hcsschemav2.VirtualMachinesResourcesStorageAttachmentV2)
	attachments["0"] = hcsschemav2.VirtualMachinesResourcesStorageAttachmentV2{
		Path: filepath.Join(sandboxFolder, "sandbox.vhdx"),
		Type: "VirtualDisk",
	}
	scsi := make(map[string]hcsschemav2.VirtualMachinesResourcesStorageScsiV2)
	scsi["0"] = hcsschemav2.VirtualMachinesResourcesStorageScsiV2{Attachments: attachments}

	// Resources
	memory := int32(1024)
	processors := int32(2)
	if numCPU() == 1 {
		processors = 1
	}
	if uvm.Resources != nil {
		if uvm.Resources.Memory != nil && uvm.Resources.Memory.Limit != nil {
			memory = int32(*uvm.Resources.Memory.Limit / 1024 / 1024) // OCI spec is in bytes. HCS takes MB
		}
		if uvm.Resources.CPU != nil && uvm.Resources.CPU.Count != nil {
			processors = int32(*uvm.Resources.CPU.Count)
		}
	}

	hcsDocument := &hcsschemav2.ComputeSystemV2{
		Owner:         uvm.Owner,
		SchemaVersion: schemaversion.SchemaV20(),
		VirtualMachine: &hcsschemav2.VirtualMachineV2{
			Chipset: &hcsschemav2.VirtualMachinesResourcesChipsetV2{
				UEFI: &hcsschemav2.VirtualMachinesResourcesUefiV2{
					BootThis: &hcsschemav2.VirtualMachinesResourcesUefiBootEntryV2{
						DevicePath: `\EFI\Microsoft\Boot\bootmgfw.efi`,
						DiskNumber: 0,
						UefiDevice: "VMBFS",
					},
				},
			},
			ComputeTopology: &hcsschemav2.VirtualMachinesResourcesComputeTopologyV2{
				Memory: &hcsschemav2.VirtualMachinesResourcesComputeMemoryV2{
					Backing:             "Virtual",
					Startup:             memory,
					DirectFileMappingMB: 1024, // Sensible default, but could be a tuning parameter somewhere
				},
				Processor: &hcsschemav2.VirtualMachinesResourcesComputeProcessorV2{
					Count: processors,
				},
			},

			Devices: &hcsschemav2.VirtualMachinesDevicesV2{
				// Add networking here.... TODO
				SCSI: scsi,
				VirtualSMBShares: []hcsschemav2.VirtualMachinesResourcesStorageVSmbShareV2{hcsschemav2.VirtualMachinesResourcesStorageVSmbShareV2{
					Flags: hcsschemav2.VsmbFlagReadOnly | hcsschemav2.VsmbFlagPseudoOplocks | hcsschemav2.VsmbFlagTakeBackupPrivilege | hcsschemav2.VsmbFlagCacheIO | hcsschemav2.VsmbFlagShareRead,
					Name:  "os",
					Path:  filepath.Join(uvmFolder, `UtilityVM\Files`),
				}},
				GuestInterface: &hcsschemav2.VirtualMachinesResourcesGuestInterfaceV2{ConnectToBridge: true},
			},
		},
	}

	hcsDocumentB, err := json.Marshal(hcsDocument)
	if err != nil {
		return err
	}
	if err := uvm.createHCSComputeSystem(string(hcsDocumentB)); err != nil {
		logrus.Debugln("failed to create UVM: ", err)
		return err
	}

	uvm.scsiLocations.hostPath[0][0] = attachments["0"].Path
	return nil

}

// CreateWCOWUVMSandbox is a helper to create a sandbox for a Windows utility VM
// with permissions to the specified VM ID in a specified directory
func CreateWCOWUVMSandbox(imagePath, destDirectory, vmID string) error {
	sourceSandbox := filepath.Join(imagePath, `UtilityVM\SystemTemplate.vhdx`)
	targetSandbox := filepath.Join(destDirectory, "sandbox.vhdx")
	logrus.Debugf("uvm::CreateWCOWUVMSandbox %s from %s", targetSandbox, sourceSandbox)
	if err := CopyFile(sourceSandbox, targetSandbox, true); err != nil {
		return err
	}
	if err := GrantVmAccess(vmID, targetSandbox); err != nil {
		// TODO: Delete the file?
		return err
	}
	return nil
}

func (uvm *UtilityVM) createHCSComputeSystem(hcsDocument string) error {
	title := fmt.Sprintf("uvm::createHCSComputeSystem id:%s ", uvm.Id)
	logrus.Debugf(title+"document:%s", hcsDocument)

	// Merge any additional JSON.
	if uvm.AdditionHCSDocumentJSON != "" {
		hcsDocumentMap := map[string]interface{}{}
		if err := json.Unmarshal([]byte(hcsDocument), &hcsDocumentMap); err != nil {
			return fmt.Errorf("failed to unmarshal %s: %s", hcsDocument, err)
		}
		additionalMap := map[string]interface{}{}
		if err := json.Unmarshal([]byte(uvm.AdditionHCSDocumentJSON), &additionalMap); err != nil {
			return fmt.Errorf("failed to unmarshal %s: %s", uvm.AdditionHCSDocumentJSON, err)
		}
		mergedMap := mergeMaps(additionalMap, hcsDocumentMap)
		mergedJSON, err := json.Marshal(mergedMap)
		if err != nil {
			return fmt.Errorf("failed to marshal merged configuration map %+v: %s", mergedMap, err)
		}
		hcsDocument = string(mergedJSON)
		logrus.Debugf(title+"updated document:%s", hcsDocument)
	}

	var (
		resultp  *uint16
		identity syscall.Handle
	)
	createError := hcsCreateComputeSystem(uvm.Id, hcsDocument, identity, &uvm.hcsHandle, &resultp)

	if createError == nil || IsPending(createError) {
		if err := uvm.registerCallback(); err != nil {
			// Terminate the container if it still exists. We're okay to ignore a failure here.
			// TODO TODO TODO uvm.Terminate()
			return uvm.makeError("registerCallBack after CreateComputeSystem", nil, hcsDocument, err)
		}
	}

	err := processAsyncHcsResult(createError, resultp, uvm.callbackNumber, hcsNotificationSystemCreateCompleted, &defaultTimeoutSeconds)
	if err != nil {
		if err == ErrTimeout {
			// Terminate the container if it still exists. We're okay to ignore a failure here.
			// TODO TODO TODO: uvm.Terminate()
		}
		return uvm.makeError("processAsyncHcsResult after CreateComputeSystem", nil, hcsDocument, err)
	}

	logrus.Debugf(title+" succeeded handle=%d", uvm.hcsHandle)
	return nil
}

// Modifies the System by sending a request to HCS
func (uvm *UtilityVM) Modify(config interface{}) error {
	uvm.handleLock.RLock()
	defer uvm.handleLock.RUnlock()
	operation := "Modify"
	title := "uvm::" + operation

	if uvm.hcsHandle == 0 {
		return uvm.makeError(operation, nil, "", ErrAlreadyClosed)
	}

	requestJSON, err := json.Marshal(config)
	if err != nil {
		return err
	}

	requestString := string(requestJSON)
	logrus.Debugf(title+" id=%s request=%s", uvm.Id, requestString)

	var resultp *uint16
	err = hcsModifyComputeSystem(uvm.hcsHandle, requestString, &resultp)
	re := processHcsResult(resultp)
	if err != nil {
		err = uvm.makeError(operation, re, requestString, err)
		return err
	}
	logrus.Debugf(title+" succeeded id=%s", uvm.Id)
	return nil
}

// UtilityVMError is an error encountered in HCS
type UtilityVMError struct {
	Id          string
	Operation   string
	ExtraInfo   string
	Err         error
	ResultError *ResultError
}

func (e *UtilityVMError) Error() string {
	if e == nil {
		return "<nil>"
	}

	s := "id " + e.Id

	if e.Operation != "" {
		s += " encountered an error during " + e.Operation
	}

	switch e.Err.(type) {
	case nil:
		break
	case syscall.Errno:
		s += fmt.Sprintf(": failure in a Windows system call: %s (0x%x)", e.Err, win32FromError(e.Err))
	default:
		s += fmt.Sprintf(": %s", e.Err.Error())
	}

	if e.ExtraInfo != "" {
		s += " extra info: " + e.ExtraInfo
	}

	if e.ResultError != nil {
		for _, ev := range e.ResultError.ErrorEvents {
			evs := " [Event Detail: " + ev.Message
			if ev.StackTrace != "" {
				evs += " Stack Trace: " + ev.StackTrace
			}
			if ev.Provider != "" {
				evs += " Provider: " + ev.Provider
			}
			if ev.EventId != 0 {
				evs = fmt.Sprintf("%s EventID: %d", evs, ev.EventId)
			}
			if ev.Flags != 0 {
				evs = fmt.Sprintf("%s EventID: %d", evs, ev.Flags)
			}
			if ev.Source != "" {
				evs += " Source: " + ev.Source
			}
			s += evs + "]"
		}
	}

	return s
}

func (uvm *UtilityVM) makeError(operation string, resultError *ResultError, extraInfo string, err error) error {
	// Don't double wrap errors
	if _, ok := err.(*UtilityVMError); ok {
		return err
	}
	return &UtilityVMError{Operation: operation, ExtraInfo: extraInfo, Err: err, ResultError: resultError}
}

// UVMResourcesFromContainerSpec takes a container spec and generates a
// resources structure suitable for creating a utility VM to host the uvm.
// This is really only relevant for a client that is running a single container
// in a utility VM using the v2 schema. It implements logic which for the v1 schema
// was implemented internally in HCS.
func UVMResourcesFromContainerSpec(spec *specs.Spec) (*specs.WindowsResources, error) {
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

func (uvm *UtilityVM) registerCallback() error {
	context := &notifcationWatcherContext{
		channels: newChannels(),
	}
	callbackMapLock.Lock()
	callbackNumber := nextCallback
	nextCallback++
	callbackMap[callbackNumber] = context
	callbackMapLock.Unlock()

	var callbackHandle hcsCallback
	err := hcsRegisterComputeSystemCallback(uvm.hcsHandle, notificationWatcherCallback, callbackNumber, &callbackHandle)
	if err != nil {
		return err
	}
	context.handle = callbackHandle
	uvm.callbackNumber = callbackNumber

	return nil
}

func (uvm *UtilityVM) unregisterCallback() error {
	callbackNumber := uvm.callbackNumber
	callbackMapLock.RLock()
	context := callbackMap[callbackNumber]
	callbackMapLock.RUnlock()

	if context == nil {
		return nil
	}
	handle := context.handle
	if handle == 0 {
		return nil
	}

	// hcsUnregisterComputeSystemCallback has its own syncronization
	// to wait for all callbacks to complete. We must NOT hold the callbackMapLock.
	err := hcsUnregisterComputeSystemCallback(handle)
	if err != nil {
		return err
	}

	closeChannels(context.channels)
	callbackMapLock.Lock()
	callbackMap[callbackNumber] = nil
	callbackMapLock.Unlock()
	handle = 0

	return nil
}

// Not sure if need to export. Regardless, it is only present for v1 LCOW utility VMs.
func (uvm *UtilityVM) mappedVirtualDisks() (map[int]MappedVirtualDiskController, error) {
	if !uvm.SchemaVersion.IsV10() {
		return nil, fmt.Errorf("MappedVirtualDisks is only supported for schema v1 containers")
	}
	uvm.handleLock.RLock()
	defer uvm.handleLock.RUnlock()
	operation := "MappedVirtualDiskList"
	title := "hcsshim::Container::" + operation
	logrus.Debugf(title+" id=%s", uvm.Id)

	if uvm.hcsHandle == 0 {
		return nil, uvm.makeError(operation, nil, "", ErrAlreadyClosed)
	}

	properties, err := uvm.properties(mappedVirtualDiskQuery)
	if err != nil {
		return nil, uvm.makeError(operation, nil, "", err)
	}

	logrus.Debugf(title+" succeeded id=%s", uvm.Id)
	logrus.Debugf("%+v", properties.MappedVirtualDiskControllers)
	return properties.MappedVirtualDiskControllers, nil
}

// Currently only used by mappedVirtualDisks which in turn is only used by v1 LCOW utility VMs
func (uvm *UtilityVM) properties(query string) (*ContainerProperties, error) {
	var (
		resultp     *uint16
		propertiesp *uint16
	)
	err := hcsGetComputeSystemProperties(uvm.hcsHandle, query, &propertiesp, &resultp)
	//re := processHcsResult(resultp)
	if err != nil {
		// TODO: Do something with the extended result
		return nil, err
	}

	if propertiesp == nil {
		return nil, ErrUnexpectedValue
	}
	propertiesRaw := convertAndFreeCoTaskMemBytes(propertiesp)
	properties := &ContainerProperties{}
	if err := json.Unmarshal(propertiesRaw, properties); err != nil {
		return nil, err
	}
	return properties, nil
}

// Terminate requests a utility VM terminate, if IsPending() on the error returned is true,
// it may not actually be shut down until Wait() succeeds.
func (uvm *UtilityVM) Terminate() error {
	uvm.handleLock.RLock()
	defer uvm.handleLock.RUnlock()
	operation := "Terminate"
	title := "uvm::" + operation
	logrus.Debugf(title+" id=%s", uvm.Id)

	if uvm.hcsHandle == 0 {
		return uvm.makeError(operation, nil, "", ErrAlreadyClosed)
	}

	var resultp *uint16
	err := hcsTerminateComputeSystem(uvm.hcsHandle, "", &resultp)
	re := processHcsResult(resultp)
	if err != nil {
		return uvm.makeError(operation, re, "", err)
	}

	logrus.Debugf(title+" succeeded id=%s", uvm.Id)
	return nil
}

// Start synchronously starts the uvm.
func (uvm *UtilityVM) Start() error {
	uvm.handleLock.RLock()
	defer uvm.handleLock.RUnlock()
	operation := "Start"
	title := "uvm::" + operation
	logrus.Debugf(title+" id=%s", uvm.Id)

	if uvm.hcsHandle == 0 {
		return uvm.makeError(operation, nil, "", ErrAlreadyClosed)
	}

	var resultp *uint16
	err := hcsStartComputeSystem(uvm.hcsHandle, "", &resultp)
	err = processAsyncHcsResult(err, resultp, uvm.callbackNumber, hcsNotificationSystemStartCompleted, &defaultTimeoutSeconds)
	if err != nil {
		return uvm.makeError(operation, nil, "", err)
	}

	logrus.Debugf(title+" succeeded id=%s", uvm.Id)
	return nil
}

// CreateProcessExParams is the structure used for calling CreateProcessEx
type UVMProcessOptions struct {
	Process    *specs.Process
	Stdin      io.Reader  // Optional reader for sending on to the processes stdin stream
	Stdout     io.Writer  // Optional writer for returning the processes stdout stream
	Stderr     io.Writer  // Optional writer for returning the processes stderr stream
	ByteCounts ByteCounts // How much data to copy on each stream if they are supplied. 0 means to io.EOF.
}

// TODO UPDATE THIS COMMENT NOW
// CreateProcessEx is a wrapper for CreateProcess that creates an arbirary process
// (most usefully inside a utility VM) and optionally performs IO copies
// with timeout between the pipes provided as input, and the pipes in the process.
// In the parameter structure, if byte-counts are non-zero, a maximum of those
// bytes are copied to the appropriate standard IO reader/writer. When zero,
// it copies until EOF. It also returns byte-counts indicating how much data
// was sent/received from the process. It is the responsibility of the caller
// to call Close() on the process returned.
func (uvm *UtilityVM) CreateProcess(opts *UVMProcessOptions) (Process, *ByteCounts, error) {
	operation := "CreateProcess"
	if opts.Process == nil {
		return nil, nil, fmt.Errorf("no Process passed to CreateProcessEx")
	}

	copiedByteCounts := &ByteCounts{}
	commandLine := strings.Join(opts.Process.Args, " ")
	environment := make(map[string]string)
	for _, v := range opts.Process.Env {
		s := strings.SplitN(v, "=", 2)
		if len(s) == 2 && len(s[1]) > 0 {
			environment[s[0]] = s[1]
		}
	}

	if uvm.OperatingSystem == "linux" {
		if _, ok := environment["PATH"]; !ok {
			environment["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:"
		}
	}

	processConfig := &ProcessConfig{
		EmulateConsole:    false,
		CreateStdInPipe:   (opts.Stdin != nil),
		CreateStdOutPipe:  (opts.Stdout != nil),
		CreateStdErrPipe:  (opts.Stderr != nil),
		CreateInUtilityVm: true,
		WorkingDirectory:  opts.Process.Cwd,
		Environment:       environment,
		CommandLine:       commandLine,
	}

	uvm.handleLock.RLock()
	defer uvm.handleLock.RUnlock()
	var (
		processInfo   hcsProcessInformation
		processHandle hcsProcess
		resultp       *uint16
	)

	if uvm.hcsHandle == 0 {
		return nil, nil, uvm.makeError(operation, nil, "", ErrAlreadyClosed)
	}

	// If we are not emulating a console, ignore any console size passed to us
	if !processConfig.EmulateConsole {
		processConfig.ConsoleSize[0] = 0
		processConfig.ConsoleSize[1] = 0
	}

	processConfigB, err := json.Marshal(processConfig)
	if err != nil {
		return nil, nil, uvm.makeError(operation, nil, "", err)
	}

	configuration := string(processConfigB)
	logrus.Debugf("uvm::CreateProcessEx id=%s config=%s", uvm.Id, configuration)

	err = hcsCreateProcess(uvm.hcsHandle, configuration, &processInfo, &processHandle, &resultp)
	re := processHcsResult(resultp)
	if err != nil {
		return nil, nil, uvm.makeError(operation, re, configuration, err)
	}

	proc := &process{
		handle:    processHandle,
		processID: int(processInfo.ProcessId),
		cachedPipes: &cachedPipes{
			stdIn:  processInfo.StdInput,
			stdOut: processInfo.StdOutput,
			stdErr: processInfo.StdError,
		},
	}

	if err := proc.registerCallback(); err != nil {
		return nil, nil, uvm.makeError(operation, nil, "", err)
	}

	processStdin, processStdout, processStderr, err := proc.Stdio()
	if err != nil {
		proc.Kill() // Should this have a timeout?
		proc.Close()
		return nil, nil, fmt.Errorf("failed to get stdio pipes for process %+v: %s", processConfig, err)
	}

	// Send the data into the process's stdin
	if opts.Stdin != nil {
		if copiedByteCounts.In, err = copyWithTimeout(processStdin,
			opts.Stdin,
			opts.ByteCounts.In,
			fmt.Sprintf("CreateProcessEx: to stdin of %q", commandLine)); err != nil {
			return nil, nil, err
		}

		// Don't need stdin now we've sent everything. This signals GCS that we are finished sending data.
		if err := proc.CloseStdin(); err != nil && !IsNotExist(err) && !IsAlreadyClosed(err) {
			// This error will occur if the compute system is currently shutting down
			if perr, ok := err.(*ProcessError); ok && perr.Err != ErrVmcomputeOperationInvalidState {
				return nil, nil, err
			}
		}
	}

	// Copy the data back from stdout
	if opts.Stdout != nil {
		// Copy the data over to the writer.
		if copiedByteCounts.Out, err = copyWithTimeout(opts.Stdout,
			processStdout,
			opts.ByteCounts.Out,
			fmt.Sprintf("CreateProcessEx: from stdout from %q", commandLine)); err != nil {
			return nil, nil, err
		}
	}

	// Copy the data back from stderr
	if opts.Stderr != nil {
		// Copy the data over to the writer.
		if copiedByteCounts.Err, err = copyWithTimeout(opts.Stderr,
			processStderr,
			opts.ByteCounts.Err,
			fmt.Sprintf("CreateProcessEx: from stderr of %s", commandLine)); err != nil {
			return nil, nil, err
		}
	}

	logrus.Debugf("hcsshim: CreateProcessEx success: %q", commandLine)
	return proc, copiedByteCounts, nil
}
