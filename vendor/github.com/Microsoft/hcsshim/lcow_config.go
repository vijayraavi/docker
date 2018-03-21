package hcsshim

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

const (
	// DefaultLCOWVhdxSizeGB is the size of the default LCOW sandbox & scratch in GB
	DefaultLCOWVhdxSizeGB = 20

	// defaultLCOWVhdxBlockSizeMB is the block-size for the sandbox/scratch VHDx's this package can create.
	defaultLCOWVhdxBlockSizeMB = 1
)

// LCOWOptions is the structure used by a client to define configurable options for a utility VM.
type LCOWOptions struct {
	KirdPath       string // Path to where kernel/initrd are found (defaults to %PROGRAMFILES%\Linux Containers)
	KernelFile     string // Kernel for Utility VM (embedded in a UEFI bootloader) - does NOT include full path, just filename
	InitrdFile     string // Initrd image for Utility VM - does NOT include full path, just filename
	BootParameters string // Additional boot parameters for initrd booting (not VHDx)
}

// LCOWConfig is the structure used to configuring a utility VM.
type LCOWConfig struct {
	LCOWOptions                            // Configuration options
	Name               string              // Name of the utility VM
	Uvm                Container           // The actual container
	MappedVirtualDisks []MappedVirtualDisk // Data-disks to be attached
}

// GetLCOWOptions generates a default set of LCOW options. For consistency
// with the LCOW graphdriver in moby, we keep the convention of an `lcow.` prefix.
func GetLCOWOptions(options []string) (*LCOWOptions, error) {
	lo := &LCOWOptions{}
	for _, v := range options {
		opt := strings.SplitN(v, "=", 2)
		if len(opt) == 2 {
			switch strings.ToLower(opt[0]) {
			case "lcow.kirdpath":
				lo.KirdPath = opt[1]
			case "lcow.kernel":
				lo.KernelFile = opt[1]
			case "lcow.initrd":
				lo.InitrdFile = opt[1]
			case "lcow.bootparameters":
				lo.BootParameters = opt[1]
			}
		}
	}

	// Set default values if not supplied
	if lo.KirdPath == "" {
		lo.KirdPath = filepath.Join(os.Getenv("ProgramFiles"), "Linux Containers")
	}
	if lo.KernelFile == "" {
		lo.KernelFile = `bootx64.efi`
	}
	if lo.InitrdFile == "" {
		lo.InitrdFile = `initrd.img`
	}

	return lo, nil
}

// TODO. SPlit this. It's really a create, followed by a start.
// StartLCOWUVM creates and starts a utility VM from a configuration.
func (config *LCOWConfig) StartLCOWUVM() error {
	logrus.Debugf("hcsshim: StartLCOWUVM: %+v", config)

	if config.KernelFile == "" || config.InitrdFile == "" || config.KirdPath == "" {
		return fmt.Errorf("must supply kernel, initrd and path to them")
	}

	if _, err := os.Stat(filepath.Join(config.KirdPath, config.KernelFile)); os.IsNotExist(err) {
		return fmt.Errorf("kernel '%s' not found", filepath.Join(config.KirdPath, config.KernelFile))
	}
	if _, err := os.Stat(filepath.Join(config.KirdPath, config.InitrdFile)); os.IsNotExist(err) {
		return fmt.Errorf("initrd '%s' not found", filepath.Join(config.KirdPath, config.InitrdFile))
	}

	// Ensure all the MappedVirtualDisks exist on the host
	for _, mvd := range config.MappedVirtualDisks {
		if _, err := os.Stat(mvd.HostPath); err != nil {
			return fmt.Errorf("mapped virtual disk '%s' not found", mvd.HostPath)
		}
		if mvd.ContainerPath == "" {
			return fmt.Errorf("mapped virtual disk '%s' requested without a container path", mvd.HostPath)
		}
	}

	configuration := &ContainerConfig{
		HvPartition:                 true,
		Name:                        config.Name,
		SystemType:                  "container",
		ContainerType:               "linux",
		TerminateOnLastHandleClosed: true,
		MappedVirtualDisks:          config.MappedVirtualDisks,
	}

	configuration.HvRuntime = &HvRuntime{
		ImagePath:           config.KirdPath,
		LinuxInitrdFile:     config.InitrdFile,
		LinuxKernelFile:     config.KernelFile,
		LinuxBootParameters: config.BootParameters,
	}

	configurationS, _ := json.Marshal(configuration)
	logrus.Debugf("hcsshim: StartLCOWUVM: calling HCS with '%s'", string(configurationS))
	uvm, err := CreateContainer(config.Name, configuration)
	if err != nil {
		return err
	}
	logrus.Debugf("hcsshim: StartLCOWUVM: uvm created, starting...")
	err = uvm.Start()
	if err != nil {
		logrus.Debugf("hcsshim: StartLCOWUVM: uvm failed to start: %s", err)
		// Make sure we don't leave it laying around as it's been created in HCS
		uvm.Terminate()
		return err
	}

	config.Uvm = uvm
	logrus.Debugf("hcsshim: StartLCOWUVM: uvm %s is running", config.Name)
	return nil
}
