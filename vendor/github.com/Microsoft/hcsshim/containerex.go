package hcsshim

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"syscall"
	"time"

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

// CreateProcessExParams is the structure used for calling CreateProcessEx
type CreateProcessEx struct {
	OCISpecification      specs.Spec    // Required to be fully populated for LCOW as passed to GCS.
	ProcessSpec           specs.Process // Command/Args, Environment and Working Directory
	TargetOperatingSystem string        // Defaults PATH if not set and is a supported OS
	CreateInUtilityVm     bool          // Whether the process is created in the utility VM or the container
	Stdin                 io.Reader     // Optional reader for sending on to the processes stdin stream
	Stdout                io.Writer     // Optional writer for returning the processes stdout stream
	Stderr                io.Writer     // Optional writer for returning the processes stderr stream
	ByteCounts            ByteCounts    // How much data to copy on each stream if they are supplied. 0 means to io.EOF.
}

// ByteCounts are the number of bytes copied to/from standard handles. Note
// this is int64 rather than uint64 to match the golang io.Copy() signature.
type ByteCounts struct {
	In  int64
	Out int64
	Err int64
}

// CreateProcessEx is a wrapper for CreateProcess that creates an arbirary process
// (most usefully inside a utility VM) and optionally performs IO copies
// with timeout between the pipes provided as input, and the pipes in the process.
// In the parameter structure, if byte-counts are non-zero, a maximum of those
// bytes are copied to the appropriate standard IO reader/writer. When zero,
// it copies until EOF. It also returns byte-counts indicating how much data
// was sent/received from the process. It is the responsibility of the caller
// to call Close() on the process returned.
func (container *container) CreateProcessEx(opts *CreateProcessEx) (Process, *ByteCounts, error) {
	logrus.Debugf("hcsshim: CreateProcessEx: %+v", opts)

	copiedByteCounts := &ByteCounts{}
	commandLine := strings.Join(opts.ProcessSpec.Args, " ")
	environment := make(map[string]string)
	for _, v := range opts.ProcessSpec.Env {
		s := strings.SplitN(v, "=", 2)
		if len(s) == 2 && len(s[1]) > 0 {
			environment[s[0]] = s[1]
		}
	}

	switch strings.ToLower(opts.TargetOperatingSystem) {
	case "windows":
		return nil, nil, fmt.Errorf("CreateProcessEx not supported yet for Windows containers")
	case "linux":
		if _, ok := environment["PATH"]; !ok {
			environment["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:"
		}
		// Is this actually necessary?
		if opts.ProcessSpec.Cwd == "" {
			opts.ProcessSpec.Cwd = "/"
		}
	}

	processConfig := &ProcessConfig{
		EmulateConsole:    false,
		CreateStdInPipe:   (opts.Stdin != nil),
		CreateStdOutPipe:  (opts.Stdout != nil),
		CreateStdErrPipe:  (opts.Stderr != nil),
		CreateInUtilityVm: opts.CreateInUtilityVm,
		WorkingDirectory:  opts.ProcessSpec.Cwd,
		Environment:       environment,
		CommandLine:       commandLine,
	}

	if opts.TargetOperatingSystem == "linux" {
		// LCOW requires the raw OCI spec passed through HCS and onwards to
		// GCS for the utility VM.
		ociBuf, err := json.Marshal(opts.OCISpecification)
		if err != nil {
			return nil, nil, err
		}
		ociRaw := json.RawMessage(ociBuf)
		processConfig.OCISpecification = &ociRaw
	}

	proc, err := container.CreateProcess(processConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create process (%+v): %s", processConfig, err)
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
			fmt.Sprintf("CreateProcessEx: to stdin of qs", commandLine)); err != nil {
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

// copyWithTimeout is a wrapper for io.Copy using a timeout duration
func copyWithTimeout(dst io.Writer, src io.Reader, size int64, context string) (int64, error) {
	log := "to EOF"
	if size > 0 {
		log = fmt.Sprintf("%d bytes", size)
	}
	logrus.Debugf(fmt.Sprintf("hcsshim: copywithtimeout (%s) %s", context, log))

	type resultType struct {
		err   error
		bytes int64
	}

	done := make(chan resultType, 1)
	go func() {
		result := resultType{}
		if logrus.GetLevel() < logrus.DebugLevel || logDataByteCount == 0 {
			result.bytes, result.err = io.Copy(dst, src)
		} else {
			// In advanced debug mode where we log (hexdump format) what is copied
			// up to the number of bytes defined by environment variable
			// HCSSHIM_LOG_DATA_BYTE_COUNT
			var buf bytes.Buffer
			tee := io.TeeReader(src, &buf)
			result.bytes, result.err = io.Copy(dst, tee)
			if result.err == nil {
				size := result.bytes
				if size > logDataByteCount {
					size = logDataByteCount
				}
				if size > 0 {
					bytes := make([]byte, size)
					if _, err := buf.Read(bytes); err == nil {
						logrus.Debugf(fmt.Sprintf("hcsshim: copyWithTimeout\n%s", hex.Dump(bytes)))
					}
				}
			}
		}
		done <- result
	}()

	var result resultType
	timedout := time.After(defaultTimeoutSeconds)

	select {
	case <-timedout:
		return 0, fmt.Errorf("hcsshim: copyWithTimeout: timed out (%s)", context)
	case result = <-done:
		if result.err != nil && result.err != io.EOF {
			// See https://github.com/golang/go/blob/f3f29d1dea525f48995c1693c609f5e67c046893/src/os/exec/exec_windows.go for a clue as to why we are doing this :)
			if se, ok := result.err.(syscall.Errno); ok {
				const (
					errNoData     = syscall.Errno(232)
					errBrokenPipe = syscall.Errno(109)
				)
				if se == errNoData || se == errBrokenPipe {
					logrus.Debugf("hcsshim: copyWithTimeout: hit NoData or BrokenPipe: %d: %s", se, context)
					return result.bytes, nil
				}
			}
			return 0, fmt.Errorf("hcsshim: copyWithTimeout: error reading: '%s' after %d bytes (%s)", result.err, result.bytes, context)
		}
	}
	logrus.Debugf("hcsshim: copyWithTimeout: success - copied %d bytes (%s)", result.bytes, context)
	return result.bytes, nil
}

// CreateOptions are the complete set of fields required to call any of the
// Create* APIs in HCSShim.
type CreateOptions struct {
	id            string                        // Identifier for the container
	hostingSystem Container                     // Container object if creating a hosted system
	owner         string                        // Arbitrary string determining the owner
	schemaVersion SchemaVersion                 // Schema version of the create request
	spec          *specs.Spec                   // Definition of the container or utility VM
	lcowOptions   *LCOWOptions                  // Configuration of an LCOW utility VM. ??Should these be part of OCI?? // What about annotations to put these in?
	logger        *logrus.Entry                 // For logging
	mountedLayers *ContainersResourcesStorageV2 // For v2 Xenon - TODO for Argon too....
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

	logrus.Debugf("CreateContainerEx %+v", createOptions)

	if err := createOptions.schemaVersion.isSupported(); err != nil {
		return nil, err
	}
	if createOptions.id == "" {
		return nil, fmt.Errorf("id must be supplied")
	}
	if createOptions.owner == "" {
		return nil, fmt.Errorf("owner must be supplied")
	}
	if createOptions.logger == nil {
		return nil, fmt.Errorf("logger must be supplied")
	}
	if createOptions.spec == nil {
		return nil, fmt.Errorf("spec must be supplied")
	}
	//logger := createOptions.logger.WithField("container", createOptions.id)
	createOptions.logger = createOptions.logger.WithField("container", createOptions.id)

	// The v1 schema way of creating a container. Back compat for RS1..RS4
	if createOptions.schemaVersion.isV10() {
		logrus.Debugf("Is a V1 schema call")
		if createOptions.hostingSystem != nil {
			return nil, fmt.Errorf("hostingSystem must not be supplied for a v1 schema request")
		}

		// spec.Linux must be nil for Windows containers, but spec.Windows
		// will be filled in regardless of container platform.  This is a
		// temporary workaround due to LCOW requiring layer folder paths,
		// which are stored under spec.Windows.
		//
		// TODO: @darrenstahlmsft fix this once the OCI spec is updated to
		// support layer folder paths for LCOW
		if createOptions.spec.Linux == nil {

			// -----------------------
			// 1/2. WCOW Argon/Xenon v1
			// -----------------------
			logrus.Debugf("Is a V1 WCOW Argon or Xenon")

			if createOptions.spec.Windows == nil {
				return nil, fmt.Errorf("containerSpec 'Windows' field must be populated")
			}

			if createOptions.lcowOptions != nil {
				return nil, fmt.Errorf("lcowOptions must not be supplied for a v1 schema Windows container request")
			}
			return createWCOWv1(createOptions)
		}

		// -----------------------
		// 3. LCOW Xenon v1
		// -----------------------

		if createOptions.lcowOptions == nil {
			return nil, fmt.Errorf("lcowOptions must be supplied for a v1 schema Linux container request")
		}
		return createLCOWv1(createOptions)
	}

	//
	// Is a V2.x schema request
	//

	logrus.Debugf("HCSShim: Processing v2 schema call")

	if createOptions.spec.Linux == nil {
		return createWCOWv2(createOptions)
	}

	return nil, fmt.Errorf("invalid request - could not determine what to do")
}
