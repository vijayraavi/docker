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
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	//	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

var (
	// Obtained from docker - for the base images used in the tests
	nanoImagePath    string
	nanoImageId      string
	alpineImagePath  string
	alpineImageId    string
	busyboxImagePath string // github.com/jhowardmsft/busybox. Just an arbitrary multi-layer iamge  // TODO We could build a simple image in here.
	busyboxImageId   string
	busyboxROLayers  []string

	cacheSandboxFile     = ""      // LCOW ext4 sandbox file
	cacheSandboxDir      = ""      // LCOW ext4 sandbox directory
	lcowServiceContainer Container // For generating LCOW ext4 sandbox
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
	logrus.SetFormatter(&logrus.TextFormatter{
		TimestampFormat: "2006-01-02T15:04:05.000000000Z07:00",
		FullTimestamp:   true,
	})

	os.Setenv("HCSSHIM_LCOW_DEBUG_ENABLE", "something")
	nanoImagePath, nanoImageId = getImagePath("microsoft/windowsservercore:latest")
	alpineImagePath, alpineImageId = getImagePath("alpine:latest")
	busyboxImagePath, busyboxImageId = getImagePath("busybox:latest")
	busyboxROLayers = getROLayerPaths("busybox:latest")
}

func getImagePath(imageName string) (string, string) {
	cmd := exec.Command("docker", "inspect", imageName, "-f", `"{{.GraphDriver.Data.dir}}"`)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		p := fmt.Sprintf("failed to get base image path for %s from docker. Daemon must be running and image installed", imageName)
		panic(p)
	}
	imagePath := strings.Replace(strings.TrimSpace(out.String()), `"`, ``, -1)
	imageId := filepath.Base(imagePath)
	return imagePath, imageId
}

func getROLayerPaths(imageName string) []string {
	var roLayerPaths []string
	for {
		imagePath, _ := getImagePath(imageName)
		parent := getParent(imageName)
		roLayerPaths = append(roLayerPaths, imagePath)
		if parent == "" {
			break
		}
		imageName = parent
	}
	return roLayerPaths
}

func getParent(imageName string) string {
	cmd := exec.Command("docker", "inspect", imageName, "-f", `"{{.Parent}}"`)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		p := fmt.Sprintf("failed to get base image path for %s from docker. Daemon must be running and image installed", imageName)
		panic(p)
	}
	return strings.Replace(strings.TrimSpace(out.String()), `"`, ``, -1)
}

// createTempDir creates a temporary directory for use by a container.
func createTempDir(t *testing.T) string {
	tempDir, err := ioutil.TempDir("", "hcsshimtestcase")
	if err != nil {
		t.Fatalf("failed to create temporary directory", err)
	}
	return tempDir
}

// createWCOWTempDirWithSandbox uses HCS to create a sandbox with VM group access
// in a temporary directory. Returns the directory, the "containerID" which is
// really the foldername where the sandbox is, and a constructed DriverInfo
// structure which is required for calling v1 APIs. Strictly VM group access is
// not required for an argon.
func createWCOWTempDirWithSandbox(t *testing.T) (string, string, DriverInfo) {
	tempDir := createTempDir(t)
	di := DriverInfo{HomeDir: filepath.Dir(tempDir)}
	if err := CreateSandboxLayer(di, filepath.Base(tempDir), nanoImageId, []string{nanoImagePath}); err != nil {
		t.Fatalf("Failed CreateSandboxLayer: %s", err)
	}
	return tempDir, filepath.Base(tempDir), di
}

// createLCOWTempDirWithSandbox uses an LCOW utility VM to create a blank
// VHDX and format it ext4.
func createLCOWTempDirWithSandbox(t *testing.T) (string, string) {
	if lcowServiceContainer == nil {
		cacheSandboxDir = createTempDir(t)
		t.Logf("Creating an LCOW service VM")
		var err error
		lcowServiceContainer, err = CreateContainerEx(&CreateOptions{
			id:            "global",
			owner:         "unit-test",
			schemaVersion: SchemaVersion{Major: 1, Minor: 0},
			logger:        logrus.WithField("module", "hcsshim unit test"),
			spec:          defaultLinuxSpec(),
			lcowOptions:   getLCOWOptions(),
		})
		if err != nil {
			t.Fatalf("Failed create: %s", err)
		}
		if err := lcowServiceContainer.Start(); err != nil {
			t.Fatal("Failed to start service container: %s", err)
		}
	}
	t.Logf("Creating EXT4 sandbox for LCOW test cases")
	tempDir := createTempDir(t)
	cacheSandboxFile = filepath.Join(cacheSandboxDir, "sandbox.vhdx")
	if err := lcowServiceContainer.CreateExt4Vhdx(filepath.Join(tempDir, "sandbox.vhdx"), DefaultLCOWVhdxSizeGB, cacheSandboxFile); err != nil {
		t.Fatalf("failed to create EXT4 sandbox for LCOW test cases: %s", err)
	}
	return tempDir, filepath.Base(tempDir)
}

func getLCOWOptions() *LCOWOptions {
	base := filepath.Join(os.Getenv("ProgramFiles"), "Linux Containers")
	return &LCOWOptions{
		KirdPath:   base,
		KernelFile: "bootx64.efi",
		InitrdFile: "initrd.img",
	}
}

// Helper to start a container and launch a process in it. At the
// point of calling, the container must have been successfully created.
func startAndRunCommand(t *testing.T, c Container, command, workdir, expectedOutput string) {
	if c == nil {
		t.Fatalf("requested container to start is nil!")
	}
	if err := c.Start(); err != nil {
		t.Fatalf("Failed start: %s", err)
	}
	p, err := c.CreateProcess(&ProcessConfig{
		CommandLine:      command,
		WorkingDirectory: workdir,
		CreateStdInPipe:  true,
		CreateStdOutPipe: true,
		CreateStdErrPipe: true,
	})
	if err != nil {
		//		c.DebugLCOWGCS()
		//		time.Sleep(60 * time.Minute)
		t.Fatalf("Failed Create Process: %s", err)

	}
	defer p.Close()
	if err := p.Wait(); err != nil {
		t.Fatalf("Failed Wait Process: %s", err)
	}
	exitCode, err := p.ExitCode()
	if err != nil {
		t.Fatalf("Failed to obtain process exit code: %s", err)
	}
	if exitCode != 0 {
		t.Fatalf("Non-zero exit code from process %s (%d)", command, exitCode)
	}
	_, o, _, err := p.Stdio()
	if err != nil {
		t.Fatalf("Failed to get Stdio handles for process: %s", err)
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(o)
	out := strings.TrimSpace(buf.String())
	if out != expectedOutput {
		t.Fatalf("Failed to get %q from process: %q", expectedOutput, out)
	}
}

// Helper to stop a container
func stopContainer(t *testing.T, c Container) {
	if err := c.Shutdown(); err != nil {
		if IsPending(err) {
			if err := c.Wait(); err != nil {
				t.Fatalf("Failed Wait shutdown: %s", err)
			}
		} else {
			t.Fatalf("Failed shutdown: %s", err)
		}
	}
	c.Terminate()
}

func iPtr(i int64) *int64 { return &i }

func defaultCapabilities() []string {
	return []string{
		"CAP_CHOWN",
		"CAP_DAC_OVERRIDE",
		"CAP_FSETID",
		"CAP_FOWNER",
		"CAP_MKNOD",
		"CAP_NET_RAW",
		"CAP_SETGID",
		"CAP_SETUID",
		"CAP_SETFCAP",
		"CAP_SETPCAP",
		"CAP_NET_BIND_SERVICE",
		"CAP_SYS_CHROOT",
		"CAP_KILL",
		"CAP_AUDIT_WRITE",
	}
}

// defaultLinuxSpec create a default spec for running Linux containers
// Note this is copied from moby/moby, but we can't use it as a package
// import as it would be circular.
func defaultLinuxSpec() *specs.Spec {
	s := &specs.Spec{
		Version: specs.Version,
		Process: &specs.Process{
			Capabilities: &specs.LinuxCapabilities{
				Bounding:    defaultCapabilities(),
				Permitted:   defaultCapabilities(),
				Inheritable: defaultCapabilities(),
				Effective:   defaultCapabilities(),
			},
		},
		Root: &specs.Root{},
	}
	s.Mounts = []specs.Mount{
		{
			Destination: "/proc",
			Type:        "proc",
			Source:      "proc",
			Options:     []string{"nosuid", "noexec", "nodev"},
		},
		{
			Destination: "/dev",
			Type:        "tmpfs",
			Source:      "tmpfs",
			Options:     []string{"nosuid", "strictatime", "mode=755", "size=65536k"},
		},
		{
			Destination: "/dev/pts",
			Type:        "devpts",
			Source:      "devpts",
			Options:     []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"},
		},
		{
			Destination: "/sys",
			Type:        "sysfs",
			Source:      "sysfs",
			Options:     []string{"nosuid", "noexec", "nodev", "ro"},
		},
		{
			Destination: "/sys/fs/cgroup",
			Type:        "cgroup",
			Source:      "cgroup",
			Options:     []string{"ro", "nosuid", "noexec", "nodev"},
		},
		{
			Destination: "/dev/mqueue",
			Type:        "mqueue",
			Source:      "mqueue",
			Options:     []string{"nosuid", "noexec", "nodev"},
		},
		{
			Destination: "/dev/shm",
			Type:        "tmpfs",
			Source:      "shm",
			Options:     []string{"nosuid", "noexec", "nodev", "mode=1777"},
		},
	}

	s.Linux = &specs.Linux{
		MaskedPaths: []string{
			"/proc/kcore",
			"/proc/keys",
			"/proc/latency_stats",
			"/proc/timer_list",
			"/proc/timer_stats",
			"/proc/sched_debug",
			"/proc/scsi",
			"/sys/firmware",
		},
		ReadonlyPaths: []string{
			"/proc/asound",
			"/proc/bus",
			"/proc/fs",
			"/proc/irq",
			"/proc/sys",
			"/proc/sysrq-trigger",
		},
		Namespaces: []specs.LinuxNamespace{
			{Type: "mount"},
			{Type: "network"},
			{Type: "uts"},
			{Type: "pid"},
			{Type: "ipc"},
		},
		// Devices implicitly contains the following devices:
		// null, zero, full, random, urandom, tty, console, and ptmx.
		// ptmx is a bind mount or symlink of the container's ptmx.
		// See also: https://github.com/opencontainers/runtime-spec/blob/master/config-linux.md#default-devices
		Devices: []specs.LinuxDevice{},
		Resources: &specs.LinuxResources{
			Devices: []specs.LinuxDeviceCgroup{
				{
					Allow:  false,
					Access: "rwm",
				},
				{
					Allow:  true,
					Type:   "c",
					Major:  iPtr(1),
					Minor:  iPtr(5),
					Access: "rwm",
				},
				{
					Allow:  true,
					Type:   "c",
					Major:  iPtr(1),
					Minor:  iPtr(3),
					Access: "rwm",
				},
				{
					Allow:  true,
					Type:   "c",
					Major:  iPtr(1),
					Minor:  iPtr(9),
					Access: "rwm",
				},
				{
					Allow:  true,
					Type:   "c",
					Major:  iPtr(1),
					Minor:  iPtr(8),
					Access: "rwm",
				},
				{
					Allow:  true,
					Type:   "c",
					Major:  iPtr(5),
					Minor:  iPtr(0),
					Access: "rwm",
				},
				{
					Allow:  true,
					Type:   "c",
					Major:  iPtr(5),
					Minor:  iPtr(1),
					Access: "rwm",
				},
				{
					Allow:  false,
					Type:   "c",
					Major:  iPtr(10),
					Minor:  iPtr(229),
					Access: "rwm",
				},
			},
		},
	}

	// For LCOW support, populate a blank Windows spec
	if runtime.GOOS == "windows" {
		s.Windows = &specs.Windows{}
	}

	return s
}

// -------------------
//
//
// Start of test cases
//
//
// -------------------

// TestCreateContainerExv1ArgonWCOW tests a v1 Argon with a single base layer
func TestCreateContainerExv1ArgonWCOW(t *testing.T) {
	t.Skip("fornow")
	tempDir, containerId, driverInfo := createWCOWTempDirWithSandbox(t)
	defer os.RemoveAll(tempDir)

	// Load the filter driver to get the mount path
	if err := ActivateLayer(driverInfo, containerId); err != nil {
		t.Fatalf("failed to activate layer: %s", err)
	}
	defer DeactivateLayer(driverInfo, containerId)
	if err := PrepareLayer(driverInfo, containerId, []string{nanoImagePath}); err != nil {
		t.Fatalf("failed to prepare layer: %s", err)
	}
	defer UnprepareLayer(driverInfo, containerId)
	mountPath, err := GetLayerMountPath(driverInfo, containerId)
	if err != nil {
		t.Fatalf("failed to getlayermountpath: %s", err)
	}

	c, err := CreateContainerEx(&CreateOptions{
		id:            "TestCreateContainerExv1ArgonWCOW",
		owner:         "unit-test",
		schemaVersion: SchemaVersion{Major: 1, Minor: 0},
		logger:        logrus.WithField("module", "hcsshim unit test"),
		spec: &specs.Spec{
			Windows: &specs.Windows{LayerFolders: []string{nanoImagePath, tempDir}},
			Root:    &specs.Root{Path: mountPath},
		},
	})
	if err != nil {
		t.Fatalf("Failed create: %s", err)
	}
	startAndRunCommand(t, c, "cmd /s /c echo Hello", `c:\`, "Hello")
	stopContainer(t, c)
}

// TestCreateContainerExv1XenonWCOW tests a v1 Xenon with a single base layer
func TestCreateContainerExv1XenonWCOW(t *testing.T) {
	t.Skip("for now")
	tempDir, _, _ := createWCOWTempDirWithSandbox(t)
	defer os.RemoveAll(tempDir)

	c, err := CreateContainerEx(&CreateOptions{
		id:            "TestCreateContainerExv1XenonWCOW",
		owner:         "unit-test",
		schemaVersion: SchemaVersion{Major: 1, Minor: 0},
		logger:        logrus.WithField("module", "hcsshim unit test"),
		spec: &specs.Spec{
			Windows: &specs.Windows{
				LayerFolders: []string{nanoImagePath, tempDir},
				HyperV:       &specs.WindowsHyperV{UtilityVMPath: filepath.Join(nanoImagePath, "UtilityVM")},
			},
		},
	})
	if err != nil {
		t.Fatalf("Failed create: %s", err)
	}
	startAndRunCommand(t, c, "cmd /s /c echo Hello", `c:\`, "Hello")
	stopContainer(t, c)
}

// TestCreateContainerExv1XenonLCOW tests a v1 Xenon with a single base layer
func TestCreateContainerExv1XenonLCOW(t *testing.T) {
	t.Skip("for now")
	tempDir, _ := createLCOWTempDirWithSandbox(t)
	defer os.RemoveAll(tempDir)

	c, err := CreateContainerEx(&CreateOptions{
		id:            "TestCreateContainerExv1XenonLCOW",
		owner:         "unit-test",
		schemaVersion: SchemaVersion{Major: 1, Minor: 0},
		logger:        logrus.WithField("module", "hcsshim unit test"),
		spec: &specs.Spec{
			Windows: &specs.Windows{LayerFolders: []string{alpineImagePath, tempDir}},
			Linux:   &specs.Linux{},
		},
		lcowOptions: getLCOWOptions(),
	})
	if err != nil {
		t.Fatalf("Failed create: %s", err)
	}
	startAndRunCommand(t, c, "echo Hello", `/bin`, "Hello")
	stopContainer(t, c)
}

// TestCreateContainerExv2TwoXenonsWCOW creates two v2 Xenons in the same UVM, each with a single base layer
func TestCreateContainerExv2TwoXenonsWCOW(t *testing.T) {
	t.Skip("Skipping for now")
	uvmID := "TestCreateContainerExv2TwoXenonsWCOW_UVM"
	uvmScratchDir, err := ioutil.TempDir("", "hcsshimtestcase")
	if err != nil {
		t.Fatalf("Failed create temporary directory: %s", err)
	}
	if err := CreateWindowsUVMSandbox(nanoImagePath, uvmScratchDir, uvmID); err != nil {
		t.Fatalf("Failed create Windows UVM Sandbox: %s", err)
	}
	defer os.RemoveAll(uvmScratchDir)

	uvm, err := CreateContainerEx(&CreateOptions{
		id:            uvmID,
		owner:         "unit-test",
		schemaVersion: *SchemaV20(),
		logger:        logrus.WithField("module", "hcsshim unit test"),
		spec: &specs.Spec{
			Windows: &specs.Windows{
				LayerFolders: []string{uvmScratchDir},
				HyperV:       &specs.WindowsHyperV{UtilityVMPath: filepath.Join(nanoImagePath, `UtilityVM\Files`)},
			},
		},
	})
	if err != nil {
		t.Fatalf("Failed create UVM: %s", err)
	}
	defer uvm.Terminate()
	if err := uvm.Start(); err != nil {
		t.Fatalf("Failed start utility VM: %s", err)
	}

	// Now an argon inside the UVM

	// Create a sandbox for the first hosted container, then create the container
	containerAScratchDir, _, _ := createWCOWTempDirWithSandbox(t)
	defer os.RemoveAll(containerAScratchDir)
	xenonA, err := CreateContainerEx(&CreateOptions{
		id:            "containerA",
		owner:         "unit-test",
		hostingSystem: uvm,
		schemaVersion: *SchemaV20(),
		logger:        logrus.WithField("module", "hcsshim unit test"),
		spec: &specs.Spec{
			Windows: &specs.Windows{
				LayerFolders: []string{nanoImagePath, containerAScratchDir},
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateContainerEx failed: %s", err)
	}

	// Create a sandbox for the second hosted container, then create the container
	containerBScratchDir, _, _ := createWCOWTempDirWithSandbox(t)
	defer os.RemoveAll(containerBScratchDir)
	xenonB, err := CreateContainerEx(&CreateOptions{
		id:            "containerB",
		owner:         "unit-test",
		hostingSystem: uvm,
		schemaVersion: *SchemaV20(),
		logger:        logrus.WithField("module", "hcsshim unit test"),
		spec: &specs.Spec{
			Windows: &specs.Windows{
				LayerFolders: []string{nanoImagePath, containerBScratchDir},
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateContainerEx failed: %s", err)
	}

	// Start/stop both containers
	startAndRunCommand(t, xenonA, "cmd /s /c echo ContainerA", `c:\`, "ContainerA")
	startAndRunCommand(t, xenonB, "cmd /s /c echo ContainerB", `c:\`, "ContainerB")
	stopContainer(t, xenonA)
	stopContainer(t, xenonB)
}

// TestCreateContainerExv2OneXenonWCOW creates a single-layer v2 Xenon in a UVM
func TestCreateContainerExv2OneXenonWCOW(t *testing.T) {
	t.Skip("Skipping for now")
	uvmID := "TestCreateContainerExv2OneXenonWCOW_UVM"
	uvmScratchDir, err := ioutil.TempDir("", "hcsshimtestcase")
	if err != nil {
		t.Fatalf("Failed create temporary directory: %s", err)
	}
	if err := CreateWindowsUVMSandbox(nanoImagePath, uvmScratchDir, uvmID); err != nil {
		t.Fatalf("Failed create Windows UVM Sandbox: %s", err)
	}
	defer os.RemoveAll(uvmScratchDir)

	uvm, err := CreateContainerEx(&CreateOptions{
		id:            uvmID,
		owner:         "unit-test",
		schemaVersion: *SchemaV20(),
		logger:        logrus.WithField("module", "hcsshim unit test"),
		spec: &specs.Spec{
			Windows: &specs.Windows{
				LayerFolders: []string{uvmScratchDir},
				HyperV:       &specs.WindowsHyperV{UtilityVMPath: filepath.Join(nanoImagePath, `UtilityVM\Files`)},
			},
		},
	})
	if err != nil {
		t.Fatalf("Failed create UVM: %s", err)
	}
	defer uvm.Terminate()
	if err := uvm.Start(); err != nil {
		t.Fatalf("Failed start utility VM: %s", err)
	}

	// Now an argon inside the UVM

	// Create a sandbox, then create the container
	containerAScratchDir, _, _ := createWCOWTempDirWithSandbox(t)
	defer os.RemoveAll(containerAScratchDir)
	xenonA, err := CreateContainerEx(&CreateOptions{
		id:            "containerA",
		owner:         "unit-test",
		hostingSystem: uvm,
		schemaVersion: *SchemaV20(),
		logger:        logrus.WithField("module", "hcsshim unit test"),
		spec: &specs.Spec{
			Windows: &specs.Windows{
				LayerFolders: []string{nanoImagePath, containerAScratchDir},
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateContainerEx failed: %s", err)
	}

	// Start/stop the containers
	startAndRunCommand(t, xenonA, "cmd /s /c echo ContainerA", `c:\`, "ContainerA")
	stopContainer(t, xenonA)
}

// TestCreateContainerExv2XenonWCOWMultiLayer creates a V2 Xenon having multiple image layers
func TestCreateContainerExv2XenonWCOWMultiLayer(t *testing.T) {

	uvmID := "TestCreateContainerExv2XenonWCOWMultiLayer_UVM"
	uvmScratchDir, err := ioutil.TempDir("", "hcsshimtestcase")
	if err != nil {
		t.Fatalf("Failed create temporary directory: %s", err)
	}
	if err := CreateWindowsUVMSandbox(nanoImagePath, uvmScratchDir, uvmID); err != nil {
		t.Fatalf("Failed create Windows UVM Sandbox: %s", err)
	}
	defer os.RemoveAll(uvmScratchDir)

	uvmMemory := uint64(1 * 1024 * 1024 * 1024)
	uvmCPUCount := uint64(2)
	uvm, err := CreateContainerEx(&CreateOptions{
		id:            uvmID,
		owner:         "unit-test",
		schemaVersion: *SchemaV20(),
		logger:        logrus.WithField("module", "hcsshim unit test"),
		spec: &specs.Spec{
			Windows: &specs.Windows{
				LayerFolders: []string{uvmScratchDir},
				HyperV:       &specs.WindowsHyperV{UtilityVMPath: filepath.Join(nanoImagePath, `UtilityVM\Files`)},
				Resources: &specs.WindowsResources{
					Memory: &specs.WindowsMemoryResources{
						Limit: &uvmMemory,
					},
					CPU: &specs.WindowsCPUResources{
						Count: &uvmCPUCount,
					},
				},
			},
		},
	})

	if err != nil {
		t.Fatalf("Failed create UVM: %s", err)
	}
	defer uvm.Terminate()
	if err := uvm.Start(); err != nil {
		t.Fatalf("Failed start utility VM: %s", err)
	}

	// Create a sandbox for the hosted container (xenon), then create the container
	containerAScratchDir, _, _ := createWCOWTempDirWithSandbox(t)
	defer os.RemoveAll(containerAScratchDir)
	xenonA, err := CreateContainerEx(&CreateOptions{
		id:            "containerA",
		owner:         "unit-test",
		hostingSystem: uvm,
		schemaVersion: *SchemaV20(),
		logger:        logrus.WithField("module", "hcsshim unit test"),
		spec: &specs.Spec{
			Windows: &specs.Windows{
				LayerFolders: append(busyboxROLayers, containerAScratchDir),
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateContainerEx failed: %s", err)
	}

	// Start/stop both containers
	startAndRunCommand(t, xenonA, "echo ContainerA", `c:\`, "ContainerA")
	stopContainer(t, xenonA)

}
