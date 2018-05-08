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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

var (
	// Obtained from docker - for the base images used in the tests
	layersNanoserver []string // Nanoserver matching the build
	layersWSC        []string // WSC matching the build
	layersWSC1709    []string // WSC 1709. Note this has both a base and a servicing layer
	layersBusybox    []string // github.com/jhowardmsft/busybox. Just an arbitrary multi-layer iamge  // TODO We could build a simple image in here.
	layersAlpine     []string

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
	layersNanoserver = getLayers("microsoft/nanoserver:latest")
	layersBusybox = getLayers("busybox")
	layersAlpine = getLayers("alpine")
}

func getLayerChain(layerFolder string) []string {
	jPath := filepath.Join(layerFolder, "layerchain.json")
	content, err := ioutil.ReadFile(jPath)
	if os.IsNotExist(err) {
		panic("layerchain not found")
	} else if err != nil {
		panic("failed to read layerchain")
	}

	var layerChain []string
	err = json.Unmarshal(content, &layerChain)
	if err != nil {
		panic("failed to unmarshal layerchain")
	}
	return layerChain
}

func getLayers(imageName string) []string {
	cmd := exec.Command("docker", "inspect", imageName, "-f", `"{{.GraphDriver.Data.dir}}"`)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		panic("failed to get layers. Is the daemon running?")
	}
	imagePath := strings.Replace(strings.TrimSpace(out.String()), `"`, ``, -1)
	layers := getLayerChain(imagePath)
	return append([]string{imagePath}, layers...)
}

// createTempDir creates a temporary directory for use by a container.
func createTempDir(t *testing.T) string {
	tempDir, err := ioutil.TempDir("", "hcsshimtestcase")
	if err != nil {
		t.Fatalf("failed to create temporary directory: %s", err)
	}
	return tempDir
}

// TODO Make this more a public function.
// createWCOWTempDirWithSandbox uses HCS to create a sandbox with VM group access
// in a temporary directory. Returns the directory, the "containerID" which is
// really the foldername where the sandbox is, and a constructed DriverInfo
// structure which is required for calling v1 APIs. Strictly VM group access is
// not required for an argon.
// TODO: This is wrong anyway. Need to search the folders.
func createWCOWTempDirWithSandbox(t *testing.T) string {
	tempDir := createTempDir(t)
	di := DriverInfo{HomeDir: filepath.Dir(tempDir)}
	fmt.Println("len=", len(layersBusybox))
	if err := CreateSandboxLayer(di, filepath.Base(tempDir), filepath.Base(layersBusybox[0]), layersBusybox[:1]); err != nil {
		t.Fatalf("Failed CreateSandboxLayer: %s", err)
	}
	return tempDir
}

// createLCOWTempDirWithSandbox uses an LCOW utility VM to create a blank
// VHDX and format it ext4.
func createLCOWTempDirWithSandbox(t *testing.T) (string, string) {
	options := make(map[string]string)
	options[HCSOPTION_ID] = "global"
	dls := getDefaultLinuxSpec(t)
	if lcowServiceContainer == nil {
		cacheSandboxDir = createTempDir(t)
		var err error
		lcowServiceContainer, err = CreateContainerEx(&CreateOptions{
			Options: options,
			Logger:  logrus.WithField("module", "hcsshim unit test"),
			Spec:    dls,
		})
		if err != nil {
			t.Fatalf("Failed create: %s", err)
		}
		if err := lcowServiceContainer.Start(); err != nil {
			t.Fatalf("Failed to start service container: %s", err)
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

func startContainer(t *testing.T, c Container) {
	if err := c.Start(); err != nil {
		t.Fatalf("Failed start: %s", err)
	}
}

// Helper to launch a process in it. At the
// point of calling, the container must have been successfully created.
// TODO Convert to CreateProcessEx using full OCI spec.
func runCommand(t *testing.T, c Container, command, workdir, expectedOutput string) {
	if c == nil {
		t.Fatalf("requested container to start is nil!")
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
	//c.Terminate()
}

// -------------------
//
//
// Start of test cases
//
//
// -------------------

// --------------------------------
//    W C O W    A R G O N   V 1
// --------------------------------

// A v1 Argon with a single base layer. It also validates hostname functionality is propagated.
func TestV1Argon(t *testing.T) {
	t.Skip("fornow")
	tempDir := createWCOWTempDirWithSandbox(t)
	defer os.RemoveAll(tempDir)

	layers := append(layersNanoserver, tempDir)
	mountPath, err := Mount(layers, nil)
	if err != nil {
		t.Fatalf("failed to mount container storage: %s", err)
	}
	defer Unmount(layers, nil, UnmountOperationAll)

	options := make(map[string]string)
	options[HCSOPTION_SCHEMA_VERSION] = SchemaV10().String()
	options[HCSOPTION_ID] = "TestV1Argon"
	options[HCSOPTION_OWNER] = "unit-test"
	c, err := CreateContainerEx(&CreateOptions{
		Options: options,
		Logger:  logrus.WithField("module", "hcsshim unit test"),
		Spec: &specs.Spec{
			Hostname: "goofy",
			Windows:  &specs.Windows{LayerFolders: layers},
			Root:     &specs.Root{Path: mountPath.(string)},
		},
	})
	if err != nil {
		t.Fatalf("Failed create: %s", err)
	}
	startContainer(t, c)
	runCommand(t, c, "cmd /s /c echo Hello", `c:\`, "Hello")
	runCommand(t, c, "cmd /s /c hostname", `c:\`, "goofy")
	stopContainer(t, c)
	c.Terminate()
}

// A v1 Argon with a single base layer which uses the auto-mount capability
func TestV1ArgonAutoMount(t *testing.T) {
	t.Skip("fornow")
	tempDir := createWCOWTempDirWithSandbox(t)
	defer os.RemoveAll(tempDir)

	layers := append(layersNanoserver, tempDir)
	options := make(map[string]string)
	options[HCSOPTION_SCHEMA_VERSION] = SchemaV10().String()
	options[HCSOPTION_ID] = "TestV1ArgonAutoMount"
	c, err := CreateContainerEx(&CreateOptions{
		Options: options,
		Logger:  logrus.WithField("module", "hcsshim unit test"),
		Spec:    &specs.Spec{Windows: &specs.Windows{LayerFolders: layers}},
	})
	if err != nil {
		t.Fatalf("Failed create: %s", err)
	}
	defer Unmount(layers, nil, UnmountOperationAll)
	startContainer(t, c)
	runCommand(t, c, "cmd /s /c echo Hello", `c:\`, "Hello")
	stopContainer(t, c)
	c.Terminate()
}

// A v1 Argon with multiple layers which uses the auto-mount capability
func TestV1ArgonMultipleBaseLayersAutoMount(t *testing.T) {
	t.Skip("fornow")
	tempDir := createWCOWTempDirWithSandbox(t)
	defer os.RemoveAll(tempDir)

	layers := append(layersBusybox, tempDir)
	options := make(map[string]string)
	options[HCSOPTION_SCHEMA_VERSION] = SchemaV10().String()
	options[HCSOPTION_ID] = "TestV1ArgonMultipleBaseLayersAutoMount"
	c, err := CreateContainerEx(&CreateOptions{
		Options: options,
		Logger:  logrus.WithField("module", "hcsshim unit test"),
		Spec:    &specs.Spec{Windows: &specs.Windows{LayerFolders: layers}},
	})
	if err != nil {
		t.Fatalf("Failed create: %s", err)
	}
	defer Unmount(layers, nil, UnmountOperationAll)
	startContainer(t, c)
	runCommand(t, c, "cmd /s /c echo Hello", `c:\`, "Hello")
	stopContainer(t, c)
	c.Terminate()
}

// --------------------------------
//    W C O W    A R G O N   V 2
// --------------------------------

// A v2 Argon with a single base layer. It also validates hostname functionality is propagated.
func TestV2Argon(t *testing.T) {
	//t.Skip("fornow")
	tempDir := createWCOWTempDirWithSandbox(t)
	defer os.RemoveAll(tempDir)

	layers := append(layersNanoserver, tempDir)
	mountPath, err := Mount(layers, nil)
	if err != nil {
		t.Fatalf("failed to mount container storage: %s", err)
	}
	defer Unmount(layers, nil, UnmountOperationAll)

	options := make(map[string]string)
	options[HCSOPTION_SCHEMA_VERSION] = SchemaV20().String()
	options[HCSOPTION_ID] = "TestV2Argon"
	c, err := CreateContainerEx(&CreateOptions{
		Options: options,
		Logger:  logrus.WithField("module", "hcsshim unit test"),
		Spec: &specs.Spec{
			Hostname: "mickey",
			Windows:  &specs.Windows{LayerFolders: layers},
			Root:     &specs.Root{Path: mountPath.(string)},
		},
	})
	if err != nil {
		t.Fatalf("Failed create: %s", err)
	}
	startContainer(t, c)
	runCommand(t, c, "cmd /s /c echo Hello", `c:\`, "Hello")
	runCommand(t, c, "cmd /s /c hostname", `c:\`, "mickey")
	stopContainer(t, c)
	c.Terminate()
}

// A v2 Argon with multiple layers
func TestV2ArgonMultipleBaseLayers(t *testing.T) {
	t.Skip("fornow")
	tempDir := createWCOWTempDirWithSandbox(t)
	defer os.RemoveAll(tempDir)

	layers := append(layersBusybox, tempDir)
	mountPath, err := Mount(layers, nil)
	if err != nil {
		t.Fatalf("failed to mount container storage: %s", err)
	}
	defer Unmount(layers, nil, UnmountOperationAll)

	options := make(map[string]string)
	options[HCSOPTION_SCHEMA_VERSION] = SchemaV20().String()
	options[HCSOPTION_ID] = "TestV2ArgonMultipleBaseLayers"
	c, err := CreateContainerEx(&CreateOptions{
		Options: options,
		Logger:  logrus.WithField("module", "hcsshim unit test"),
		Spec: &specs.Spec{
			Windows: &specs.Windows{LayerFolders: layers},
			Root:    &specs.Root{Path: mountPath.(string)},
		},
	})
	if err != nil {
		t.Fatalf("Failed create: %s", err)
	}
	startContainer(t, c)
	runCommand(t, c, "cmd /s /c echo Hello", `c:\`, "Hello")
	stopContainer(t, c)
	c.Terminate()
}

// A v2 Argon with multiple layers which uses the auto-mount capability
func TestV2ArgonAutoMountMultipleBaseLayers(t *testing.T) {
	t.Skip("fornow")
	tempDir := createWCOWTempDirWithSandbox(t)
	defer os.RemoveAll(tempDir)

	layers := append(layersBusybox, tempDir)
	options := make(map[string]string)
	options[HCSOPTION_SCHEMA_VERSION] = SchemaV20().String()
	options[HCSOPTION_ID] = "TestV2ArgonAutoMountMultipleBaseLayers"
	c, err := CreateContainerEx(&CreateOptions{
		Options: options,
		Logger:  logrus.WithField("module", "hcsshim unit test"),
		Spec:    &specs.Spec{Windows: &specs.Windows{LayerFolders: layers}},
	})
	if err != nil {
		t.Fatalf("Failed create: %s", err)
	}
	defer Unmount(layers, nil, UnmountOperationAll)
	startContainer(t, c)
	runCommand(t, c, "cmd /s /c echo Hello", `c:\`, "Hello")
	stopContainer(t, c)
	c.Terminate()
}

// --------------------------------
//    W C O W    X E N O N   V 1
// --------------------------------

// A v1 WCOW Xenon with a single base layer
func TestV1XenonWCOW(t *testing.T) {
	t.Skip("for now")
	tempDir := createWCOWTempDirWithSandbox(t)
	defer os.RemoveAll(tempDir)

	layers := layersNanoserver
	uvmImagePath, err := LocateWCOWUVMFolderFromLayerFolders(layers)
	if err != nil {
		t.Fatalf("LocateWCOWUVMFolderFromLayerFolders failed %s", err)
	}
	options := make(map[string]string)
	options[HCSOPTION_SCHEMA_VERSION] = SchemaV10().String()
	options[HCSOPTION_ID] = "TestV1XenonWCOW"
	c, err := CreateContainerEx(&CreateOptions{
		Options: options,
		Logger:  logrus.WithField("module", "hcsshim unit test"),
		Spec: &specs.Spec{
			Windows: &specs.Windows{
				LayerFolders: append(layers, tempDir),
				HyperV:       &specs.WindowsHyperV{UtilityVMPath: filepath.Join(uvmImagePath, "UtilityVM")},
			},
		},
	})
	if err != nil {
		t.Fatalf("Failed create: %s", err)
	}
	startContainer(t, c)
	runCommand(t, c, "cmd /s /c echo Hello", `c:\`, "Hello")
	stopContainer(t, c)
}

// A v1 WCOW Xenon with a single base layer but let HCSShim find the utility VM path
func TestV1XenonWCOWNoUVMPath(t *testing.T) {
	t.Skip("for now")
	tempDir := createWCOWTempDirWithSandbox(t)
	defer os.RemoveAll(tempDir)

	options := make(map[string]string)
	options[HCSOPTION_SCHEMA_VERSION] = SchemaV10().String()
	options[HCSOPTION_ID] = "TestV1XenonWCOWNoUVMPath"
	options[HCSOPTION_OWNER] = "unit-test"
	c, err := CreateContainerEx(&CreateOptions{
		Options: options,
		Logger:  logrus.WithField("module", "hcsshim unit test"),
		Spec: &specs.Spec{
			Windows: &specs.Windows{
				LayerFolders: append(layersNanoserver, tempDir),
				HyperV:       &specs.WindowsHyperV{},
			},
		},
	})
	if err != nil {
		t.Fatalf("Failed create: %s", err)
	}
	startContainer(t, c)
	runCommand(t, c, "cmd /s /c echo Hello", `c:\`, "Hello")
	stopContainer(t, c)
}

// A v1 WCOW Xenon with multiple layers letting HCSShim find the utilityVM Path
func TestV1XenonMultipleBaseLayersNoUVMPath(t *testing.T) {
	t.Skip("for now")
	tempDir := createWCOWTempDirWithSandbox(t)
	defer os.RemoveAll(tempDir)

	layers := layersBusybox
	options := make(map[string]string)
	options[HCSOPTION_SCHEMA_VERSION] = SchemaV10().String()
	options[HCSOPTION_ID] = "TestV1XenonWCOW"
	c, err := CreateContainerEx(&CreateOptions{
		Options: options,
		Logger:  logrus.WithField("module", "hcsshim unit test"),
		Spec: &specs.Spec{
			Windows: &specs.Windows{
				LayerFolders: append(layers, tempDir),
				HyperV:       &specs.WindowsHyperV{},
			},
		},
	})
	if err != nil {
		t.Fatalf("Failed create: %s", err)
	}
	startContainer(t, c)
	runCommand(t, c, "cmd /s /c echo Hello", `c:\`, "Hello")
	stopContainer(t, c)
}

// --------------------------------
//    W C O W    X E N O N   V 2
// --------------------------------

// Helper for the v2 Xenon tests to create a utility VM. Returns the container
// object; folder used as its scratch
func createv2WCOWUVM(t *testing.T, uvmLayers []string, uvmID string) (Container, string) {
	uvmScratchDir := createTempDir(t)
	options := make(map[string]string)
	options[HCSOPTION_SCHEMA_VERSION] = SchemaV20().String()
	options[HCSOPTION_IS_UTILITY_VM] = "yes"
	if uvmID != "" {
		options[HCSOPTION_ID] = uvmID // TODO Test to make sure this is optional
	}
	uvm, err := CreateContainerEx(&CreateOptions{
		Options: options,
		Logger:  logrus.WithField("module", "hcsshim unit test"),
		Spec: &specs.Spec{
			Windows: &specs.Windows{LayerFolders: append(uvmLayers, uvmScratchDir)},
		},
	})
	if err != nil {
		t.Fatalf("Failed create UVM: %s", err)
	}
	return uvm, uvmScratchDir
}

// A single WCOW xenon
func TestV2XenonWCOW(t *testing.T) {
	t.Skip("Skipping for now")
	uvm, uvmScratchDir := createv2WCOWUVM(t, layersNanoserver, "TestV2XenonWCOW_UVM")
	defer os.RemoveAll(uvmScratchDir)
	defer uvm.Terminate()
	if err := uvm.Start(); err != nil {
		t.Fatalf("Failed start utility VM: %s", err)
	}

	// Create the container hosted inside the utility VM
	containerScratchDir := createWCOWTempDirWithSandbox(t)
	defer os.RemoveAll(containerScratchDir)
	options := make(map[string]string)
	options[HCSOPTION_SCHEMA_VERSION] = SchemaV20().String() // TODO: We need a check to verify this matches that of the hosting system (not in test code, in the product code)
	options[HCSOPTION_ID] = "container"
	layerFolders := append(layersNanoserver, containerScratchDir)
	hostedContainer, err := CreateContainerEx(&CreateOptions{
		HostingSystem: uvm,
		Options:       options,
		Logger:        logrus.WithField("module", "hcsshim unit test"),
		Spec:          &specs.Spec{Windows: &specs.Windows{LayerFolders: layerFolders}},
	})
	if err != nil {
		t.Fatalf("CreateContainerEx failed: %s", err)
	}
	defer Unmount(layerFolders, uvm, UnmountOperationAll)

	// Start/stop the container
	startContainer(t, hostedContainer)
	runCommand(t, hostedContainer, "cmd /s /c echo TestV2XenonWCOW", `c:\`, "TestV2XenonWCOW")
	stopContainer(t, hostedContainer)
	hostedContainer.Terminate()
}

// TODO: Have a similar test where the UVM scratch folder does not exist.
// A single WCOW xenon but where the container sandbox folder is not pre-created by the client
func TestV2XenonWCOWContainerSandboxFolderDoesNotExist(t *testing.T) {
	t.Skip("Skipping for now")
	uvm, uvmScratchDir := createv2WCOWUVM(t, layersNanoserver, "TestV2XenonWCOWContainerSandboxFolderDoesNotExist_UVM")
	defer os.RemoveAll(uvmScratchDir)
	defer uvm.Terminate()
	if err := uvm.Start(); err != nil {
		t.Fatalf("Failed start utility VM: %s", err)
	}

	// Create the container hosted inside the utility VM
	containerScratchDir := createWCOWTempDirWithSandbox(t)
	os.RemoveAll(containerScratchDir) // This is the important bit for this test. It's deleted here.
	options := make(map[string]string)
	options[HCSOPTION_SCHEMA_VERSION] = SchemaV20().String() // TODO: We need a check to verify this matches that of the hosting system (not in test code, in the product code)
	options[HCSOPTION_ID] = "container"
	layerFolders := append(layersNanoserver, containerScratchDir)
	hostedContainer, err := CreateContainerEx(&CreateOptions{
		HostingSystem: uvm,
		Options:       options,
		Logger:        logrus.WithField("module", "hcsshim unit test"),
		Spec:          &specs.Spec{Windows: &specs.Windows{LayerFolders: layerFolders}},
	})
	if err != nil {
		t.Fatalf("CreateContainerEx failed: %s", err)
	}
	defer Unmount(layerFolders, uvm, UnmountOperationAll)

	// Start/stop the container
	startContainer(t, hostedContainer)
	runCommand(t, hostedContainer, "cmd /s /c echo TestV2XenonWCOW", `c:\`, "TestV2XenonWCOW")
	stopContainer(t, hostedContainer)
	hostedContainer.Terminate()
}

// TODO What about mount. Test with the client doing the mount.
// TODO Test as above, but where sandbox for UVM is entirely created by a client to show how it's done.

// Two v2 WCOW containers in the same UVM, each with a single base layer
func TestV2XenonWCOWTwoContainers(t *testing.T) {
	t.Skip("Skipping for now")
	uvm, uvmScratchDir := createv2WCOWUVM(t, layersNanoserver, "TestV2XenonWCOWTwoContainers_UVM")
	defer os.RemoveAll(uvmScratchDir)
	defer uvm.Terminate()
	if err := uvm.Start(); err != nil {
		t.Fatalf("Failed start utility VM: %s", err)
	}

	// First hosted container
	firstContainerScratchDir := createWCOWTempDirWithSandbox(t)
	defer os.RemoveAll(firstContainerScratchDir)
	options := make(map[string]string)
	options[HCSOPTION_SCHEMA_VERSION] = SchemaV20().String()
	options[HCSOPTION_ID] = "FirstContainer"
	firstLayerFolders := append(layersNanoserver, firstContainerScratchDir)
	firstHostedContainer, err := CreateContainerEx(&CreateOptions{
		HostingSystem: uvm,
		Options:       options,
		Logger:        logrus.WithField("module", "hcsshim unit test"),
		Spec:          &specs.Spec{Windows: &specs.Windows{LayerFolders: firstLayerFolders}},
	})
	if err != nil {
		t.Fatalf("CreateContainerEx failed: %s", err)
	}
	defer Unmount(firstLayerFolders, uvm, UnmountOperationAll)

	// Second hosted container
	secondContainerScratchDir := createWCOWTempDirWithSandbox(t)
	defer os.RemoveAll(firstContainerScratchDir)
	options[HCSOPTION_ID] = "SecondContainer"
	secondLayerFolders := append(layersNanoserver, secondContainerScratchDir)
	secondHostedContainer, err := CreateContainerEx(&CreateOptions{
		HostingSystem: uvm,
		Options:       options,
		Logger:        logrus.WithField("module", "hcsshim unit test"),
		Spec:          &specs.Spec{Windows: &specs.Windows{LayerFolders: secondLayerFolders}},
	})
	if err != nil {
		t.Fatalf("CreateContainerEx failed: %s", err)
	}
	defer Unmount(secondLayerFolders, uvm, UnmountOperationAll)

	startContainer(t, firstHostedContainer)
	runCommand(t, firstHostedContainer, "cmd /s /c echo FirstContainer", `c:\`, "FirstContainer")
	startContainer(t, secondHostedContainer)
	runCommand(t, secondHostedContainer, "cmd /s /c echo SecondContainer", `c:\`, "SecondContainer")
	stopContainer(t, firstHostedContainer)
	stopContainer(t, secondHostedContainer)
	firstHostedContainer.Terminate()
	secondHostedContainer.Terminate()
}

// Lots of v2 WCOW containers in the same UVM, each with a single base layer. Containers aren't
// actually started, but it stresses the SCSI controller hot-add logic.
func TestV2XenonWCOWCreateLots(t *testing.T) {
	t.Skip("Skipping for now")
	uvm, uvmScratchDir := createv2WCOWUVM(t, layersNanoserver, "TestV2XenonWCOWTwoContainers_UVM")
	defer os.RemoveAll(uvmScratchDir)
	defer uvm.Terminate()
	if err := uvm.Start(); err != nil {
		t.Fatalf("Failed start utility VM: %s", err)
	}

	for i := 0; i < 64; i++ {
		containerScratchDir := createWCOWTempDirWithSandbox(t)
		defer os.RemoveAll(containerScratchDir)
		options := make(map[string]string)
		options[HCSOPTION_SCHEMA_VERSION] = SchemaV20().String()
		options[HCSOPTION_ID] = fmt.Sprintf("container%d", i)
		layerFolders := append(layersNanoserver, containerScratchDir)
		hostedContainer, err := CreateContainerEx(&CreateOptions{
			HostingSystem: uvm,
			Options:       options,
			Logger:        logrus.WithField("module", "hcsshim unit test"),
			Spec:          &specs.Spec{Windows: &specs.Windows{LayerFolders: layerFolders}},
		})
		if err != nil {
			t.Fatalf("CreateContainerEx failed: %s", err)
		}
		defer hostedContainer.Terminate()
		defer Unmount(layerFolders, uvm, UnmountOperationAll)
	}

	// TODO: Push it over 64 now and will get a failure.
}

// TODO: Test UVMResourcesFromContainerSpec
func TestUVMSizing(t *testing.T) {

}

//// This verifies the container storage is unmounted correctly so that a second
//// container can be started from the same storage.
//func TestV2XenonWCOWWithRemount(t *testing.T) {
////	t.Skip("Skipping for now")
//	uvmID := "Testv2XenonWCOWWithRestart_UVM"
//	uvmScratchDir, err := ioutil.TempDir("", "uvmScratch")
//	if err != nil {
//		t.Fatalf("Failed create temporary directory: %s", err)
//	}
//	if err := CreateWCOWSandbox(layersNanoserver[0], uvmScratchDir, uvmID); err != nil {
//		t.Fatalf("Failed create Windows UVM Sandbox: %s", err)
//	}
//	defer os.RemoveAll(uvmScratchDir)

//	uvm, err := CreateContainerEx(&CreateOptions{
//		Id:              uvmID,
//		Owner:           "unit-test",
//		SchemaVersion:   SchemaV20(),
//		Logger:          logrus.WithField("module", "hcsshim unit test"),
//		IsHostingSystem: true,
//		Spec: &specs.Spec{
//			Windows: &specs.Windows{
//				LayerFolders: []string{uvmScratchDir},
//				HyperV:       &specs.WindowsHyperV{UtilityVMPath: filepath.Join(layersNanoserver[0], `UtilityVM\Files`)},
//			},
//		},
//	})
//	if err != nil {
//		t.Fatalf("Failed create UVM: %s", err)
//	}
//	defer uvm.Terminate()
//	if err := uvm.Start(); err != nil {
//		t.Fatalf("Failed start utility VM: %s", err)
//	}

//	// Mount the containers storage in the utility VM
//	containerScratchDir := createWCOWTempDirWithSandbox(t)
//	layerFolders := append(layersNanoserver, containerScratchDir)
//	cls, err := Mount(layerFolders, uvm, SchemaV20())
//	if err != nil {
//		t.Fatalf("failed to mount container storage: %s", err)
//	}
//	combinedLayers := cls.(CombinedLayersV2)
//	mountedLayers := &ContainersResourcesStorageV2{
//		Layers: combinedLayers.Layers,
//		Path:   combinedLayers.ContainerRootPath,
//	}
//	defer func() {
//		if err := Unmount(layerFolders, uvm, SchemaV20(), UnmountOperationAll); err != nil {
//			t.Fatalf("failed to unmount container storage: %s", err)
//		}
//	}()

//	// Create the first container
//	defer os.RemoveAll(containerScratchDir)
//	xenon, err := CreateContainerEx(&CreateOptions{
//		Id:            "container",
//		Owner:         "unit-test",
//		HostingSystem: uvm,
//		SchemaVersion: SchemaV20(),
//		Logger:        logrus.WithField("module", "hcsshim unit test"),
//		Spec:          &specs.Spec{Windows: &specs.Windows{}}, // No layerfolders as we mounted them ourself.
//	})
//	if err != nil {
//		t.Fatalf("CreateContainerEx failed: %s", err)
//	}

//	// Start/stop the first container
//	startContainer(t, xenon)
//	runCommand(t, xenon, "cmd /s /c echo TestV2XenonWCOWFirstStart", `c:\`, "TestV2XenonWCOWFirstStart")
//	stopContainer(t, xenon)
//	xenon.Terminate()

//	// Now unmount and remount to exactly the same places
//	if err := Unmount(layerFolders, uvm, SchemaV20(), UnmountOperationAll); err != nil {
//		t.Fatalf("failed to unmount container storage: %s", err)
//	}
//	if _, err = Mount(layerFolders, uvm, SchemaV20()); err != nil {
//		t.Fatalf("failed to mount container storage: %s", err)
//	}

//	// Create an identical second container and verify it works too.
//	xenon2, err := CreateContainerEx(&CreateOptions{
//		Id:            "container",
//		Owner:         "unit-test",
//		HostingSystem: uvm,
//		SchemaVersion: SchemaV20(),
//		Logger:        logrus.WithField("module", "hcsshim unit test"),
//		Spec:          &specs.Spec{Windows: &specs.Windows{LayerFolders: layerFolders}},
//		MountedLayers: mountedLayers,
//	})
//	if err != nil {
//		t.Fatalf("CreateContainerEx failed: %s", err)
//	}
//	startContainer(t, xenon2)
//	runCommand(t, xenon2, "cmd /s /c echo TestV2XenonWCOWAfterRemount", `c:\`, "TestV2XenonWCOWAfterRemount")
//	stopContainer(t, xenon2)
//	xenon2.Terminate()
//}

// TestCreateContainerExv2XenonWCOWMultiLayer creates a V2 Xenon having multiple image layers
func TestCreateContainerExv2XenonWCOWMultiLayer(t *testing.T) {
	t.Skip("for now")
	uvmID := "TestCreateContainerExv2XenonWCOWMultiLayer_UVM"
	uvmScratchDir, err := ioutil.TempDir("", "hcsshimtestcase")
	if err != nil {
		t.Fatalf("Failed create temporary directory: %s", err)
	}
	if err := CreateWCOWUVMSandbox(layersNanoserver[0], uvmScratchDir, uvmID); err != nil {
		t.Fatalf("Failed create Windows UVM Sandbox: %s", err)
	}
	defer os.RemoveAll(uvmScratchDir)

	uvmMemory := uint64(1 * 1024 * 1024 * 1024)
	uvmCPUCount := uint64(2)
	options := make(map[string]string)
	options[HCSOPTION_SCHEMA_VERSION] = SchemaV20().String()
	options[HCSOPTION_IS_UTILITY_VM] = "yes"
	options[HCSOPTION_ID] = uvmID
	uvm, err := CreateContainerEx(&CreateOptions{
		Logger: logrus.WithField("module", "hcsshim unit test"),
		Spec: &specs.Spec{
			Windows: &specs.Windows{
				LayerFolders: []string{uvmScratchDir},
				HyperV:       &specs.WindowsHyperV{UtilityVMPath: filepath.Join(layersNanoserver[0], `UtilityVM\Files`)},
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

	// Create a sandbox for the hosted container
	containerAScratchDir := createWCOWTempDirWithSandbox(t)
	defer os.RemoveAll(containerAScratchDir)

	// Create the container
	options = make(map[string]string)
	options[HCSOPTION_SCHEMA_VERSION] = SchemaV20().String()
	options[HCSOPTION_ID] = "containerA"
	xenon, err := CreateContainerEx(&CreateOptions{
		HostingSystem: uvm,
		Options:       options,
		Logger:        logrus.WithField("module", "hcsshim unit test"),
		Spec:          &specs.Spec{Windows: &specs.Windows{LayerFolders: append(layersBusybox, containerAScratchDir)}},
	})
	if err != nil {
		t.Fatalf("CreateContainerEx failed: %s", err)
	}

	// Start/stop the container
	startContainer(t, xenon)
	runCommand(t, xenon, "echo Container", `c:\`, "Container")
	stopContainer(t, xenon)
	xenon.Terminate()
}

// Note that the .syso file is required to manifest the test app
func TestDetermineSchemaVersion(t *testing.T) {
	t.Skip("for now")
	m := make(map[string]string)
	if sv := determineSchemaVersion(nil); !sv.IsV10() { // TODO: Toggle this at some point so default is 2.0
		t.Fatalf("expected v2")
	}
	if sv := determineSchemaVersion(m); !sv.IsV10() { // TODO: Toggle this too
		t.Fatalf("expected v2")
	}
	m[HCSOPTION_SCHEMA_VERSION] = SchemaV20().String()
	if sv := determineSchemaVersion(m); !sv.IsV20() {
		t.Fatalf("expected requested v2")
	}
	m[HCSOPTION_SCHEMA_VERSION] = SchemaV10().String()
	if sv := determineSchemaVersion(m); !sv.IsV10() {
		t.Fatalf("expected requested v1")
	}
	m[HCSOPTION_SCHEMA_VERSION] = (&SchemaVersion{}).String()
	if sv := determineSchemaVersion(m); !sv.IsV10() { // Should also log a warning that 0.0 is ignored // TODO: Toggle this too
		t.Fatalf("expected requested v2")
	}
}
func getDefaultLinuxSpec(t *testing.T) *specs.Spec {
	content, err := ioutil.ReadFile(`.\testassets\defaultlinuxspec.json`)
	if err != nil {
		t.Fatalf("failed to read defaultlinuxspec.json: %s", err.Error())
	}
	spec := specs.Spec{}
	if err := json.Unmarshal(content, &spec); err != nil {
		t.Fatalf("failed to unmarshal contents of defaultlinuxspec.json: %s", err.Error())
	}
	return &spec
}

// A v1 LCOW
// TODO LCOW doesn't work currently
func TestV1XenonLCOW(t *testing.T) {
	t.Skip("for now")
	tempDir, _ := createLCOWTempDirWithSandbox(t)
	defer os.RemoveAll(tempDir)

	options := make(map[string]string)
	options[HCSOPTION_SCHEMA_VERSION] = SchemaV10().String()
	options[HCSOPTION_ID] = "TestV1XenonLCOW"

	spec := getDefaultLinuxSpec(t)
	spec.Windows.LayerFolders = append(layersAlpine, tempDir)
	//spec.Linux = &specs.Linux{}
	c, err := CreateContainerEx(&CreateOptions{
		Options: options,
		Logger:  logrus.WithField("module", "hcsshim unit test"),
		Spec:    spec,
	})
	if err != nil {
		t.Fatalf("Failed create: %s", err)
	}
	startContainer(t, c)
	time.Sleep(5 * time.Second)
	runCommand(t, c, "echo Hello", `/bin`, "Hello")
	stopContainer(t, c)
	c.Terminate()
}
