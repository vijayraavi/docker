package hcsshim

import (
	"os"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// --------------------------------
//    W C O W    A R G O N   V 1
// --------------------------------

// A v1 Argon with a single base layer. It also validates hostname functionality is propagated.
func TestV1Argon(t *testing.T) {
	t.Skip("fornow")
	tempDir := createWCOWTempDirWithSandbox(t)
	defer os.RemoveAll(tempDir)

	layers := append(layersNanoserver, tempDir)
	mountPath, err := MountContainerLayers(layers, nil)
	if err != nil {
		t.Fatalf("failed to mount container storage: %s", err)
	}
	defer UnmountContainerLayers(layers, nil, UnmountOperationAll)

	options := make(map[string]string)
	options[HCSOPTION_SCHEMA_VERSION] = SchemaV10().String()
	c, err := CreateContainerEx(&CreateOptions{
		Options: options,
		Id:      "TestV1Argon",
		Owner:   "unit-test",
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

	layers := append(layersBusybox, tempDir)
	options := make(map[string]string)
	options[HCSOPTION_SCHEMA_VERSION] = SchemaV10().String()
	c, err := CreateContainerEx(&CreateOptions{
		Id:      "TestV1ArgonAutoMount",
		Options: options,
		Spec:    &specs.Spec{Windows: &specs.Windows{LayerFolders: layers}},
	})
	if err != nil {
		t.Fatalf("Failed create: %s", err)
	}
	defer UnmountContainerLayers(layers, nil, UnmountOperationAll)
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
	c, err := CreateContainerEx(&CreateOptions{
		Id:      "TestV1ArgonMultipleBaseLayersAutoMount",
		Options: options,
		Spec:    &specs.Spec{Windows: &specs.Windows{LayerFolders: layers}},
	})
	if err != nil {
		t.Fatalf("Failed create: %s", err)
	}
	defer UnmountContainerLayers(layers, nil, UnmountOperationAll)
	startContainer(t, c)
	runCommand(t, c, "cmd /s /c echo Hello", `c:\`, "Hello")
	stopContainer(t, c)
	c.Terminate()
}

// --------------------------------
//    W C O W    A R G O N   V 2
// --------------------------------

// A v2 Argon with a single base layer. It also validates hostname functionality is propagated.
// It also uses an auto-generated ID.
func TestV2Argon(t *testing.T) {
	t.Skip("fornow")
	tempDir := createWCOWTempDirWithSandbox(t)
	defer os.RemoveAll(tempDir)

	layers := append(layersNanoserver, tempDir)
	mountPath, err := MountContainerLayers(layers, nil)
	if err != nil {
		t.Fatalf("failed to mount container storage: %s", err)
	}
	defer UnmountContainerLayers(layers, nil, UnmountOperationAll)

	options := make(map[string]string)
	options[HCSOPTION_SCHEMA_VERSION] = SchemaV20().String()
	c, err := CreateContainerEx(&CreateOptions{
		Options: options,
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
	mountPath, err := MountContainerLayers(layers, nil)
	if err != nil {
		t.Fatalf("failed to mount container storage: %s", err)
	}
	defer UnmountContainerLayers(layers, nil, UnmountOperationAll)

	options := make(map[string]string)
	options[HCSOPTION_SCHEMA_VERSION] = SchemaV20().String()
	c, err := CreateContainerEx(&CreateOptions{
		Options: options,
		Id:      "TestV2ArgonMultipleBaseLayers",
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
	c, err := CreateContainerEx(&CreateOptions{
		Id:      "TestV2ArgonAutoMountMultipleBaseLayers",
		Options: options,
		Spec:    &specs.Spec{Windows: &specs.Windows{LayerFolders: layers}},
	})
	if err != nil {
		t.Fatalf("Failed create: %s", err)
	}
	defer UnmountContainerLayers(layers, nil, UnmountOperationAll)
	startContainer(t, c)
	runCommand(t, c, "cmd /s /c echo Hello", `c:\`, "Hello")
	stopContainer(t, c)
	c.Terminate()
}
