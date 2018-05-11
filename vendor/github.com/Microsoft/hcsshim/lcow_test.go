package hcsshim

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

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
			Spec:    dls,
		})
		if err != nil {
			t.Fatalf("Failed create: %s", err)
		}
		if err := lcowServiceContainer.Start(); err != nil {
			t.Fatalf("Failed to start service container: %s", err)
		}
	}
	tempDir := createTempDir(t)
	cacheSandboxFile = filepath.Join(cacheSandboxDir, "sandbox.vhdx")
	if err := CreateLCOWScratch(lcowServiceContainer, filepath.Join(tempDir, "sandbox.vhdx"), DefaultLCOWScratchSizeGB, cacheSandboxFile); err != nil {
		t.Fatalf("failed to create EXT4 sandbox for LCOW test cases: %s", err)
	}
	return tempDir, filepath.Base(tempDir)
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

// createLCOWTempDirWithSandbox uses an LCOW utility VM to create a blank
// VHDX and format it ext4.
func TestCreateLCOWScratch(t *testing.T) {
	t.Skip("for now")
	cacheDir := createTempDir(t)
	cacheFile := filepath.Join(cacheDir, "cache.vhdx")
	uvm, err := CreateContainerEx(&CreateOptions{Spec: getDefaultLinuxSpec(t)})
	if err != nil {
		t.Fatalf("Failed create: %s", err)
	}
	defer uvm.Terminate()
	if err := uvm.Start(); err != nil {
		t.Fatalf("Failed to start service container: %s", err)
	}

	// 1: Default size, cache doesn't exist, but no UVM passed. Cannot be created
	err = CreateLCOWScratch(nil, filepath.Join(cacheDir, "default.vhdx"), DefaultLCOWScratchSizeGB, cacheFile)
	if err == nil {
		t.Fatalf("expected an error creating LCOW scratch")
	}
	if err.Error() != "cannot create scratch disk as cache is not present and no utility VM supplied" {
		t.Fatalf("Not expecting error %s", err)
	}

	// 2: Default size, no cache supplied and no UVM
	err = CreateLCOWScratch(nil, filepath.Join(cacheDir, "default.vhdx"), DefaultLCOWScratchSizeGB, "")
	if err == nil {
		t.Fatalf("expected an error creating LCOW scratch")
	}
	if err.Error() != "cannot create scratch disk as cache is not present and no utility VM supplied" {
		t.Fatalf("Not expecting error %s", err)
	}

	// 3: Default size. This should work and the cache should be created.
	err = CreateLCOWScratch(uvm, filepath.Join(cacheDir, "default.vhdx"), DefaultLCOWScratchSizeGB, cacheFile)
	if err != nil {
		t.Fatalf("should succeed creating default size cache file: %s", err)
	}
	if _, err = os.Stat(cacheFile); err != nil {
		t.Fatalf("failed to stat cache file after created: %s", err)
	}
	if _, err = os.Stat(filepath.Join(cacheDir, "default.vhdx")); err != nil {
		t.Fatalf("failed to stat default.vhdx after created: %s", err)
	}

	// 4: Non-defaultsize. This should work and the cache should be created.
	err = CreateLCOWScratch(uvm, filepath.Join(cacheDir, "nondefault.vhdx"), DefaultLCOWScratchSizeGB+1, cacheFile)
	if err != nil {
		t.Fatalf("should succeed creating default size cache file: %s", err)
	}
	if _, err = os.Stat(cacheFile); err != nil {
		t.Fatalf("failed to stat cache file after created: %s", err)
	}
	if _, err = os.Stat(filepath.Join(cacheDir, "nondefault.vhdx")); err != nil {
		t.Fatalf("failed to stat default.vhdx after created: %s", err)
	}

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
	c, err := CreateContainerEx(&CreateOptions{
		Options: options,
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
