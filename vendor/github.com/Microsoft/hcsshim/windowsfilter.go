package hcsshim

import (
	"path/filepath"
	"sync"
	"syscall"

	"github.com/sirupsen/logrus"
)

// ActivateLayer will find the layer with the given id and mount it's filesystem.
// For a read/write layer, the mounted filesystem will appear as a volume on the
// host, while a read-only layer is generally expected to be a no-op.
// An activated layer must later be deactivated via DeactivateLayer.
func ActivateLayer(info DriverInfo, id string) error {
	title := "hcsshim::ActivateLayer "
	logrus.Debugf(title+"Flavour %d ID %s", info.Flavour, id)

	infop, err := convertDriverInfo(info)
	if err != nil {
		logrus.Error(err)
		return err
	}

	err = activateLayer(&infop, id)
	if err != nil {
		err = makeErrorf(err, title, "id=%s flavour=%d", id, info.Flavour)
		logrus.Error(err)
		return err
	}

	logrus.Debugf(title+" - succeeded id=%s flavour=%d", id, info.Flavour)
	return nil
}

// CreateLayer creates a new, empty, read-only layer on the filesystem based on
// the parent layer provided.
func CreateLayer(info DriverInfo, id, parent string) error {
	title := "hcsshim::CreateLayer "
	logrus.Debugf(title+"Flavour %d ID %s parent %s", info.Flavour, id, parent)

	// Convert info to API calling convention
	infop, err := convertDriverInfo(info)
	if err != nil {
		logrus.Error(err)
		return err
	}

	err = createLayer(&infop, id, parent)
	if err != nil {
		err = makeErrorf(err, title, "id=%s parent=%s flavour=%d", id, parent, info.Flavour)
		logrus.Error(err)
		return err
	}

	logrus.Debugf(title+" - succeeded id=%s parent=%s flavour=%d", id, parent, info.Flavour)
	return nil
}

// CreateSandboxLayer creates and populates new read-write layer for use by a container.
// This requires both the id of the direct parent layer, as well as the full list
// of paths to all parent layers up to the base (and including the direct parent
// whose id was provided).
func CreateSandboxLayer(info DriverInfo, layerId, parentId string, parentLayerPaths []string) error {
	title := "hcsshim::CreateSandboxLayer "
	logrus.Debugf(title+"layerId %s parentId %s", layerId, parentId)

	// Generate layer descriptors
	layers, err := layerPathsToDescriptors(parentLayerPaths)
	if err != nil {
		return err
	}

	// Convert info to API calling convention
	infop, err := convertDriverInfo(info)
	if err != nil {
		logrus.Error(err)
		return err
	}

	err = createSandboxLayer(&infop, layerId, parentId, layers)
	if err != nil {
		err = makeErrorf(err, title, "layerId=%s parentId=%s", layerId, parentId)
		logrus.Error(err)
		return err
	}

	logrus.Debugf(title+"- succeeded layerId=%s parentId=%s", layerId, parentId)
	return nil
}

// DeactivateLayer will dismount a layer that was mounted via ActivateLayer.
func DeactivateLayer(info DriverInfo, id string) error {
	title := "hcsshim::DeactivateLayer "
	logrus.Debugf(title+"Flavour %d ID %s", info.Flavour, id)

	// Convert info to API calling convention
	infop, err := convertDriverInfo(info)
	if err != nil {
		logrus.Error(err)
		return err
	}

	err = deactivateLayer(&infop, id)
	if err != nil {
		err = makeErrorf(err, title, "id=%s flavour=%d", id, info.Flavour)
		logrus.Error(err)
		return err
	}

	logrus.Debugf(title+"succeeded flavour=%d id=%s", info.Flavour, id)
	return nil
}

// DestroyLayer will remove the on-disk files representing the layer with the given
// id, including that layer's containing folder, if any.
func DestroyLayer(info DriverInfo, id string) error {
	title := "hcsshim::DestroyLayer "
	logrus.Debugf(title+"Flavour %d ID %s", info.Flavour, id)

	// Convert info to API calling convention
	infop, err := convertDriverInfo(info)
	if err != nil {
		logrus.Error(err)
		return err
	}

	err = destroyLayer(&infop, id)
	if err != nil {
		err = makeErrorf(err, title, "id=%s flavour=%d", id, info.Flavour)
		logrus.Error(err)
		return err
	}

	logrus.Debugf(title+"succeeded flavour=%d id=%s", info.Flavour, id)
	return nil
}

// ExpandSandboxSize expands the size of a layer to at least size bytes.
func ExpandSandboxSize(info DriverInfo, layerId string, size uint64) error {
	title := "hcsshim::ExpandSandboxSize "
	logrus.Debugf(title+"layerId=%s size=%d", layerId, size)

	// Convert info to API calling convention
	infop, err := convertDriverInfo(info)
	if err != nil {
		logrus.Error(err)
		return err
	}

	err = expandSandboxSize(&infop, layerId, size)
	if err != nil {
		err = makeErrorf(err, title, "layerId=%s  size=%d", layerId, size)
		logrus.Error(err)
		return err
	}

	logrus.Debugf(title+"- succeeded layerId=%s size=%d", layerId, size)
	return nil
}

// GetLayerMountPath will look for a mounted layer with the given id and return
// the path at which that layer can be accessed.  This path may be a volume path
// if the layer is a mounted read-write layer, otherwise it is expected to be the
// folder path at which the layer is stored.
func GetLayerMountPath(info DriverInfo, id string) (string, error) {
	title := "hcsshim::GetLayerMountPath "
	logrus.Debugf(title+"Flavour %d ID %s", info.Flavour, id)

	// Convert info to API calling convention
	infop, err := convertDriverInfo(info)
	if err != nil {
		logrus.Error(err)
		return "", err
	}

	var mountPathLength uintptr
	mountPathLength = 0

	// Call the procedure itself.
	logrus.Debugf("Calling proc (1)")
	err = getLayerMountPath(&infop, id, &mountPathLength, nil)
	if err != nil {
		err = makeErrorf(err, title, "(first call) id=%s flavour=%d", id, info.Flavour)
		logrus.Error(err)
		return "", err
	}

	// Allocate a mount path of the returned length.
	if mountPathLength == 0 {
		return "", nil
	}
	mountPathp := make([]uint16, mountPathLength)
	mountPathp[0] = 0

	// Call the procedure again
	logrus.Debugf("Calling proc (2)")
	err = getLayerMountPath(&infop, id, &mountPathLength, &mountPathp[0])
	if err != nil {
		err = makeErrorf(err, title, "(second call) id=%s flavour=%d", id, info.Flavour)
		logrus.Error(err)
		return "", err
	}

	path := syscall.UTF16ToString(mountPathp[0:])
	logrus.Debugf(title+"succeeded flavour=%d id=%s path=%s", info.Flavour, id, path)
	return path, nil
}

// LayerExists will return true if a layer with the given id exists and is known
// to the system.
func LayerExists(info DriverInfo, id string) (bool, error) {
	title := "hcsshim::LayerExists "
	logrus.Debugf(title+"Flavour %d ID %s", info.Flavour, id)

	// Convert info to API calling convention
	infop, err := convertDriverInfo(info)
	if err != nil {
		logrus.Error(err)
		return false, err
	}

	// Call the procedure itself.
	var exists uint32

	err = layerExists(&infop, id, &exists)
	if err != nil {
		err = makeErrorf(err, title, "id=%s flavour=%d", id, info.Flavour)
		logrus.Error(err)
		return false, err
	}

	logrus.Debugf(title+"succeeded flavour=%d id=%s exists=%d", info.Flavour, id, exists)
	return exists != 0, nil
}

var prepareLayerLock sync.Mutex

// PrepareLayer finds a mounted read-write layer matching layerId and enables the
// the filesystem filter for use on that layer.  This requires the paths to all
// parent layers, and is necessary in order to view or interact with the layer
// as an actual filesystem (reading and writing files, creating directories, etc).
// Disabling the filter must be done via UnprepareLayer.
func PrepareLayer(info DriverInfo, layerId string, parentLayerPaths []string) error {
	title := "hcsshim::PrepareLayer "
	logrus.Debugf(title+"flavour %d layerId %s", info.Flavour, layerId)

	// Generate layer descriptors
	layers, err := layerPathsToDescriptors(parentLayerPaths)
	if err != nil {
		return err
	}

	// Convert info to API calling convention
	infop, err := convertDriverInfo(info)
	if err != nil {
		logrus.Error(err)
		return err
	}

	// This lock is a temporary workaround for a Windows bug. Only allowing one
	// call to prepareLayer at a time vastly reduces the chance of a timeout.
	prepareLayerLock.Lock()
	defer prepareLayerLock.Unlock()
	err = prepareLayer(&infop, layerId, layers)
	if err != nil {
		err = makeErrorf(err, title, "layerId=%s flavour=%d", layerId, info.Flavour)
		logrus.Error(err)
		return err
	}

	logrus.Debugf(title+"succeeded flavour=%d layerId=%s", info.Flavour, layerId)
	return nil
}

// UnprepareLayer disables the filesystem filter for the read-write layer with
// the given id.
func UnprepareLayer(info DriverInfo, layerId string) error {
	title := "hcsshim::UnprepareLayer "
	logrus.Debugf(title+"flavour %d layerId %s", info.Flavour, layerId)

	// Convert info to API calling convention
	infop, err := convertDriverInfo(info)
	if err != nil {
		logrus.Error(err)
		return err
	}

	err = unprepareLayer(&infop, layerId)
	if err != nil {
		err = makeErrorf(err, title, "layerId=%s flavour=%d", layerId, info.Flavour)
		logrus.Error(err)
		return err
	}

	logrus.Debugf(title+"succeeded flavour %d layerId=%s", info.Flavour, layerId)
	return nil
}

// GrantVmAccess adds the VM group SID to a file (usually a VHD(X))
func GrantVmAccess(vmID string, file string) error {
	title := "hcsshim::GrantVmAccess "
	logrus.Debugf(title+"vmID: %s Path %s", vmID, file)

	if err := grantVmAccess(vmID, file); err != nil {
		err = makeErrorf(err, title, "vmID: %s Path: %s", vmID, file)
		logrus.Error(err)
		return err
	}

	logrus.Debugf(title+"succeeded vmID: %s Path: %s", vmID, file)
	return nil
}

/* To pass into syscall, we need a struct matching the following:
enum GraphDriverType
{
    DiffDriver,
    FilterDriver
};

struct DriverInfo {
    GraphDriverType Flavour;
    LPCWSTR HomeDir;
};
*/
type DriverInfo struct {
	Flavour int
	HomeDir string
}

type driverInfo struct {
	Flavour  int
	HomeDirp *uint16
}

func convertDriverInfo(info DriverInfo) (driverInfo, error) {
	homedirp, err := syscall.UTF16PtrFromString(info.HomeDir)
	if err != nil {
		logrus.Debugf("Failed conversion of home to pointer for driver info: %s", err.Error())
		return driverInfo{}, err
	}

	return driverInfo{
		Flavour:  info.Flavour,
		HomeDirp: homedirp,
	}, nil
}

/* To pass into syscall, we need a struct matching the following:
typedef struct _WC_LAYER_DESCRIPTOR {

    //
    // The ID of the layer
    //

    GUID LayerId;

    //
    // Additional flags
    //

    union {
        struct {
            ULONG Reserved : 31;
            ULONG Dirty : 1;    // Created from sandbox as a result of snapshot
        };
        ULONG Value;
    } Flags;

    //
    // Path to the layer root directory, null-terminated
    //

    PCWSTR Path;

} WC_LAYER_DESCRIPTOR, *PWC_LAYER_DESCRIPTOR;
*/
type WC_LAYER_DESCRIPTOR struct {
	LayerId GUID
	Flags   uint32
	Pathp   *uint16
}

func layerPathsToDescriptors(parentLayerPaths []string) ([]WC_LAYER_DESCRIPTOR, error) {
	// Array of descriptors that gets constructed.
	var layers []WC_LAYER_DESCRIPTOR

	for i := 0; i < len(parentLayerPaths); i++ {
		// Create a layer descriptor, using the folder name
		// as the source for a GUID LayerId
		_, folderName := filepath.Split(parentLayerPaths[i])
		g, err := NameToGuid(folderName)
		if err != nil {
			logrus.Debugf("Failed to convert name to guid %s", err)
			return nil, err
		}

		p, err := syscall.UTF16PtrFromString(parentLayerPaths[i])
		if err != nil {
			logrus.Debugf("Failed conversion of parentLayerPath to pointer %s", err)
			return nil, err
		}

		layers = append(layers, WC_LAYER_DESCRIPTOR{
			LayerId: g,
			Flags:   0,
			Pathp:   p,
		})
	}

	return layers, nil
}
