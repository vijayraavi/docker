package hcsshim

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

// TODO Move this
const (
	// DefaultLCOWVhdxSizeGB is the size of the default LCOW sandbox & scratch in GB
	DefaultLCOWVhdxSizeGB = 20

	// defaultLCOWVhdxBlockSizeMB is the block-size for the sandbox/scratch VHDx's this package can create.
	defaultLCOWVhdxBlockSizeMB = 1
)

func getLCOWSettings(createOptions *CreateOptions) {
	createOptions.lcowkird = valueFromStringMap(createOptions.Options, HCSOPTION_LCOW_KIRD_PATH)
	if createOptions.lcowkird == "" {
		createOptions.lcowkird = filepath.Join(os.Getenv("ProgramFiles"), "Linux Containers")
	}
	createOptions.lcowkernel = valueFromStringMap(createOptions.Options, HCSOPTION_LCOW_KERNEL_FILE)
	if createOptions.lcowkernel == "" {
		createOptions.lcowkernel = "bootx64.efi"
	}
	createOptions.lcowinitrd = valueFromStringMap(createOptions.Options, HCSOPTION_LCOW_INITRD_FILE)
	if createOptions.lcowinitrd == "" {
		createOptions.lcowinitrd = "initrd.img"
	}
	createOptions.lcowbootparams = valueFromStringMap(createOptions.Options, HCSOPTION_LCOW_BOOT_PARAMETERS)
}

// createLCOWv1 creates a Linux (LCOW) container using the V1 schema.
func createLCOWv1(createOptions *CreateOptions) (Container, error) {

	configuration := &ContainerConfig{
		HvPartition:   true,
		Name:          createOptions.id,
		SystemType:    "container",
		ContainerType: "linux",
		Owner:         createOptions.owner,
		TerminateOnLastHandleClosed: true,
	}
	configuration.HvRuntime = &HvRuntime{
		ImagePath:           createOptions.lcowkird,
		LinuxKernelFile:     createOptions.lcowkernel,
		LinuxInitrdFile:     createOptions.lcowinitrd,
		LinuxBootParameters: createOptions.lcowbootparams,
	}

	// TODO These checks were elsewhere. In common with v2 too.
	//	if _, err := os.Stat(filepath.Join(config.KirdPath, config.KernelFile)); os.IsNotExist(err) {
	//		return fmt.Errorf("kernel '%s' not found", filepath.Join(config.KirdPath, config.KernelFile))
	//	}
	//	if _, err := os.Stat(filepath.Join(config.KirdPath, config.InitrdFile)); os.IsNotExist(err) {
	//		return fmt.Errorf("initrd '%s' not found", filepath.Join(config.KirdPath, config.InitrdFile))
	//	}

	//	// Ensure all the MappedVirtualDisks exist on the host
	//	for _, mvd := range config.MappedVirtualDisks {
	//		if _, err := os.Stat(mvd.HostPath); err != nil {
	//			return fmt.Errorf("mapped virtual disk '%s' not found", mvd.HostPath)
	//		}
	//		if mvd.ContainerPath == "" {
	//			return fmt.Errorf("mapped virtual disk '%s' requested without a container path", mvd.HostPath)
	//		}
	//	}

	if createOptions.Spec.Windows != nil {
		// Strip off the top-most layer as that's passed in separately to HCS
		if len(createOptions.Spec.Windows.LayerFolders) > 0 {
			configuration.LayerFolderPath = createOptions.Spec.Windows.LayerFolders[len(createOptions.Spec.Windows.LayerFolders)-1]
			layerFolders := createOptions.Spec.Windows.LayerFolders[:len(createOptions.Spec.Windows.LayerFolders)-1]

			for _, layerPath := range layerFolders {
				_, filename := filepath.Split(layerPath)
				g, err := NameToGuid(filename)
				if err != nil {
					return nil, err
				}
				configuration.Layers = append(configuration.Layers, Layer{
					ID:   g.ToString(),
					Path: filepath.Join(layerPath, "layer.vhd"),
				})
			}
		}

		if createOptions.Spec.Windows.Network != nil {
			configuration.EndpointList = createOptions.Spec.Windows.Network.EndpointList
			configuration.AllowUnqualifiedDNSQuery = createOptions.Spec.Windows.Network.AllowUnqualifiedDNSQuery
			if createOptions.Spec.Windows.Network.DNSSearchList != nil {
				configuration.DNSSearchList = strings.Join(createOptions.Spec.Windows.Network.DNSSearchList, ",")
			}
			configuration.NetworkSharedContainerName = createOptions.Spec.Windows.Network.NetworkSharedContainerName
		}
	}

	// Add the mounts (volumes, bind mounts etc) to the structure. We have to do
	// some translation for both the mapped directories passed into HCS and in
	// the spec.
	//
	// For HCS, we only pass in the mounts from the spec which are type "bind".
	// Further, the "ContainerPath" field (which is a little mis-leadingly
	// named when it applies to the utility VM rather than the container in the
	// utility VM) is moved to under /tmp/gcs/<ID>/binds, where this is passed
	// by the caller through a 'uvmpath' option.
	//
	// We do similar translation for the mounts in the spec by stripping out
	// the uvmpath option, and translating the Source path to the location in the
	// utility VM calculated above.
	//
	// From inside the utility VM, you would see a 9p mount such as in the following
	// where a host folder has been mapped to /target. The line with /tmp/gcs/<ID>/binds
	// specifically:
	//
	//	/ # mount
	//	rootfs on / type rootfs (rw,size=463736k,nr_inodes=115934)
	//	proc on /proc type proc (rw,relatime)
	//	sysfs on /sys type sysfs (rw,relatime)
	//	udev on /dev type devtmpfs (rw,relatime,size=498100k,nr_inodes=124525,mode=755)
	//	tmpfs on /run type tmpfs (rw,relatime)
	//	cgroup on /sys/fs/cgroup type cgroup (rw,relatime,cpuset,cpu,cpuacct,blkio,memory,devices,freezer,net_cls,perf_event,net_prio,hugetlb,pids,rdma)
	//	mqueue on /dev/mqueue type mqueue (rw,relatime)
	//	devpts on /dev/pts type devpts (rw,relatime,mode=600,ptmxmode=000)
	//	/binds/b3ea9126d67702173647ece2744f7c11181c0150e9890fc9a431849838033edc/target on /binds/b3ea9126d67702173647ece2744f7c11181c0150e9890fc9a431849838033edc/target type 9p (rw,sync,dirsync,relatime,trans=fd,rfdno=6,wfdno=6)
	//	/dev/pmem0 on /tmp/gcs/b3ea9126d67702173647ece2744f7c11181c0150e9890fc9a431849838033edc/layer0 type ext4 (ro,relatime,block_validity,delalloc,norecovery,barrier,dax,user_xattr,acl)
	//	/dev/sda on /tmp/gcs/b3ea9126d67702173647ece2744f7c11181c0150e9890fc9a431849838033edc/scratch type ext4 (rw,relatime,block_validity,delalloc,barrier,user_xattr,acl)
	//	overlay on /tmp/gcs/b3ea9126d67702173647ece2744f7c11181c0150e9890fc9a431849838033edc/rootfs type overlay (rw,relatime,lowerdir=/tmp/base/:/tmp/gcs/b3ea9126d67702173647ece2744f7c11181c0150e9890fc9a431849838033edc/layer0,upperdir=/tmp/gcs/b3ea9126d67702173647ece2744f7c11181c0150e9890fc9a431849838033edc/scratch/upper,workdir=/tmp/gcs/b3ea9126d67702173647ece2744f7c11181c0150e9890fc9a431849838033edc/scratch/work)
	//
	//  /tmp/gcs/b3ea9126d67702173647ece2744f7c11181c0150e9890fc9a431849838033edc # ls -l
	//	total 16
	//	drwx------    3 0        0               60 Sep  7 18:54 binds
	//	-rw-r--r--    1 0        0             3345 Sep  7 18:54 config.json
	//	drwxr-xr-x   10 0        0             4096 Sep  6 17:26 layer0
	//	drwxr-xr-x    1 0        0             4096 Sep  7 18:54 rootfs
	//	drwxr-xr-x    5 0        0             4096 Sep  7 18:54 scratch
	//
	//	/tmp/gcs/b3ea9126d67702173647ece2744f7c11181c0150e9890fc9a431849838033edc # ls -l binds
	//	total 0
	//	drwxrwxrwt    2 0        0             4096 Sep  7 16:51 target

	mds := []MappedDir{}
	specMounts := []specs.Mount{}
	for _, mount := range createOptions.Spec.Mounts {
		specMount := mount
		if mount.Type == "bind" {
			// Strip out the uvmpath from the options
			updatedOptions := []string{}
			uvmPath := ""
			readonly := false
			for _, opt := range mount.Options {
				dropOption := false
				elements := strings.SplitN(opt, "=", 2)
				switch elements[0] {
				case "uvmpath":
					uvmPath = elements[1]
					dropOption = true
				case "rw":
				case "ro":
					readonly = true
				case "rbind":
				default:
					return nil, fmt.Errorf("unsupported option %q", opt)
				}
				if !dropOption {
					updatedOptions = append(updatedOptions, opt)
				}
			}
			mount.Options = updatedOptions
			if uvmPath == "" {
				return nil, fmt.Errorf("no uvmpath for bind mount %+v", mount)
			}
			md := MappedDir{
				HostPath:          mount.Source,
				ContainerPath:     path.Join(uvmPath, mount.Destination),
				CreateInUtilityVM: true,
				ReadOnly:          readonly,
			}
			mds = append(mds, md)
			specMount.Source = path.Join(uvmPath, mount.Destination)
		}
		specMounts = append(specMounts, specMount)
	}
	configuration.MappedDirectories = mds

	container, err := CreateContainer(createOptions.id, configuration)
	if err != nil {
		return nil, err
	}

	// TODO - Not sure why after CreateContainer, but that's how I coded it in libcontainerd and it worked....
	createOptions.Spec.Mounts = specMounts

	createOptions.Logger.Debug("createLCOWv1() completed successfully")
	return container, nil
}

func debugCommand(s string) string {
	return fmt.Sprintf(`echo -e 'DEBUG COMMAND: %s\\n--------------\\n';%s;echo -e '\\n\\n';`, s, s)
}

// DebugLCOWGCS extracts logs from the GCS in LCOW. It's a useful hack for debugging,
// but not necessarily optimal, but all that is available to us in RS3.
func (container *container) DebugLCOWGCS() {
	if logrus.GetLevel() < logrus.DebugLevel || len(os.Getenv("HCSSHIM_LCOW_DEBUG_ENABLE")) == 0 {
		return
	}

	var out bytes.Buffer
	cmd := os.Getenv("HCSSHIM_LCOW_DEBUG_COMMAND")
	if cmd == "" {
		cmd = `sh -c "`
		cmd += debugCommand("kill -10 `pidof gcs`") // SIGUSR1 for stackdump
		cmd += debugCommand("ls -l /tmp")
		cmd += debugCommand("cat /tmp/gcs.log")
		cmd += debugCommand("cat /tmp/gcs/gcs-stacks*")
		cmd += debugCommand("cat /tmp/gcs/paniclog*")
		cmd += debugCommand("ls -l /tmp/gcs")
		cmd += debugCommand("ls -l /tmp/gcs/*")
		cmd += debugCommand("cat /tmp/gcs/*/config.json")
		cmd += debugCommand("ls -lR /var/run/gcsrunc")
		cmd += debugCommand("cat /tmp/gcs/global-runc.log")
		cmd += debugCommand("cat /tmp/gcs/*/runc.log")
		cmd += debugCommand("ps -ef")
		cmd += `"`
	}

	proc, _, err := container.CreateProcessEx(
		&CreateProcessEx{
			OCISpecification: &specs.Spec{
				Process: &specs.Process{Args: []string{cmd}},
				Linux:   &specs.Linux{},
			},
			CreateInUtilityVm: true,
			Stdout:            &out,
		})
	defer func() {
		if proc != nil {
			proc.Kill()
			proc.Close()
		}
	}()
	if err != nil {
		logrus.Debugln("benign failure getting gcs logs: ", err)
	}
	if proc != nil {
		proc.WaitTimeout(time.Duration(int(time.Second) * 30))
	}
	logrus.Debugf("GCS Debugging:\n%s\n\nEnd GCS Debugging", strings.TrimSpace(out.String()))
}
