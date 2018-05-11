package hcsshim

import "time"

// This file contains the structures necessary to call the HCS in v1 schema format.
// This was supported from RS1..RS4. It is present in RS5 but legacy, and clients
// should move over to the V2 schema for RS5+.

type Layer struct {
	ID   string
	Path string
}

type MappedDir struct {
	HostPath          string
	ContainerPath     string
	ReadOnly          bool
	BandwidthMaximum  uint64
	IOPSMaximum       uint64
	CreateInUtilityVM bool
}

type MappedPipe struct {
	HostPath          string
	ContainerPipeName string
}

type HvRuntime struct {
	ImagePath           string `json:",omitempty"`
	SkipTemplate        bool   `json:",omitempty"`
	LinuxInitrdFile     string `json:",omitempty"` // File under ImagePath on host containing an initrd image for starting a Linux utility VM
	LinuxKernelFile     string `json:",omitempty"` // File under ImagePath on host containing a kernel for starting a Linux utility VM
	LinuxBootParameters string `json:",omitempty"` // Additional boot parameters for starting a Linux Utility VM in initrd mode
	BootSource          string `json:",omitempty"` // "Vhd" for Linux Utility VM booting from VHD
	WritableBootSource  bool   `json:",omitempty"` // Linux Utility VM booting from VHD
}

type MappedVirtualDisk struct {
	HostPath          string `json:",omitempty"` // Path to VHD on the host
	ContainerPath     string // Platform-specific mount point path in the container
	CreateInUtilityVM bool   `json:",omitempty"`
	ReadOnly          bool   `json:",omitempty"`
	Cache             string `json:",omitempty"` // "" (Unspecified); "Disabled"; "Enabled"; "Private"; "PrivateAllowSharing"
	AttachOnly        bool   `json:",omitempty:` // If true, then not mapped to ContainerPath. This is used, for instance, if the disk doesn't yet have a file system on it.
}

// ContainerConfig is used as both the input of CreateContainer
// and to convert the parameters to JSON for passing onto the HCS
type ContainerConfig struct {
	SystemType                  string              // HCS requires this to be hard-coded to "Container"
	Name                        string              // Name (ID) of the container
	Owner                       string              `json:",omitempty"` // The management platform that created this container
	VolumePath                  string              `json:",omitempty"` // Windows volume path for scratch space. Used by Windows Server Containers only. Format \\?\\Volume{GUID}
	IgnoreFlushesDuringBoot     bool                `json:",omitempty"` // Optimization hint for container startup in Windows
	LayerFolderPath             string              `json:",omitempty"` // Where the layer folders are located. Used by Windows Server Containers only. Format  %root%\windowsfilter\containerID
	Layers                      []Layer             // List of storage layers. Required for Windows Server and Hyper-V Containers. Format ID=GUID;Path=%root%\windowsfilter\layerID
	Credentials                 string              `json:",omitempty"` // Credentials information
	ProcessorCount              uint32              `json:",omitempty"` // Number of processors to assign to the container.
	ProcessorWeight             uint64              `json:",omitempty"` // CPU shares (relative weight to other containers with cpu shares). Range is from 1 to 10000. A value of 0 results in default shares.
	ProcessorMaximum            int64               `json:",omitempty"` // Specifies the portion of processor cycles that this container can use as a percentage times 100. Range is from 1 to 10000. A value of 0 results in no limit.
	StorageIOPSMaximum          uint64              `json:",omitempty"` // Maximum Storage IOPS
	StorageBandwidthMaximum     uint64              `json:",omitempty"` // Maximum Storage Bandwidth in bytes per second
	StorageSandboxSize          uint64              `json:",omitempty"` // Size in bytes that the container system drive should be expanded to if smaller
	MemoryMaximumInMB           int64               `json:",omitempty"` // Maximum memory available to the container in Megabytes
	HostName                    string              `json:",omitempty"` // Hostname
	MappedDirectories           []MappedDir         `json:",omitempty"` // List of mapped directories (volumes/mounts)
	MappedPipes                 []MappedPipe        `json:",omitempty"` // List of mapped Windows named pipes
	HvPartition                 bool                // True if it a Hyper-V Container
	NetworkSharedContainerName  string              `json:",omitempty"` // Name (ID) of the container that we will share the network stack with.
	EndpointList                []string            `json:",omitempty"` // List of networking endpoints to be attached to container
	HvRuntime                   *HvRuntime          `json:",omitempty"` // Hyper-V container settings. Used by Hyper-V containers only. Format ImagePath=%root%\BaseLayerID\UtilityVM
	AllowUnqualifiedDNSQuery    bool                `json:",omitempty"` // True to allow unqualified DNS name resolution
	DNSSearchList               string              `json:",omitempty"` // Comma seperated list of DNS suffixes to use for name resolution
	ContainerType               string              `json:",omitempty"` // "Linux" for Linux containers on Windows. Omitted otherwise.
	TerminateOnLastHandleClosed bool                `json:",omitempty"` // Should HCS terminate the container once all handles have been closed
	MappedVirtualDisks          []MappedVirtualDisk `json:",omitempty"` // Array of virtual disks to mount at start

	// Deprecated fields.
	Servicing bool `json:",omitempty"` // Always ignored
}

// ContainerProperties holds the properties for a container and the processes running in that container
type ContainerProperties struct {
	ID                           string `json:"Id"`
	Name                         string
	SystemType                   string
	Owner                        string
	SiloGUID                     string                              `json:"SiloGuid,omitempty"`
	RuntimeID                    string                              `json:"RuntimeId,omitempty"`
	IsRuntimeTemplate            bool                                `json:",omitempty"`
	RuntimeImagePath             string                              `json:",omitempty"`
	Stopped                      bool                                `json:",omitempty"`
	ExitType                     string                              `json:",omitempty"`
	AreUpdatesPending            bool                                `json:",omitempty"` // Legacy field. Always false.
	ObRoot                       string                              `json:",omitempty"`
	Statistics                   Statistics                          `json:",omitempty"`
	ProcessList                  []ProcessListItem                   `json:",omitempty"`
	MappedVirtualDiskControllers map[int]MappedVirtualDiskController `json:",omitempty"`
}

// MemoryStats holds the memory statistics for a container
type MemoryStats struct {
	UsageCommitBytes            uint64 `json:"MemoryUsageCommitBytes,omitempty"`
	UsageCommitPeakBytes        uint64 `json:"MemoryUsageCommitPeakBytes,omitempty"`
	UsagePrivateWorkingSetBytes uint64 `json:"MemoryUsagePrivateWorkingSetBytes,omitempty"`
}

// ProcessorStats holds the processor statistics for a container
type ProcessorStats struct {
	TotalRuntime100ns  uint64 `json:",omitempty"`
	RuntimeUser100ns   uint64 `json:",omitempty"`
	RuntimeKernel100ns uint64 `json:",omitempty"`
}

// StorageStats holds the storage statistics for a container
type StorageStats struct {
	ReadCountNormalized  uint64 `json:",omitempty"`
	ReadSizeBytes        uint64 `json:",omitempty"`
	WriteCountNormalized uint64 `json:",omitempty"`
	WriteSizeBytes       uint64 `json:",omitempty"`
}

// NetworkStats holds the network statistics for a container
type NetworkStats struct {
	BytesReceived          uint64 `json:",omitempty"`
	BytesSent              uint64 `json:",omitempty"`
	PacketsReceived        uint64 `json:",omitempty"`
	PacketsSent            uint64 `json:",omitempty"`
	DroppedPacketsIncoming uint64 `json:",omitempty"`
	DroppedPacketsOutgoing uint64 `json:",omitempty"`
	EndpointId             string `json:",omitempty"`
	InstanceId             string `json:",omitempty"`
}

// Statistics is the structure returned by a statistics call on a container
type Statistics struct {
	Timestamp          time.Time      `json:",omitempty"`
	ContainerStartTime time.Time      `json:",omitempty"`
	Uptime100ns        uint64         `json:",omitempty"`
	Memory             MemoryStats    `json:",omitempty"`
	Processor          ProcessorStats `json:",omitempty"`
	Storage            StorageStats   `json:",omitempty"`
	Network            []NetworkStats `json:",omitempty"`
}

// ProcessList is the structure of an item returned by a ProcessList call on a container
type ProcessListItem struct {
	CreateTimestamp              time.Time `json:",omitempty"`
	ImageName                    string    `json:",omitempty"`
	KernelTime100ns              uint64    `json:",omitempty"`
	MemoryCommitBytes            uint64    `json:",omitempty"`
	MemoryWorkingSetPrivateBytes uint64    `json:",omitempty"`
	MemoryWorkingSetSharedBytes  uint64    `json:",omitempty"`
	ProcessId                    uint32    `json:",omitempty"`
	UserTime100ns                uint64    `json:",omitempty"`
}

// MappedVirtualDiskController is the structure of an item returned by a MappedVirtualDiskList call on a container
type MappedVirtualDiskController struct {
	MappedVirtualDisks map[int]MappedVirtualDisk `json:",omitempty"`
}

// ResourceModificationRequestResponse is the structure used to send request to the container to modify the system.
type ResourceModificationRequestResponse struct {
	Resource ResourceType `json:"ResourceType"`
	Data     interface{}  `json:"Settings,omitempty"`
	Request  RequestType  `json:"RequestType,omitempty"`
}

// Type of Request Support in ModifySystem (v1) or ModifySettingsRequest (v2)
type RequestType string

// Type of Resource in ModifySystem (v1) or ModifySettingsRequest (v2)
type ResourceType string

// RequestType const
const (
	RequestTypeAdd    RequestType = "Add"
	RequestTypeRemove RequestType = "Remove"
	RequestTypeUpdate RequestType = "Update" // V2
)

// ResourceType const
const (
	ResourceTypeMemory             ResourceType = "Memory"
	ResourceTypeCpuGroup           ResourceType = "CpuGroup"
	ResourceTypeMappedDirectory    ResourceType = "MappedDirectory"
	ResourceTypeMappedPipe         ResourceType = "MappedPipe"
	ResourceTypeMappedVirtualDisk  ResourceType = "MappedVirtualDisk"
	ResourceTypeNetwork            ResourceType = "Network"
	ResourceTypeVSmbShare          ResourceType = "VSmbShare"
	ResourceTypePlan9Share         ResourceType = "Plan9Share"
	ResourceTypeCombinedLayers     ResourceType = "CombinedLayers"
	ResourceTypeHvSocket           ResourceType = "HvSocket"
	ResourceTypeSharedMemoryRegion ResourceType = "SharedMemoryRegion"
	ResourceTypeVPMemDevice        ResourceType = "VPMemDevice"
	ResourceTypeGpu                ResourceType = "Gpu"
	ResourceTypeCosIndex           ResourceType = "CosIndex" // v2.1
	ResourceTypeRmid               ResourceType = "Rmid"     // v2.1
)
