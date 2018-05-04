package hcsshim

// LCOWConfig is the structure used to configuring a utility VM.
type LCOWConfig struct {
	Name               string              // Name of the utility VM
	Uvm                Container           // The actual container
	MappedVirtualDisks []MappedVirtualDisk // Data-disks to be attached
}
