package hcsshim

import "fmt"

// SchemaV10 makes it easy for callers to get a v1.0 schema version object
func SchemaV10() *SchemaVersion {
	return &SchemaVersion{Major: 1, Minor: 0}
}

// SchemaV20 makes it easy for callers to get a v2.0 schema version object
func SchemaV20() *SchemaVersion {
	return &SchemaVersion{Major: 2, Minor: 0}
}

// isSupported determines if a given schema version is supported
func (sv *SchemaVersion) isSupported() error {
	if (sv.Major == 1 && sv.Minor == 0) || (sv.Major == 2 && sv.Minor == 0) {
		return nil
	}
	return fmt.Errorf("unsupported schema version %d.%d", sv.Major, sv.Minor)
}

// isV10 determines if a given schema version object is 1.0. This was the only thing
// supported in RS1..3. It lives on in RS5, but will be deprecated in a future release.
func (sv *SchemaVersion) isV10() bool {
	if sv.Major == 1 && sv.Minor == 0 {
		return true
	}
	return false
}

// isV20 determines if a given schema version object is 2.0. This was introduced in
// RS4, but not fully implemented. Recommended for applications using HCS in RS5
// onwards.
func (sv *SchemaVersion) isV20() bool {
	if sv.Major == 2 && sv.Minor == 0 {
		return true
	}
	return false
}
