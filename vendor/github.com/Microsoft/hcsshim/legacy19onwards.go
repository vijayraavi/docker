// +build go1.9

// Note - the above build tag means 1.9 and later.

package hcsshim

// Due to a bug in go1.8 and before, directory reparse points need to be skipped
// during filepath.Walk. This is fixed in go1.9
var shouldSkipDirectoryReparse = false
