// +build !windows

package rootfs

import "path/filepath"

// cleanResourcePath preappends a to combine with a mnt path.
func cleanScopedPath(path string) string {
	return filepath.Join(string(filepath.Separator), path)
}
