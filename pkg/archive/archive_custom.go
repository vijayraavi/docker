package archive

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/docker/docker/pkg/idtools"
	"github.com/docker/docker/pkg/promise"
	"github.com/docker/docker/pkg/rootfs"
	"github.com/docker/docker/pkg/system"
	"github.com/sirupsen/logrus"
)

// TarFunc provides a function definition for a custom Tar function
type TarFunc func(string, *TarOptions) (io.ReadCloser, error)

// UntarFunc provides a function definition for a custom Untar function
type UntarFunc func(io.Reader, string, *TarOptions) error

// CustomArchiver allows the reuse of most utility functions of this package
// with a pluggable Tar/Untar function. Also, to facilitate the passing of
// specific id mappings for untar, an archiver can be created with maps
// which will then be passed to Untar operations
type CustomArchiver struct {
	srcDriver  rootfs.Driver
	dstDriver  rootfs.Driver
	tar        TarFunc
	untar      UntarFunc
	idMappings *idtools.IDMappings
}

// NewCustomArchiver provides a way to create a custom Archiver.
func NewCustomArchiver(src, dst rootfs.Driver, tar TarFunc, untar UntarFunc, mapping *idtools.IDMappings) Archiver {
	return &CustomArchiver{
		srcDriver:  src,
		dstDriver:  dst,
		tar:        tar,
		untar:      untar,
		idMappings: mapping,
	}
}

// NewLocalArchiver provides a way to have a custom tar and untar functions that work on the local file system.
func NewLocalArchiver(tar TarFunc, untar UntarFunc, mapping *idtools.IDMappings) Archiver {
	return &CustomArchiver{
		srcDriver:  rootfs.NewLocalDriver(),
		dstDriver:  rootfs.NewLocalDriver(),
		tar:        tar,
		untar:      untar,
		idMappings: mapping,
	}
}

// NewDefaultArchiver creates an Archiver with the default tar/untar functions (TarWithOptions & Untar)
func NewDefaultArchiver() Archiver {
	return NewLocalArchiver(TarWithOptions, Untar, &idtools.IDMappings{})
}

// TarUntar is a convenience function which calls Tar and Untar, with the output of one piped into the other.
// If either Tar or Untar fails, TarUntar aborts and returns the error.
func (archiver *CustomArchiver) TarUntar(src, dst string) error {
	logrus.Debugf("TarUntar(%s %s)", src, dst)
	archive, err := archiver.tar(src, &TarOptions{Compression: Uncompressed})
	if err != nil {
		return err
	}
	defer archive.Close()
	options := &TarOptions{
		UIDMaps: archiver.idMappings.UIDs(),
		GIDMaps: archiver.idMappings.GIDs(),
	}
	return archiver.untar(archive, dst, options)
}

// UntarPath untar a file from path to a destination, src is the source tar file path.
func (archiver *CustomArchiver) UntarPath(src, dst string) error {
	archive, err := archiver.srcDriver.Open(src)
	if err != nil {
		return err
	}
	defer archive.Close()
	options := &TarOptions{
		UIDMaps: archiver.idMappings.UIDs(),
		GIDMaps: archiver.idMappings.GIDs(),
	}
	return archiver.untar(archive, dst, options)
}

// CopyWithTar creates a tar archive of filesystem path `src`, and
// unpacks it at filesystem path `dst`.
// The archive is streamed directly with fixed buffering and no
// intermediary disk IO.
func (archiver *CustomArchiver) CopyWithTar(src, dst string) error {
	srcSt, err := archiver.srcDriver.Stat(src)
	if err != nil {
		return err
	}
	if !srcSt.IsDir() {
		return archiver.CopyFileWithTar(src, dst)
	}

	// if this archiver is set up with ID mapping we need to create
	// the new destination directory with the remapped root UID/GID pair
	// as owner
	rootIDs := archiver.idMappings.RootPair()
	// Create dst, copy src's content into it
	logrus.Debugf("Creating dest directory: %s", dst)
	if err := idtools.MkdirAllAndChownNew(dst, 0755, rootIDs); err != nil {
		return err
	}
	logrus.Debugf("Calling TarUntar(%s, %s)", src, dst)
	return archiver.TarUntar(src, dst)
}

// CopyFileWithTar emulates the behavior of the 'cp' command-line
// for a single file. It copies a regular file from path `src` to
// path `dst`, and preserves all its metadata.
func (archiver *CustomArchiver) CopyFileWithTar(src, dst string) (err error) {
	logrus.Debugf("CopyFileWithTar(%s, %s)", src, dst)
	srcDriver := archiver.srcDriver
	dstDriver := archiver.dstDriver

	srcSt, err := srcDriver.Stat(src)
	if err != nil {
		return err
	}

	if srcSt.IsDir() {
		return fmt.Errorf("Can't copy a directory")
	}

	// Clean up the trailing slash. This must be done in an operating
	// system specific manner.
	if dst[len(dst)-1] == dstDriver.Separator() {
		dst = dstDriver.Join(dst, srcDriver.Base(src))
	}

	// The original call was system.MkdirAll, which is just
	// os.MkdirAll on not-Windows and changed for Windows.
	if dstDriver.Platform() == "windows" {
		// Now we are WCOW
		if err := system.MkdirAll(filepath.Dir(dst), 0700, ""); err != nil {
			return err
		}
	} else {
		// We can just use the driver.MkdirAll function
		if err := dstDriver.MkdirAll(dstDriver.Dir(dst), 0700); err != nil {
			return err
		}
	}

	r, w := io.Pipe()
	errC := promise.Go(func() error {
		defer w.Close()

		srcF, err := srcDriver.Open(src)
		if err != nil {
			return err
		}
		defer srcF.Close()

		hdr, err := tar.FileInfoHeader(srcSt, "")
		if err != nil {
			return err
		}
		hdr.Name = dstDriver.Base(dst)
		if dstDriver.Platform() == "windows" {
			hdr.Mode = int64(chmodTarEntry(os.FileMode(hdr.Mode)))
		} else {
			hdr.Mode = int64(os.FileMode(hdr.Mode))
		}

		if err := remapIDs(archiver.idMappings, hdr); err != nil {
			return err
		}

		tw := tar.NewWriter(w)
		defer tw.Close()
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := io.Copy(tw, srcF); err != nil {
			return err
		}
		return nil
	})
	defer func() {
		if er := <-errC; err == nil && er != nil {
			err = er
		}
	}()

	err = archiver.untar(r, dstDriver.Dir(dst), nil)
	if err != nil {
		r.CloseWithError(err)
	}
	return err
}

// IDMappings returns the IDMappings of the archiver.
func (archiver *CustomArchiver) IDMappings() *idtools.IDMappings {
	return archiver.idMappings
}

func remapIDs(idMappings *idtools.IDMappings, hdr *tar.Header) error {
	ids, err := idMappings.ToHost(idtools.IDPair{UID: hdr.Uid, GID: hdr.Gid})
	hdr.Uid, hdr.Gid = ids.UID, ids.GID
	return err
}
