// +build windows

package hcsshim

import (
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"io"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

var (
	modkernel32   = syscall.NewLazyDLL("kernel32.dll")
	procCopyFileW = modkernel32.NewProc("CopyFileW")
)

type GUID [16]byte

func NewGUID(source string) *GUID {
	h := sha1.Sum([]byte(source))
	var g GUID
	copy(g[0:], h[0:16])
	return &g
}

func GenerateGUID() (*GUID, error) { // https://play.golang.org/p/4FkNSiUDMg
	g := make([]byte, 16)
	n, err := io.ReadFull(rand.Reader, g)
	if n != len(g) || err != nil {
		return nil, err
	}
	g[8] = g[8]&^0xc0 | 0x80
	g[6] = g[6]&^0xf0 | 0x40
	var g2 GUID
	copy(g2[0:], g[:])
	return &g2, nil
}

func (g *GUID) ToString() string {
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x-%02x", g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6], g[8:10], g[10:])
}

// NameToGuid converts the given string into a GUID using the algorithm in the
// Host Compute Service, ensuring GUIDs generated with the same string are common
// across all clients.
func NameToGuid(name string) (id GUID, err error) {
	title := "hcsshim::NameToGuid "
	err = nameToGuid(name, &id)
	if err != nil {
		err = makeErrorf(err, title, "name=%s", name)
		logrus.Error(err)
		return
	}
	logrus.Debugf(title+"Name %s GUID %s", name, id.ToString())
	return
}

// makeOpenFiles calls winio.MakeOpenFile for each handle in a slice but closes all the handles
// if there is an error.
func makeOpenFiles(hs []syscall.Handle) (_ []io.ReadWriteCloser, err error) {
	fs := make([]io.ReadWriteCloser, len(hs))
	for i, h := range hs {
		if h != syscall.Handle(0) {
			if err == nil {
				fs[i], err = winio.MakeOpenFile(h)
			}
			if err != nil {
				syscall.Close(h)
			}
		}
	}
	if err != nil {
		for _, f := range fs {
			if f != nil {
				f.Close()
			}
		}
		return nil, err
	}
	return fs, nil
}

var (
	kernel32               = windows.NewLazySystemDLL("kernel32.dll")
	getCurrentProcess      = kernel32.NewProc("GetCurrentProcess")
	getProcessAffinityMask = kernel32.NewProc("GetProcessAffinityMask")
)

func numCPUAPI() int {
	// Gets the affinity mask for a process
	var mask, sysmask uintptr
	currentProcess, _, _ := getCurrentProcess.Call()
	ret, _, _ := getProcessAffinityMask.Call(currentProcess, uintptr(unsafe.Pointer(&mask)), uintptr(unsafe.Pointer(&sysmask)))
	if ret == 0 {
		return 0
	}
	// For every available thread a bit is set in the mask.
	ncpu := int(popcnt(uint64(mask)))
	return ncpu
}

// numCPU returns the number of CPUs which are currently online
func numCPU() int {
	if ncpu := numCPUAPI(); ncpu > 0 {
		return ncpu
	}
	return runtime.NumCPU()
}

// popcnt returns bit count of 1, used by numCPU
func popcnt(x uint64) (n byte) {
	x -= (x >> 1) & 0x5555555555555555
	x = (x>>2)&0x3333333333333333 + x&0x3333333333333333
	x += x >> 4
	x &= 0x0f0f0f0f0f0f0f0f
	x *= 0x0101010101010101
	return byte(x >> 56)
}

// CopyFile is a utility for copying a file - used for the LCOW sandbox cache.
// Uses CopyFileW win32 API for performance.
func CopyFile(srcFile, destFile string, overwrite bool) error {
	var bFailIfExists uint32 = 1
	if overwrite {
		bFailIfExists = 0
	}

	lpExistingFileName, err := syscall.UTF16PtrFromString(srcFile)
	if err != nil {
		return err
	}
	lpNewFileName, err := syscall.UTF16PtrFromString(destFile)
	if err != nil {
		return err
	}
	r1, _, err := syscall.Syscall(
		procCopyFileW.Addr(),
		3,
		uintptr(unsafe.Pointer(lpExistingFileName)),
		uintptr(unsafe.Pointer(lpNewFileName)),
		uintptr(bFailIfExists))
	if r1 == 0 {
		return fmt.Errorf("failed CopyFileW Win32 call from '%s' to '%s': %s", srcFile, destFile, err)
	}
	return nil
}
