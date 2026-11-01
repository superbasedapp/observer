//go:build windows

package regularfile

import (
	"os"
	"syscall"
)

// openForRead opens path read-only. Windows has no named pipe that a plain
// open blocks on at a settings path; Read still stats the open descriptor
// and refuses anything that is not a regular file.
func openForRead(path string) (*os.File, error) {
	return os.Open(path)
}

// openNoFollow opens path ITSELF, never what a reparse point names:
// CreateFile with FILE_FLAG_OPEN_REPARSE_POINT (a symbolic link, a junction
// or any other reparse point opens as itself, not its target) and
// FILE_FLAG_BACKUP_SEMANTICS (a directory opens too, so it is refused below
// instead of failing obscurely), sharing read only. The handle's own
// attributes (GetFileInformationByHandle, GetFileType) must name a disk file
// that is neither a directory nor a reparse point; the returned *os.File
// wraps that same handle, so readOpen's fstat, cap and read run on the file
// that was checked, whatever is renamed over the path afterwards.
// ReadNoFollow's Lstat is not needed here.
func openNoFollow(path string, _ os.FileInfo) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ, syscall.FILE_SHARE_READ, nil,
		syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(h, &info); err != nil {
		_ = syscall.CloseHandle(h)
		return nil, &os.PathError{Op: "stat", Path: path, Err: err}
	}
	ft, err := syscall.GetFileType(h)
	if err != nil || ft != syscall.FILE_TYPE_DISK ||
		info.FileAttributes&(syscall.FILE_ATTRIBUTE_REPARSE_POINT|syscall.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		_ = syscall.CloseHandle(h)
		return nil, notRegular(path)
	}
	return os.NewFile(uintptr(h), path), nil
}
