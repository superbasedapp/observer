//go:build windows

package superbased

import (
	"errors"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

// readOwnerOnlyFile refuses on Windows: the machine has no hardened file
// store there (contract destination.md section 4.1), so the machine's key
// comes from SUPERBASED_API_KEY. Only the SDK-held file is read on Windows
// (readSDKHeldFile).
func readOwnerOnlyFile(path string, limit int64) ([]byte, string) {
	return nil, "credential files are not read on Windows; set SUPERBASED_API_KEY"
}

// finalPathFlags is FILE_NAME_NORMALIZED | VOLUME_NAME_DOS (both zero).
const finalPathFlags = 0

// readSDKHeldFile reads the SDK-held credential file under the Windows rule
// (SDK quickstart ruling R4), all on one open handle so nothing can be
// swapped between the checks and the read:
//
//   - the file itself is not a reparse point (a symlink or a mount point is
//     opened as itself, never followed) and not a directory;
//   - its final path, after any junction or symlink in a parent folder, is
//     inside the final path of root, the user's %LOCALAPPDATA% (contract
//     destination.md section 6a: whatever chose the path);
//   - its owner SID is the current user's.
//
// The DACL is the writer's concern (setup sets an owner-only one); the
// reader does not check it. It returns (bytes, problem, reason, missing);
// missing is true when there is no file at path.
func readSDKHeldFile(path, root string, limit int64) ([]byte, string, string, bool) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, "cannot read the SDK credential file: " + err.Error(), "", false
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil, "", "", true
		}
		return nil, "cannot read the SDK credential file: " + errText(err), "", false
	}
	f := os.NewFile(uintptr(h), path)
	defer f.Close()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return nil, "cannot read the SDK credential file: " + errText(err), "", false
	}
	facts := windowsFacts{
		reparsePoint: info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0,
		directory:    info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0,
	}
	if !facts.reparsePoint && !facts.directory {
		final, err := finalPath(h)
		if err != nil {
			return nil, "cannot read the SDK credential file: " + errText(err), "", false
		}
		if base, err := dirFinalPath(root); err == nil {
			facts.insideRoot = underWindowsDir(final, base)
		}
		facts.ownerIsUser, facts.ownerError = ownerIsUser(h)
	}
	if p, reason := windowsFileProblem(facts); p != "" {
		return nil, p, reason, false
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return nil, "cannot read the SDK credential file: " + errText(err), "", false
	}
	return raw, "", "", false
}

// finalPath is the normalized DOS path of an open handle.
func finalPath(h windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_PATH)
	for {
		n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), finalPathFlags)
		if err != nil {
			return "", err
		}
		if int(n) < len(buf) {
			return windows.UTF16ToString(buf[:n]), nil
		}
		buf = make([]uint16, n+1)
	}
}

// dirFinalPath is the final path of the folder dir ("" dir: an error, so
// nothing is inside it).
func dirFinalPath(dir string) (string, error) {
	if dir == "" {
		return "", errors.New("LOCALAPPDATA is not set")
	}
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return "", err
	}
	h, err := windows.CreateFile(name, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h) //nolint:errcheck // a read-only handle
	return finalPath(h)
}

// ownerIsUser reports whether the open file's owner SID is the current
// user's; the string says why the owner could not be read.
func ownerIsUser(h windows.Handle) (bool, string) {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false, "cannot read the SDK credential file's owner: " + errText(err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return false, "cannot read the SDK credential file's owner; refused"
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false, "cannot read the current user: " + errText(err)
	}
	return owner.Equals(user.User.Sid), ""
}

func errText(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	var en syscall.Errno
	if errors.As(err, &en) {
		return en.Error()
	}
	return err.Error()
}
