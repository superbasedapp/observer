//go:build windows

package sandboxrelayd

import (
	"io/fs"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// owner_windows.go is the record privacy check on native Windows (lane
// SBX-P6, the MXC driver's relay): a record and its directory must be
// owned by this process's user, must not be a link or a reparse point,
// and their DACL may grant write access to no one but that user, SYSTEM
// and the Administrators group (the inherited ACL of a user profile and
// its temp directory). Permission bits mean nothing on Windows (os.Stat
// reports 0666 for any writable file), so they are not read.

// oNoFollow has no open flag on Windows: privateFile checks the path with
// Lstat and the opened handle's attributes instead.
const oNoFollow = 0

// oNonblock has no meaning for Windows files.
const oNonblock = 0

// clearNonblock has nothing to clear on Windows.
func clearNonblock(*os.File) {}

// writeMask is every access right that can change a file or its security.
const writeMask = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA |
	windows.FILE_WRITE_ATTRIBUTES | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
	windows.GENERIC_WRITE | windows.GENERIC_ALL | fileDeleteChild

// fileDeleteChild is FILE_DELETE_CHILD (a directory right).
const fileDeleteChild = 0x40

// trustedWriters are the SIDs besides the owner a private record's DACL
// may let write.
var trustedWriters = []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid, windows.WinCreatorOwnerSid}

// privateFile checks an opened record: not a link, owned by this user, and
// writable by no one else.
func privateFile(path string, f *os.File, fi fs.FileInfo) bool {
	if lfi, err := os.Lstat(path); err != nil || !lfi.Mode().IsRegular() || !os.SameFile(lfi, fi) {
		return false
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	return err == nil && privateDescriptor(sd)
}

// privateDir checks a record's directory the same way, by path.
func privateDir(dir string, fi fs.FileInfo) bool {
	if fi.Mode()&fs.ModeSymlink != 0 || fi.Mode()&fs.ModeIrregular != 0 {
		return false
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	return err == nil && privateDescriptor(sd)
}

// currentUser is this process's token user.
func currentUser() (*windows.SID, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return u.User.Sid, nil
}

// claimOwnership makes this process's token user the owner of a record or
// record directory it just created (lane SBX-UPD, P6 leftover; every create
// site since the Windows 11 Pro live run, B2, through OwnRecord). A process
// whose token is elevated creates files owned by BUILTIN\Administrators
// by default, which the strict reader rule below (owner must be the token
// user) refuses. An elevated token therefore always sets the owner
// explicitly, whatever the object's default owner was; the reader rule is
// unchanged. A token that is not elevated claims nothing at all (SBX-UPD
// audit finding 7: such a token cannot take an object owned by another
// principal, and its own creations are already its own).
func claimOwnership(path string) error {
	if !tokenIsElevated() {
		return nil
	}
	me, err := currentUser()
	if err != nil {
		return err
	}
	return setOwner(path, me)
}

// tokenIsElevated and setOwner are the elevation read and the owner write,
// variables so a test can drive the elevated branch without elevation.
var (
	tokenIsElevated = tokenElevated
	setOwner        = func(path string, owner *windows.SID) error {
		return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil)
	}
)

// tokenElevated reports whether this process's token is elevated.
func tokenElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// privateDescriptor applies the owner and DACL rule.
func privateDescriptor(sd *windows.SECURITY_DESCRIPTOR) bool {
	me, err := currentUser()
	if err != nil {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.Equals(me) {
		return false
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		// A NULL DACL grants everyone everything.
		return false
	}
	trusted := []*windows.SID{me}
	for _, t := range trustedWriters {
		if s, err := windows.CreateWellKnownSid(t); err == nil {
			trusted = append(trusted, s)
		}
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return false
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if ace.Mask&writeMask == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		ok := false
		for _, t := range trusted {
			ok = ok || sid.Equals(t)
		}
		if !ok {
			return false
		}
	}
	return true
}
