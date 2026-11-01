//go:build windows

package fsatomic

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// createOwnerOnly creates path fresh with a protected DACL that grants only
// this user and SYSTEM (the 0600 equivalent): no inherited ACE reaches it.
// Moved here from cmd/observer's MXC driver (finding F2 of lane SBX-P6),
// which now calls CreateOwnerOnly.
func createOwnerOnly(path string) (*os.File, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("the token user: %w", err)
	}
	// The owner is named too: an elevated process would otherwise make
	// BUILTIN\Administrators the owner, which FileIsOwnerOnly refuses.
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf("O:%sD:P(A;;FA;;;%s)(A;;FA;;;SY)", u.User.Sid.String(), u.User.Sid.String()))
	if err != nil {
		return nil, fmt.Errorf("the owner-only descriptor: %w", err)
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE, 0, sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "create", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

// isOwnerOnlyFile reads the open file's owner and DACL from its handle
// (never by path, WINFIX4 audit finding 5).
func isOwnerOnlyFile(f *os.File) (bool, error) {
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false, err
	}
	return sdOwnerOnly(sd, u.User.Sid)
}

// sdOwnerOnly is the Windows rule over a descriptor: the owner is user, the
// DACL is protected (nothing inherited) and every entry allows only user or
// SYSTEM.
func sdOwnerOnly(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID) (bool, error) {
	owner, _, err := sd.Owner()
	if err != nil {
		return false, err
	}
	if owner == nil || !owner.Equals(user) {
		return false, nil
	}
	control, _, err := sd.Control()
	if err != nil {
		return false, err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return false, nil
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return false, err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return false, err
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return false, err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return false, nil
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(user) && !sid.Equals(system) {
			return false, nil
		}
	}
	return true, nil
}
