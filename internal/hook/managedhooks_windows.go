//go:build windows

package hook

import (
	"os"

	"golang.org/x/sys/windows"
)

// managedHooksOwnerUntrusted is the trust rule of an administrator hooks
// file (and its directory) on Windows: owned by BUILTIN\Administrators,
// SYSTEM or TrustedInstaller. A standard user can create a directory under
// %ProgramData% and would then own it, so a user-owned file or directory
// never stands Observer down.
func managedHooksOwnerUntrusted(path string, _ os.FileInfo) string {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return path + " owner could not be read"
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return path + " owner could not be read"
	}
	if owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || owner.IsWellKnown(windows.WinLocalSystemSid) {
		return ""
	}
	if ti, err := windows.StringToSid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"); err == nil && owner.Equals(ti) {
		return ""
	}
	return path + " is not owned by Administrators or SYSTEM"
}
