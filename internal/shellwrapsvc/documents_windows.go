//go:build windows

package shellwrapsvc

import (
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// userShellFoldersKey is where Explorer records per-user folder redirection
// (OneDrive folder backup, Group Policy folder redirection).
const userShellFoldersKey = `Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

// osDocumentsKnownFolder asks the shell for FOLDERID_Documents, the same
// lookup PowerShell's $PROFILE is built from. KF_FLAG_DONT_VERIFY returns the
// configured location even when the folder does not exist yet.
func osDocumentsKnownFolder() (string, error) {
	return windows.KnownFolderPath(windows.FOLDERID_Documents, windows.KF_FLAG_DONT_VERIFY)
}

// osDocumentsShellFolder reads the raw (unexpanded) "Personal" value; the
// pure ladder expands its %VAR% references.
func osDocumentsShellFolder() (string, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, userShellFoldersKey, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer func() { _ = k.Close() }()
	v, _, err := k.GetStringValue("Personal")
	return v, err
}
