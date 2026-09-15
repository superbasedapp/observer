package crossmount

import (
	"os"
	"path/filepath"
	"strings"
)

// EnvAllWindowsProfiles is the escape hatch that disables the
// Windows-profile filter applied to /mnt/c/Users enumeration. Set it to
// a truthy value ("1", "true", "yes", "on", case-insensitive) and every
// directory under /mnt/c/Users becomes a candidate home again — the
// pre-filter behaviour.
//
// It exists because the filter is a heuristic over an open-ended
// namespace: a domain-joined box, a redirected profile root, or a
// vendor that provisions a profile without the usual markers could in
// principle host real sessions under a directory this package drops.
// The escape hatch is the honest answer to "we cannot enumerate every
// legitimate shape"; nothing else in the tree reads it.
const EnvAllWindowsProfiles = "OBSERVER_CROSSMOUNT_ALL_PROFILES"

// nonUserWindowsProfiles names the directories that live under
// C:\Users but are NOT a human user's profile. Compared case-folded,
// because the enumeration comes off a case-insensitive filesystem
// reached over DrvFs.
//
// Rows, and why each is here:
//
//   - "default", "default user": the profile TEMPLATE Windows copies
//     when it provisions a new account. Both carry a real NTUSER.DAT
//     and a real AppData tree, so the marker gate below cannot catch
//     them — the name table is the only thing that can. On Windows 7+
//     "Default User" is a junction onto "Default"; from WSL over DrvFs
//     a junction reads as a directory, so both spellings appear.
//   - "public": the shared-documents profile. No NTUSER.DAT, no
//     AppData — the marker gate would drop it anyway; listed so the
//     intent is explicit rather than incidental.
//   - "all users": a junction onto C:\ProgramData. Machine-wide state,
//     never a user home.
//   - "defaultuser0": the transient OOBE account Windows creates during
//     out-of-box setup and normally deletes afterwards. A leftover one
//     is a stale template, not a user.
//   - "wdagutilityaccount": the built-in Windows Defender Application
//     Guard container account.
//   - "wsiaccount": the service profile the Windows Subsystem installer
//     provisions. Grounded on the 2026-09-03 dev box, where it was one
//     of the profiles the WSL daemon fanned watch roots across.
//   - "desktop.ini": a FILE, already dropped by the is-a-directory
//     check in wslWindowsHomes. Listed so the table reads as the
//     complete answer to "what is under C:\Users that is not a user".
//
// Everything NOT in this table is subject only to the marker gate, so
// an unusual-but-real account name (a service account an operator
// actually codes under, a domain login) still enumerates.
var nonUserWindowsProfiles = map[string]struct{}{
	"default":            {},
	"default user":       {},
	"public":             {},
	"all users":          {},
	"defaultuser0":       {},
	"wdagutilityaccount": {},
	"wsiaccount":         {},
	"desktop.ini":        {},
}

// isNonUserProfileName reports whether name is a well-known non-user
// entry under C:\Users.
func isNonUserProfileName(name string) bool {
	_, ok := nonUserWindowsProfiles[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

// hasUserProfileMarker reports whether the directory at path carries at
// least one structural marker of a real, logged-into Windows profile:
//
//   - NTUSER.DAT — the per-user registry hive. Every provisioned
//     profile has one. Probed in both the canonical upper-case spelling
//     and lower-case, because a case-SENSITIVE mount (a WSL distro with
//     `options=case=off` turned around, a network share) would miss the
//     other one.
//   - AppData — the per-user application-data tree. Present on every
//     profile a user has actually signed into, and the parent of the
//     Windows shape every adapter composes.
//
// A directory with neither is not somewhere an AI tool has ever stored
// a session, so enumerating it only produces watch roots that can never
// exist.
func (d *detector) hasUserProfileMarker(path string) bool {
	exists := d.exists
	if exists == nil {
		exists = fileExists
	}
	for _, marker := range []string{"NTUSER.DAT", "ntuser.dat"} {
		if exists(filepath.Join(path, marker)) {
			return true
		}
	}
	return d.statDir(filepath.Join(path, "AppData"))
}

// allProfilesForced reports whether the operator disabled the profile
// filter via EnvAllWindowsProfiles.
func (d *detector) allProfilesForced() bool {
	get := d.getenv
	if get == nil {
		get = os.Getenv
	}
	switch strings.ToLower(strings.TrimSpace(get(EnvAllWindowsProfiles))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
