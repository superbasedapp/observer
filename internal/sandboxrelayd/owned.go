package sandboxrelayd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// owned.go is the ONE ownership helper for everything the sandbox creates
// on the host: run records, liveness locks, the CLI end markers and the MXC
// driver's per-run box, temp and plan files (Windows 11 Pro live run, B2).
// An elevated Windows token creates objects owned by BUILTIN\Administrators
// by default; each create site hands what it just made to OwnRecord, which
// sets the owner explicitly to the token user (the run's user SID), so a
// record never depends on whether the daemon or the launcher was elevated.
// Off Windows, and on Windows when the token is not elevated, a created
// object is already its creator's and OwnRecord does nothing.

// OwnRecord makes the token user the owner of a file or directory the
// sandbox just created (owner_windows.go has the elevated-token case).
func OwnRecord(path string) error { return claimOwned(path) }

// MkdirAllOwned creates dir and any missing parents (0700) and gives each
// directory it created to the token user (OwnRecord).
func MkdirAllOwned(dir string) error { return MkdirAllClaimed(dir, claimOwned) }

// MkdirAllClaimed is MkdirAllOwned with the claim passed in (a caller's own
// test seam). Only the directories this call creates are claimed, outermost
// first (SBX-UPD audit finding 7): one that already exists keeps its owner,
// which a token that is not elevated may not be able to change.
func MkdirAllClaimed(dir string, claim func(string) error) error {
	var created []string
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		if _, err := os.Lstat(d); !errors.Is(err, os.ErrNotExist) { //nolint:gosec // G703: a parent of the sandbox's own record dir
			break
		}
		created = append(created, d)
		if filepath.Dir(d) == d {
			break
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil { //nolint:gosec // G703: the sandbox's own record dir
		return err
	}
	for i := len(created) - 1; i >= 0; i-- {
		if err := claim(created[i]); err != nil {
			return fmt.Errorf("own %s: %w", filepath.Base(created[i]), err)
		}
	}
	return nil
}
