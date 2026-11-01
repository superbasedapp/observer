package crossmount

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// windowsUserProbe is the identity-probe seam. It is a package var (like the
// detector fakes) so a test can force a deterministic Windows username without
// shelling out to cmd.exe (restore it in a defer). Production points it at
// probeWindowsUserName.
var windowsUserProbe = probeWindowsUserName

// windowsUserIsWSL is the WSL-gate seam for the user probe, split out from the
// exported IsWSL so a test can force the WSL / not-WSL branch of
// resolveWindowsUserName without touching /proc (restore it in a defer).
var windowsUserIsWSL = IsWSL

// probeWindowsUserName resolves the CURRENT Windows user's login name via WSL
// interop. It execs the Windows-side cmd.exe (reachable from WSL at the fixed
// System32 path) to echo %USERNAME%, with a 2s timeout, and returns the
// trimmed value or "" on any failure (interop disabled, cmd.exe absent,
// timeout). An unknown name ("") is the caller's signal that ownership is
// unverifiable.
func probeWindowsUserName() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/mnt/c/Windows/System32/cmd.exe", "/c", "echo %USERNAME%").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// resolveWindowsUserName is the non-memoized core of WindowsUserName: it is
// only meaningful under WSL (a native Linux/macOS/Windows host cannot own a
// /mnt/c/Users/<u> home over the interop bind), returning "" otherwise, and
// otherwise delegates to the injectable probe.
func resolveWindowsUserName() string {
	if !windowsUserIsWSL() {
		return ""
	}
	return windowsUserProbe()
}

// currentWindowsUser memoizes resolveWindowsUserName once per process — the
// cmd.exe interop shell is ~tens of ms and every cross-OS home resolution
// (proxy route AND hook detection) consults it, so it must not re-shell per
// call.
var currentWindowsUser = sync.OnceValue(resolveWindowsUserName)

// WindowsUserName returns the current Windows login name when the process runs
// inside WSL with Windows interop, or "" when it can't be determined (not WSL,
// interop disabled, cmd.exe absent, or the probe timed out). Memoized per
// process. It is the one owner of the cross-OS ownership primitive: a WSL
// daemon uses it to prove that an auto-detected Windows-side home
// (/mnt/c/Users/<u>/.claude, /.codex, /.cursor) belongs to the operator before
// rewriting that user's config — an empty result means "ownership
// unverifiable" and the caller must refuse to auto-pick rather than guess.
//
// A layout staged by StageForeignLayoutForTest pins the answer. Otherwise,
// while foreign discovery is suppressed (EnvDisableForeignHomes, or the
// test-binary guard in testguard.go) it returns "" WITHOUT probing: no
// cmd.exe interop exec happens from a test binary, and the memo is never
// filled from a suppressed state.
func WindowsUserName() string {
	if staged := stagedForeign.Load(); staged != nil {
		return staged.windowsUser
	}
	if foreignSuppressedWith(nil, os.Getenv(EnvDisableForeignHomes), testBinaryGuard) || IsolationReason() != "" {
		return ""
	}
	return currentWindowsUser()
}

// HomeOwnedByCurrentWindowsUser reports whether the Windows USER home dir
// (e.g. /mnt/c/Users/<u>) belongs to the current Windows user, by a
// case-insensitive match of its base name against WindowsUserName(). It is
// false whenever the username is unknown ("" — ownership unverifiable), which
// is the safe default: the caller then declines to auto-rewrite the home.
func HomeOwnedByCurrentWindowsUser(home string) bool {
	return homeOwnedBy(home, WindowsUserName())
}

// homeOwnedBy is the pure ownership predicate: home's base name matches user
// (case-insensitive), and an empty user never owns anything.
func homeOwnedBy(home, user string) bool {
	if user == "" {
		return false
	}
	return strings.EqualFold(filepath.Base(home), user)
}
