package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// update_swap.go is §3.7 step 6 — the atomic replacement of the running
// executable, and the restore that undoes it.
//
// TWO STRATEGIES, ONE FILE, NO BUILD TAGS. The plan sketched
// update_swap_unix.go / update_swap_windows.go, but build tags would make
// the Windows sequence uncompilable and untestable on the machine this is
// developed and CI'd on — and the Windows sequence is the one with the
// interrupted-swap recovery worth testing. So the branch is on a CAPABILITY
// ("can this OS replace the file a running process is executing?"), chosen
// from runtime.GOOS, over an injected filesystem seam. Both strategies are
// exercised by the same table on every platform (CLAUDE.md #3/#5).
//
// WHY REPLACING A RUNNING BINARY IS SAFE ON UNIX, AND WHY THAT MATTERS HERE:
// rename() swaps the directory entry, not the inode. The old daemon keeps
// executing its own inode for as long as it lives, which is exactly what
// makes it a usable SUPERVISOR for the handshake in step 7 and what lets it
// restore itself in step 8. Windows refuses to replace a running .exe but
// permits RENAMING it, so the same end state is reached in two moves —
// which is also why the handshake, not execve, unifies the platforms.
//
// The invariant both strategies hold: THERE IS NO WINDOW IN WHICH NO
// EXECUTABLE EXISTS AT exePath. On Unix rename is a single atomic step. On
// Windows a failure between the two renames leaves the `.old-<version>` file
// present, which is a state the next start detects and restores from.

// swapFS is the filesystem seam. Injecting it is what lets a test drive an
// interrupted two-rename sequence deterministically instead of hoping to
// crash at the right microsecond.
type swapFS interface {
	Rename(oldPath, newPath string) error
	Remove(name string) error
	Stat(name string) (os.FileInfo, error)
}

// osSwapFS is the real implementation.
type osSwapFS struct{}

func (osSwapFS) Rename(o, n string) error           { return os.Rename(o, n) }
func (osSwapFS) Remove(n string) error              { return os.Remove(n) }
func (osSwapFS) Stat(n string) (os.FileInfo, error) { return os.Stat(n) }

// swapStrategy names how a platform replaces a running executable.
type swapStrategy string

const (
	// swapInPlace: rename(new, exePath) is legal while the process runs.
	swapInPlace swapStrategy = "in_place"
	// swapRenameAside: the running .exe must be renamed out of the way
	// first, then the new one moved in.
	swapRenameAside swapStrategy = "rename_aside"
)

// strategyForOS picks the strategy. It is a function of the OS's file
// semantics, not of a tool name, so a new platform is a row here.
func strategyForOS(goos string) swapStrategy {
	if goos == "windows" {
		return swapRenameAside
	}
	return swapInPlace
}

// asidePath is where the running executable is moved on the rename-aside
// platform. Deterministic, so the next start can find and clean it.
func asidePath(exePath, oldVersion string) string {
	slug := strings.NewReplacer("/", "-", `\`, "-", ":", "-", " ", "-").Replace(oldVersion)
	if strings.TrimSpace(slug) == "" {
		slug = "previous"
	}
	return exePath + ".old-" + slug
}

// swapResult describes what a swap left on disk, so the caller can undo it.
type swapResult struct {
	// Strategy is the strategy used.
	Strategy swapStrategy
	// AsideName is the path the previous executable was renamed to on the
	// rename-aside platform, empty on the in-place one.
	AsideName string
}

// swapBinary moves staged into exePath.
//
// prevCopy is a path where the CURRENT executable has already been preserved
// (§3.7 step 5 stages the rollback BEFORE anything on the live path is
// touched). It is not written here; it is only checked, because a swap that
// cannot be undone must not begin.
func swapBinary(fs swapFS, goos, staged, exePath, prevCopy, oldVersion string) (swapResult, error) {
	if strings.TrimSpace(staged) == "" || strings.TrimSpace(exePath) == "" {
		return swapResult{}, errors.New("observer update: swap needs both a staged binary and a target path")
	}
	if _, err := fs.Stat(staged); err != nil {
		return swapResult{}, fmt.Errorf("observer update: staged binary %s: %w", staged, err)
	}
	// Refuse to begin a swap whose rollback does not exist. This is the
	// fail-closed direction: an apply that cannot be undone is not an
	// apply, it is a one-way replacement of the operator's daemon.
	if strings.TrimSpace(prevCopy) == "" {
		return swapResult{}, errors.New("observer update: refusing to swap without a staged rollback binary")
	}
	if _, err := fs.Stat(prevCopy); err != nil {
		return swapResult{}, fmt.Errorf("observer update: rollback binary %s is missing, refusing to swap: %w", prevCopy, err)
	}

	strategy := strategyForOS(goos)
	if strategy == swapInPlace {
		if err := fs.Rename(staged, exePath); err != nil {
			return swapResult{}, fmt.Errorf("observer update: swap: %w", err)
		}
		return swapResult{Strategy: swapInPlace}, nil
	}

	aside := asidePath(exePath, oldVersion)
	// A leftover aside file from an abandoned apply would make the first
	// rename fail; clear it deliberately rather than inheriting it.
	if err := fs.Remove(aside); err != nil && !os.IsNotExist(err) {
		return swapResult{}, fmt.Errorf("observer update: clearing %s: %w", aside, err)
	}
	if err := fs.Rename(exePath, aside); err != nil {
		// Nothing has moved. This is the ERROR_ACCESS_DENIED case (an AV
		// scanner, a second instance): abort with the original in place.
		return swapResult{}, fmt.Errorf("observer update: swap (rename aside): %w", err)
	}
	if err := fs.Rename(staged, exePath); err != nil {
		// The window the two-rename dance opens. Put the original back
		// immediately; if even that fails, say so loudly — the aside file
		// is the recovery, and the next start detects it.
		if back := fs.Rename(aside, exePath); back != nil {
			return swapResult{Strategy: swapRenameAside, AsideName: aside},
				fmt.Errorf("observer update: swap failed AND the previous executable could not be restored; it is at %s: %w", aside, err)
		}
		return swapResult{}, fmt.Errorf("observer update: swap (rename in): %w", err)
	}
	return swapResult{Strategy: swapRenameAside, AsideName: aside}, nil
}

// restoreBinary puts prevCopy back at exePath after a failed handshake.
//
// It uses the same two-rename dance on the rename-aside platform, for the
// same reason: on Windows the NEW executable is the one currently running as
// the child, and although the parent has killed it by now, an antivirus
// handle can still hold it briefly. Renaming aside always works where
// replacing does not.
func restoreBinary(fs swapFS, goos, prevCopy, exePath, oldVersion string) error {
	if strings.TrimSpace(prevCopy) == "" {
		return errors.New("observer update: no previous binary recorded; nothing to restore")
	}
	if _, err := fs.Stat(prevCopy); err != nil {
		return fmt.Errorf("observer update: previous binary %s: %w", prevCopy, err)
	}
	if strategyForOS(goos) == swapInPlace {
		if err := fs.Rename(prevCopy, exePath); err != nil {
			return fmt.Errorf("observer update: restore: %w", err)
		}
		return nil
	}
	failed := asidePath(exePath, "failed")
	if err := fs.Remove(failed); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("observer update: clearing %s: %w", failed, err)
	}
	if err := fs.Rename(exePath, failed); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("observer update: restore (rename aside): %w", err)
	}
	if err := fs.Rename(prevCopy, exePath); err != nil {
		// Put the failed binary back rather than leaving no executable at
		// all: a node running a broken new version is recoverable by hand,
		// a node with no binary is not.
		_ = fs.Rename(failed, exePath)
		return fmt.Errorf("observer update: restore (rename in): %w", err)
	}
	_ = fs.Remove(failed)
	return nil
}

// recoverInterruptedSwap is the boot-time half of the two-rename invariant.
//
// If an aside file exists but exePath does not, the process was killed
// between the two renames and the node has no executable at its own path.
// Putting the aside file back is the only correct move — and it is why the
// aside name is deterministic rather than a temp name nobody could find.
func recoverInterruptedSwap(fs swapFS, exePath, oldVersion string) (bool, error) {
	aside := asidePath(exePath, oldVersion)
	if _, err := fs.Stat(aside); err != nil {
		return false, nil
	}
	if _, err := fs.Stat(exePath); err == nil {
		// Both exist: the swap completed. The aside file is now just
		// retention, cleaned by keep_previous_days.
		return false, nil
	}
	if err := fs.Rename(aside, exePath); err != nil {
		return false, fmt.Errorf("observer update: recovering an interrupted swap: %w", err)
	}
	return true, nil
}

// preserveExecutable copies the running executable to dest so a rollback has
// something to restore.
//
// It tries a HARD LINK first and falls back to a copy. The link is not an
// optimisation: it is atomic and cannot half-succeed, whereas a copy
// interrupted by a full disk leaves a truncated "rollback binary" that would
// pass a stat check and fail to execute. The copy path therefore writes to a
// temp name and renames, so dest is either absent or complete.
func preserveExecutable(exePath, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("observer update: rollback dir: %w", err)
	}
	if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("observer update: clearing %s: %w", dest, err)
	}
	if err := os.Link(exePath, dest); err == nil {
		return nil
	}
	src, err := os.Open(exePath) //nolint:gosec // the running executable's own path
	if err != nil {
		return fmt.Errorf("observer update: reading the running executable: %w", err)
	}
	defer func() { _ = src.Close() }()
	tmp := dest + ".part"
	if err := os.Remove(tmp); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("observer update: clearing %s: %w", tmp, err)
	}
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755) //nolint:gosec // an executable, deliberately 0755
	if err != nil {
		return fmt.Errorf("observer update: staging the rollback binary: %w", err)
	}
	if _, err := io.Copy(out, src); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("observer update: copying the rollback binary: %w", err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("observer update: closing the rollback binary: %w", err)
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("observer update: publishing the rollback binary: %w", err)
	}
	return nil
}
