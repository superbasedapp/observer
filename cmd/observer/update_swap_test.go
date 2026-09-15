package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// update_swap_test.go exercises BOTH swap strategies on whatever platform
// the tests run on. That is the whole reason strategyForOS takes a goos
// string instead of reading runtime.GOOS: the Windows two-rename sequence —
// the one with the interrupted-swap recovery worth testing — would otherwise
// be uncompilable and unexercised on the Linux machine this is developed and
// CI'd on.

// fakeSwapFS is an in-memory filesystem that can be told to fail a specific
// rename. Injecting the failure is what makes "interrupted between the two
// renames" a deterministic test rather than a race someone hopes to hit.
type fakeSwapFS struct {
	files map[string]string
	// failRename fails the Nth rename (1-based); 0 disables.
	failRename int
	renames    int
	// renameLog records every rename for order assertions.
	renameLog []string
}

func newFakeSwapFS(files map[string]string) *fakeSwapFS {
	cp := map[string]string{}
	for k, v := range files {
		cp[k] = v
	}
	return &fakeSwapFS{files: cp}
}

func (f *fakeSwapFS) Rename(oldPath, newPath string) error {
	f.renames++
	if f.failRename == f.renames {
		return errors.New("simulated rename failure")
	}
	body, ok := f.files[oldPath]
	if !ok {
		return os.ErrNotExist
	}
	delete(f.files, oldPath)
	f.files[newPath] = body
	f.renameLog = append(f.renameLog, oldPath+" -> "+newPath)
	return nil
}

func (f *fakeSwapFS) Remove(name string) error {
	if _, ok := f.files[name]; !ok {
		return os.ErrNotExist
	}
	delete(f.files, name)
	return nil
}

type fakeInfo struct{ name string }

func (fakeInfo) Size() int64        { return 0 }
func (fakeInfo) Mode() os.FileMode  { return 0o755 }
func (fakeInfo) ModTime() time.Time { return time.Time{} }
func (fakeInfo) IsDir() bool        { return false }
func (fakeInfo) Sys() any           { return nil }
func (i fakeInfo) Name() string     { return i.name }

func (f *fakeSwapFS) Stat(name string) (os.FileInfo, error) {
	if _, ok := f.files[name]; !ok {
		return nil, os.ErrNotExist
	}
	return fakeInfo{name: filepath.Base(name)}, nil
}

const (
	swapExe    = "/opt/observer/observer"
	swapStaged = "/state/v9.9.9/observer"
	swapPrev   = "/state/rollback/observer-v9.9.8"
)

func baseFiles() map[string]string {
	return map[string]string{
		swapExe:    "OLD",
		swapStaged: "NEW",
		swapPrev:   "OLD",
	}
}

// TestSwapStrategyIsChosenByFileSemantics pins the capability branch.
func TestSwapStrategyIsChosenByFileSemantics(t *testing.T) {
	for goos, want := range map[string]swapStrategy{
		"linux":   swapInPlace,
		"darwin":  swapInPlace,
		"freebsd": swapInPlace,
		"windows": swapRenameAside,
	} {
		if got := strategyForOS(goos); got != want {
			t.Errorf("strategyForOS(%q) = %q, want %q", goos, got, want)
		}
	}
}

// TestSwapBothStrategiesReplaceTheBinary is the happy path for each.
func TestSwapBothStrategiesReplaceTheBinary(t *testing.T) {
	for _, goos := range []string{"linux", "windows"} {
		t.Run(goos, func(t *testing.T) {
			fs := newFakeSwapFS(baseFiles())
			res, err := swapBinary(fs, goos, swapStaged, swapExe, swapPrev, "v9.9.8")
			if err != nil {
				t.Fatalf("swapBinary: %v", err)
			}
			if fs.files[swapExe] != "NEW" {
				t.Fatalf("%s holds %q, want NEW", swapExe, fs.files[swapExe])
			}
			if goos == "windows" {
				if res.AsideName == "" {
					t.Fatal("the rename-aside strategy reported no aside path")
				}
				if fs.files[res.AsideName] != "OLD" {
					t.Errorf("the previous executable is not at %s", res.AsideName)
				}
				if len(fs.renameLog) != 2 {
					t.Errorf("renames = %v, want exactly two", fs.renameLog)
				}
			} else if res.AsideName != "" {
				t.Errorf("the in-place strategy reported an aside path %q", res.AsideName)
			}
		})
	}
}

// TestSwapRefusesWithoutAStagedRollback is the fail-closed direction: an
// apply that cannot be undone is not an apply, it is a one-way replacement
// of the operator's daemon.
func TestSwapRefusesWithoutAStagedRollback(t *testing.T) {
	for _, tc := range []struct {
		name string
		prev string
		fs   *fakeSwapFS
	}{
		{"no rollback path recorded", "", newFakeSwapFS(baseFiles())},
		{"the recorded rollback binary is missing", swapPrev, newFakeSwapFS(map[string]string{
			swapExe: "OLD", swapStaged: "NEW",
		})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := swapBinary(tc.fs, "linux", swapStaged, swapExe, tc.prev, "v9.9.8")
			if err == nil {
				t.Fatal("the swap proceeded with no rollback available")
			}
			if tc.fs.files[swapExe] != "OLD" {
				t.Fatalf("%s was replaced by a refused swap", swapExe)
			}
		})
	}
}

// TestWindowsSwapRestoresAfterAnInterruptedSecondRename is the plan's named
// case: a failure BETWEEN the two renames must put the original back, and
// there must never be a moment where no executable exists at exePath.
func TestWindowsSwapRestoresAfterAnInterruptedSecondRename(t *testing.T) {
	fs := newFakeSwapFS(baseFiles())
	fs.failRename = 2 // the "move the new binary in" step
	_, err := swapBinary(fs, "windows", swapStaged, swapExe, swapPrev, "v9.9.8")
	if err == nil {
		t.Fatal("swapBinary reported success although the second rename failed")
	}
	if got := fs.files[swapExe]; got != "OLD" {
		t.Fatalf("%s holds %q, want the ORIGINAL restored", swapExe, got)
	}
	if _, still := fs.files[asidePath(swapExe, "v9.9.8")]; still {
		t.Error("the aside file was left behind after a successful restore")
	}
}

// TestWindowsSwapAbortsCleanlyWhenTheFirstRenameFails is the
// ERROR_ACCESS_DENIED case (an AV scanner, a second instance): nothing has
// moved, so nothing needs undoing.
func TestWindowsSwapAbortsCleanlyWhenTheFirstRenameFails(t *testing.T) {
	fs := newFakeSwapFS(baseFiles())
	fs.failRename = 1
	_, err := swapBinary(fs, "windows", swapStaged, swapExe, swapPrev, "v9.9.8")
	if err == nil {
		t.Fatal("swapBinary reported success although the first rename failed")
	}
	if !strings.Contains(err.Error(), "rename aside") {
		t.Errorf("error = %v, want it to name the failing step", err)
	}
	if fs.files[swapExe] != "OLD" {
		t.Fatal("the original executable did not stay in place")
	}
	if fs.files[swapStaged] != "NEW" {
		t.Error("the staged binary was consumed by an aborted swap")
	}
}

// TestRestoreBinaryPutsThePreviousBinaryBack covers both strategies.
func TestRestoreBinaryPutsThePreviousBinaryBack(t *testing.T) {
	for _, goos := range []string{"linux", "windows"} {
		t.Run(goos, func(t *testing.T) {
			fs := newFakeSwapFS(map[string]string{
				swapExe:  "NEW-AND-BROKEN",
				swapPrev: "OLD",
			})
			if err := restoreBinary(fs, goos, swapPrev, swapExe, "v9.9.8"); err != nil {
				t.Fatalf("restoreBinary: %v", err)
			}
			if got := fs.files[swapExe]; got != "OLD" {
				t.Fatalf("%s holds %q, want OLD", swapExe, got)
			}
		})
	}
}

// TestRestoreRefusesWhenThereIsNothingToRestore: saying so is better than
// silently leaving a broken binary in place and reporting rolled_back.
func TestRestoreRefusesWhenThereIsNothingToRestore(t *testing.T) {
	fs := newFakeSwapFS(map[string]string{swapExe: "NEW-AND-BROKEN"})
	if err := restoreBinary(fs, "linux", "", swapExe, "v9.9.8"); err == nil {
		t.Fatal("restoreBinary succeeded with no previous binary recorded")
	}
	if err := restoreBinary(fs, "linux", swapPrev, swapExe, "v9.9.8"); err == nil {
		t.Fatal("restoreBinary succeeded with a missing previous binary")
	}
}

// TestRecoverInterruptedSwap is the boot-time half of the two-rename
// invariant: an aside file with NO executable at exePath means the process
// was killed mid-swap, and the aside file is the only correct recovery.
func TestRecoverInterruptedSwap(t *testing.T) {
	aside := asidePath(swapExe, "v9.9.8")

	t.Run("killed between the renames", func(t *testing.T) {
		fs := newFakeSwapFS(map[string]string{aside: "OLD"})
		recovered, err := recoverInterruptedSwap(fs, swapExe, "v9.9.8")
		if err != nil {
			t.Fatalf("recoverInterruptedSwap: %v", err)
		}
		if !recovered {
			t.Fatal("the interrupted swap was not recovered")
		}
		if fs.files[swapExe] != "OLD" {
			t.Fatalf("%s holds %q, want the aside file restored", swapExe, fs.files[swapExe])
		}
	})

	t.Run("a completed swap leaves the aside file as retention only", func(t *testing.T) {
		fs := newFakeSwapFS(map[string]string{aside: "OLD", swapExe: "NEW"})
		recovered, err := recoverInterruptedSwap(fs, swapExe, "v9.9.8")
		if err != nil || recovered {
			t.Fatalf("recovered = %v err = %v, want no recovery when both files exist", recovered, err)
		}
		if fs.files[swapExe] != "NEW" {
			t.Error("a completed swap was undone")
		}
	})

	t.Run("nothing to do", func(t *testing.T) {
		fs := newFakeSwapFS(map[string]string{swapExe: "NEW"})
		if recovered, err := recoverInterruptedSwap(fs, swapExe, "v9.9.8"); recovered || err != nil {
			t.Fatalf("recovered = %v err = %v, want a no-op", recovered, err)
		}
	})
}

// TestPreserveExecutableProducesACompleteCopy: the rollback binary must be
// either absent or complete — a truncated one would pass a stat check and
// fail to execute.
func TestPreserveExecutableProducesACompleteCopy(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "observer")
	if err := os.WriteFile(src, []byte("BINARY-BYTES"), 0o755); err != nil { //nolint:gosec // a fake binary in a temp dir
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "rollback", "observer-v9.9.8")
	if err := preserveExecutable(src, dest); err != nil {
		t.Fatalf("preserveExecutable: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("no rollback binary at %s: %v", dest, err)
	}
	if string(got) != "BINARY-BYTES" {
		t.Fatalf("rollback binary holds %q", got)
	}
	// A second call must overwrite rather than fail, so a retried apply
	// re-stages cleanly.
	if err := preserveExecutable(src, dest); err != nil {
		t.Fatalf("preserveExecutable (second call): %v", err)
	}
	if _, err := os.Stat(dest + ".part"); err == nil {
		t.Error("a .part file was left behind")
	}
}

// TestAsidePathIsDeterministic: the recovery depends on being able to FIND
// the aside file at the next start, which a temp name would make impossible.
func TestAsidePathIsDeterministic(t *testing.T) {
	a := asidePath("/opt/observer/observer.exe", "v1.33.0")
	b := asidePath("/opt/observer/observer.exe", "v1.33.0")
	if a != b {
		t.Fatalf("asidePath is not deterministic: %q vs %q", a, b)
	}
	if !strings.HasSuffix(a, ".old-v1.33.0") {
		t.Fatalf("asidePath = %q, want a readable .old-<version> suffix", a)
	}
	if got := asidePath("/opt/observer/observer.exe", ""); !strings.HasSuffix(got, ".old-previous") {
		t.Fatalf("an empty version produced %q, want a usable fallback name", got)
	}
}
