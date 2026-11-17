//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// liveWindowsDrives lists the Windows drives this host has mounted by an
// oracle independent of the code under test: a plain scan of /proc/mounts for
// a drvfs filesystem or a 9p mount with aname=drvfs. (A test that asked
// foreignMountRoots which drives exist would skip, not fail, if that function
// regressed to find none.)
func liveWindowsDrives(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile("/proc/mounts")
	if err != nil {
		t.Skipf("cannot read /proc/mounts: %v", err)
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && (f[2] == "drvfs" || (f[2] == "9p" && strings.Contains(f[3], "aname=drvfs"))) {
			out = append(out, f[1])
		}
	}
	return out
}

// drvfsScratch makes a scratch directory on a Windows drive of this host,
// trying each drive in turn, and returns it with the roots every box must
// hide. foreignMountRoots must name every drive the independent scan finds.
// It skips when the host has no writable Windows drive (anything that is not
// WSL2 with a mounted drive).
func drvfsScratch(t *testing.T) (scratch string, roots []string) {
	t.Helper()
	drives := liveWindowsDrives(t)
	if len(drives) == 0 {
		t.Skip("this host has no foreign-OS drive mounted (not WSL2 with a Windows drive)")
	}
	found, err := foreignMountRoots()
	if err != nil {
		t.Fatalf("foreignMountRoots on the live host: %v", err)
	}
	for _, d := range drives {
		if !slices.Contains(found, d) {
			t.Errorf("foreignMountRoots %v misses the mounted drive %s", found, d)
		}
	}
	roots = drives
	for _, r := range roots {
		d, err := os.MkdirTemp(r, "sbo-drive-mask-")
		if err != nil {
			continue
		}
		t.Cleanup(func() { _ = os.RemoveAll(d) })
		return d, roots
	}
	t.Skipf("no writable directory on any of %v", roots)
	return "", nil
}

// prepLiveWrapArgvAt is prepLiveWrapArgvCfg for a caller-chosen home,
// workspace and observer dir (the helper there always makes them under the
// temp dir): a real sandboxRuntime, Prepare for a live workspace, and the
// composed WrapArgv.
func prepLiveWrapArgvAt(t *testing.T, home, workspace, observerDir string) []string {
	t.Helper()
	t.Setenv("HOME", home)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	rt, err := newSandboxRuntime(config.TerminalSandboxConfig{Enabled: true, HomeMode: "tmpfs", Egress: "host"}, nil, observerDir, exe, nil)
	if err != nil {
		t.Fatalf("newSandboxRuntime: %v", err)
	}
	res, err := rt.Prepare(context.Background(), termsvc.PrepareRequest{Tool: "claude-code", ProjectRoot: workspace, WorkspaceSource: "live"})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if len(res.WrapArgv) < 3 || res.WrapArgv[len(res.WrapArgv)-1] != "--" {
		t.Fatalf("WrapArgv %v", res.WrapArgv)
	}
	return res.WrapArgv
}

// TestBwrapHidesEveryWindowsDriveLive is the live regression for ledger
// SBX-BE-24, run with a real bwrap on a WSL2 host: a sandbox box must not
// see the Windows drives' contents, whether or not a foreign AI-tool home
// sits on the drive (the box runs under a scratch HOME, where crossmount
// detects none, which is the shape that left every drive readable), while a
// workspace that lives on a drive stays bound read-write and a home on a
// drive still gets its private tmpfs.
func TestBwrapHidesEveryWindowsDriveLive(t *testing.T) {
	bwrapPath := bwrapUsableForTest(t)
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH")
	}
	scratch, roots := drvfsScratch(t)

	// A secret next to the workspace on the same drive, and the workspace.
	outside := filepath.Join(scratch, "outside", "secret.txt")
	ws := filepath.Join(scratch, "ws", "proj")
	for _, d := range []string{filepath.Dir(outside), ws} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Skipf("cannot prepare the drive scratch: %v", err)
		}
	}
	if err := os.WriteFile(outside, []byte("DRIVE-SECRET"), 0o600); err != nil {
		t.Skipf("cannot write to the drive scratch: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ws, "inside.txt"), []byte("INSIDE"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Control: with no mask a plain read-only root bind shows the secret, so
	// the assertions below are not vacuous (and the host can read its drive).
	ctl, err := exec.Command(bwrapPath, "--ro-bind", "/", "/", "--tmpfs", "/tmp", "--die-with-parent", "--", "cat", outside).CombinedOutput() //nolint:gosec // fixed argv; the path is this test's own scratch
	if err != nil || strings.TrimSpace(string(ctl)) != "DRIVE-SECRET" {
		t.Skipf("control: a plain bwrap root bind cannot read %s (%v: %s)", outside, err, ctl)
	}

	// What the box may show of each drive: only the path components that lead
	// to the workspace's own bind.
	var allowed []string
	for _, r := range roots {
		if rel, err := filepath.Rel(r, ws); err == nil && !strings.HasPrefix(rel, "..") {
			allowed = append(allowed, r+"="+strings.SplitN(rel, string(filepath.Separator), 2)[0])
		}
	}
	script := fmt.Sprintf(`
fail() { echo "FAIL: $*"; exit 1; }
[ ! -e %[1]q ] || fail "the secret next to the workspace is visible"
[ "$(cat %[2]q/inside.txt)" = INSIDE ] || fail "the workspace on the drive is not readable"
touch %[2]q/written || fail "the workspace on the drive is not writable"
[ -d "$HOME" ] && touch "$HOME/probe" || fail "the home is not a usable directory"
[ ! -e "$HOME/.ssh/secret" ] || fail "the real home's credential is visible"
for spec in %[3]s; do
  root=${spec%%=*}; ok=${spec#*=}
  for e in $(ls -A "$root" 2>/dev/null); do
    [ "$e" = "$ok" ] || fail "$root shows $e"
  done
done
echo MASKS_OK
`, outside, ws, shellWords(append(append([]string(nil), allowed...), emptyEntries(roots, allowed)...)))

	run := func(t *testing.T, home, observerDir string) {
		t.Helper()
		wrap := prepLiveWrapArgvAt(t, home, ws, observerDir)
		argv := append(append([]string(nil), wrap...), "bash", "-c", script)
		cmd := exec.Command(argv[0], argv[1:]...) //nolint:gosec // argv[0] is the Prepare-resolved helper or bwrap path; the rest is this test's fixed script
		cmd.Env = append(os.Environ(), "HOME="+home)
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "MASKS_OK") {
			t.Fatalf("the box shows a drive (or cannot use the workspace): %v\n%s", err, out)
		}
	}

	t.Run("scratch home on the Linux filesystem", func(t *testing.T) {
		run(t, t.TempDir(), t.TempDir())
	})
	t.Run("home on the masked drive", func(t *testing.T) {
		home := filepath.Join(scratch, "home")
		if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
			t.Skipf("cannot prepare a home on the drive: %v", err)
		}
		if err := os.WriteFile(filepath.Join(home, ".ssh", "secret"), []byte("HOME-SECRET"), 0o600); err != nil {
			t.Skipf("cannot prepare a home on the drive: %v", err)
		}
		// The observer directory stays on the Linux filesystem: the capture
		// relay refuses a run record that is not a private regular file, which
		// a Windows drive's mount cannot hold (unrelated to the masks).
		run(t, home, t.TempDir())
	})
}

// shellWords joins values into one shell-quoted word list.
func shellWords(vals []string) string {
	q := make([]string, len(vals))
	for i, v := range vals {
		q[i] = fmt.Sprintf("%q", v)
	}
	return strings.Join(q, " ")
}

// emptyEntries returns "root=" specs for the roots that lead nowhere to the
// workspace: nothing at all may be listed under them.
func emptyEntries(roots, allowed []string) []string {
	var out []string
	for _, r := range roots {
		held := false
		for _, a := range allowed {
			held = held || strings.HasPrefix(a, r+"=")
		}
		if !held {
			out = append(out, r+"=")
		}
	}
	return out
}
