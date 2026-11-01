//go:build linux && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// terminal_sandbox_oci_livefix_linux_test.go: the OCI residuals of the Linux
// live check on the one-off Azure VM (2026-10-23, P-097): R1, R2 and R3.

// TestOCIAfterRunRemovesTheProjection (R1): once the container has ended,
// the helper removes the run's projected state root (after the db-copy
// collection), while the daemon lives; a root that is a symlink is left
// alone and reported.
func TestOCIAfterRunRemovesTheProjection(t *testing.T) {
	managed := t.TempDir()
	root := filepath.Join(managed, "runid0000000000000001"+sandboxoci.ProjectionLeaf)
	proj, err := sandboxoci.PlanProjection(root, "/home/dev", []string{".claude", ".claude.json.d"})
	if err != nil {
		t.Fatal(err)
	}
	for _, pd := range proj {
		if err := os.MkdirAll(pd.Host, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pd.Host, "state.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tt := newOCITestTerm()
	ociAfterRun(ociPlanFile{Projections: proj, DBCopyDest: filepath.Join(t.TempDir(), "dbcopies", "run")}, tt.term)
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("the projected state root is still there after the run: %v", err)
	}
	if strings.Contains(tt.out.String(), "not removed") {
		t.Fatalf("a removal failure was reported: %q", tt.out.String())
	}

	// A root that is a symlink is never followed.
	target := t.TempDir()
	keep := filepath.Join(target, "keep")
	if err := os.WriteFile(keep, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(managed, "runid0000000000000002"+sandboxoci.ProjectionLeaf)
	if err := os.Symlink(target, linked); err != nil {
		t.Fatal(err)
	}
	lproj, _ := sandboxoci.PlanProjection(linked, "/home/dev", []string{".claude"})
	tt2 := newOCITestTerm()
	ociAfterRun(ociPlanFile{Projections: lproj}, tt2.term)
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("a symlinked root was followed: %v", err)
	}
	if !strings.Contains(tt2.out.String(), "not removed") {
		t.Fatalf("a symlinked root was not reported: %q", tt2.out.String())
	}
	// No projection (oci-runc): nothing to do, nothing said.
	tt3 := newOCITestTerm()
	ociAfterRun(ociPlanFile{}, tt3.term)
	if tt3.out.String() != "" {
		t.Fatalf("a run with no projection printed %q", tt3.out.String())
	}
}

// TestOCIStartSweepEndsAKilledCLIRun (R2): a run whose helper and CLI were
// killed while the daemon was down is handed to the daemon's run ender by
// the daemon-start sweep (which ends a CLI run's row with process_gone,
// TestRelayGoneRunEndEndsOnlyAKilledCLIRun), never pruned unseen. Before the
// ender exists the sweep keeps the record, so the row cannot be stranded;
// the sweep waits for the ender the relay sets.
func TestOCIStartSweepEndsAKilledCLIRun(t *testing.T) {
	obs := t.TempDir()
	run := "killedrun0000002"
	writeTestRunRecord(t, obs, run)
	// SIGKILL while the daemon was down: the lock file stays, held by nobody.
	if err := os.WriteFile(filepath.Join(sandboxrelayd.RunsDir(obs), run+".alive"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	prevWait := ociStartSweepEnderWait
	t.Cleanup(func() { ociStartSweepEnderWait = prevWait })
	prev := relayGoneRunEnder.Swap(nil)
	t.Cleanup(func() { relayGoneRunEnder.Store(prev) })

	// No ender (the relay not started yet, and it never starts in time).
	ociStartSweepEnderWait = 100 * time.Millisecond
	ociSweepRunStateAtStart(&sandboxRuntime{observerDir: obs})
	if _, err := sandboxrelayd.ReadRun(obs, run); err != nil {
		t.Fatalf("the record was pruned before the run ender existed, so its row would stay running: %v", err)
	}

	// The relay sets the ender while the sweep waits.
	var mu sync.Mutex
	var ended []string
	ender := func(rec sandboxrelayd.RunRecord) { mu.Lock(); ended = append(ended, rec.RunID); mu.Unlock() }
	ociStartSweepEnderWait = 10 * time.Second
	go func() {
		time.Sleep(150 * time.Millisecond)
		relayGoneRunEnder.Store(&ender)
	}()
	ociSweepRunStateAtStart(&sandboxRuntime{observerDir: obs})
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(ended, ",") != run {
		t.Fatalf("the run ender saw %v, want %s", ended, run)
	}
	if _, err := sandboxrelayd.ReadRun(obs, run); err == nil {
		t.Fatal("the dead helper's record was kept after the run was ended")
	}
}

// TestOCIBoxEnvCarriesTheTierFromTheHelper (R3): on the OCI rows the box's
// environment carries the tier the container host helper's own network
// flags name, from the one tier table, replacing an inherited (stale or
// spoofed) value; the launcher in the box then says the tier's own route,
// so the none tier never claims traffic goes straight to Anthropic.
func TestOCIBoxEnvCarriesTheTierFromTheHelper(t *testing.T) {
	for _, tier := range []sandbox.Egress{sandbox.EgressInternet, sandbox.EgressProxyOnly, sandbox.EgressNone} {
		host, err := sandbox.RelayHostArgv("/usr/local/bin/observer", sandbox.NetRequest{
			Egress: tier, ProxyPort: 8820, HostSocketDir: "/tmp/observer-sbx-run1",
		}, nil, sandbox.RelayRequest{RunID: "AbCdEfGhIjKlMnOpQrStUv", HostObserverDir: "/home/dev/.observer"})
		if err != nil {
			t.Fatal(err)
		}
		// The OCI wrap: sandbox-oci-host --plan <f> -- <host services> <marker> <inner>.
		args := append(append([]string{"--plan", "/p.json", "--"}, host...), ociInnerMarker, "/usr/local/bin/observer", "claude")
		_, h, err := parseOCIHostArgs(args)
		if err != nil {
			t.Fatalf("tier %s: %v", tier, err)
		}
		env := withSandboxTier(ociContainerEnv([]string{"PATH=/usr/bin", sandbox.EnvEgress + "=host"}), h)
		var got []string
		for _, kv := range env {
			if v, ok := strings.CutPrefix(kv, sandbox.EnvEgress+"="); ok {
				got = append(got, v)
			}
		}
		if len(got) != 1 || got[0] != string(tier) {
			t.Errorf("tier %s: the box's tier values are %v", tier, got)
		}
	}
	t.Setenv(sandboxEnvMarker, "1")
	t.Setenv(sandbox.EnvEgress, string(sandbox.EgressNone))
	if got := sandboxTierRouteNotice("claude", "http://127.0.0.1:8820"); got == "" || strings.Contains(got, "straight to Anthropic") {
		t.Fatalf("the in-box notice under none: %q", got)
	}
}

// TestOCIEnterRawDropsTheCanonicalEOF (R3, the stray NUL): an end of file
// the launch's terminal received while still canonical (the typescript's
// Ctrl-D when its input ended) waits as the line discipline's NUL marker.
// Set raw with TCSETS (term.MakeRaw) that marker is read as a NUL byte,
// which the helper sent to the box and the box's terminal echoed as "^@";
// ociEnterRaw discards it, and a keystroke typed after the switch (a real
// Ctrl-@ included) still passes as itself.
func TestOCIEnterRawDropsTheCanonicalEOF(t *testing.T) {
	pending := func(t *testing.T, fd int) []byte {
		t.Helper()
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}} //nolint:gosec // G115: a small descriptor number
		n, err := unix.Poll(fds, 300)
		if err != nil || n == 0 {
			return nil
		}
		buf := make([]byte, 64)
		m, err := unix.Read(fd, buf)
		if err != nil || m <= 0 {
			return nil
		}
		return buf[:m]
	}
	open := func(t *testing.T) (*os.File, int) {
		t.Helper()
		master, slave, err := pty.Open()
		if err != nil {
			t.Skipf("no pty: %v", err)
		}
		t.Cleanup(func() { _ = master.Close(); _ = slave.Close() })
		fd := int(slave.Fd()) //nolint:gosec // G115: a small descriptor number
		if _, err := master.Write([]byte{4}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
		return master, fd
	}

	// The mechanism, with the old raw entry.
	_, fd := open(t)
	st, err := term.MakeRaw(fd)
	if err != nil {
		t.Fatal(err)
	}
	if got := pending(t, fd); string(got) != "\x00" {
		t.Fatalf("TCSETS raw entry: the canonical end of file reads as %q, want one NUL", got)
	}
	_ = term.Restore(fd, st)

	// The fix.
	master, fd := open(t)
	restore, err := ociEnterRaw(fd)
	if err != nil {
		t.Fatal(err)
	}
	defer restore()
	if got := pending(t, fd); len(got) != 0 {
		t.Fatalf("ociEnterRaw left %q pending, which the box would echo", got)
	}
	if _, err := master.Write([]byte{0, 'a'}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if got := pending(t, fd); string(got) != "\x00a" {
		t.Fatalf("a keystroke after the switch reads as %q", got)
	}
	tio, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil || tio.Lflag&(unix.ICANON|unix.ECHO|unix.ISIG) != 0 || tio.Cc[unix.VMIN] != 1 {
		t.Fatalf("not raw: %+v %v", tio, err)
	}
	restore()
	if tio, _ := unix.IoctlGetTermios(fd, unix.TCGETS); tio.Lflag&unix.ICANON == 0 {
		t.Fatal("the restore did not bring canonical mode back")
	}
}

// TestOCIRunRemovesAFailedCreateByName (Podman on runc, the first create):
// a create whose answer failed may still have made the container, so the
// helper removes the run's container by its name before it reports.
func TestOCIRunRemovesAFailedCreateByName(t *testing.T) {
	f := newOCIFake(t)
	f.createFails = true
	tt := newOCITestTerm()
	code := driveOCIRun(context.Background(), ociRunPlan(t, f), []string{"/usr/bin/observer", "claude"}, nil, tt.term)
	if code != sandboxHelperFailCode || !strings.Contains(tt.out.String(), "create the container") {
		t.Fatalf("code %d out %q", code, tt.out.String())
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.removed) != 1 || !strings.HasPrefix(f.removed[0], "observer-sbx-") {
		t.Fatalf("the failed create's container was not removed by name: %v", f.removed)
	}
}
