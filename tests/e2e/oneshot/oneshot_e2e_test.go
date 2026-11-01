// Package e2e exercises the npx one-shot `observer usage` report end to
// end through the REAL compiled CLI binary, spawned as a genuine
// subprocess with a fully scratch/fake $HOME — proving the zero-side-
// effect promise (docs/plans/npx-one-shot-report-plan-2026-07-30.md
// §2.4, §4) holds through main() and a real os.Signal, not just through
// the usageDeps-injected in-process unit tests in
// cmd/observer/usage_test.go.
//
// Machine-dependent caveat (grounded empirically 2026-07-30, WSL2 dev
// host): internal/adapter/claudecode's adapter calls
// internal/platform/crossmount.AllHomes(), which on a WSL2 host also
// enumerates every /mnt/c/Users/<u>/.claude/projects tree it finds —
// INDEPENDENT of the spawned process's $HOME. Since 2026-10-02
// buildScratchEnv sets crossmount.EnvDisableForeignHomes, so the child no
// longer sees that real corpus; the assertions stay deliberately
// INCLUSIVE ("the fixture's row is present", "the tree we planted is
// unchanged") rather than EXCLUSIVE ("the table has exactly N rows") so
// they do not depend on that knob.
package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// fixtureRelPath is the canonical claude-code fixture, relative to the
// repo root (mirrors cmd/observer/usage_test.go::seedClaudeCode).
const fixtureRelPath = "testdata/claudecode/simple-session.jsonl"

// oneShotDaemonPorts are the two sockets a running daemon (proxy +
// dashboard) would bind. The one-shot report must never bind either —
// see docs/plans/npx-one-shot-report-plan-2026-07-30.md §2.4.
var oneShotDaemonPorts = []int{8820, 8081}

// observerBinEnv names an already-built observer binary to use instead of
// building one. Unset, the suite builds ./cmd/observer once per test binary.
const observerBinEnv = "SBO_E2E_OBSERVER_BIN"

var (
	buildOnce sync.Once
	buildErr  error
	binPath   string
	binNote   string // set when SBO_E2E_OBSERVER_BIN supplied the binary
)

// binaryPath builds the real observer CLI once per test-binary run (or
// reuses the binary named by SBO_E2E_OBSERVER_BIN when that is set), into
// a private os.MkdirTemp location outside the repo (never the repo's own
// gitignored bin/, so this suite never races a developer's `make
// build`). No existing tests/e2e/* suite in this repo spawns the real
// binary (tests/e2e/orgserver drives an in-process httptest handler
// instead), so this helper establishes that pattern for the one-shot
// report, which — unlike every other subcommand — must be provable
// through a real, unmodified main() and a real OS signal.
func binaryPath(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		// Full tier only: every caller spawns the real binary.
		t.Skip("spawns the built observer binary (full tier)")
	}
	buildOnce.Do(func() {
		if prebuilt := os.Getenv(observerBinEnv); prebuilt != "" {
			// A job that already built observer passes its path, so the
			// suites share one build instead of each running go build.
			fi, err := os.Stat(prebuilt)
			if err != nil {
				buildErr = fmt.Errorf("%s=%q: %w", observerBinEnv, prebuilt, err)
				return
			}
			// Freshness is the caller's job; say which binary ran so a
			// stale one is visible in the log.
			binNote = fmt.Sprintf("using prebuilt %s=%s (modified %s)", observerBinEnv, prebuilt, fi.ModTime().Format(time.RFC3339))
			binPath = prebuilt
			return
		}
		dir, err := os.MkdirTemp("", "oneshot-e2e-bin-*")
		if err != nil {
			buildErr = fmt.Errorf("mkdir temp build dir: %w", err)
			return
		}
		name := "observer"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		out := filepath.Join(dir, name)
		root, err := repoRootDir()
		if err != nil {
			buildErr = err
			return
		}
		cmd := exec.Command("go", "build", "-o", out, "./cmd/observer")
		cmd.Dir = root
		combined, err := cmd.CombinedOutput()
		if err != nil {
			buildErr = fmt.Errorf("go build ./cmd/observer: %w\n%s", err, combined)
			return
		}
		binPath = out
	})
	if buildErr != nil {
		t.Fatalf("build observer binary: %v", buildErr)
	}
	if binNote != "" {
		t.Log(binNote)
	}
	return binPath
}

// repoRootDir resolves the module root from this test file's own
// directory (tests/e2e/oneshot -> three levels up), so it works
// regardless of the working directory `go test` happens to be invoked
// from.
func repoRootDir() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getwd: %w", err)
	}
	root, err := filepath.Abs(filepath.Join(wd, "..", "..", ".."))
	if err != nil {
		return "", fmt.Errorf("abs repo root: %w", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return "", fmt.Errorf("resolved repo root %s has no go.mod: %w", root, err)
	}
	return root, nil
}

// seedClaudeCode copies testdata/claudecode/simple-session.jsonl into
// home/.claude/projects/<fixture-N>/sess-001.jsonl, n times, each under
// its own project directory. Mirrors cmd/observer/usage_test.go's
// seedClaudeCode layout and its "shift the fixture's date to yesterday"
// approach (so the default 30-day window always includes it), extended
// to support n>1 copies for the SIGINT stress test below.
func seedClaudeCode(t *testing.T, home string, n int) {
	t.Helper()
	root, err := repoRootDir()
	if err != nil {
		t.Fatalf("repoRootDir: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(root, fixtureRelPath))
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixtureRelPath, err)
	}
	recent := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")
	body := strings.ReplaceAll(string(raw), "2026-04-16", recent)

	projects := filepath.Join(home, ".claude", "projects")
	for i := 0; i < n; i++ {
		dir := filepath.Join(projects, fmt.Sprintf("-tmp-superbased-fixture-simple-%d", i))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir fixture project dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "sess-001.jsonl"), []byte(body), 0o600); err != nil {
			t.Fatalf("write fixture session file: %v", err)
		}
	}
}

// hashTree walks root and returns a relative-path -> sha256(content) map
// for every regular file, plus a "<dir>/" sentinel entry (empty hash) for
// every directory, skipping the subtree rooted at exclude (typically
// $scratch/tmp, the CLI's own permitted scratch space). Comparing two
// snapshots this way catches content changes, added files, removed
// files, and added/removed directories alike, without being sensitive to
// mtime/atime noise from merely reading the tree.
func hashTree(t *testing.T, root, exclude string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		if exclude != "" && (path == exclude || strings.HasPrefix(path, exclude+string(filepath.Separator))) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		if d.IsDir() {
			out[rel+"/"] = ""
			return nil
		}
		f, oerr := os.Open(path)
		if oerr != nil {
			return oerr
		}
		defer f.Close()
		h := sha256.New()
		if _, cerr := io.Copy(h, f); cerr != nil {
			return cerr
		}
		out[rel] = hex.EncodeToString(h.Sum(nil))
		return nil
	})
	if err != nil {
		t.Fatalf("hashTree(%s): %v", root, err)
	}
	return out
}

// assertTreeUnchanged fails the test with every discrepancy between two
// hashTree snapshots of the same root (added, removed, or modified
// entries) — the "$scratch tree excluding tmp/ is byte-identical
// before/after" check from the plan.
func assertTreeUnchanged(t *testing.T, before, after map[string]string) {
	t.Helper()
	for path, sum := range before {
		got, ok := after[path]
		if !ok {
			t.Errorf("scratch tree entry %q disappeared during the run", path)
			continue
		}
		if got != sum {
			t.Errorf("scratch tree entry %q changed content during the run", path)
		}
	}
	for path := range after {
		if _, ok := before[path]; !ok {
			t.Errorf("scratch tree gained a new entry %q during the run (outside tmp/) — the one-shot must have no side effects on $HOME", path)
		}
	}
}

// assertNoObserverHome fails if $home/.observer exists — the one-shot
// must never create or touch the daemon's state directory.
func assertNoObserverHome(t *testing.T, home string) {
	t.Helper()
	_, err := os.Stat(filepath.Join(home, ".observer"))
	switch {
	case err == nil:
		t.Errorf("%s/.observer was created — the one-shot must never touch the daemon's state dir", home)
	case errors.Is(err, os.ErrNotExist):
		// expected
	default:
		t.Fatalf("stat %s/.observer: %v", home, err)
	}
}

// assertNoStaleScratchDirs fails if $tmpdir still contains an
// observer-usage-* directory (the scratch-DB temp dir the CLI is
// documented to create-then-remove around every run).
func assertNoStaleScratchDirs(t *testing.T, tmpdir string) {
	t.Helper()
	entries, err := os.ReadDir(tmpdir)
	if err != nil {
		t.Fatalf("read tmpdir %s: %v", tmpdir, err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "observer-usage-") {
			t.Errorf("%s still contains %s — the scratch DB dir was not cleaned up", tmpdir, e.Name())
		}
	}
}

// listeningPorts returns the set of TCP ports in LISTEN state on this
// host, parsed from /proc/net/tcp and /proc/net/tcp6 (Linux-only). The
// second return value is false when neither file was readable, so
// callers can skip the assertion gracefully rather than fail on a
// platform/sandbox where the probe itself isn't available.
func listeningPorts(t *testing.T) (map[int]bool, bool) {
	t.Helper()
	ports := map[int]bool{}
	available := false
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		available = true
		lines := strings.Split(string(data), "\n")
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			const tcpListen = "0A"
			if fields[3] != tcpListen {
				continue
			}
			parts := strings.Split(fields[1], ":")
			if len(parts) != 2 {
				continue
			}
			portNum, perr := strconv.ParseInt(parts[1], 16, 32)
			if perr != nil {
				continue
			}
			ports[int(portNum)] = true
		}
	}
	return ports, available
}

// assertNoNewListener fails if any of oneShotDaemonPorts is present in
// `after` but absent from `before` — i.e. something started listening on
// a daemon port during the window between the two snapshots. Ports that
// were already listening before the run (a real daemon happens to be up
// on this dev box) are deliberately ignored: the assertion is "the
// one-shot bound nothing new", not "nothing else on this machine ever
// listens on 8820/8081".
func assertNoNewListener(t *testing.T, before, after map[int]bool, label string) {
	t.Helper()
	for _, port := range oneShotDaemonPorts {
		if !before[port] && after[port] {
			t.Errorf("port %d newly appeared as LISTEN %s — the one-shot must never bind a socket", port, label)
		}
	}
}

// buildScratchEnv returns a minimal, fully-replaced environment for the
// spawned subprocess: HOME=home, TMPDIR=home/tmp, PATH inherited (needed
// to resolve the dynamic loader / any shell-outs), and every other
// variable — including all XDG_* dirs — unset by omission.
// EnvDisableForeignHomes keeps the child off the real /mnt/c/Users mount,
// which $HOME does not control (incident 2026-10-02).
func buildScratchEnv(home, tmpdir string) []string {
	return []string{
		"HOME=" + home,
		"TMPDIR=" + tmpdir,
		"PATH=" + os.Getenv("PATH"),
		crossmount.EnvDisableForeignHomes + "=1",
		// The built binary uses the in-memory keyring, never the
		// developer's OS keychain (WINFIX2 audit finding 10).
		keystore.EnvTestKeystore + "=" + keystore.TestKeystoreMemory,
	}
}

// TestOneShotUsageE2E_HappyPath runs the real compiled binary against a
// scratch $HOME seeded with exactly one fixture session, and checks
// every zero-side-effect guarantee from plan §2.4/§4 through actual
// process boundaries: exit code, stdout content, tree hash before/after,
// scratch-tmp cleanliness, and (best-effort) that no daemon port ever
// appears.
func TestOneShotUsageE2E_HappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns `go build` + the real binary; skipped under -short")
	}
	t.Parallel()
	bin := binaryPath(t)

	home := t.TempDir()
	tmpdir := filepath.Join(home, "tmp")
	if err := os.MkdirAll(tmpdir, 0o755); err != nil {
		t.Fatalf("mkdir scratch tmp: %v", err)
	}
	seedClaudeCode(t, home, 1)

	portsBefore, portsAvailable := listeningPorts(t)
	before := hashTree(t, home, tmpdir)

	cmd := exec.Command(bin, "usage", "--no-progress", "--budget", "20s")
	cmd.Dir = home
	cmd.Env = buildScratchEnv(home, tmpdir)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	var portsDuring map[int]bool
	var duringOK bool
	sampled := make(chan struct{})
	go func() {
		defer close(sampled)
		time.Sleep(150 * time.Millisecond)
		portsDuring, duringOK = listeningPorts(t)
	}()

	runErr := cmd.Run()
	<-sampled

	if runErr != nil {
		t.Fatalf("observer usage exited with error: %v\n--- stdout ---\n%s\n--- stderr ---\n%s",
			runErr, stdout.String(), stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "claude-code") {
		t.Errorf("stdout missing a claude-code row:\n%s", out)
	}
	if !strings.Contains(out, "estimated list price, not invoiced") {
		t.Errorf("stdout missing the honesty disclaimer (\"estimated list price, not invoiced\"):\n%s", out)
	}

	after := hashTree(t, home, tmpdir)
	assertTreeUnchanged(t, before, after)
	assertNoObserverHome(t, home)
	assertNoStaleScratchDirs(t, tmpdir)

	if portsAvailable {
		assertNoNewListener(t, portsBefore, portsBefore, "at start (sanity)")
		if duringOK {
			assertNoNewListener(t, portsBefore, portsDuring, "mid-run")
		}
		if portsAfter, ok := listeningPorts(t); ok {
			assertNoNewListener(t, portsBefore, portsAfter, "after exit")
		}
	} else {
		t.Log("/proc/net/tcp{,6} unavailable on this host; skipping the no-new-listener assertion (best-effort per plan §4)")
	}
}

// TestOneShotUsageE2E_SIGINTCleansUpScratchDir starts the real binary
// against a scratch $HOME seeded with a large duplicated fixture set and
// an unlimited (--budget 0) wall-clock budget — guaranteeing the scan is
// still in flight well past the 300ms mark regardless of what else this
// host's adapters happen to discover (see the package doc's WSL2
// crossmount caveat) — sends a genuine SIGINT, and asserts the scratch
// observer-usage-* temp dir is removed within a grace window.
//
// Grounded empirically 2026-07-30: with 200 duplicated fixture copies
// and --budget 0, the process was still running at the 300ms mark and
// exited non-zero (interrupted) within ~500ms of SIGINT, with the
// scratch tmp dir already empty by the time Wait() returned. This test
// uses a larger multiple (fixtureCopiesForSIGINT) for margin on faster
// hardware / CI runners without this box's cross-mount corpus.
func TestOneShotUsageE2E_SIGINTCleansUpScratchDir(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns `go build` + the real binary; skipped under -short")
	}
	if runtime.GOOS == "windows" {
		t.Skip("SIGINT semantics differ on windows; this path is exercised on unix CI")
	}
	t.Parallel()
	bin := binaryPath(t)

	home := t.TempDir()
	tmpdir := filepath.Join(home, "tmp")
	if err := os.MkdirAll(tmpdir, 0o755); err != nil {
		t.Fatalf("mkdir scratch tmp: %v", err)
	}
	const fixtureCopiesForSIGINT = 300
	seedClaudeCode(t, home, fixtureCopiesForSIGINT)

	cmd := exec.Command(bin, "usage", "--no-progress", "--budget", "0")
	cmd.Dir = home
	cmd.Env = buildScratchEnv(home, tmpdir)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start observer usage: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})

	time.Sleep(300 * time.Millisecond)

	// Confirm it is still running before we credit the SIGINT with
	// having interrupted anything — a process that already exited on
	// its own would make the rest of this test vacuous.
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("process already exited before SIGINT was sent (fixture set finished too fast for this margin): %v\n--- stdout ---\n%s\n--- stderr ---\n%s",
			err, stdout.String(), stderr.String())
	}

	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatalf("send SIGINT: %v", err)
	}

	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()

	select {
	case err := <-waitErr:
		if err == nil {
			t.Fatalf("observer usage exited 0 after SIGINT (expected a non-zero interrupted exit)\n--- stdout ---\n%s\n--- stderr ---\n%s",
				stdout.String(), stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("observer usage did not exit within 10s of SIGINT")
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		entries, err := os.ReadDir(tmpdir)
		if err != nil {
			t.Fatalf("read tmpdir %s: %v", tmpdir, err)
		}
		var stale []string
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "observer-usage-") {
				stale = append(stale, e.Name())
			}
		}
		if len(stale) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("observer-usage-* scratch dir(s) %v still present %s after SIGINT (grace window exceeded)",
				stale, 5*time.Second)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
