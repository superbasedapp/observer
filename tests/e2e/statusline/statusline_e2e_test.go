// Package e2e exercises `observer statusline` and the `observer init
// --statusline` / `observer start` registration surfaces end to end
// through the REAL compiled CLI binary, spawned as a genuine
// subprocess with a fully scratch/fake $HOME — proving the WP1-WP4
// invariants from docs/plans/observer-statusline-plan-2026-07-30.md
// (§5, §7, §10 WP5 AC) hold through main() and real process
// boundaries, not just the in-process unit tests.
//
// Model: tests/e2e/oneshot/oneshot_e2e_test.go (build-once binary,
// buildScratchEnv, listeningPorts/assertNoNewListener). This is a
// SEPARATE package instance (its own `go test` binary per directory),
// so identically-named helpers here do not collide with oneshot's.
package e2e

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

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
// reuses the binary named by SBO_E2E_OBSERVER_BIN when that is set),
// into a private os.MkdirTemp location outside the repo (mirrors
// tests/e2e/oneshot's binaryPath).
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
		dir, err := os.MkdirTemp("", "statusline-e2e-bin-*")
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
// directory (tests/e2e/statusline -> three levels up).
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

// buildScratchEnv returns a minimal, fully-replaced environment for the
// spawned subprocess: HOME=home, TMPDIR=home/tmp, PATH inherited. Every
// other variable (including every XDG_* dir, and crucially NO_COLOR) is
// unset by omission — the registration/statusline paths under test all
// resolve their state through $HOME alone (grounded by reading
// hook.NewRegistry, cmd/observer/init.go, cmd/observer/start.go, and
// cmd/observer/statusline.go's defaultStatuslineDeps — none of them set
// hook.Options.HomeDir explicitly, so all fall back to
// os.UserHomeDir()).
//
// $HOME alone does NOT isolate the cross-OS targets: `observer start`'s
// autoRegisterHooks resolves "claude-code-windows" through crossmount's fixed
// /mnt/c/Users root, so on a WSL2 dev host the child would rewrite the
// operator's REAL Windows-side ~/.claude/settings.json (incident 2026-10-02).
// The spawned binary is not a test binary, so crossmount's in-process guard
// does not cover it; EnvDisableForeignHomes is what does.
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

// newScratchHome creates home/tmp beneath a fresh t.TempDir() and
// returns (home, tmpdir).
func newScratchHome(t *testing.T) (string, string) {
	t.Helper()
	home := t.TempDir()
	tmpdir := filepath.Join(home, "tmp")
	if err := os.MkdirAll(tmpdir, 0o755); err != nil {
		t.Fatalf("mkdir scratch tmp: %v", err)
	}
	return home, tmpdir
}

// runObserver spawns bin with args against a scratch env, waits for it
// to exit (bounded by the process's own behavior — every invocation in
// this suite is a genuine one-shot command, never the long-running
// daemon, which gets its own helper below), and returns stdout, stderr,
// and the process exit code (0 on a nil error from cmd.Run wrapped in
// *exec.ExitError, matching cobra/main.go's os.Exit(exitCode) contract).
func runObserver(t *testing.T, bin, home, tmpdir string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = home
	cmd.Env = buildScratchEnv(home, tmpdir)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	runErr := cmd.Run()
	code := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			code = exitErr.ExitCode()
		} else {
			t.Fatalf("observer %v failed to run at all (not just a non-zero exit): %v\n--- stdout ---\n%s\n--- stderr ---\n%s",
				args, runErr, outBuf.String(), errBuf.String())
		}
	}
	return outBuf.String(), errBuf.String(), code
}

// freePort dynamically allocates a free TCP port on 127.0.0.1 by
// binding then immediately closing a listener. This is the standard
// (small, generally-accepted TOCTOU risk) Go idiom for handing an
// ephemeral port to a subprocess started moments later — used here so
// the critical `observer start` e2e test below never collides with the
// real daemon's 8820, nor with a concurrently-running test's own
// dynamically-chosen port, and so this suite never hardcodes a port a
// developer's real daemon might already hold.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// writeClaudeSettings seeds home/.claude/settings.json with the given
// top-level key/value map, JSON-marshaled per key so callers can pass
// arbitrary raw shapes (mirrors the map[string]json.RawMessage shape
// hook/register.go itself reads/writes).
func writeClaudeSettings(t *testing.T, home string, settings map[string]any) string {
	t.Helper()
	dir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	path := filepath.Join(dir, "settings.json")
	raw, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		t.Fatalf("marshal seed settings: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// readClaudeSettings reads and JSON-unmarshals home/.claude/settings.json
// into a map. Fails the test if the file is missing or malformed (every
// test that calls this expects the file to exist at that point).
func readClaudeSettings(t *testing.T, home string) map[string]any {
	t.Helper()
	path := filepath.Join(home, ".claude", "settings.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal %s: %v\nraw: %s", path, err, raw)
	}
	return out
}

// assertSemanticJSONEqual compares two already-decoded JSON values
// (map[string]any / []any / string / float64 / bool / nil, the shapes
// encoding/json produces into `any`) for DATA equality.
//
// This is deliberately NOT a byte-for-byte comparison. Reading
// internal/hook/register.go::writeJSONIndented closely shows it
// re-serializes EVERY top-level settings.json value through
// json.Unmarshal-into-any + json.MarshalIndent on every single write —
// including keys the current call never touched (e.g. "hooks" survives
// a statusLine-only registration, but re-indented/re-emitted, not
// copied verbatim). So "hooks unchanged" / "unknown key preserved" can
// only ever mean semantically unchanged; asserting literal byte
// equality here would be asserting an implementation detail the
// registrar was never designed to hold, and would make this test
// permanently, spuriously red. Documented deviation from the literal
// task wording ("byte-identical").
func assertSemanticJSONEqual(t *testing.T, label string, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s: JSON value changed\n got:  %#v\nwant: %#v", label, got, want)
	}
}

// TestStatuslineRegistrationE2E seeds a settings.json with hooks + an
// unknown top-level key, registers the statusline, asserts the new
// "statusLine" key plus untouched hooks/unknown key, then uninstalls
// and asserts full removal of just the "statusLine" key.
func TestStatuslineRegistrationE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns `go build` + the real binary; skipped under -short")
	}
	t.Parallel()
	bin := binaryPath(t)
	home, tmpdir := newScratchHome(t)

	seededHooks := map[string]any{
		"PreToolUse": []any{
			map[string]any{
				"matcher": "*",
				"hooks": []any{
					map[string]any{"type": "command", "command": "echo hi"},
				},
			},
		},
	}
	seededUnknown := map[string]any{"foo": "bar", "n": float64(3)}
	writeClaudeSettings(t, home, map[string]any{
		"hooks":              seededHooks,
		"unknownTopLevelKey": seededUnknown,
	})

	stdout, stderr, code := runObserver(t, bin, home, tmpdir,
		"init", "--claude-code", "--statusline", "--force",
		"--skip-hooks", "--skip-mcp", "--skip-proxy-route", "--skip-extension", "--skip-guard-dialect")
	if code != 0 {
		t.Fatalf("init --statusline exited %d\n--- stdout ---\n%s\n--- stderr ---\n%s", code, stdout, stderr)
	}
	binExpr := bin // no spaces in the mkdtemp path, so shellQuoteIfNeeded is a no-op
	if !strings.Contains(stdout, fmt.Sprintf("statusline: registered claude-code \"statusLine\" -> %s statusline", binExpr)) {
		t.Errorf("stdout missing the registration confirmation line:\n%s", stdout)
	}
	if !strings.Contains(stdout, "estimated list price, not invoiced") {
		t.Errorf("stdout missing the §4.2 dollar-figure disclaimer:\n%s", stdout)
	}

	settings := readClaudeSettings(t, home)
	statusLine, ok := settings["statusLine"].(map[string]any)
	if !ok {
		t.Fatalf("settings.json has no \"statusLine\" object after registration: %#v", settings)
	}
	wantCmd := binExpr + " statusline"
	if got := statusLine["command"]; got != wantCmd {
		t.Errorf("statusLine.command = %q, want %q", got, wantCmd)
	}
	if got := statusLine["type"]; got != "command" {
		t.Errorf("statusLine.type = %v, want \"command\"", got)
	}
	if got := statusLine["padding"]; got != float64(0) {
		t.Errorf("statusLine.padding = %v, want 0", got)
	}

	var wantHooks, wantUnknown any
	roundtrip(t, seededHooks, &wantHooks)
	roundtrip(t, seededUnknown, &wantUnknown)
	assertSemanticJSONEqual(t, "hooks", settings["hooks"], wantHooks)
	assertSemanticJSONEqual(t, "unknownTopLevelKey", settings["unknownTopLevelKey"], wantUnknown)

	// Uninstall: the "statusLine" key must be removed entirely; hooks
	// and the unknown key must survive.
	stdout, stderr, code = runObserver(t, bin, home, tmpdir,
		"init", "--claude-code", "--statusline", "--uninstall",
		"--skip-hooks", "--skip-mcp", "--skip-proxy-route", "--skip-extension", "--skip-guard-dialect")
	if code != 0 {
		t.Fatalf("init --statusline --uninstall exited %d\n--- stdout ---\n%s\n--- stderr ---\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "statusline: removed \"statusLine\" key from") {
		t.Errorf("stdout missing the removal confirmation line:\n%s", stdout)
	}

	settings = readClaudeSettings(t, home)
	if _, ok := settings["statusLine"]; ok {
		t.Errorf("settings.json still has a \"statusLine\" key after uninstall: %#v", settings["statusLine"])
	}
	assertSemanticJSONEqual(t, "hooks (post-uninstall)", settings["hooks"], wantHooks)
	assertSemanticJSONEqual(t, "unknownTopLevelKey (post-uninstall)", settings["unknownTopLevelKey"], wantUnknown)
}

// roundtrip marshals then unmarshals v into out, so a hand-built
// map[string]any{...} literal (which may contain int literals, etc.)
// is compared against the SAME any-shape encoding/json would produce
// when decoding real JSON bytes (int -> float64, etc.), rather than
// tripping reflect.DeepEqual over a type mismatch that has nothing to
// do with the behavior under test.
func roundtrip(t *testing.T, v any, out any) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("roundtrip marshal: %v", err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("roundtrip unmarshal: %v", err)
	}
}

// TestStatuslineRegistrationIdempotentE2E runs the registration twice
// and asserts the second run is a true no-op: the file's bytes (and
// therefore mtime) are unchanged, and stdout reports "already set"
// rather than re-registering.
func TestStatuslineRegistrationIdempotentE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns `go build` + the real binary; skipped under -short")
	}
	t.Parallel()
	bin := binaryPath(t)
	home, tmpdir := newScratchHome(t)

	stdout1, stderr1, code1 := runObserver(t, bin, home, tmpdir,
		"init", "--claude-code", "--statusline",
		"--skip-hooks", "--skip-mcp", "--skip-proxy-route", "--skip-extension", "--skip-guard-dialect")
	if code1 != 0 {
		t.Fatalf("first init --statusline exited %d\n--- stdout ---\n%s\n--- stderr ---\n%s", code1, stdout1, stderr1)
	}
	if !strings.Contains(stdout1, "statusline: registered") {
		t.Fatalf("first run did not report a fresh registration:\n%s", stdout1)
	}

	path := filepath.Join(home, ".claude", "settings.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read settings.json after first run: %v", err)
	}
	infoBefore, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat settings.json after first run: %v", err)
	}

	stdout2, stderr2, code2 := runObserver(t, bin, home, tmpdir,
		"init", "--claude-code", "--statusline",
		"--skip-hooks", "--skip-mcp", "--skip-proxy-route", "--skip-extension", "--skip-guard-dialect")
	if code2 != 0 {
		t.Fatalf("second init --statusline exited %d\n--- stdout ---\n%s\n--- stderr ---\n%s", code2, stdout2, stderr2)
	}
	if !strings.Contains(stdout2, "statusline: already set in") {
		t.Errorf("second run did not report \"already set\":\n%s", stdout2)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read settings.json after second run: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("settings.json bytes changed on the idempotent second run\nbefore:\n%s\nafter:\n%s", before, after)
	}
	infoAfter, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat settings.json after second run: %v", err)
	}
	if !infoBefore.ModTime().Equal(infoAfter.ModTime()) {
		t.Errorf("settings.json mtime changed on the idempotent second run: before=%v after=%v (the AlreadySet path must return before any write)",
			infoBefore.ModTime(), infoAfter.ModTime())
	}
}

// TestStatuslineForeignConflictE2E seeds a foreign (non-observer)
// "statusLine" entry and asserts: registering without --force fails
// with a clear stderr error and leaves the file untouched; registering
// WITH --force overwrites it.
func TestStatuslineForeignConflictE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns `go build` + the real binary; skipped under -short")
	}
	t.Parallel()
	bin := binaryPath(t)
	home, tmpdir := newScratchHome(t)

	foreignEntry := map[string]any{
		"type":    "command",
		"command": "/usr/bin/my-custom-statusline",
		"padding": float64(0),
	}
	writeClaudeSettings(t, home, map[string]any{
		"hooks":      map[string]any{},
		"statusLine": foreignEntry,
	})
	path := filepath.Join(home, ".claude", "settings.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read seeded settings.json: %v", err)
	}

	stdout, stderr, code := runObserver(t, bin, home, tmpdir,
		"init", "--claude-code", "--statusline",
		"--skip-hooks", "--skip-mcp", "--skip-proxy-route", "--skip-extension", "--skip-guard-dialect")
	if code == 0 {
		t.Fatalf("expected a non-zero exit when a foreign statusLine blocks registration without --force\n--- stdout ---\n%s\n--- stderr ---\n%s", stdout, stderr)
	}
	if !strings.Contains(stderr, "already has a non-observer") {
		t.Errorf("stderr does not mention the foreign-entry conflict clearly:\n%s", stderr)
	}
	if !strings.Contains(stderr, "--force") {
		t.Errorf("stderr does not tell the operator how to override (--force):\n%s", stderr)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read settings.json after the failed (no-force) run: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("settings.json was modified even though registration failed without --force\nbefore:\n%s\nafter:\n%s", before, after)
	}

	// Now with --force: must overwrite the foreign entry.
	stdout, stderr, code = runObserver(t, bin, home, tmpdir,
		"init", "--claude-code", "--statusline", "--force",
		"--skip-hooks", "--skip-mcp", "--skip-proxy-route", "--skip-extension", "--skip-guard-dialect")
	if code != 0 {
		t.Fatalf("--force run exited %d\n--- stdout ---\n%s\n--- stderr ---\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "statusline: registered claude-code \"statusLine\" ->") {
		t.Errorf("stdout does not confirm the --force overwrite:\n%s", stdout)
	}

	settings := readClaudeSettings(t, home)
	statusLine, ok := settings["statusLine"].(map[string]any)
	if !ok {
		t.Fatalf("settings.json has no \"statusLine\" object after --force registration: %#v", settings)
	}
	if got := statusLine["command"]; got == foreignEntry["command"] {
		t.Errorf("statusLine.command still equals the foreign command after --force: %v", got)
	}
	if got, want := statusLine["command"], bin+" statusline"; got != want {
		t.Errorf("statusLine.command = %q, want %q", got, want)
	}
}

// stdoutTail is a small mutex-guarded byte buffer used as a long-running
// subprocess's Stdout/Stderr target: exec.Cmd's internal io.Copy
// goroutines write to it concurrently with this test's own polling
// reads of its current contents.
type stdoutTail struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *stdoutTail) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *stdoutTail) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// TestStatuslineStartNeverRegistersE2E is, per the plan's own framing,
// the single most important e2e assertion in this arc: `observer
// start`'s auto-register-hooks path (cmd/observer/start.go::
// autoRegisterHooks, called unconditionally near the top of `start`'s
// RunE) must NEVER write the "statusLine" key — that registration is
// exclusively `observer init --statusline`'s job (RegisterClaudeCodeStatusline
// / UnregisterClaudeCodeStatusline are deliberately not wired into the
// tool-name-dispatched Register(tool) switch autoRegisterHooks calls).
//
// The scratch $HOME seeds a real (empty) ~/.claude/projects directory so
// hook.Registry.Installed() detects "claude-code" and autoRegisterHooks
// actually fires a live registration — proving this is a positive,
// non-vacuous check (hooks DO appear) rather than a test that would
// trivially pass on a host where claude-code isn't even detected.
func TestStatuslineStartNeverRegistersE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns `go build` + the real binary + a live `observer start`; skipped under -short")
	}
	if runtime.GOOS == "windows" {
		t.Skip("SIGTERM semantics differ on windows; this path is exercised on unix CI")
	}
	t.Parallel()
	bin := binaryPath(t)
	home, tmpdir := newScratchHome(t)

	claudeProjects := filepath.Join(home, ".claude", "projects")
	if err := os.MkdirAll(claudeProjects, 0o755); err != nil {
		t.Fatalf("mkdir fake claude projects dir: %v", err)
	}

	port := freePort(t)
	configPath := filepath.Join(home, "scratch-config.toml") // deliberately never created; config.Load treats a missing file as defaults

	cmd := exec.Command(
		bin, "start",
		"--no-dashboard", "--no-open",
		"--port", fmt.Sprintf("%d", port),
		"--config", configPath,
	)
	cmd.Dir = home
	cmd.Env = buildScratchEnv(home, tmpdir)
	var stdout, stderr stdoutTail
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start `observer start`: %v", err)
	}
	// Always make sure the process is gone by the end of the test, even
	// if an assertion below fails first.
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})

	// Poll for the "ready" line start.go prints AFTER buildProxy +
	// buildWatcher construction — which is itself AFTER
	// autoRegisterHooks has already run synchronously to completion
	// (start.go's RunE calls autoRegisterHooks, then buildProxy, then
	// buildWatcher, then prints this line right before the errgroup's
	// listener goroutines start). Seeing this line is proof positive
	// that hook auto-registration has already happened — a robust
	// readiness signal, not a guessed sleep.
	const readyMarker = "ctrl-c to stop"
	deadline := time.Now().Add(20 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		if strings.Contains(stdout.String(), readyMarker) {
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		t.Fatalf("`observer start` never printed the ready line within the deadline\n--- stdout ---\n%s\n--- stderr ---\n%s",
			stdout.String(), stderr.String())
	}

	// Signal the daemon to shut down via SIGTERM (the same signal
	// start.go's signal.NotifyContext listens for), then give it a
	// modest grace window — but do NOT require a clean exit within it.
	//
	// Empirically grounded 2026-07-30 on this WSL2 dev host: a real
	// Windows-side corpus is mounted at /mnt/c (the WARN lines above
	// name it), and crossmount-driven adapter scans of that GENUINE,
	// unrelated data (not anything this test seeded) can make the
	// watcher's graceful shutdown take up to ~80s on this specific
	// box, even though shutdown begins immediately (the proxy's
	// in-flight prewarm HTTP calls are canceled within milliseconds of
	// the signal — see the "context canceled" lines). A bare CI
	// runner with no /mnt/c exits in well under a second. Since the
	// invariant under test (no "statusLine" key in settings.json) is
	// already fully determined by the time the ready line printed —
	// autoRegisterHooks runs synchronously to completion before
	// start.go ever prints it — a clean exit is not required to check
	// it: after a short grace window we force-kill and move on to the
	// filesystem assertion regardless of how shutdown was progressing.
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}
	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()
	select {
	case err := <-waitErr:
		// A non-zero exit from a SIGTERM'd process is normal/expected
		// on some platforms; we only care that it actually exited.
		_ = err
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-waitErr
	}

	settingsPath := filepath.Join(home, ".claude", "settings.json")
	raw, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read %s after `observer start` ran: %v\n--- stdout ---\n%s\n--- stderr ---\n%s",
			settingsPath, err, stdout.String(), stderr.String())
	}
	var settings map[string]any
	if err := json.Unmarshal(raw, &settings); err != nil {
		t.Fatalf("unmarshal %s: %v\nraw: %s", settingsPath, err, raw)
	}

	if _, ok := settings["statusLine"]; ok {
		t.Errorf("`observer start` wrote a \"statusLine\" key into %s — statusline registration must be init-only, never auto-registered by start\nfull settings.json: %s",
			settingsPath, raw)
	}
	// Positive check: hooks SHOULD have appeared (auto-register working
	// as designed) — this is what makes the statusLine absence above a
	// meaningful negative rather than a vacuous one.
	if _, ok := settings["hooks"]; !ok {
		t.Errorf("`observer start` did not auto-register hooks for the detected claude-code home — the test's own precondition (a live, non-vacuous auto-register run) did not hold\n--- stdout ---\n%s\n--- stderr ---\n%s",
			stdout.String(), stderr.String())
	}
}

// statuslineLatencyBudget is the bound this test asserts against for
// 20 sequential `observer statusline --no-daemon` runs against a
// scratch $HOME with no daemon, no lockfile, and no stdin data. The
// no-daemon path never opens the database (it only stats a lockfile
// glob via internal/diag.LiveLocks, which is skipped entirely here
// because --no-daemon short-circuits before that check) and never
// dials a socket, so its real-world budget is far smaller than this —
// 500ms is a deliberately generous CI-safe bound chosen to still
// reliably catch a class of regression like "a stray database open"
// (empirically ~160ms on this project's other DB-opening one-shot
// paths) creeping into this command, without flaking on a loaded CI
// runner. The plan's own tighter latency budget is measured/enforced
// elsewhere (the injected-deps unit tests in
// cmd/observer/statusline_test.go); this is a coarse e2e backstop, not
// the precision benchmark.
const statuslineLatencyBudget = 500 * time.Millisecond

// TestStatuslineLatencyE2E runs `observer statusline --no-daemon` 20
// times against a scratch $HOME and asserts p95 wall-clock latency is
// within statuslineLatencyBudget, and that stdout is byte-exactly the
// bare wordmark line every single time (no daemon, no stdin, no flags,
// no env => every optional segment's datum is absent per
// internal/statusline/segments.go, so Render's output is the wordmark
// alone).
func TestStatuslineLatencyE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns `go build` + the real binary 20x; skipped under -short")
	}
	t.Parallel()
	bin := binaryPath(t)
	home, tmpdir := newScratchHome(t)

	const wantLine = "▞ superbased\n"
	const n = 20
	durations := make([]time.Duration, 0, n)

	for i := 0; i < n; i++ {
		cmd := exec.Command(bin, "statusline", "--no-daemon")
		cmd.Dir = home
		cmd.Env = buildScratchEnv(home, tmpdir)
		var outBuf, errBuf bytes.Buffer
		cmd.Stdout = &outBuf
		cmd.Stderr = &errBuf

		start := time.Now()
		err := cmd.Run()
		elapsed := time.Since(start)

		if err != nil {
			t.Fatalf("run %d: observer statusline --no-daemon failed: %v\n--- stdout ---\n%s\n--- stderr ---\n%s",
				i, err, outBuf.String(), errBuf.String())
		}
		if outBuf.String() != wantLine {
			t.Fatalf("run %d: stdout = %q, want %q (stderr: %s)", i, outBuf.String(), wantLine, errBuf.String())
		}
		durations = append(durations, elapsed)
	}

	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	// p95 over 20 samples: the 19th (0-indexed) value, i.e. ceil(0.95*20)=19.
	p95Index := int(float64(n)*0.95) - 1
	if p95Index < 0 {
		p95Index = 0
	}
	if p95Index >= n {
		p95Index = n - 1
	}
	p95 := durations[p95Index]

	t.Logf("observer statusline --no-daemon latencies over %d runs: min=%s p95=%s max=%s",
		n, durations[0], p95, durations[n-1])

	if p95 > statuslineLatencyBudget {
		t.Errorf("p95 latency %s exceeds budget %s over %d runs (all: %v)", p95, statuslineLatencyBudget, n, durations)
	}
}
