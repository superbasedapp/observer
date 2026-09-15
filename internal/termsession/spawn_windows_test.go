//go:build windows

package termsession

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// comspec is the absolute cmd.exe this file's probe children run through.
func comspec() string {
	if cs := os.Getenv("ComSpec"); cs != "" {
		return cs
	}
	return `C:\Windows\System32\cmd.exe`
}

// setupSpec builds a Spec that runs a fixed argv verbatim (SpecSetup's shape),
// which is what these spawner-level probes want: no observer binary, no
// handoff flags, just the program under test.
func setupSpec(rows, cols uint16, dir string, argv ...string) Spec {
	return Spec{Kind: SpecSetup, SetupArgv: argv, Rows: rows, Cols: cols, Dir: dir}
}

// ptyReader drains a PTY on its own goroutine (a ConPTY's output pipe does not
// reach EOF when the child exits — conhost keeps it open until the
// pseudoconsole is closed — so tests must never simply "read until EOF").
type ptyReader struct {
	mu  sync.Mutex
	buf strings.Builder
}

func startPTYReader(p PTY) *ptyReader {
	r := &ptyReader{}
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := p.Read(b)
			if n > 0 {
				r.mu.Lock()
				r.buf.Write(b[:n])
				r.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	return r
}

func (r *ptyReader) text() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.String()
}

var (
	reOSC = regexp.MustCompile("\x1b\\][^\x07\x1b]*(\x07|\x1b\\\\)")
	reCSI = regexp.MustCompile("\x1b\\[[0-9;?]*[ -/]*[@-~]")
	reESC = regexp.MustCompile("\x1b[=>()][0-9A-Za-z]?")
)

// normalizeTerminal strips the VT sequences conhost interleaves and the line
// breaks it inserts when a line wraps, so an assertion can look for a literal
// string the child printed.
func normalizeTerminal(s string) string {
	s = reOSC.ReplaceAllString(s, "")
	s = reCSI.ReplaceAllString(s, "")
	s = reESC.ReplaceAllString(s, "")
	s = strings.NewReplacer("\r", "", "\n", "").Replace(s)
	return strings.ToLower(s)
}

// waitForOutput polls the drained terminal output for want until the deadline.
func waitForOutput(r *ptyReader, want string, timeout time.Duration) bool {
	want = normalizeTerminal(want)
	deadline := time.Now().Add(timeout)
	for {
		if strings.Contains(normalizeTerminal(r.text()), want) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitExit reaps the child with a bound, failing the test on a hang.
func waitExit(t *testing.T, p PTY, timeout time.Duration) int {
	t.Helper()
	type res struct {
		code int
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := p.Wait()
		ch <- res{c, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("wait: %v", r.err)
		}
		return r.code
	case <-time.After(timeout):
		_ = p.Kill()
		t.Fatal("timed out waiting for the ConPTY child to exit")
		return -1
	}
}

// TestPTYSupportedWindows pins that a ConPTY-capable Windows host reports the
// embedded terminal as available — cmd relies on this to WIRE the launch seam
// (and show the "Launch here" button) on native Windows. On a pre-1809 host
// (no CreatePseudoConsole) it would be false and the seam stays unwired; the
// CI/dev hosts this runs on are modern, so we assert true here.
func TestPTYSupportedWindows(t *testing.T) {
	if !PTYSupported() {
		t.Skip("ConPTY not available on this Windows host (pre-1809); launch seam stays unwired by design")
	}
}

// TestRealConPTYEchoes exercises the actual ConPTY spawner (not the fake): it
// runs `cmd.exe /c echo <token>` through a real pseudoconsole, reads the
// echoed token back off the output pipe, confirms a clean exit, and reaps the
// job object. This is the Windows counterpart to the unix TestRealSpawnerEchoes
// — real CreateProcess + ConPTY + job-object teardown.
func TestRealConPTYEchoes(t *testing.T) {
	if !PTYSupported() {
		t.Skip("ConPTY not available on this Windows host")
	}
	sp := NewOSSpawner()
	p, err := sp.Spawn(setupSpec(24, 120, "", comspec(), "/c", "echo", "hello-from-conpty"))
	if err != nil {
		t.Fatalf("real conpty spawn: %v", err)
	}
	t.Cleanup(func() { _ = p.Kill() })

	r := startPTYReader(p)
	if code := waitExit(t, p, 20*time.Second); code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !waitForOutput(r, "hello-from-conpty", 5*time.Second) {
		t.Errorf("ConPTY output %q did not echo the token", r.text())
	}
	// Kill is idempotent — a second call must not panic or double-close.
	_ = p.Kill()
	_ = p.Kill()
}

// TestConPTYSpawnCapturesStdout is the DI-08b regression pin. `go test` runs
// this process with PIPED stdio, which is exactly the shape a real deployment
// has (`observer start > log`, nohup, a service wrapper): before the spawner
// set STARTF_USESTDHANDLES with NULL handles, the child INHERITED the daemon's
// pipe handles, so its stdout bypassed the terminal into the daemon's own log
// and the dashboard showed nothing — while the process still exited 0. The
// child here writes ONLY to plain stdout (no CONOUT$), so the assertion fails
// if that binding regresses.
func TestConPTYSpawnCapturesStdout(t *testing.T) {
	if !PTYSupported() {
		t.Skip("ConPTY not available on this Windows host")
	}
	const marker = "conpty-stdout-marker-9f3a"
	sp := NewOSSpawner()
	p, err := sp.Spawn(setupSpec(24, 120, "", comspec(), "/c", "echo", marker))
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}
	t.Cleanup(func() { _ = p.Kill() })

	r := startPTYReader(p)
	if code := waitExit(t, p, 20*time.Second); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !waitForOutput(r, marker, 5*time.Second) {
		t.Fatalf("the child's stdout never reached the pseudoconsole (DI-08b): output = %q", r.text())
	}
}

// TestConPTYSpawnExitCode pins that a non-zero child exit code survives the
// job-object + WaitForSingleObject path (259/STILL_ACTIVE collisions and
// swallowed codes are the classic failure).
func TestConPTYSpawnExitCode(t *testing.T) {
	if !PTYSupported() {
		t.Skip("ConPTY not available on this Windows host")
	}
	sp := NewOSSpawner()
	p, err := sp.Spawn(setupSpec(24, 80, "", comspec(), "/c", "exit", "3"))
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}
	t.Cleanup(func() { _ = p.Kill() })
	startPTYReader(p)
	if code := waitExit(t, p, 20*time.Second); code != 3 {
		t.Fatalf("exit code = %d, want 3", code)
	}
}

// TestWindowsSpawnResolvesArgv0ViaPATHEXT pins DI-01: a BARE argv[0] that
// exists only as a .cmd on PATH (the shape every npm-installed CLI shim has)
// must launch. CreateProcess alone appends only ".exe" and would fail with
// ERROR_FILE_NOT_FOUND; the spawner resolves argv[0] with a %PATHEXT%-aware
// LookPath and passes the result as lpApplicationName.
func TestWindowsSpawnResolvesArgv0ViaPATHEXT(t *testing.T) {
	if !PTYSupported() {
		t.Skip("ConPTY not available on this Windows host")
	}
	const marker = "pathext-marker-4c71"
	dir := t.TempDir()
	script := filepath.Join(dir, "observer-pathext-probe.cmd")
	if err := os.WriteFile(script, []byte("@echo off\r\necho "+marker+"\r\n"), 0o600); err != nil {
		t.Fatalf("write probe .cmd: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	sp := NewOSSpawner()
	p, err := sp.Spawn(setupSpec(24, 120, "", "observer-pathext-probe"))
	if err != nil {
		t.Fatalf("spawn of a bare .cmd name failed (DI-01): %v", err)
	}
	t.Cleanup(func() { _ = p.Kill() })

	r := startPTYReader(p)
	if code := waitExit(t, p, 20*time.Second); code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !waitForOutput(r, marker, 5*time.Second) {
		t.Fatalf(".cmd shim output never reached the terminal: %q", r.text())
	}
}

// TestWindowsSpawnHonoursDir pins that Spec.Dir reaches lpCurrentDirectory: a
// fresh launch's validated, allow-listed project root used to be dropped on
// Windows (nil lpCurrentDirectory), so every dashboard launch started in the
// daemon's own cwd.
func TestWindowsSpawnHonoursDir(t *testing.T) {
	if !PTYSupported() {
		t.Skip("ConPTY not available on this Windows host")
	}
	dir := t.TempDir()
	sp := NewOSSpawner()
	// `cd` with no arguments prints the current directory. A wide terminal
	// keeps the path off a wrap boundary (normalizeTerminal handles the rest).
	p, err := sp.Spawn(setupSpec(24, 400, dir, comspec(), "/c", "cd"))
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}
	t.Cleanup(func() { _ = p.Kill() })

	r := startPTYReader(p)
	if code := waitExit(t, p, 20*time.Second); code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !waitForOutput(r, dir, 5*time.Second) {
		t.Fatalf("child cwd is not Spec.Dir %q: terminal output = %q", dir, r.text())
	}
}

// TestWindowsSpawnUnknownProgramErrors pins the honest failure: an argv[0]
// that is on no PATH entry must come back as a named error BEFORE any handle
// is allocated — never as a ghost session that "exits 0" with no output.
func TestWindowsSpawnUnknownProgramErrors(t *testing.T) {
	if !PTYSupported() {
		t.Skip("ConPTY not available on this Windows host")
	}
	sp := NewOSSpawner()
	p, err := sp.Spawn(setupSpec(24, 80, "", "observer-no-such-program-b7d2"))
	if err == nil {
		_ = p.Kill()
		t.Fatal("spawn of a nonexistent program succeeded, want an error")
	}
	if p != nil {
		t.Fatalf("spawn returned a live PTY alongside error %v", err)
	}
	if !strings.Contains(err.Error(), "observer-no-such-program-b7d2") {
		t.Errorf("error %q does not name the program", err)
	}
	if !strings.Contains(err.Error(), "PATH") {
		t.Errorf("error %q does not say the lookup was a PATH lookup", err)
	}
}

// TestWindowsSpawnRejectsEmptyArgv pins the fail-closed edge at the spawner
// itself (Manager.Create validates too, but the spawner is the last gate).
func TestWindowsSpawnRejectsEmptyArgv(t *testing.T) {
	if !PTYSupported() {
		t.Skip("ConPTY not available on this Windows host")
	}
	sp := NewOSSpawner()
	if _, err := sp.Spawn(setupSpec(24, 80, "")); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("empty argv: err = %v, want ErrInvalidSpec", err)
	}
}
