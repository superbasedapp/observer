package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/diag"
)

// newStatuslineLockDir writes a live lockfile (this test process's own
// PID, which diag.processAlive will always find running) into a fresh
// temp directory and registers cleanup, so hasLiveDaemonLock(dir)
// reports true for the lifetime of the test.
func newStatuslineLockDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	info := diag.LockInfo{
		PID:        os.Getpid(),
		StartedAt:  time.Now(),
		DBPath:     filepath.Join(dir, "observer.db"),
		BinaryPath: "statusline-test",
	}
	path, err := diag.WriteLock(dir, info)
	if err != nil {
		t.Fatalf("diag.WriteLock: %v", err)
	}
	t.Cleanup(func() { _ = diag.RemoveLock(path) })
	return dir
}

// baseStatuslineDeps returns a deps value with every seam pinned to
// deterministic test values: no environment leakage, no stdin (a real
// TTY stand-in), and resolve() returning whatever the test supplies.
func baseStatuslineDeps(dbDir, daemonBase string) statuslineDeps {
	return statuslineDeps{
		getenv: func(string) string { return "" },
		resolve: func() (string, string, error) {
			return dbDir, daemonBase, nil
		},
		stdinTTY: func() bool { return true },
	}
}

func TestStatusline_DaemonUp_FullLine(t *testing.T) {
	setTestHome(t, t.TempDir())
	dbDir := newStatuslineLockDir(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/statusline" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"today_usd":                18.90,
			"session_usd":              nil,
			"session_cache_read_share": nil,
			"generated_at":             time.Now().UTC().Format(time.RFC3339),
		})
	}))
	defer ts.Close()

	deps := baseStatuslineDeps(dbDir, ts.URL)
	cmd := newStatuslineCmdWith(deps)
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetIn(strings.NewReader(""))
	cmd.SetArgs([]string{"--session-cost", "3.42", "--model", "claude-opus-4-5"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\nstderr: %s", err, errBuf.String())
	}

	got := strings.TrimRight(out.String(), "\n")
	want := "▞ superbased · $3.42 session · $18.90 today · claude-opus-4-5"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
	if strings.Count(out.String(), "\n") != 1 {
		t.Errorf("expected exactly one line (one trailing newline), got %q", out.String())
	}
}

func TestStatusline_NoLockfile_WordmarkOnly_ZeroDials(t *testing.T) {
	setTestHome(t, t.TempDir())
	emptyDBDir := t.TempDir() // no lockfile ever written here

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	dialed := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
			select {
			case dialed <- struct{}{}:
			default:
			}
		}
	}()

	deps := baseStatuslineDeps(emptyDBDir, "http://"+ln.Addr().String())
	cmd := newStatuslineCmdWith(deps)
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetIn(strings.NewReader(""))
	cmd.SetArgs([]string{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\nstderr: %s", err, errBuf.String())
	}

	got := strings.TrimRight(out.String(), "\n")
	if got != "▞ superbased" {
		t.Errorf("got %q want wordmark-only %q", got, "▞ superbased")
	}

	select {
	case <-dialed:
		t.Fatal("daemon was dialed despite no live lockfile - zero-dial invariant violated")
	case <-time.After(75 * time.Millisecond):
		// no connection attempt observed — expected.
	}
}

func TestStatusline_LockfilePresent_DeadPort_DegradesBounded(t *testing.T) {
	setTestHome(t, t.TempDir())
	dbDir := newStatuslineLockDir(t)

	// Grab an ephemeral port, then close it immediately so nothing is
	// listening there — connections should be refused promptly.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	deadAddr := ln.Addr().String()
	ln.Close()

	deps := baseStatuslineDeps(dbDir, "http://"+deadAddr)
	cmd := newStatuslineCmdWith(deps)
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetIn(strings.NewReader(""))
	cmd.SetArgs([]string{"--timeout", "80ms", "--explain"})

	start := time.Now()
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\nstderr: %s", err, errBuf.String())
	}
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Errorf("degrade took too long: %s (should be bounded well under 2s)", elapsed)
	}
	got := strings.TrimRight(out.String(), "\n")
	if got != "▞ superbased" {
		t.Errorf("got %q want wordmark-only %q", got, "▞ superbased")
	}
	if !strings.Contains(errBuf.String(), "daemon_reason=") {
		t.Errorf("expected --explain stderr to carry a daemon_reason, got %q", errBuf.String())
	}
}

func TestStatusline_StdinJSON_SessionSegment_DaemonDown(t *testing.T) {
	setTestHome(t, t.TempDir())
	emptyDBDir := t.TempDir() // no lockfile -> daemon path never attempted

	deps := statuslineDeps{
		getenv:   func(string) string { return "" },
		resolve:  func() (string, string, error) { return emptyDBDir, "", nil },
		stdinTTY: func() bool { return false }, // stdin is piped, not a TTY
	}
	cmd := newStatuslineCmdWith(deps)
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetIn(strings.NewReader(`{"model":{"display_name":"claude-opus-4-5"},"cost":{"total_cost_usd":7.11}}`))
	cmd.SetArgs([]string{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\nstderr: %s", err, errBuf.String())
	}
	got := strings.TrimRight(out.String(), "\n")
	want := "▞ superbased · $7.11 session · claude-opus-4-5"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestStatusline_MalformedStdin_NoPanic(t *testing.T) {
	setTestHome(t, t.TempDir())
	emptyDBDir := t.TempDir()

	deps := statuslineDeps{
		getenv:   func(string) string { return "" },
		resolve:  func() (string, string, error) { return emptyDBDir, "", nil },
		stdinTTY: func() bool { return false },
	}
	cmd := newStatuslineCmdWith(deps)
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetIn(strings.NewReader("this is not json { { {")) // malformed / non-JSON
	cmd.SetArgs([]string{})

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("statusline panicked on malformed stdin: %v", r)
		}
	}()

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\nstderr: %s", err, errBuf.String())
	}
	got := strings.TrimRight(out.String(), "\n")
	if got != "▞ superbased" {
		t.Errorf("got %q want degraded wordmark-only %q", got, "▞ superbased")
	}
}

func TestStatusline_Explain_StderrOnly_StdoutUnchanged(t *testing.T) {
	setTestHome(t, t.TempDir())
	dbDir := newStatuslineLockDir(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"today_usd": 5.00, "generated_at": time.Now().UTC().Format(time.RFC3339)})
	}))
	defer ts.Close()

	run := func(explain bool) (string, string) {
		deps := baseStatuslineDeps(dbDir, ts.URL)
		cmd := newStatuslineCmdWith(deps)
		var out, errBuf bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errBuf)
		cmd.SetIn(strings.NewReader(""))
		args := []string{"--model", "claude-opus-4-5"}
		if explain {
			args = append(args, "--explain")
		}
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("Execute: %v\nstderr: %s", err, errBuf.String())
		}
		return out.String(), errBuf.String()
	}

	plainOut, plainErr := run(false)
	explainOut, explainErr := run(true)

	if plainOut != explainOut {
		t.Errorf("stdout differs between --explain and non---explain runs:\nplain:   %q\nexplain: %q", plainOut, explainOut)
	}
	if plainErr != "" {
		t.Errorf("expected empty stderr without --explain, got %q", plainErr)
	}
	if !strings.Contains(explainErr, "path=daemon") {
		t.Errorf("expected --explain stderr to report path=daemon, got %q", explainErr)
	}
}

func TestStatusline_JSONOutput_SchemaAndFields(t *testing.T) {
	setTestHome(t, t.TempDir())
	dbDir := newStatuslineLockDir(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"today_usd": 12.34, "generated_at": time.Now().UTC().Format(time.RFC3339)})
	}))
	defer ts.Close()

	deps := baseStatuslineDeps(dbDir, ts.URL)
	cmd := newStatuslineCmdWith(deps)
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetIn(strings.NewReader(""))
	cmd.SetArgs([]string{"--json", "--model", "claude-opus-4-5", "--session-cost", "1.50"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\nstderr: %s", err, errBuf.String())
	}

	var got struct {
		Schema     string   `json:"schema"`
		Line       string   `json:"line"`
		TodayUSD   *float64 `json:"today_usd"`
		SessionUSD *float64 `json:"session_usd"`
		Model      string   `json:"model"`
		Source     string   `json:"source"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("json.Unmarshal(%q): %v", out.String(), err)
	}
	if got.Schema != "superbased.statusline/1" {
		t.Errorf("schema = %q", got.Schema)
	}
	if got.Source != "daemon" {
		t.Errorf("source = %q, want daemon", got.Source)
	}
	if got.TodayUSD == nil || *got.TodayUSD != 12.34 {
		t.Errorf("today_usd = %v, want 12.34", got.TodayUSD)
	}
	if got.SessionUSD == nil || *got.SessionUSD != 1.50 {
		t.Errorf("session_usd = %v, want 1.50", got.SessionUSD)
	}
	if got.Model != "claude-opus-4-5" {
		t.Errorf("model = %q", got.Model)
	}
	if got.Line == "" {
		t.Error("line is empty")
	}
}

func TestStatusline_SegmentsSubset(t *testing.T) {
	setTestHome(t, t.TempDir())
	emptyDBDir := t.TempDir()

	deps := statuslineDeps{
		getenv:   func(string) string { return "" },
		resolve:  func() (string, string, error) { return emptyDBDir, "", nil },
		stdinTTY: func() bool { return true },
	}
	cmd := newStatuslineCmdWith(deps)
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetIn(strings.NewReader(""))
	cmd.SetArgs([]string{"--segments", "wordmark,model", "--model", "claude-opus-4-5", "--session-cost", "9.99"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\nstderr: %s", err, errBuf.String())
	}
	got := strings.TrimRight(out.String(), "\n")
	want := "▞ superbased · claude-opus-4-5" // session segment must NOT appear even though --session-cost was passed
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestStatusline_NoDaemonFlag_SkipsResolveAndDial(t *testing.T) {
	setTestHome(t, t.TempDir())

	resolveCalled := false
	deps := statuslineDeps{
		getenv: func(string) string { return "" },
		resolve: func() (string, string, error) {
			resolveCalled = true
			return "", "", nil
		},
		stdinTTY: func() bool { return true },
	}
	cmd := newStatuslineCmdWith(deps)
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetIn(strings.NewReader(""))
	cmd.SetArgs([]string{"--no-daemon", "--explain"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\nstderr: %s", err, errBuf.String())
	}
	if resolveCalled {
		t.Error("--no-daemon must skip the daemon attempt entirely, including config/lockfile resolution")
	}
	if !strings.Contains(errBuf.String(), "path=none") {
		t.Errorf("expected --explain to report path=none, got %q", errBuf.String())
	}
}

// TestStatusline_OversizedStdin_TreatedAsAbsent covers F3: a stdin
// stream larger than statuslineStdinLimit whose first `limit` bytes
// happen to parse as a complete, valid JSON value on their own must
// still be treated as wholly absent, not parsed from its truncated
// prefix. The payload is built so the JSON closes EXACTLY at the
// documented limit, with one extra byte appended past it.
func TestStatusline_OversizedStdin_TreatedAsAbsent(t *testing.T) {
	setTestHome(t, t.TempDir())
	emptyDBDir := t.TempDir()

	deps := statuslineDeps{
		getenv:   func(string) string { return "" },
		resolve:  func() (string, string, error) { return emptyDBDir, "", nil },
		stdinTTY: func() bool { return false },
	}

	const prefix = `{"model":{"display_name":"`
	const suffix = `"}}`
	padLen := int(statuslineStdinLimit) - len(prefix) - len(suffix)
	if padLen < 0 {
		t.Fatal("statuslineStdinLimit too small for this payload shape")
	}
	var payload bytes.Buffer
	payload.WriteString(prefix)
	payload.Write(bytes.Repeat([]byte("x"), padLen))
	payload.WriteString(suffix)
	if int64(payload.Len()) != statuslineStdinLimit {
		t.Fatalf("payload construction bug: built %d bytes, want exactly %d", payload.Len(), statuslineStdinLimit)
	}
	payload.WriteByte('\n') // one extra byte past the documented limit

	cmd := newStatuslineCmdWith(deps)
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetIn(bytes.NewReader(payload.Bytes()))
	cmd.SetArgs([]string{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\nstderr: %s", err, errBuf.String())
	}
	got := strings.TrimRight(out.String(), "\n")
	if got != "▞ superbased" {
		t.Errorf("F3: oversized stdin should degrade to wordmark-only, got %q", got)
	}
}

// TestStatusline_StalledStdinPipe_BoundedWordmarkOnly covers F2(a): a
// host that opens the statusLine stdin pipe and never writes or closes
// it must never block this command forever. readStatuslineStdin's own
// deadline (statuslineStdinReadTimeout, 500ms) must save this well
// inside the total wall-clock budget.
func TestStatusline_StalledStdinPipe_BoundedWordmarkOnly(t *testing.T) {
	setTestHome(t, t.TempDir())
	emptyDBDir := t.TempDir()

	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = pw.Close() // unblocks any still-pending read with EOF
		_ = pr.Close()
	})

	deps := statuslineDeps{
		getenv:   func(string) string { return "" },
		resolve:  func() (string, string, error) { return emptyDBDir, "", nil },
		stdinTTY: func() bool { return false }, // piped, not a TTY -> stdin read attempted
	}
	cmd := newStatuslineCmdWith(deps)
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetIn(pr)
	cmd.SetArgs([]string{})

	start := time.Now()
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\nstderr: %s", err, errBuf.String())
	}
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Errorf("F2a: stalled stdin should degrade near the %s stdin-read timeout, took %s", statuslineStdinReadTimeout, elapsed)
	}
	got := strings.TrimRight(out.String(), "\n")
	if got != "▞ superbased" {
		t.Errorf("got %q want wordmark-only %q", got, "▞ superbased")
	}
}

// TestStatusline_TimeoutClampedTo2s covers F2(b): --timeout 1h must be
// clamped to statuslineMaxDaemonTimeout (2s), never honored literally.
// A closed ephemeral port refuses instantly regardless of the timeout
// requested, so the bound on elapsed time here is really about the
// overall run never resembling "an hour"; the --explain output is what
// actually proves the clamp took effect.
func TestStatusline_TimeoutClampedTo2s(t *testing.T) {
	setTestHome(t, t.TempDir())
	dbDir := newStatuslineLockDir(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	deadAddr := ln.Addr().String()
	ln.Close() // nothing listening -> connection refused promptly

	deps := baseStatuslineDeps(dbDir, "http://"+deadAddr)
	cmd := newStatuslineCmdWith(deps)
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetIn(strings.NewReader(""))
	cmd.SetArgs([]string{"--timeout", "1h", "--explain"})

	start := time.Now()
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\nstderr: %s", err, errBuf.String())
	}
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Errorf("F2b: --timeout 1h must be clamped to the %s ceiling, took %s", statuslineMaxDaemonTimeout, elapsed)
	}
	if !strings.Contains(errBuf.String(), "daemon_timeout=2s") {
		t.Errorf("expected --explain to report the clamped daemon_timeout=2s, got %q", errBuf.String())
	}
}

// TestStatusline_TotalDeadline_FallsBackAndExits0 covers F2(c): ONE
// total wall-clock deadline over the whole run. Here deps.resolve
// itself is deliberately slower than the (test-shrunk) deadline,
// simulating a wedged config/lockfile-resolution step — proving it's
// the overall budget, not just the per-call daemon HTTP timeout, that
// bounds this command.
func TestStatusline_TotalDeadline_FallsBackAndExits0(t *testing.T) {
	setTestHome(t, t.TempDir())

	origDeadline := statuslineTotalDeadline
	statuslineTotalDeadline = 150 * time.Millisecond
	t.Cleanup(func() { statuslineTotalDeadline = origDeadline })

	deps := statuslineDeps{
		getenv: func(string) string { return "" },
		resolve: func() (string, string, error) {
			time.Sleep(2 * time.Second) // deliberately past the shrunk total deadline
			return "", "", nil
		},
		stdinTTY: func() bool { return true },
	}
	cmd := newStatuslineCmdWith(deps)
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetIn(strings.NewReader(""))
	cmd.SetArgs([]string{"--explain", "--model", "claude-opus-4-5"})

	start := time.Now()
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\nstderr: %s", err, errBuf.String())
	}
	elapsed := time.Since(start)
	if elapsed > time.Second {
		t.Errorf("F2c: total-deadline fallback should fire near the shrunk %s deadline, took %s", statuslineTotalDeadline, elapsed)
	}
	got := strings.TrimRight(out.String(), "\n")
	want := "▞ superbased · claude-opus-4-5" // model was flag-supplied (fast, no I/O), so the fallback's "best line so far" includes it
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
	if !strings.Contains(errBuf.String(), "path=none") {
		t.Errorf("expected the deadline-fallback --explain output to report path=none, got %q", errBuf.String())
	}
}

// findNonLoopbackIPv4 returns the first non-loopback IPv4 address found
// on this machine's own interfaces, or "" if none exists — used only to
// prove F4's loopback-only guard against a REAL, dialable non-loopback
// address without hardcoding an environment-specific IP or reaching an
// actual remote host.
func findNonLoopbackIPv4(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() {
			continue
		}
		v4 := ipNet.IP.To4()
		if v4 == nil {
			continue
		}
		return v4.String()
	}
	return ""
}

// TestStatusline_NonLoopbackDaemonAddr_SkippedZeroDials covers F4: a
// resolved daemon address whose host is not loopback (e.g. a poisoned
// OBSERVER_DASHBOARD_ADDR or a configured non-loopback [dashboard].addr)
// must never be dialed at all — the request carries session_id, and a
// non-loopback destination could exfiltrate it off-machine in plaintext.
func TestStatusline_NonLoopbackDaemonAddr_SkippedZeroDials(t *testing.T) {
	setTestHome(t, t.TempDir())
	dbDir := newStatuslineLockDir(t)

	nonLoopbackIP := findNonLoopbackIPv4(t)
	if nonLoopbackIP == "" {
		t.Skip("no non-loopback IPv4 interface available in this sandbox")
	}

	ln, err := net.Listen("tcp", nonLoopbackIP+":0")
	if err != nil {
		t.Skipf("cannot bind %s: %v (sandbox likely blocks non-loopback binds)", nonLoopbackIP, err)
	}
	defer ln.Close()

	dialed := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
			select {
			case dialed <- struct{}{}:
			default:
			}
		}
	}()

	deps := baseStatuslineDeps(dbDir, "http://"+ln.Addr().String())
	cmd := newStatuslineCmdWith(deps)
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetIn(strings.NewReader(""))
	cmd.SetArgs([]string{"--explain"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\nstderr: %s", err, errBuf.String())
	}

	got := strings.TrimRight(out.String(), "\n")
	if got != "▞ superbased" {
		t.Errorf("got %q want wordmark-only %q", got, "▞ superbased")
	}
	if !strings.Contains(errBuf.String(), "not loopback") {
		t.Errorf("expected --explain to report the non-loopback skip reason, got %q", errBuf.String())
	}

	select {
	case <-dialed:
		t.Fatal("F4: statusline dialed a non-loopback daemon address - zero-dial invariant violated")
	case <-time.After(75 * time.Millisecond):
		// no connection attempt observed — expected.
	}
}

// TestStatusline_LockfilePIDReused_TreatedDeadZeroDials covers F5: bare
// PID-existence liveness (internal/diag.LiveLocks) is fooled by PID
// reuse. PID 1 is always init/systemd, never this observer binary — a
// stand-in for a lockfile whose recorded PID has since been recycled by
// an unrelated process. F5's /proc/<pid>/cmdline corroboration is
// Linux-only (documented fail-open elsewhere), so this test is too.
func TestStatusline_LockfilePIDReused_TreatedDeadZeroDials(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("F5's cmdline corroboration only runs on Linux; other platforms fail open by design")
	}
	setTestHome(t, t.TempDir())
	dbDir := t.TempDir()

	info := diag.LockInfo{
		PID:        1,
		StartedAt:  time.Now(),
		DBPath:     filepath.Join(dbDir, "observer.db"),
		BinaryPath: "statusline-test",
	}
	path, err := diag.WriteLock(dbDir, info)
	if err != nil {
		t.Fatalf("diag.WriteLock: %v", err)
	}
	t.Cleanup(func() { _ = diag.RemoveLock(path) })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	dialed := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
			select {
			case dialed <- struct{}{}:
			default:
			}
		}
	}()

	deps := baseStatuslineDeps(dbDir, "http://"+ln.Addr().String())
	cmd := newStatuslineCmdWith(deps)
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetIn(strings.NewReader(""))
	cmd.SetArgs([]string{"--explain"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\nstderr: %s", err, errBuf.String())
	}
	got := strings.TrimRight(out.String(), "\n")
	if got != "▞ superbased" {
		t.Errorf("got %q want wordmark-only %q", got, "▞ superbased")
	}
	if !strings.Contains(errBuf.String(), "no live daemon lockfile") {
		t.Errorf("expected --explain to report the reused-PID lock treated as dead, got %q", errBuf.String())
	}

	select {
	case <-dialed:
		t.Fatal("F5: statusline dialed a daemon whose lockfile PID was reused by a non-observer process")
	case <-time.After(75 * time.Millisecond):
	}
}
