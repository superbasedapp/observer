//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// relayHarness is the daemon side of the relay over a real unix socket,
// with the production executor running a real observer binary.
type relayHarness struct {
	home, obs, cfg, link string
	rec                  sandboxrelayd.RunRecord
	daemon               *sandboxrelayd.Daemon
}

func relayShortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "sbr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// writeRelayConfig writes a config whose DB lives under obs.
func writeRelayConfig(t *testing.T, obs, extra string) string {
	t.Helper()
	cfg := filepath.Join(obs, "config.toml")
	body := fmt.Sprintf("[observer]\ndb_path = %q\n%s", filepath.Join(obs, "observer.db"), extra)
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func startRelayHarness(t *testing.T, bin, workspace, extraConfig string) *relayHarness {
	t.Helper()
	h := &relayHarness{home: t.TempDir(), obs: relayShortDir(t)}
	h.cfg = writeRelayConfig(t, h.obs, extraConfig)
	rec, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{
		RunID: "run-eq", Tool: "claude-code", ProjectRoot: workspace, WorkspaceDir: workspace, Roots: []string{workspace},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.rec = rec
	if err := sandboxrelayd.WriteRun(h.obs, rec); err != nil {
		t.Fatal(err)
	}
	h.link = filepath.Join(h.obs, "link.sock")
	ln, err := net.Listen("unix", h.link)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h.daemon = &sandboxrelayd.Daemon{ObserverDir: h.obs, Exec: relayExecutor(h.cfg, bin), Rules: relayRules, Peer: sandboxrelayd.PeerSameUser}
	go func() { _ = h.daemon.Serve(ctx, ln) }()
	return h
}

// relayed sends one request over the link, exactly as the host helper does.
func (h *relayHarness) relayed(t *testing.T, req sandboxrelay.HookRequest) (sandboxrelay.HookResponse, error) {
	t.Helper()
	msg, err := sandboxrelay.EncodeHookRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := sandboxrelayd.LinkRoundTrip(ctx, func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", h.link)
	}, h.rec, msg, sandboxrelay.DefaultConnLimits)
	if err != nil {
		return sandboxrelay.HookResponse{}, err
	}
	return sandboxrelay.DecodeHookResponse(out)
}

// direct runs the same invocation as a plain host hook.
func direct(t *testing.T, bin, cfg, dir string, args []string, stdin []byte) (int, []byte) {
	t.Helper()
	cmd := exec.Command(bin, append(append([]string{"hook"}, args...), "--config", cfg)...) //nolint:gosec // G204: the test's own observer binary
	cmd.Stdin = bytes.NewReader(stdin)
	cmd.Dir = dir
	cmd.Env = relayChildEnv(os.Environ(), sandboxrelay.KindHook)
	cmd.Env = removeEnv(cmd.Env, relayEnvFD)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("direct run: %v", err)
	}
	return code, out.Bytes()
}

func removeEnv(env []string, key string) []string {
	var out []string
	for _, kv := range env {
		if !strings.HasPrefix(kv, key+"=") {
			out = append(out, kv)
		}
	}
	return out
}

// tableCounts is the row count of every table of the DB at path.
func tableCounts(t *testing.T, path string) map[string]int64 {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		return map[string]int64{}
	}
	var names []string
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		names = append(names, n)
	}
	_ = rows.Close()
	out := map[string]int64{}
	for _, n := range names {
		var c int64
		if err := db.QueryRow(`SELECT COUNT(*) FROM "` + n + `"`).Scan(&c); err == nil && c > 0 {
			out[n] = c
		}
	}
	return out
}

// relayEquivalenceTables are tables whose rows depend on the hook
// process's own ancestry or on which process ran first (process lineage,
// the per-process migration record), which the relay path deliberately
// does not have: the channel supplies no host ancestry for a box.
var relayEquivalenceTables = map[string]bool{
	// The session-to-agent-process bridge is built from the hook's own
	// /proc ancestry. A box's processes live in a private pid namespace, so
	// their ids mean nothing on the host; the relay supplies no ancestry
	// and the bridge row is not written (decided in lane sbx-p2).
	"session_pid_bridge": true,
}

// TestRelayDirectEquivalence is the P2 acceptance "every hook-capable
// adapter's events land identically through relay and direct paths": for
// every wired hook binding of every registry row, the same payload run as a
// plain host hook and relayed through the daemon handler answers with the
// same exit code and stdout and lands the same rows.
func TestRelayDirectEquivalence(t *testing.T) {
	bin := probeHookTestBinary(t)
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "a.txt"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setTestHome(t, t.TempDir())
	relay := startRelayHarness(t, bin, ws, "")
	directObs := relayShortDir(t)
	directCfg := writeRelayConfig(t, directObs, "")
	type pair struct{ tool, event string }
	var cases []pair
	for _, c := range integration.Capabilities() {
		for _, b := range c.Hook.Bindings {
			if !b.Wired || b.NativeEvent == "" {
				continue
			}
			cases = append(cases, pair{c.Tool, b.NativeEvent})
		}
	}
	if len(cases) < 20 {
		t.Fatalf("only %d wired hook bindings found; the registry walk is broken", len(cases))
	}
	sort.Slice(cases, func(i, j int) bool { return cases[i].tool+cases[i].event < cases[j].tool+cases[j].event })
	tools := map[string]bool{}
	for i, c := range cases {
		args := []string{c.tool, c.event}
		if err := checkRelayArgs(args); err != nil {
			t.Logf("%s %s: not relayable (%v), skipped", c.tool, c.event, err)
			continue
		}
		tools[c.tool] = true
		payload := []byte(fmt.Sprintf(`{"session_id":"relay-eq-%d","hook_event_name":%q,"cwd":%q,"tool_name":"Read","tool_input":{"file_path":%q},"prompt":"hello"}`,
			i, c.event, ws, filepath.Join(ws, "a.txt")))
		dcode, dout := direct(t, bin, directCfg, ws, args, payload)
		resp, err := relay.relayed(t, sandboxrelay.HookRequest{Kind: sandboxrelay.KindHook, Args: args, Cwd: ws, Stdin: payload})
		if err != nil {
			t.Errorf("%s %s: relayed: %v", c.tool, c.event, err)
			continue
		}
		if resp.Exit != dcode || !bytes.Equal(resp.Stdout, dout) {
			t.Errorf("%s %s: direct exit %d stdout %q; relayed exit %d stdout %q", c.tool, c.event, dcode, dout, resp.Exit, resp.Stdout)
		}
	}
	dc := tableCounts(t, filepath.Join(directObs, "observer.db"))
	rc := tableCounts(t, filepath.Join(relay.obs, "observer.db"))
	for name, n := range dc {
		if relayEquivalenceTables[name] {
			continue
		}
		if rc[name] != n {
			t.Errorf("table %s: direct %d rows, relayed %d", name, n, rc[name])
		}
	}
	for name, n := range rc {
		if _, ok := dc[name]; !ok && !relayEquivalenceTables[name] {
			t.Errorf("table %s: relayed %d rows, direct none", name, n)
		}
	}
	t.Logf("%d bindings across %d tools compared; %d tables hold rows", len(cases), len(tools), len(dc))
}

// checkRelayArgs reports whether the box would send args (the schema).
func checkRelayArgs(args []string) error {
	msg, err := sandboxrelay.EncodeHookRequest(sandboxrelay.HookRequest{Args: args})
	if err != nil {
		return err
	}
	_, err = sandboxrelay.DecodeHookRequest(msg, relayRules)
	return err
}

// TestRelayGuardDenyRoundTrips (P2 acceptance "a guard deny round-trips
// and blocks the tool"): with guard enforcing, every served tool gate's
// dangerous-command fixture relayed out of a box is answered with the same
// block, byte for byte and exit code for exit code, as the direct hook.
func TestRelayGuardDenyRoundTrips(t *testing.T) {
	bin := probeHookTestBinary(t)
	ws := t.TempDir()
	setTestHome(t, t.TempDir())
	guardCfg := "[guard]\nenabled = true\nmode = \"enforce\"\n"
	relay := startRelayHarness(t, bin, ws, guardCfg)
	writePosture(t, relay.cfg, enforcedPosture)
	directObs := relayShortDir(t)
	directCfg := writeRelayConfig(t, directObs, guardCfg)
	writePosture(t, directCfg, enforcedPosture)
	n := 0
	for _, g := range servedToolGates(t) {
		if g.b.NativeEvent == "pre_mcp_tool_use" {
			continue // no builtin rule judges an arbitrary MCP call
		}
		args := []string{g.tool, g.b.NativeEvent}
		if checkRelayArgs(args) != nil {
			continue
		}
		payload := []byte(toolGateE2EFixture(g.tool, g.b.NativeEvent, g.b.Dialect, ws))
		dcode, dout := direct(t, bin, directCfg, ws, args, payload)
		fc, _ := hook.BuildFailClosedReply(g.b.Dialect, "x")
		if !toolGateBlockWords.Match(dout) && (fc.ExitCode == 0 || dcode != fc.ExitCode) {
			t.Errorf("%s %s: the direct hook did not block (exit %d): %s", g.tool, g.b.NativeEvent, dcode, dout)
			continue
		}
		resp, err := relay.relayed(t, sandboxrelay.HookRequest{Kind: sandboxrelay.KindHook, Args: args, Cwd: ws, Stdin: payload})
		if err != nil {
			t.Errorf("%s %s: relayed: %v", g.tool, g.b.NativeEvent, err)
			continue
		}
		if resp.Exit != dcode || !bytes.Equal(resp.Stdout, dout) {
			t.Errorf("%s %s: relayed exit %d %s, direct exit %d %s", g.tool, g.b.NativeEvent, resp.Exit, resp.Stdout, dcode, dout)
		}
		n++
	}
	if n == 0 {
		t.Fatal("no tool gate was compared")
	}
	t.Logf("%d tool gates blocked identically through the relay", n)
}

// TestRelayLaunchGate: an in-box launcher's gate walk runs host-side
// through the relay (the box has no database): a maintenance launch is
// allowed (exit 0), and evidence the box forged out of shape is refused
// before the walk reads it.
func TestRelayLaunchGate(t *testing.T) {
	bin := probeHookTestBinary(t)
	ws := t.TempDir()
	setTestHome(t, t.TempDir())
	relay := startRelayHarness(t, bin, ws, "")
	gate := func(ev string) sandboxrelay.HookResponse {
		t.Helper()
		resp, err := relay.relayed(t, sandboxrelay.HookRequest{Kind: sandboxrelay.KindLaunchGate, Args: []string{"claude-code"}, Cwd: ws, Stdin: []byte(ev)})
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	if r := gate(fmt.Sprintf(`{"Route":%d}`, budgetLaunchRouteMaintenance)); r.Exit != 0 {
		t.Fatalf("a maintenance launch was refused: %d %s", r.Exit, r.Stderr)
	}
	if r := gate(`{"Route":200}`); r.Exit != 2 || !bytes.Contains(r.Stderr, []byte("refused")) {
		t.Fatalf("an out-of-range route was not refused: %d %s", r.Exit, r.Stderr)
	}
}

// TestBoxLaunchEvidence: one case per validation rule of the box's launch
// evidence.
func TestBoxLaunchEvidence(t *testing.T) {
	ok := budgetLaunchEvidence{Route: budgetLaunchRouteObserverProxy, ProxyURL: "http://127.0.0.1:8820", Executable: "/usr/bin/claude", Arguments: []string{"-p"}}
	for _, tc := range []struct {
		name string
		mut  func(e *budgetLaunchEvidence)
		ok   bool
	}{
		{"valid", func(*budgetLaunchEvidence) {}, true},
		{"route out of range", func(e *budgetLaunchEvidence) { e.Route = 9 }, false},
		{"relative executable", func(e *budgetLaunchEvidence) { e.Executable = "claude" }, false},
		{"remote proxy url", func(e *budgetLaunchEvidence) { e.ProxyURL = "http://evil.example:80" }, false},
		{"unknown surface class", func(e *budgetLaunchEvidence) { e.SurfaceClass = "browser" }, false},
		{"too many arguments", func(e *budgetLaunchEvidence) { e.Arguments = make([]string, maxBoxEvidenceArgs+1) }, false},
	} {
		e := ok
		tc.mut(&e)
		if _, err := boxLaunchEvidence(e); (err == nil) != tc.ok {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}
