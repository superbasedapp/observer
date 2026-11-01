package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/procmodel"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestShouldCorrelateDebounce pins the per-session correlation debounce (A1):
// the Processes drawer polls every few seconds, so the WRITE passes must run at
// most once per correlateMinInterval per session, independently per session.
func TestShouldCorrelateDebounce(t *testing.T) {
	now := time.Now().UTC()
	s := &Server{
		lastCorrelate: map[string]time.Time{},
		now:           func() time.Time { return now },
	}
	if !s.shouldCorrelate("a") {
		t.Fatal("first call for a session should correlate")
	}
	if s.shouldCorrelate("a") {
		t.Error("second call within the interval should be debounced")
	}
	if !s.shouldCorrelate("b") {
		t.Error("a different session should correlate independently")
	}
	now = now.Add(correlateMinInterval + time.Second)
	if !s.shouldCorrelate("a") {
		t.Error("after the interval elapses, the session should correlate again")
	}
}

func dashProcRun(key, parent, sess string, pid int, exe, argv string, started time.Time) procmodel.ProcessRun {
	return procmodel.ProcessRun{
		ProcessKey:       key,
		ParentProcessKey: parent,
		BootID:           "boot",
		PID:              pid,
		StartTimeTicks:   int64(pid) * 100,
		Attribution: procmodel.Attribution{
			SessionID: sess, Tool: "claude-code",
			Source: procmodel.AttrInherited, Confidence: procmodel.ConfHigh,
		},
		ExeBasename: exe,
		ArgvPreview: argv,
		StartedAt:   started,
		LastSeenAt:  started,
		Exited:      true,
		DurationMs:  1200,
	}
}

// TestHandleSessionProcesses pins the /api/session/<id>/processes drawer
// payload: the attributed tree assembles correctly AND the lazy §9.2.4
// correlation labels the subtree with the spawning command.
func TestHandleSessionProcesses(t *testing.T) {
	s, _ := newTestServer(t) // seeds session "sA"
	ctx := context.Background()
	st := store.New(s.db())

	base := time.Now().UTC().Add(-30 * time.Minute)
	// A run_command action "npm test" at turn 3.
	if _, err := st.Ingest(ctx, []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "run1", SessionID: "sA",
		ProjectRoot: t.TempDir(), Timestamp: base, Tool: models.ToolClaudeCode,
		ActionType: models.ActionRunCommand, Target: "npm test", TurnIndex: 3, Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatalf("Ingest run_command: %v", err)
	}

	// Process tree sh → npm → node, spawned ~1s after the action.
	runs := []procmodel.ProcessRun{
		dashProcRun("k_sh", "", "sA", 100, "bash", "bash -c npm test", base.Add(time.Second)),
		dashProcRun("k_npm", "k_sh", "sA", 200, "npm", "npm test", base.Add(time.Second)),
		dashProcRun("k_node", "k_npm", "sA", 300, "node", "node x.js", base.Add(2*time.Second)),
	}
	if _, err := st.PersistRuns(ctx, runs); err != nil {
		t.Fatalf("PersistRuns: %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/session/sA/processes", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET processes: %d - %s", rr.Code, rr.Body.String())
	}

	var resp SessionProcessResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v - %s", err, rr.Body.String())
	}
	if resp.SessionID != "sA" || resp.Total != 3 {
		t.Fatalf("resp = %+v, want sA/3", resp)
	}
	if len(resp.Roots) != 1 {
		t.Fatalf("roots = %d, want 1 (bash root)", len(resp.Roots))
	}
	root := resp.Roots[0]
	if root.Exe != "bash" || len(root.Children) != 1 {
		t.Fatalf("root = %+v, want bash with 1 child", root)
	}
	npm := root.Children[0]
	if npm.Exe != "npm" || len(npm.Children) != 1 || npm.Children[0].Exe != "node" {
		t.Fatalf("npm node mis-nested: %+v", npm)
	}
	// The §9.2.4 correlation labeled the subtree with the spawning command.
	if root.Command != "npm test" {
		t.Errorf("root.Command = %q, want 'npm test' (correlated)", root.Command)
	}
	// last_seen_at rides along for the Call stack view's "exit not seen" bars.
	if want := base.Add(time.Second).UTC().Format(time.RFC3339); root.LastSeenAt != want {
		t.Errorf("root.LastSeenAt = %q, want %q", root.LastSeenAt, want)
	}
	if root.ActionID == nil || root.TurnIndex == nil || *root.TurnIndex != 3 {
		t.Errorf("root action link = id:%v turn:%v, want set/turn 3", root.ActionID, root.TurnIndex)
	}
}

// TestHandleProcessFindings pins the §14 findings surfaces: the recent
// cross-session rollup (/api/process/findings) and the per-session drawer
// flags both derive privileged_exec + executable_from_tmp from the envelope.
func TestHandleProcessFindings(t *testing.T) {
	s, _ := newTestServer(t) // seeds session "sA"
	ctx := context.Background()
	st := store.New(s.db())

	now := time.Now().UTC().Add(-10 * time.Minute)
	mk := func(key string, pid int, exe, base string, uid, euid int) procmodel.ProcessRun {
		return procmodel.ProcessRun{
			ProcessKey: key, BootID: "boot", PID: pid, StartTimeTicks: int64(pid) * 100,
			Attribution: procmodel.Attribution{
				SessionID: "sA", Tool: "claude-code",
				Source: procmodel.AttrBridge, Confidence: procmodel.ConfHigh,
			},
			ExePath: exe, ExeBasename: base, UID: uid, EUID: euid,
			StartedAt: now, LastSeenAt: now,
		}
	}
	runs := []procmodel.ProcessRun{
		mk("p_norm", 100, "/usr/bin/node", "node", 1000, 1000),
		mk("p_priv", 101, "/usr/bin/sudo", "sudo", 1000, 0),
		mk("p_tmp", 102, "/tmp/x/payload", "payload", 1000, 1000),
	}
	if _, err := st.PersistRuns(ctx, runs); err != nil {
		t.Fatalf("PersistRuns: %v", err)
	}

	// Recent rollup endpoint.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/process/findings?hours=24", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET findings: %d - %s", rr.Code, rr.Body.String())
	}
	var resp ProcessFindingsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v - %s", err, rr.Body.String())
	}
	if resp.Total != 2 {
		t.Fatalf("total findings = %d, want 2: %+v", resp.Total, resp.Findings)
	}
	if resp.ByRule[string(procmodel.FindingPrivilegedExec)] != 1 || resp.ByRule[string(procmodel.FindingExecutableFromTmp)] != 1 {
		t.Errorf("by_rule = %+v, want one each", resp.ByRule)
	}
	if resp.BySeverity[procmodel.SeverityHigh] != 1 || resp.BySeverity[procmodel.SeverityWarn] != 1 {
		t.Errorf("by_severity = %+v, want high:1 warn:1", resp.BySeverity)
	}

	// The same findings appear as side-effect flags on the session drawer.
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/api/session/sA/processes", nil)
	s.Handler().ServeHTTP(rr2, req2)
	var sresp SessionProcessResponse
	if err := json.Unmarshal(rr2.Body.Bytes(), &sresp); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	if len(sresp.Findings) != 2 {
		t.Errorf("session drawer findings = %d, want 2: %+v", len(sresp.Findings), sresp.Findings)
	}
}

// TestHandleSessionProcessesEmpty pins the empty-but-valid shape.
func TestHandleSessionProcessesEmpty(t *testing.T) {
	s, _ := newTestServer(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/session/sA/processes", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	var resp SessionProcessResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Total != 0 || resp.Roots == nil {
		t.Errorf("empty response should have total 0 + non-nil roots: %+v", resp)
	}
	if resp.Diagnostics.ProcessEnabled {
		t.Errorf("default diagnostics should report process disabled: %+v", resp.Diagnostics)
	}
	if !hasReason(resp.Diagnostics.ReasonCodes, "process_disabled") {
		t.Errorf("diagnostics reasons = %v, want process_disabled", resp.Diagnostics.ReasonCodes)
	}
	if resp.Diagnostics.ProcessSettingsURL != "/settings?section=process" {
		t.Errorf("process settings URL = %q", resp.Diagnostics.ProcessSettingsURL)
	}
}

// TestHandleSessionProcessesDiagnosticsProxyOnly pins the case that originally
// hid API calls: proxy network events can exist for a session even when there
// are no process_runs rows to render in the OS process tree.
func TestHandleSessionProcessesDiagnosticsProxyOnly(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	if _, err := store.New(s.db()).PersistProcessEvents(ctx, []procmodel.ProcessEvent{{
		ProcessKey: "proxy:req123",
		Timestamp:  time.Now().UTC(),
		Type:       procmodel.EventNetworkConnect,
		Attribution: procmodel.Attribution{
			SessionID:  "sA",
			Source:     procmodel.AttrHeuristic,
			Confidence: procmodel.ConfMedium,
		},
		TargetKind: "url",
		Target:     "https://api.openai.com/v1/responses",
		Details:    map[string]any{"capture_source": "proxy", "status_code": 502},
	}}); err != nil {
		t.Fatalf("PersistProcessEvents: %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/session/sA/processes", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var resp SessionProcessResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Total != 0 || resp.NetworkTotal != 1 {
		t.Fatalf("counts = process:%d network:%d, want 0/1", resp.Total, resp.NetworkTotal)
	}
	if resp.Diagnostics.ProxyOnlyNetworkEvents != 1 {
		t.Errorf("proxy-only network events = %d, want 1", resp.Diagnostics.ProxyOnlyNetworkEvents)
	}
	if !hasReason(resp.Diagnostics.ReasonCodes, "proxy_only_network_events") {
		t.Errorf("diagnostics reasons = %v, want proxy_only_network_events", resp.Diagnostics.ReasonCodes)
	}
}

func hasReason(reasons []string, want string) bool {
	for _, r := range reasons {
		if r == want {
			return true
		}
	}
	return false
}

// TestNodeFromRowLastSeenAt pins the last_seen_at field the Call stack view
// reads to draw an honest "exit not seen" bar: RFC3339 UTC when the capture
// recorded it, absent (empty) when it did not.
func TestNodeFromRowLastSeenAt(t *testing.T) {
	seen := time.Date(2026, 10, 15, 14, 5, 36, 0, time.FixedZone("x", 2*3600))
	cases := []struct {
		name string
		row  store.ProcessRunRow
		want string
	}{
		{"recorded", store.ProcessRunRow{ProcessKey: "k1", LastSeenAt: seen}, "2026-10-15T12:05:36Z"},
		{"zero time is absent", store.ProcessRunRow{ProcessKey: "k2"}, ""},
		{"running process keeps it", store.ProcessRunRow{ProcessKey: "k3", LastSeenAt: seen, Exited: false}, "2026-10-15T12:05:36Z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := nodeFromRow(tc.row, nil, nil, nil)
			if n.LastSeenAt != tc.want {
				t.Fatalf("LastSeenAt = %q, want %q", n.LastSeenAt, tc.want)
			}
			b, err := json.Marshal(n)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var m map[string]any
			if err := json.Unmarshal(b, &m); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			_, present := m["last_seen_at"]
			if present != (tc.want != "") {
				t.Fatalf("last_seen_at present=%v, want %v (omitempty)", present, tc.want != "")
			}
		})
	}
}
