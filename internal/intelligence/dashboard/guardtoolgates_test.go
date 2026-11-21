package dashboard

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// TestAPIGuardSummaryToolGates pins the T-340 follow-up: /api/guard/summary
// carries the daemon's per-tool node state (does the hook_block tool's
// tool-gate hook hold here, and the channel it falls back to), and omits it
// when no seam is wired rather than showing the bare capability.
func TestAPIGuardSummaryToolGates(t *testing.T) {
	t.Parallel()
	get := func(t *testing.T, s *Server) map[string]any {
		t.Helper()
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/guard/summary", nil))
		if rec.Code != 200 {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
		}
		var m map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return m
	}
	t.Run("no seam: absent", func(t *testing.T) {
		s, _ := newTestServer(t)
		if v, ok := get(t, s)["tool_gates"]; ok {
			t.Fatalf("tool_gates = %v, want absent with no seam", v)
		}
	})
	t.Run("seam rows", func(t *testing.T) {
		s, _ := newTestServer(t)
		s.opts.GuardToolGates = func() []GuardToolGate {
			return []GuardToolGate{
				{Tool: "claude-code", Channel: "hook_block", Current: true, Installed: true, Reason: "its PreToolUse hook is registered and current"},
				{Tool: "codex", Channel: "sandbox_enforce", Installed: true, Reason: "its PreToolUse hook is missing or stale", Fixable: true},
			}
		}
		rows, ok := get(t, s)["tool_gates"].([]any)
		if !ok || len(rows) != 2 {
			t.Fatalf("tool_gates = %v, want 2 rows", rows)
		}
		r := rows[1].(map[string]any)
		if r["tool"] != "codex" || r["channel"] != "sandbox_enforce" || r["current"] != false || r["installed"] != true || r["reason"] != "its PreToolUse hook is missing or stale" || r["fixable"] != true {
			t.Errorf("row = %v", r)
		}
	})
}
