package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestIsPolicyBlock table-drives the anti-flood gate directly: a block is
// enforced OR decided deny/ask, regardless of whether it's a tool-call
// verdict or a prompt-guard verdict (operator decision 2026-09-21 —
// prompt-guard rows are no longer excluded here; the frontend renderers
// label them distinctly instead). An informational flag/unenforced row is
// dropped either way.
func TestIsPolicyBlock(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		row  store.GuardEventAnchoredRow
		want bool
	}{
		{
			name: "tool-call enforced deny passes",
			row: store.GuardEventAnchoredRow{GuardEventRow: store.GuardEventRow{
				EventKind: "shell_exec", RuleID: "R-110", Decision: "deny", Enforced: true,
			}},
			want: true,
		},
		{
			name: "tool-call unenforced flag is dropped",
			row: store.GuardEventAnchoredRow{GuardEventRow: store.GuardEventRow{
				EventKind: "shell_exec", RuleID: "R-101", Decision: "flag", Enforced: false,
			}},
			want: false,
		},
		{
			name: "prompt-guard deny now passes (previously excluded)",
			row: store.GuardEventAnchoredRow{GuardEventRow: store.GuardEventRow{
				EventKind: "user_prompt", RuleID: "R-172", Decision: "deny", Enforced: false,
			}},
			want: true,
		},
		{
			name: "prompt-guard ask now passes (previously excluded)",
			row: store.GuardEventAnchoredRow{GuardEventRow: store.GuardEventRow{
				EventKind: "user_prompt", RuleID: "R-190", Decision: "ask", Enforced: false,
			}},
			want: true,
		},
		{
			name: "prompt-guard enforced now passes (previously excluded)",
			row: store.GuardEventAnchoredRow{GuardEventRow: store.GuardEventRow{
				EventKind: "user_prompt", RuleID: "R-172", Decision: "flag", Enforced: true,
			}},
			want: true,
		},
		{
			name: "prompt-guard unenforced flag is still dropped",
			row: store.GuardEventAnchoredRow{GuardEventRow: store.GuardEventRow{
				EventKind: "user_prompt", RuleID: "R-172", Decision: "flag", Enforced: false,
			}},
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isPolicyBlock(&tc.row); got != tc.want {
				t.Errorf("isPolicyBlock(%+v) = %v, want %v", tc.row, got, tc.want)
			}
		})
	}
}

// TestAPISessionGuardEvents pins /api/session/<id>/guard — the
// session-scoped feed the Messages tab merges into its timeline
// (docs/plans/loc-guardmsg-apm-followups-2026-09-21.md, Item 2). Reuses
// seedGuardEvents (guard_test.go): for session "sA", R-101 is an
// UNENFORCED `flag` and R-110 is an enforced `deny`; for "sB", R-152 is an
// unenforced `flag`. None of these are prompt-guard rows (event_kind
// shell_exec/file_access, not user_prompt), so they exercise the
// enforced/deny/ask half of isPolicyBlock; see
// TestAPISessionGuardEvents_IncludesPromptGuard for the prompt-guard half.
//
// DEFAULT FILTER: the handler drops informational flag-only rows unless
// ?include_flags=1 is passed (live-DB grounding: 34,406 tool-call guard
// events, all flag/unenforced on this observe-mode estate — see
// sessionguard.go's doc comment for the corrected population and why the
// first pass's "35 real blocks" figure was actually prompt-guard noise).
func TestAPISessionGuardEvents(t *testing.T) {
	t.Parallel()
	s, _ := newTestServer(t)
	seedGuardEvents(t, s)

	get := func(session, query string) (int, []map[string]any) {
		t.Helper()
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/session/"+session+"/guard"+query, nil))
		var resp struct {
			Events []map[string]any `json:"events"`
			Count  int              `json:"count"`
		}
		if rec.Code == 200 {
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
		}
		return rec.Code, resp.Events
	}

	// Default (no include_flags): sA's unenforced R-101 flag is dropped,
	// leaving only the enforced R-110 deny.
	code, evs := get("sA", "")
	if code != 200 {
		t.Fatalf("status = %d", code)
	}
	if len(evs) != 1 {
		t.Fatalf("sA default-filtered events = %d, want 1 (only the enforced deny; the unenforced flag must be dropped)", len(evs))
	}
	if evs[0]["rule_id"] != "R-110" || evs[0]["decision"] != "deny" || evs[0]["enforced"] != true {
		t.Errorf("sA[0] = %+v, want the enforced R-110 deny row", evs[0])
	}

	// sB's only row is an unenforced flag -> empty by default, not an error.
	if _, evs := get("sB", ""); len(evs) != 0 {
		t.Errorf("sB default-filtered events = %d, want 0 (its one row is an unenforced flag)", len(evs))
	}

	// include_flags=1 restores the full unbounded history for both.
	if _, evs := get("sA", "?include_flags=1"); len(evs) != 2 {
		t.Errorf("sA include_flags events = %d, want 2", len(evs))
	}
	if _, evs := get("sB", "?include_flags=1"); len(evs) != 1 {
		t.Errorf("sB include_flags events = %d, want 1", len(evs))
	}

	// A session with no guard history gets an honest empty list, not an
	// error — most sessions never trip a rule.
	code, evs = get("s-with-no-guard-history", "")
	if code != 200 || len(evs) != 0 {
		t.Errorf("unknown session = (%d, %d events), want (200, 0)", code, len(evs))
	}

	// Missing session id is a 400, not a panic or a silent all-sessions
	// dump. Exercised directly against the handler — "/api/session//guard"
	// never reaches it, since ServeMux 301-redirects the doubled slash away
	// first (router behavior, not this handler's concern).
	rec := httptest.NewRecorder()
	s.handleSessionGuardEvents(rec, httptest.NewRequest("GET", "/api/session//guard", nil), "")
	if rec.Code != 400 {
		t.Errorf("empty session id status = %d, want 400", rec.Code)
	}
}

// TestAPISessionGuardEvents_IncludesPromptGuard pins the operator decision
// (2026-09-21) reversing the prior exclusion: a prompt-guard verdict
// (R-172/R-190, event_kind=user_prompt) DOES surface through the default
// filter when it is enforced/deny/ask, alongside tool-call verdicts — the
// frontend is responsible for labelling the two distinctly. An unenforced
// prompt-guard flag is still dropped by the same anti-flood gate that
// drops unenforced tool-call flags.
func TestAPISessionGuardEvents_IncludesPromptGuard(t *testing.T) {
	t.Parallel()
	s, _ := newTestServer(t)
	st := store.New(s.opts.DB)
	ctx := context.Background()
	ts := time.Now().UTC()

	if _, err := st.InsertGuardEvents(ctx, []store.GuardEventRow{
		{
			TS: ts, SessionID: "sPrompt", Tool: "claude-code",
			EventKind: "user_prompt", RuleID: "R-172", Category: "secrets",
			Severity: "critical", Decision: "ask", Enforced: true, Source: "builtin",
			Reason: "detected github_pat in the prompt text",
		},
		{
			TS: ts.Add(time.Minute), SessionID: "sPrompt", Tool: "claude-code",
			EventKind: "shell_exec", RuleID: "R-110", Category: "destructive",
			Severity: "critical", Decision: "deny", Enforced: true, Source: "builtin",
			Reason: "force push to protected branch",
		},
		{
			TS: ts.Add(2 * time.Minute), SessionID: "sPrompt", Tool: "claude-code",
			EventKind: "user_prompt", RuleID: "R-190", Category: "pii",
			Severity: "low", Decision: "flag", Enforced: false, Source: "builtin",
			Reason: "possible email address in the prompt text",
		},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	get := func(query string) []map[string]any {
		t.Helper()
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/session/sPrompt/guard"+query, nil))
		if rec.Code != 200 {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Events []map[string]any `json:"events"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return resp.Events
	}

	evs := get("")
	if len(evs) != 2 {
		t.Fatalf("default-filtered events = %+v, want 2 (the tool-call R-110 deny AND the enforced R-172 prompt-guard ask; the unenforced R-190 flag stays dropped)", evs)
	}
	gotRules := map[string]bool{}
	for _, e := range evs {
		gotRules[fmt.Sprint(e["rule_id"])] = true
	}
	if !gotRules["R-110"] || !gotRules["R-172"] {
		t.Fatalf("default-filtered rule ids = %v, want R-110 and R-172 both present", gotRules)
	}

	all := get("?include_flags=1")
	if len(all) != 3 {
		t.Fatalf("include_flags events = %d, want 3 (all rows, including the unenforced prompt-guard flag)", len(all))
	}
}

// TestAPISessionGuardEvents_MessageAnchorResolution pins the LEFT JOIN in
// store.LoadGuardEventsForSessionWithMessageAnchor: a guard event whose
// action_id points at a real actions row surfaces that row's message_id on
// the wire, which is what the Messages tab's merge (@shared/lib/
// guardMessages) uses for exact placement instead of guessing from
// timestamps.
func TestAPISessionGuardEvents_MessageAnchorResolution(t *testing.T) {
	t.Parallel()
	s, _ := newTestServer(t)
	st := store.New(s.opts.DB)
	ctx := context.Background()
	root := t.TempDir()
	ts := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

	if _, err := st.Ingest(ctx, []models.ToolEvent{
		{
			SourceFile: "f", SourceEventID: "tu_anchor", SessionID: "sAnchor",
			ProjectRoot: root, Timestamp: ts, Tool: models.ToolClaudeCode,
			ActionType: models.ActionRunCommand, Target: "rm -rf /tmp/x", Success: true,
			MessageID: "msg_anchor_1",
		},
	}, nil, store.IngestOptions{}); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	var actionID int64
	if err := s.opts.DB.QueryRowContext(ctx,
		`SELECT id FROM actions WHERE session_id = ? AND source_event_id = ?`, "sAnchor", "tu_anchor",
	).Scan(&actionID); err != nil {
		t.Fatalf("resolve seeded action id: %v", err)
	}

	if _, err := st.InsertGuardEvents(ctx, []store.GuardEventRow{
		{
			TS: ts, SessionID: "sAnchor", ActionID: &actionID, Tool: "claude-code",
			EventKind: "shell_exec", RuleID: "R-101", Category: "destructive",
			Severity: "critical", Decision: "deny", Enforced: true, Source: "builtin",
			Reason: "rm -rf targeting tmp", TargetHash: "h1", TargetExcerpt: "rm -rf /tmp/x",
		},
	}); err != nil {
		t.Fatalf("seed guard event: %v", err)
	}

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/session/sAnchor/guard", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Events []struct {
			RuleID    string `json:"rule_id"`
			ActionID  int64  `json:"action_id"`
			MessageID string `json:"message_id"`
		} `json:"events"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(resp.Events))
	}
	if resp.Events[0].ActionID != actionID {
		t.Errorf("action_id = %d, want %d", resp.Events[0].ActionID, actionID)
	}
	if resp.Events[0].MessageID != "msg_anchor_1" {
		t.Errorf("message_id = %q, want %q (the LEFT JOIN onto actions must resolve it)", resp.Events[0].MessageID, "msg_anchor_1")
	}
}
