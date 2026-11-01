package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/freshness"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// newGuardedStore wires a real Guard (built-ins only, observe mode)
// into a fresh test store — the §3.2 seam-3 composition the daemon
// does in cmd/observer/main.go::wireGuard.
func newGuardedStore(t *testing.T) *Store {
	t.Helper()
	s, _ := newTestStore(t)
	g, err := guard.New(guard.Options{
		Config: config.GuardConfig{
			Enabled: true, Mode: "observe",
			Taint: config.GuardTaintConfig{Enabled: true, DecayTurns: 10},
		},
		Home:     "/home/u",
		ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
	})
	if err != nil {
		t.Fatalf("guard.New: %v", err)
	}
	s.SetGuard(g)
	return s
}

// TestIngest_GuardSeam is the watcher-flagging end-to-end test (guard
// spec §7): a destructive command ingested through the normal batch
// path lands a guard_events row LINKED to its action row; benign
// actions stay silent; re-ingesting the same batch (watcher re-parse)
// adds NOTHING — dedup-skipped actions never re-evaluate.
func TestIngest_GuardSeam(t *testing.T) {
	t.Parallel()
	s := newGuardedStore(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)

	events := []models.ToolEvent{
		{
			SourceFile: "f.jsonl", SourceEventID: "e1", SessionID: "sG", ProjectRoot: "/home/u/proj",
			Timestamp: now, Tool: models.ToolClaudeCode, ActionType: models.ActionRunCommand,
			Target: "rm -rf ~/projects", Success: true,
		},
		{
			SourceFile: "f.jsonl", SourceEventID: "e2", SessionID: "sG", ProjectRoot: "/home/u/proj",
			Timestamp: now.Add(time.Second), Tool: models.ToolClaudeCode, ActionType: models.ActionRunCommand,
			Target: "go test ./...", Success: true,
		},
	}
	res, err := s.Ingest(ctx, events, nil, IngestOptions{})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if res.ActionsInserted != 2 {
		t.Fatalf("inserted = %d, want 2", res.ActionsInserted)
	}
	if res.GuardEventsRecorded != 1 {
		t.Fatalf("GuardEventsRecorded = %d, want 1 (only the rm -rf flags)", res.GuardEventsRecorded)
	}

	rows, err := s.LoadGuardEventsForSession(ctx, "sG")
	if err != nil {
		t.Fatalf("LoadGuardEventsForSession: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("guard rows = %d, want 1", len(rows))
	}
	row := rows[0]
	if row.RuleID != "R-101" || row.Category != "destructive" || row.Decision != "flag" {
		t.Errorf("row = %+v, want R-101/destructive/flag", row)
	}
	if row.EventKind != "shell_exec" || row.Tool != models.ToolClaudeCode {
		t.Errorf("row kind/tool = %s/%s", row.EventKind, row.Tool)
	}
	if row.ActionID == nil {
		t.Fatal("guard event not linked to its action row")
	}
	if row.Enforced {
		t.Error("post-hoc watcher verdict marked enforced")
	}
	// The anchor must point at the rm -rf action.
	var target string
	if err := s.db.QueryRowContext(ctx,
		`SELECT target FROM actions WHERE id = ?`, *row.ActionID).Scan(&target); err != nil {
		t.Fatalf("resolve anchored action: %v", err)
	}
	if target != "rm -rf ~/projects" {
		t.Errorf("anchored action target = %q", target)
	}
	if row.TargetHash == "" || row.TargetExcerpt != "rm -rf ~/projects" {
		t.Errorf("target hash/excerpt = %q/%q", row.TargetHash, row.TargetExcerpt)
	}

	// Idempotency: the watcher re-parses files constantly; the same
	// batch re-ingested dedups every action and must add ZERO guard
	// events (no re-evaluation of dedup-skipped rows).
	res, err = s.Ingest(ctx, events, nil, IngestOptions{})
	if err != nil {
		t.Fatalf("re-Ingest: %v", err)
	}
	if res.ActionsInserted != 0 || res.GuardEventsRecorded != 0 {
		t.Errorf("re-ingest = (actions %d, guard %d), want (0, 0)", res.ActionsInserted, res.GuardEventsRecorded)
	}
	if rows, _ = s.LoadGuardEventsForSession(ctx, "sG"); len(rows) != 1 {
		t.Errorf("guard rows after re-ingest = %d, want still 1", len(rows))
	}

	// The chain stays verifiable through the seam.
	report, err := s.VerifyGuardChain(ctx)
	if err != nil || !report.OK {
		t.Errorf("chain after ingest = (%+v, %v), want OK", report, err)
	}
}

// TestIngest_GuardSeamFileActionReparse pins the file-action branch of the
// same idempotency rule. File actions insert one at a time through
// insertSingleAction (the freshness classifier path), whose upsert takes
// the UPDATE branch on a re-read; it used to report that as an insert, so
// every whole-store re-parse (deepagents-code, stakpak, ibm-bob, dimcode,
// kiro-cli...) wrote the same file_access flag again.
func TestIngest_GuardSeamFileActionReparse(t *testing.T) {
	t.Parallel()
	s := newGuardedStore(t)
	ctx := context.Background()
	classifier := freshness.New(s.db, freshness.Options{MaxHashSizeMB: 10, FastPathStatOnly: true})
	now := time.Date(2026, 10, 21, 18, 30, 0, 0, time.UTC)

	events := []models.ToolEvent{{
		SourceFile: "sessions.db", SourceEventID: "read:1", SessionID: "sF", ProjectRoot: "/home/u/proj",
		Timestamp: now, Tool: models.ToolDeepAgentsCode, ActionType: models.ActionReadFile,
		Target: "/home/u/.ssh/id_rsa", Success: true, RawToolName: "read_file",
	}}
	opts := IngestOptions{Classifier: classifier}

	res, err := s.Ingest(ctx, events, nil, opts)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if res.ActionsInserted != 1 || res.GuardEventsRecorded != 1 {
		t.Fatalf("first ingest = (actions %d, guard %d), want (1, 1)", res.ActionsInserted, res.GuardEventsRecorded)
	}

	for pass := 2; pass <= 4; pass++ {
		res, err = s.Ingest(ctx, events, nil, opts)
		if err != nil {
			t.Fatalf("re-Ingest pass %d: %v", pass, err)
		}
		if res.ActionsInserted != 0 || res.GuardEventsRecorded != 0 {
			t.Errorf("re-ingest pass %d = (actions %d, guard %d), want (0, 0)",
				pass, res.ActionsInserted, res.GuardEventsRecorded)
		}
	}
	rows, err := s.LoadGuardEventsForSession(ctx, "sF")
	if err != nil {
		t.Fatalf("LoadGuardEventsForSession: %v", err)
	}
	if len(rows) != 1 || rows[0].EventKind != "file_access" || rows[0].ActionID == nil {
		t.Errorf("guard rows after re-parses = %+v, want one linked file_access row", rows)
	}
}

// TestIngest_NoGuardIsNoop pins the nil-guard baseline: without
// SetGuard the ingest path writes no guard rows and reports zero.
func TestIngest_NoGuardIsNoop(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()
	res, err := s.Ingest(ctx, []models.ToolEvent{
		{
			SourceFile: "f.jsonl", SourceEventID: "e1", SessionID: "sN", ProjectRoot: "/p",
			Timestamp: time.Now().UTC(), Tool: models.ToolClaudeCode,
			ActionType: models.ActionRunCommand, Target: "rm -rf ~/x", Success: true,
		},
	}, nil, IngestOptions{})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if res.GuardEventsRecorded != 0 {
		t.Errorf("GuardEventsRecorded = %d, want 0 without a guard", res.GuardEventsRecorded)
	}
	var n int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM guard_events`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("guard_events rows = %d, want 0", n)
	}
}

// TestPersistGuardVerdicts_ProxySeam pins the proxy-seam translation
// (G9): an egress mask verdict persists with decision="mask" (the
// §8.2 proxy-only decision string, substituted for the policy
// decision at this one seam), unanchored (both action_id and
// api_turn_id NULL — proxy events precede any row they could anchor
// to), and the chain stays verifiable with the extra vocabulary.
func TestPersistGuardVerdicts_ProxySeam(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)

	verdicts := []guard.ActionVerdict{
		{
			Input:    guard.ActionInput{SessionID: "sP", Target: "anthropic:claude-opus-4-8", Timestamp: now},
			Kind:     "api_request",
			Category: "exfil",
			Verdict: policy.Verdict{
				Decision: policy.DecisionFlag, RuleID: "R-172",
				Severity: policy.SeverityCritical,
				Reason:   "secret-shaped content in an outbound LLM API request: detected github_pat×2",
				Source:   "builtin",
			},
			Enforced:    true,
			ProxyAction: "mask",
		},
	}
	if _, err := s.PersistGuardVerdicts(ctx, verdicts); err != nil {
		t.Fatalf("PersistGuardVerdicts: %v", err)
	}
	rows, err := s.LoadGuardEventsForSession(ctx, "sP")
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows = %+v (err %v), want 1", rows, err)
	}
	row := rows[0]
	if row.Decision != "mask" {
		t.Errorf("decision = %q, want the proxy-only \"mask\" string", row.Decision)
	}
	if !row.Enforced || row.RuleID != "R-172" || row.EventKind != "api_request" {
		t.Errorf("row = %+v, want enforced R-172 api_request", row)
	}
	if row.ActionID != nil || row.APITurnID != nil {
		t.Errorf("anchors = (%v, %v), want both NULL on the proxy seam", row.ActionID, row.APITurnID)
	}
	report, err := s.VerifyGuardChain(ctx)
	if err != nil || !report.OK {
		t.Errorf("chain = (%+v, %v), want OK", report, err)
	}
}

// TestPersistGuardVerdicts_APITurnAnchor pins the P6 GuardVerdict follow-up:
// a verdict carrying Input.APITurnID (the proxy response-inspection anchor)
// persists guard_events.api_turn_id, so the obs trajectory enrichment can join
// the verdict to the span by api_turn id. The chain stays valid (api_turn_id
// is part of the canonical row bytes).
func TestPersistGuardVerdicts_APITurnAnchor(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC)

	// api_turn_id is a real FK → seed a proxy turn and anchor to its id.
	turnID, err := s.InsertAPITurn(ctx, models.APITurn{
		Provider: "anthropic", Model: "claude-opus-4-8", RequestID: "req-anchor",
		InputTokens: 10, OutputTokens: 5, Source: SourceProxy, Timestamp: now,
	})
	if err != nil {
		t.Fatalf("InsertAPITurn: %v", err)
	}

	verdicts := []guard.ActionVerdict{{
		Input:    guard.ActionInput{SessionID: "sT", Target: "Bash:rm -rf ~", Timestamp: now, APITurnID: turnID},
		Kind:     "tool_use",
		Category: "destructive",
		Verdict: policy.Verdict{
			Decision: policy.DecisionFlag, RuleID: "R-101",
			Severity: policy.SeverityHigh, Reason: "destructive command in model response", Source: "builtin",
		},
	}}
	if _, err := s.PersistGuardVerdicts(ctx, verdicts); err != nil {
		t.Fatalf("PersistGuardVerdicts: %v", err)
	}
	rows, err := s.LoadGuardEventsForSession(ctx, "sT")
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows = %+v (err %v), want 1", rows, err)
	}
	if rows[0].APITurnID == nil || *rows[0].APITurnID != turnID {
		t.Errorf("api_turn_id = %v, want %d", rows[0].APITurnID, turnID)
	}
	if rows[0].ActionID != nil {
		t.Errorf("action_id = %v, want NULL on the proxy response-inspection seam", rows[0].ActionID)
	}
	if report, err := s.VerifyGuardChain(ctx); err != nil || !report.OK {
		t.Errorf("chain = (%+v, %v), want OK", report, err)
	}
}
