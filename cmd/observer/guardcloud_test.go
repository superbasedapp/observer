package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// cloudStubDoer records outbound requests and serves canned per-URL
// responses.
type cloudStubDoer struct {
	mu     sync.Mutex
	urls   []string
	bodies [][]byte
	// respond maps an endpoint URL to its response body (200).
	respond map[string]string
}

func (d *cloudStubDoer) Do(r *http.Request) (*http.Response, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
	}
	d.urls = append(d.urls, r.URL.String())
	d.bodies = append(d.bodies, body)
	resp := d.respond[r.URL.String()]
	return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader([]byte(resp)))}, nil
}

func (d *cloudStubDoer) snapshot() ([]string, [][]byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.urls...), append([][]byte(nil), d.bodies...)
}

func newCloudTestStore(t *testing.T) *store.Store {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "observer.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return store.New(database)
}

// insertGuardEvent appends one event and returns its assigned id.
func insertGuardEvent(t *testing.T, st *store.Store, sessionID, ruleID, severity, decision, source string) int64 {
	t.Helper()
	ctx := context.Background()
	if _, err := st.InsertGuardEvents(ctx, []store.GuardEventRow{{
		TS: time.Now().UTC(), SessionID: sessionID, Tool: "claude-code",
		EventKind: "shell_exec", RuleID: ruleID, Category: "destructive",
		Severity: severity, Decision: decision, Source: source,
		Reason: "test verdict", TargetExcerpt: "rm -rf /x", TargetHash: "th",
	}}); err != nil {
		t.Fatalf("insert guard event: %v", err)
	}
	rows, err := st.GuardEventsAfter(ctx, 0, 0)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	return rows[len(rows)-1].ID
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestCloudDispatcher_FirstEnableAnchorsAtTail(t *testing.T) {
	st := newCloudTestStore(t)
	ctx := context.Background()
	insertGuardEvent(t, st, "s1", "R-001", "high", "deny", "hook") // pre-existing history

	doer := &cloudStubDoer{}
	d := newCloudDispatcher(config.GuardCloudConfig{
		Enabled: true, PayloadMaxBytes: 4096,
		Webhooks: []config.GuardWebhookConfig{{URL: "https://hooks.example/w", Kind: "generic"}},
	}, st, quietLogger(), doer)
	defer d.egress.Close()

	if err := d.anchorCursor(ctx); err != nil {
		t.Fatalf("anchor: %v", err)
	}
	d.sweep(ctx)
	d.egress.Close()
	if urls, _ := doer.snapshot(); len(urls) != 0 {
		t.Errorf("pre-existing history dispatched on first enable: %v", urls)
	}
}

func TestCloudDispatcher_WebhookSeverityFanout(t *testing.T) {
	st := newCloudTestStore(t)
	ctx := context.Background()
	doer := &cloudStubDoer{}
	d := newCloudDispatcher(config.GuardCloudConfig{
		Enabled: true, PayloadMaxBytes: 4096,
		Webhooks: []config.GuardWebhookConfig{
			{URL: "https://hooks.example/high", Kind: "generic"},                          // default min high
			{URL: "https://hooks.example/all", Kind: "slack", MinSeverity: "info"},        // everything
			{URL: "https://hooks.example/crit", Kind: "generic", MinSeverity: "critical"}, // critical only
		},
	}, st, quietLogger(), doer)
	if err := d.anchorCursor(ctx); err != nil {
		t.Fatalf("anchor: %v", err)
	}

	insertGuardEvent(t, st, "s1", "R-001", "high", "deny", "hook")
	d.sweep(ctx)
	d.egress.Close()

	urls, bodies := doer.snapshot()
	got := strings.Join(urls, " ")
	if !strings.Contains(got, "/high") || !strings.Contains(got, "/all") || strings.Contains(got, "/crit") {
		t.Errorf("fanout urls = %v, want high+all, not crit", urls)
	}
	for i, u := range urls {
		if strings.Contains(u, "/all") && !strings.Contains(string(bodies[i]), `"text"`) {
			t.Errorf("slack body shape missing: %s", bodies[i])
		}
	}

	// Cursor advanced: a second sweep dispatches nothing new.
	doer2 := &cloudStubDoer{}
	d2 := newCloudDispatcher(d.cfg, st, quietLogger(), doer2)
	d2.sweep(ctx)
	d2.egress.Close()
	if urls2, _ := doer2.snapshot(); len(urls2) != 0 {
		t.Errorf("re-sweep re-dispatched: %v", urls2)
	}
}

// judgeResponse builds a chat-completions body carrying the verdict.
func judgeResponse(verdict string, confidence float64, rationale string) string {
	inner, _ := json.Marshal(map[string]any{"verdict": verdict, "confidence": confidence, "rationale": rationale})
	outer, _ := json.Marshal(map[string]any{
		"choices": []map[string]any{{"message": map[string]string{"content": string(inner)}}},
	})
	return string(outer)
}

func TestCloudDispatcher_JudgeFlow(t *testing.T) {
	const endpoint = "https://judge.example/v1/chat/completions"
	cases := []struct {
		name         string
		decision     string
		verdict      string
		confidence   float64
		wantApproval bool
	}{
		{"high_confidence_allow_resolves_ask", "ask", "allow", 0.9, true},
		{"low_confidence_allow_records_only", "ask", "allow", 0.4, false},
		{"allow_on_flag_records_only", "flag", "allow", 0.9, false},
		{"deny_verdict_never_approves", "ask", "deny", 0.95, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newCloudTestStore(t)
			ctx := context.Background()
			doer := &cloudStubDoer{respond: map[string]string{
				endpoint: judgeResponse(tc.verdict, tc.confidence, "because"),
			}}
			d := newCloudDispatcher(config.GuardCloudConfig{
				Enabled: true, PayloadMaxBytes: 4096,
				LLMJudge: config.GuardLLMJudgeConfig{Enabled: true, Endpoint: endpoint, Model: "m"},
			}, st, quietLogger(), doer)
			if err := d.anchorCursor(ctx); err != nil {
				t.Fatalf("anchor: %v", err)
			}

			insertGuardEvent(t, st, "s1", "R-110", "high", tc.decision, "hook")
			d.sweep(ctx)
			d.egress.Close() // drains the judge call + its onResult completion

			// The review is recorded as a guard event with the §15.2 source.
			rows, err := st.GuardEventsAfter(ctx, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			var judged *store.GuardEventRow
			for i := range rows {
				if rows[i].Source == "llm_judge" {
					judged = &rows[i]
				}
			}
			if judged == nil {
				t.Fatalf("no llm_judge event recorded; rows=%d", len(rows))
			}
			if judged.Decision != tc.verdict || judged.Enforced || judged.RuleID != "R-110" {
				t.Errorf("judge row = %+v", judged)
			}
			if !strings.Contains(judged.Reason, "confidence") {
				t.Errorf("judge reason = %q", judged.Reason)
			}

			// Approval only for the high-confidence allow on an ask.
			got := st.ApprovalActiveFor(ctx, "R-110", "s1", "", time.Now().UTC())
			if got != tc.wantApproval {
				t.Errorf("approval active = %v, want %v", got, tc.wantApproval)
			}
		})
	}
}

func TestCloudDispatcher_JudgeRowsNotReReviewed(t *testing.T) {
	const endpoint = "https://judge.example/v1/chat/completions"
	st := newCloudTestStore(t)
	ctx := context.Background()
	doer := &cloudStubDoer{respond: map[string]string{
		endpoint: judgeResponse("allow", 0.9, "ok"),
	}}
	cfg := config.GuardCloudConfig{
		Enabled: true, PayloadMaxBytes: 4096,
		LLMJudge: config.GuardLLMJudgeConfig{Enabled: true, Endpoint: endpoint, Model: "m"},
	}
	d := newCloudDispatcher(cfg, st, quietLogger(), doer)
	if err := d.anchorCursor(ctx); err != nil {
		t.Fatal(err)
	}
	insertGuardEvent(t, st, "s1", "R-110", "high", "ask", "hook")
	d.sweep(ctx)
	d.egress.Close() // records the judge row

	// Next sweep sees the judge row; it must not submit another review.
	doer2 := &cloudStubDoer{respond: doer.respond}
	d2 := newCloudDispatcher(cfg, st, quietLogger(), doer2)
	d2.sweep(ctx)
	d2.egress.Close()
	if urls, _ := doer2.snapshot(); len(urls) != 0 {
		t.Errorf("judge row re-reviewed: %v", urls)
	}
}

func TestCloudDispatcher_DenyNeverJudged(t *testing.T) {
	const endpoint = "https://judge.example/v1/chat/completions"
	st := newCloudTestStore(t)
	ctx := context.Background()
	doer := &cloudStubDoer{}
	d := newCloudDispatcher(config.GuardCloudConfig{
		Enabled: true, PayloadMaxBytes: 4096,
		LLMJudge: config.GuardLLMJudgeConfig{Enabled: true, Endpoint: endpoint, Model: "m"},
	}, st, quietLogger(), doer)
	if err := d.anchorCursor(ctx); err != nil {
		t.Fatal(err)
	}
	insertGuardEvent(t, st, "s1", "R-001", "critical", "deny", "hook")
	d.sweep(ctx)
	d.egress.Close()
	if urls, _ := doer.snapshot(); len(urls) != 0 {
		t.Errorf("clear deny shipped to the judge: %v", urls)
	}
}

func TestCloudDispatcher_HasEventFeatures(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.GuardCloudConfig
		want bool
	}{
		{"nothing_configured", config.GuardCloudConfig{Enabled: true}, false},
		{"reputation_only_is_not_event_fed", config.GuardCloudConfig{
			Enabled: true, Reputation: config.GuardReputationConfig{Enabled: true},
		}, false},
		{"webhook_configured", config.GuardCloudConfig{
			Enabled: true, Webhooks: []config.GuardWebhookConfig{{URL: "https://h/x"}},
		}, true},
		{"judge_configured", config.GuardCloudConfig{
			Enabled: true, LLMJudge: config.GuardLLMJudgeConfig{Enabled: true, Endpoint: "https://j"},
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newCloudTestStore(t)
			d := newCloudDispatcher(tc.cfg, st, quietLogger(), &cloudStubDoer{})
			defer d.egress.Close()
			if got := d.hasEventFeatures(); got != tc.want {
				t.Errorf("hasEventFeatures = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGuardMCPReputationCmd_RequiresOptIn(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfgBody := "[observer]\ndb_path = '" + filepath.ToSlash(filepath.Join(dir, "o.db")) + "'\n"
	if err := os.WriteFile(cfgPath, []byte(cfgBody), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newGuardMCPReputationCmd()
	cmd.SetArgs([]string{"left-pad", "--config", cfgPath})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "opt in") {
		t.Errorf("without opt-in err = %v, want D1 refusal", err)
	}
}
