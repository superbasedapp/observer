package dashboard

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// promptCanarySecret is an obviously-fake, non-functional GitHub PAT
// shape (gh[pousr]_ + 20+ alnum, internal/scrub/detect.go's
// "github_pat" row) — long and distinctive enough that it could never
// appear in any response by coincidence. Never a real credential.
const promptCanarySecret = "ghp_CANARYVALUEMUSTNEVERAPPEARINANYRESPONSE1234567890" //nolint:gosec // G101: canary marker for TestGuardPromptEventsNeverLeaksCanary, never a real credential

// seedRealPromptGuardEvent runs the ACTUAL prompt-submit intervention
// pipeline (BuildPromptFindings -> EvaluatePrompt -> ActionVerdictFromPrompt
// -> PersistGuardVerdicts) over a prompt containing promptCanarySecret,
// exactly the sequence cmd/observer/hook.go's makePromptGuardPersist and
// internal/guard/proxyguard.go's scanPrompt run in production. This is
// deliberately NOT a hand-built store.GuardEventRow fixture: the point of
// the canary test is to catch a REGRESSION in the real pipeline (upstream
// OR this package's own event-JSON building), not just to assert that
// hand-written test data looks safe.
func seedRealPromptGuardEvent(t *testing.T, s *Server, sessionID string) {
	t.Helper()
	cfg := config.Default()
	g, err := guard.New(guard.Options{Config: cfg.Guard})
	if err != nil {
		t.Fatalf("guard.New: %v", err)
	}
	// Wire the reconsider-once store to the SAME db the test server
	// reads from — EvaluatePrompt fails closed (treats the prompt as
	// unwired -> block) without this, per promptguard.go's own doc
	// comment on promptReconsiderWired.
	st := store.New(s.opts.DB)
	g.SetPromptReconsiderStore(guard.PromptReconsiderFuncs{
		Lookup: func(fp string, now time.Time) (time.Time, bool, error) {
			row, ok, err := st.LookupPromptReconsider(context.Background(), fp, now)
			return row.WarnedAt, ok, err
		},
		Record: func(fp, sid, tool, detectors string, warnedAt, expiresAt time.Time) error {
			return st.RecordPromptWarned(context.Background(), store.PromptReconsiderRow{
				Fingerprint: fp, SessionID: sid, Tool: tool, Detectors: detectors,
				WarnedAt: warnedAt, ExpiresAt: expiresAt,
			})
		},
		Confirm: func(fp string, now time.Time) (bool, error) {
			return st.ConfirmPromptReconsider(context.Background(), fp, now)
		},
	})

	prompt := "here is my token: " + promptCanarySecret
	secrets, pii, truncated := g.BuildPromptFindings(prompt)
	if len(secrets) == 0 {
		t.Fatalf("test setup: canary secret was not detected by BuildPromptFindings (findings=%v)", secrets)
	}
	caps, _ := guard.CapabilitiesFor("claude-code", "hook:UserPromptSubmit")
	ev := policy.Event{
		Kind: policy.KindUserPrompt, Tool: "claude-code", SessionID: sessionID,
		Caps: caps, Secrets: secrets, PIIFindings: pii, PromptTruncated: truncated,
		Now: time.Now().UTC(),
	}
	pv := g.EvaluatePrompt(ev)
	em := guard.ResolveEmission(pv.Verdict, caps)
	av := g.ActionVerdictFromPrompt(pv, em, guard.ActionInput{
		SessionID: sessionID, Tool: "claude-code", ActionType: models.ActionUserPrompt,
		Timestamp: time.Now().UTC(),
	})
	if _, err := st.PersistGuardVerdicts(context.Background(), []guard.ActionVerdict{av}); err != nil {
		t.Fatalf("persist verdict: %v", err)
	}
	// Sanity: the row this test just wrote really is what the handler
	// under test will scan — a KindUserPrompt row is stored with
	// event_kind "user_prompt" (policy.EventKind's own String()/wire
	// value), matching handleGuardPromptEvents' filter.
	rows, err := st.LoadRecentGuardEvents(context.Background(), time.Now().Add(-time.Hour), 10)
	if err != nil {
		t.Fatalf("load seeded rows: %v", err)
	}
	found := false
	for _, r := range rows {
		if r.SessionID == sessionID && r.EventKind == "user_prompt" {
			found = true
		}
	}
	if !found {
		t.Fatalf("test setup: no user_prompt guard_events row landed for session %q (rows=%+v)", sessionID, rows)
	}
}

// TestGuardPromptEventsNeverLeaksCanary is the privacy canary this
// build's task requires: run the REAL detection+persistence pipeline
// over a prompt containing a distinctive, unmistakable secret value,
// then assert the value NEVER appears anywhere in
// GET /api/guard/prompt/events' response body — not in detectors, not
// in the fingerprint, not in any field. This pins the upstream
// invariant guard_prompt.go's package doc comment documents (Reason is
// always a content-free "type×count" summary, TargetExcerpt is always
// the opaque fingerprint, never the matched value) at the ACTUAL wire
// boundary the Security page reads, not just at the unit level.
func TestGuardPromptEventsNeverLeaksCanary(t *testing.T) {
	t.Parallel()
	s, _ := newTestServer(t)
	seedRealPromptGuardEvent(t, s, "canary-session")

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/guard/prompt/events?since=8760h&limit=50", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if body == "" || body == "{}" {
		t.Fatalf("expected at least one event in the response, got: %s", body)
	}
	if strings.Contains(body, promptCanarySecret) {
		t.Fatalf("CANARY LEAK: /api/guard/prompt/events response contains the matched secret value:\n%s", body)
	}
	// Also confirm the response contains SOMETHING for this session —
	// an empty-but-technically-canary-free response would pass the
	// Contains check above vacuously and hide a real regression
	// elsewhere (e.g. the event_kind filter silently dropping every
	// row).
	if !strings.Contains(body, "canary-session") {
		t.Fatalf("expected the seeded session id in the response (proves the row round-tripped, not just that it's absent): %s", body)
	}
	// The detector type name itself (github_pat) is fine to see — only
	// the VALUE is a canary.
	if !strings.Contains(body, "github_pat") {
		t.Errorf("expected the github_pat detector type to be named (content-free by design): %s", body)
	}

	// Same canary check against GET /api/guard/prompt/status (approvals
	// + pending rows carry detector-id CSV strings and session ids, but
	// never a matched value either).
	rec2 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec2, httptest.NewRequest("GET", "/api/guard/prompt/status", nil))
	if rec2.Code != 200 {
		t.Fatalf("status endpoint = %d: %s", rec2.Code, rec2.Body.String())
	}
	if strings.Contains(rec2.Body.String(), promptCanarySecret) {
		t.Fatalf("CANARY LEAK: /api/guard/prompt/status response contains the matched secret value:\n%s", rec2.Body.String())
	}
}
