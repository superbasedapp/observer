package prove_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/foundry"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/prove"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

const (
	proveKey  = "prove-lane-key-do-not-reuse"
	workerKey = "PRODUCTION-WORKER-KEY-MUST-NEVER-APPEAR"
	routeID   = "session_enrichment.luna.prove"
)

// --- fakes -----------------------------------------------------------------

// fakeControl is a scripted ControlPlane. It records every read so a test can
// prove a gate ran (or did not).
type fakeControl struct {
	route        store.RouteInfo
	routeErr     error
	dialectOK    bool
	dialectErr   error
	routeReads   int
	dialectReads int
}

func (c *fakeControl) RouteByID(context.Context, string) (store.RouteInfo, error) {
	c.routeReads++
	return c.route, c.routeErr
}

func (c *fakeControl) DialectVerified(context.Context, store.RouteInfo, time.Time) (bool, error) {
	c.dialectReads++
	return c.dialectOK, c.dialectErr
}

type fakeAttestor struct {
	verified bool
	reason   string
	err      error
	calls    int
}

func (a *fakeAttestor) Attest(context.Context, store.RouteInfo, time.Time) (jobs.Attestation, error) {
	a.calls++
	if a.err != nil {
		return jobs.Attestation{}, a.err
	}
	return jobs.Attestation{Verified: a.verified, Reason: a.reason}, nil
}

// fakeFoundry is an httptest Azure OpenAI endpoint. It records the api-key
// header and the exact user message of every request, and answers with a
// caller-chosen completion — so the tests drive the REAL foundry.AzureClient
// over real HTTP rather than stubbing the provider seam.
type fakeFoundry struct {
	srv *httptest.Server

	mu      sync.Mutex
	calls   int
	apiKeys []string
	systems []string
	users   []string
	paths   []string
	status  int    // non-zero ⇒ answer this status instead of a completion
	content string // the model's structured output
}

func newFakeFoundry(t *testing.T, content string) *fakeFoundry {
	t.Helper()
	f := &fakeFoundry{content: content}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var req struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(body, &req)
		f.mu.Lock()
		f.calls++
		f.apiKeys = append(f.apiKeys, r.Header.Get("api-key"))
		f.paths = append(f.paths, r.URL.Path)
		for _, m := range req.Messages {
			switch m.Role {
			case "system":
				f.systems = append(f.systems, m.Content)
			case "user":
				f.users = append(f.users, m.Content)
			}
		}
		status, content := f.status, f.content
		f.mu.Unlock()

		if status != 0 {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"synthetic provider failure"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Answer in the shape the requested surface uses, so the tests drive the
		// real client's per-dialect parsing rather than one canned body.
		var resp map[string]any
		if strings.Contains(r.URL.Path, "/openai/responses") {
			resp = map[string]any{
				"output_text": content,
				"usage":       map[string]any{"input_tokens": 123, "output_tokens": 45},
			}
		} else {
			resp = map[string]any{
				"choices": []map[string]any{{"message": map[string]any{"content": content}}},
				"usage":   map[string]any{"prompt_tokens": 123, "completion_tokens": 45},
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeFoundry) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeFoundry) snapshot() (apiKeys, systems, users, paths []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.apiKeys...), append([]string(nil), f.systems...),
		append([]string(nil), f.users...), append([]string(nil), f.paths...)
}

func (f *fakeFoundry) setStatus(code int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = code
}

// resultJSON builds a valid session_enrichment.v2-candidate completion.
func resultJSON(title string, refs []string) string {
	r := cloudcontract.Result{
		Title: title, Description: "synthetic fixture summary", TaxonomyTags: []string{"refactor"},
		SuggestedTags: []string{"fixture"}, Confidence: cloudcontract.ConfidenceLow,
		EvidenceRefs: refs, Limitations: []string{"synthetic fixture, not a real session"},
		SchemaVersion: cloudcontract.ResultSchemaVersion,
	}
	b, _ := json.Marshal(r)
	return string(b)
}

func activeRoute(t *testing.T, endpoint, dialect string) store.RouteInfo {
	t.Helper()
	return store.RouteInfo{
		RouteID: routeID, Feature: store.FeatureSessionEnrichment,
		Deployment: "luna-prove", Dialect: dialect, RouteVersion: 1, PromptVersion: 1,
		PriceVersion: "p1", Active: true, Generation: 7,
		// The proving lane accepts ONLY a route the operator has classified
		// non-production (F10). The column defaults to 'production', so every
		// fixture route here has to say so explicitly — which is exactly the
		// fail-closed posture under test.
		Environment: store.RouteEnvironmentNonProduction,
		Endpoint:    endpoint, APIVersion: "2024-10-21", MaxOutputTokens: 800,
		InputPricePerMTok: 1, OutputPricePerMTok: 2,
		TenantID: "t", SubscriptionID: "s", ARMResourceID: "/subscriptions/s/x", EndpointAudience: "https://management.azure.com",
	}
}

// stepStatus returns the status recorded for a step, or "" when absent.
func stepStatus(fr prove.FixtureReport, step prove.Step) prove.Status {
	for _, s := range fr.Steps {
		if s.Step == step {
			return s.Status
		}
	}
	return ""
}

// --- end-to-end ------------------------------------------------------------

// TestProvePipelineEndToEnd drives every compiled-in fixture through the REAL
// foundry.AzureClient against a fake Azure endpoint, with the real
// jobs.BuildLunaPrompt / BuildLunaRequest / ProcessLunaCompletion stages. It is
// deliverable 3's proof: the lane exercises the worker's actual code path.
func TestProvePipelineEndToEnd(t *testing.T) {
	fake := newFakeFoundry(t, resultJSON("SYNTHETIC FIXTURE session", []string{"metrics", "a1"}))
	control := &fakeControl{route: activeRoute(t, fake.srv.URL, string(foundry.DialectChatCompletions))}
	att := &fakeAttestor{verified: true, reason: "ContentLogging disabled"}

	var audits []string
	rep, err := prove.Run(context.Background(), prove.Options{
		FoundryAPIKey: proveKey,
		RouteID:       routeID,
		Control:       control,
		Attestor:      att,
		Provider:      &foundry.AzureClient{},
		Audit: func(_ context.Context, eventType, detail string) error {
			audits = append(audits, eventType+" "+detail)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !rep.Passed() {
		var buf bytes.Buffer
		rep.Print(&buf)
		t.Fatalf("run did not pass:\n%s", buf.String())
	}
	catalog := prove.Catalog()
	if len(rep.Fixtures) != len(catalog) {
		t.Fatalf("reported %d fixtures, catalog has %d", len(rep.Fixtures), len(catalog))
	}
	if fake.callCount() != len(catalog) {
		t.Fatalf("provider called %d times, want one per fixture (%d)", fake.callCount(), len(catalog))
	}
	if att.calls != len(catalog) {
		t.Fatalf("attestor called %d times, want one per fixture (%d)", att.calls, len(catalog))
	}
	if control.routeReads != len(catalog) {
		t.Fatalf("route resolved %d times, want one per fixture (%d)", control.routeReads, len(catalog))
	}
	// chat_completions needs no dialect record — the gate must be SKIPPED, not
	// silently passed, and the store must not have been read for it.
	if control.dialectReads != 0 {
		t.Fatalf("dialect record read %d times for a chat_completions route", control.dialectReads)
	}
	for _, fr := range rep.Fixtures {
		if got := stepStatus(fr, prove.StepDialect); got != prove.StatusSkip {
			t.Fatalf("fixture %s dialect step = %q, want SKIP (not applicable)", fr.Fixture, got)
		}
		for _, step := range []prove.Step{prove.StepFixture, prove.StepRoute, prove.StepAttestation, prove.StepProvider, prove.StepNormalize} {
			if got := stepStatus(fr, step); got != prove.StatusPass {
				t.Fatalf("fixture %s step %s = %q, want PASS", fr.Fixture, step, got)
			}
		}
	}

	apiKeys, systems, users, paths := fake.snapshot()
	for i, k := range apiKeys {
		if k != proveKey {
			t.Fatalf("request %d carried api-key %q, want the explicit prove-lane key", i, k)
		}
	}
	for i, p := range paths {
		if !strings.Contains(p, "/openai/deployments/luna-prove/chat/completions") {
			t.Fatalf("request %d hit %q, not the route's deployment path", i, p)
		}
	}
	// The worker's evidence-as-data framing must be on the wire, unchanged.
	for i, sys := range systems {
		if !strings.Contains(sys, "UNTRUSTED DATA") || !strings.Contains(sys, "MUST NOT") {
			t.Fatalf("system prompt %d is not the worker's evidence-as-data framing:\n%s", i, sys)
		}
	}
	// The adversarial fixture's forged close marker must sit INSIDE the real
	// per-request fence (FE2), not terminate it.
	var canary string
	for _, u := range users {
		if strings.Contains(u, "IGNORE PREVIOUS INSTRUCTIONS") {
			canary = u
		}
	}
	if canary == "" {
		t.Fatal("the injection_canary fixture never reached the provider")
	}
	begin := strings.Index(canary, "BEGIN EVIDENCE")
	last := strings.LastIndex(canary, "END EVIDENCE")
	inj := strings.Index(canary, "IGNORE PREVIOUS INSTRUCTIONS")
	if begin < 0 || last < 0 || !(begin < inj && inj < last) {
		t.Fatalf("injection bait not enclosed by the real fence (begin=%d inj=%d end=%d)", begin, inj, last)
	}

	if len(audits) != 1 {
		t.Fatalf("want exactly one audit event, got %d: %v", len(audits), audits)
	}
	if !rep.AuditRecorded {
		t.Fatalf("report says the audit was not recorded: %q", rep.AuditDetail)
	}
	if !strings.HasPrefix(audits[0], prove.AuditEventType+" ") {
		t.Fatalf("audit event type wrong: %q", audits[0])
	}
	// The audit detail is content-free: counts and the route id only.
	detail := strings.TrimPrefix(audits[0], prove.AuditEventType+" ")
	if !json.Valid([]byte(detail)) {
		t.Fatalf("audit detail is not valid JSON: %q", detail)
	}
	for _, leak := range []string{prove.SyntheticMarker, "lorem", "IGNORE PREVIOUS", proveKey} {
		if strings.Contains(detail, leak) {
			t.Fatalf("audit detail leaked %q: %q", leak, detail)
		}
	}
}

// TestProveReportNeverPrintsTheCredential pins that the printed report — the
// artifact an operator pastes into a ticket — cannot carry the prove key.
func TestProveReportNeverPrintsTheCredential(t *testing.T) {
	fake := newFakeFoundry(t, resultJSON("SYNTHETIC FIXTURE session", []string{"metrics"}))
	rep, err := prove.Run(context.Background(), prove.Options{
		FoundryAPIKey: proveKey,
		RouteID:       routeID,
		Control:       &fakeControl{route: activeRoute(t, fake.srv.URL, string(foundry.DialectChatCompletions))},
		Attestor:      &fakeAttestor{verified: true, reason: "ok"},
		Provider:      &foundry.AzureClient{},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var buf bytes.Buffer
	rep.Print(&buf)
	if strings.Contains(buf.String(), proveKey) {
		t.Fatal("the printed report contains the provider credential")
	}
	if !strings.Contains(buf.String(), "audit: NOT recorded") {
		t.Fatalf("a run with no auditor must SAY so, not silently omit it:\n%s", buf.String())
	}
}

// --- per-step failure ------------------------------------------------------

// TestProveFailsAtEachStep drives one deliberate failure per pipeline step and
// asserts it surfaces as THAT step's FAIL, with every later step SKIP (never a
// pass), and with no provider call for the gates that precede dispatch.
func TestProveFailsAtEachStep(t *testing.T) {
	cases := []struct {
		name          string
		wantStep      prove.Step
		dialect       string
		mutate        func(c *fakeControl, a *fakeAttestor, f *fakeFoundry)
		wantProvider  int
		wantDetailSub string
	}{
		{
			name: "route_unresolvable", wantStep: prove.StepRoute,
			dialect: string(foundry.DialectChatCompletions),
			mutate: func(c *fakeControl, _ *fakeAttestor, _ *fakeFoundry) {
				c.routeErr = store.ErrNotFound
			},
			wantDetailSub: "not resolvable",
		},
		{
			name: "route_inactive", wantStep: prove.StepRoute,
			dialect: string(foundry.DialectChatCompletions),
			mutate: func(c *fakeControl, _ *fakeAttestor, _ *fakeFoundry) {
				c.route.Active = false
			},
			wantDetailSub: "INACTIVE",
		},
		{
			// F10: the lane refuses a PRODUCTION route even when it is active
			// and everything else would pass. 'production' is the column's
			// DEFAULT, so this also covers an unclassified route.
			name: "route_is_production", wantStep: prove.StepRoute,
			dialect: string(foundry.DialectChatCompletions),
			mutate: func(c *fakeControl, _ *fakeAttestor, _ *fakeFoundry) {
				c.route.Environment = store.RouteEnvironmentProduction
			},
			wantDetailSub: "environment=",
		},
		{
			// An empty environment is what a route read by a client that predates
			// the column would look like. It is not 'nonproduction', so it is
			// refused: the lane never proves against a route it cannot classify.
			name: "route_environment_unset", wantStep: prove.StepRoute,
			dialect: string(foundry.DialectChatCompletions),
			mutate: func(c *fakeControl, _ *fakeAttestor, _ *fakeFoundry) {
				c.route.Environment = ""
			},
			wantDetailSub: "accepts only",
		},
		{
			name: "attestation_unverified", wantStep: prove.StepAttestation,
			dialect: string(foundry.DialectChatCompletions),
			mutate: func(_ *fakeControl, a *fakeAttestor, _ *fakeFoundry) {
				a.verified, a.reason = false, "ContentLogging is enabled"
			},
			wantDetailSub: "NOT verified",
		},
		{
			name: "attestation_error", wantStep: prove.StepAttestation,
			dialect: string(foundry.DialectChatCompletions),
			mutate: func(_ *fakeControl, a *fakeAttestor, _ *fakeFoundry) {
				a.err = errors.New("ARM unreachable")
			},
			wantDetailSub: "attestation error",
		},
		{
			name: "dialect_unverified", wantStep: prove.StepDialect,
			dialect: string(foundry.DialectResponsesStoreFalse),
			mutate: func(c *fakeControl, _ *fakeAttestor, _ *fakeFoundry) {
				c.dialectOK = false
			},
			wantDetailSub: "no live record",
		},
		{
			name: "dialect_lookup_error", wantStep: prove.StepDialect,
			dialect: string(foundry.DialectResponsesStoreFalse),
			mutate: func(c *fakeControl, _ *fakeAttestor, _ *fakeFoundry) {
				c.dialectErr = errors.New("control plane down")
			},
			wantDetailSub: "verification lookup failed",
		},
		{
			name: "provider_error", wantStep: prove.StepProvider,
			dialect: string(foundry.DialectChatCompletions),
			mutate: func(_ *fakeControl, _ *fakeAttestor, f *fakeFoundry) {
				f.setStatus(http.StatusInternalServerError)
			},
			wantProvider: 1, wantDetailSub: "provider error",
		},
		{
			name: "provider_quota", wantStep: prove.StepProvider,
			dialect: string(foundry.DialectChatCompletions),
			mutate: func(_ *fakeControl, _ *fakeAttestor, f *fakeFoundry) {
				f.setStatus(http.StatusTooManyRequests)
			},
			wantProvider: 1, wantDetailSub: "provider error",
		},
		{
			name: "result_unparseable", wantStep: prove.StepNormalize,
			dialect: string(foundry.DialectChatCompletions),
			mutate: func(_ *fakeControl, _ *fakeAttestor, f *fakeFoundry) {
				f.content = "this is prose, not the strict JSON object"
			},
			wantProvider: 1, wantDetailSub: "unparseable output",
		},
		{
			name: "result_control_chars", wantStep: prove.StepNormalize,
			dialect: string(foundry.DialectChatCompletions),
			mutate: func(_ *fakeControl, _ *fakeAttestor, f *fakeFoundry) {
				f.content = resultJSON("bad\x00title", []string{"metrics"})
			},
			wantProvider: 1, wantDetailSub: "validate:",
		},
		{
			name: "result_ungrounded_ref", wantStep: prove.StepNormalize,
			dialect: string(foundry.DialectChatCompletions),
			mutate: func(_ *fakeControl, _ *fakeAttestor, f *fakeFoundry) {
				f.content = resultJSON("SYNTHETIC FIXTURE", []string{"a99_invented"})
			},
			wantProvider: 1, wantDetailSub: "ungrounded evidence_ref",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fake := newFakeFoundry(t, resultJSON("SYNTHETIC FIXTURE session", []string{"metrics"}))
			control := &fakeControl{route: activeRoute(t, fake.srv.URL, c.dialect), dialectOK: true}
			att := &fakeAttestor{verified: true, reason: "ok"}
			c.mutate(control, att, fake)

			// One fixture keeps the assertion about provider-call counts exact.
			one := prove.Catalog()[:1]
			rep, err := prove.Run(context.Background(), prove.Options{
				FoundryAPIKey: proveKey, RouteID: routeID,
				Control: control, Attestor: att, Provider: &foundry.AzureClient{}, Fixtures: one,
			})
			if err != nil {
				t.Fatalf("Run returned a configuration error, want a reported step failure: %v", err)
			}
			if rep.Passed() {
				var buf bytes.Buffer
				rep.Print(&buf)
				t.Fatalf("run passed but %s should have failed:\n%s", c.wantStep, buf.String())
			}
			fr := rep.Fixtures[0]

			// Exactly one FAIL, at the expected step.
			var failed []prove.StepResult
			for _, s := range fr.Steps {
				if s.Status == prove.StatusFail {
					failed = append(failed, s)
				}
			}
			if len(failed) != 1 {
				t.Fatalf("want exactly one FAIL, got %d: %+v", len(failed), failed)
			}
			if failed[0].Step != c.wantStep {
				t.Fatalf("failed at %s, want %s (detail %q)", failed[0].Step, c.wantStep, failed[0].Detail)
			}
			if c.wantDetailSub != "" && !strings.Contains(failed[0].Detail, c.wantDetailSub) {
				t.Fatalf("failure detail %q does not mention %q", failed[0].Detail, c.wantDetailSub)
			}

			// Every LATER step must be SKIP — never PASS, never absent.
			after := false
			for _, step := range prove.Steps() {
				if step == c.wantStep {
					after = true
					continue
				}
				if !after {
					continue
				}
				if got := stepStatus(fr, step); got != prove.StatusSkip {
					t.Fatalf("step %s after the failure = %q, want SKIP (a step that did not run must never read as a pass)", step, got)
				}
			}

			if got := fake.callCount(); got != c.wantProvider {
				t.Fatalf("provider called %d times, want %d — a gate before dispatch must stop the call", got, c.wantProvider)
			}
		})
	}
}

// TestProveDialectGateReadsTheRecordForResponsesStoreFalse pins the positive
// half of the FA5 gate: with a live record the run proceeds to the call.
func TestProveDialectGateReadsTheRecordForResponsesStoreFalse(t *testing.T) {
	fake := newFakeFoundry(t, resultJSON("SYNTHETIC FIXTURE", []string{"metrics"}))
	control := &fakeControl{route: activeRoute(t, fake.srv.URL, string(foundry.DialectResponsesStoreFalse)), dialectOK: true}
	rep, err := prove.Run(context.Background(), prove.Options{
		FoundryAPIKey: proveKey, RouteID: routeID,
		Control: control, Attestor: &fakeAttestor{verified: true, reason: "ok"},
		Provider: &foundry.AzureClient{}, Fixtures: prove.Catalog()[:1],
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if control.dialectReads != 1 {
		t.Fatalf("dialect record read %d times, want 1 for a responses_store_false route", control.dialectReads)
	}
	if got := stepStatus(rep.Fixtures[0], prove.StepDialect); got != prove.StatusPass {
		t.Fatalf("dialect step = %q, want PASS", got)
	}
	if !rep.Passed() {
		var buf bytes.Buffer
		rep.Print(&buf)
		t.Fatalf("run did not pass:\n%s", buf.String())
	}
	// The store:false-forcing surface was actually used.
	_, _, _, paths := fake.snapshot()
	if len(paths) != 1 || !strings.Contains(paths[0], "/openai/responses") {
		t.Fatalf("responses_store_false route did not hit the responses surface: %v", paths)
	}
}

// --- credential separation -------------------------------------------------

// TestProveRefusesWithoutItsOwnCredential pins deliverable 2's refusal: an
// unset prove-lane key stops the run before anything — and the error names the
// prove variable, never the worker's.
func TestProveRefusesWithoutItsOwnCredential(t *testing.T) {
	fake := newFakeFoundry(t, resultJSON("t", nil))
	control := &fakeControl{route: activeRoute(t, fake.srv.URL, string(foundry.DialectChatCompletions))}
	_, err := prove.Run(context.Background(), prove.Options{
		FoundryAPIKey: "   ",
		RouteID:       routeID,
		Control:       control,
		Attestor:      &fakeAttestor{verified: true},
		Provider:      &foundry.AzureClient{},
	})
	if !errors.Is(err, prove.ErrNoProveCredential) {
		t.Fatalf("want ErrNoProveCredential, got %v", err)
	}
	if fake.callCount() != 0 || control.routeReads != 0 {
		t.Fatalf("a credential-less run touched something: provider=%d routes=%d", fake.callCount(), control.routeReads)
	}
	if !strings.Contains(err.Error(), "SBCI_PROVE_FOUNDRY_API_KEY") {
		t.Fatalf("the refusal must name the prove-lane variable: %v", err)
	}
}

// TestProveRefusesWithoutAnAttestor pins the fail-closed default: no attestor
// means no provider call, ever — the same posture jobs.UnverifiedAttestor
// encodes for the worker.
func TestProveRefusesMissingDependencies(t *testing.T) {
	fake := newFakeFoundry(t, resultJSON("t", nil))
	base := func() prove.Options {
		return prove.Options{
			FoundryAPIKey: proveKey, RouteID: routeID,
			Control:  &fakeControl{route: activeRoute(t, fake.srv.URL, string(foundry.DialectChatCompletions))},
			Attestor: &fakeAttestor{verified: true}, Provider: &foundry.AzureClient{},
		}
	}
	cases := map[string]func(o *prove.Options){
		"no_route":    func(o *prove.Options) { o.RouteID = "" },
		"no_control":  func(o *prove.Options) { o.Control = nil },
		"no_attestor": func(o *prove.Options) { o.Attestor = nil },
		"no_provider": func(o *prove.Options) { o.Provider = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			o := base()
			mutate(&o)
			if _, err := prove.Run(context.Background(), o); err == nil {
				t.Fatalf("Run accepted a %s configuration", name)
			}
			if fake.callCount() != 0 {
				t.Fatalf("a misconfigured run reached the provider (%d calls)", fake.callCount())
			}
		})
	}
}

// TestProveOptionsCarryNoCredentialSource is the CONSTRUCT-level half of the
// credential-separation property (deliverable 4). prove.Options has no field
// that can carry a jobs.CredentialSource, so the lane structurally cannot
// consult the worker's credential seam — it can only use the explicit string it
// is handed. A future refactor that adds one fails here.
func TestProveOptionsCarryNoCredentialSource(t *testing.T) {
	credType := reflect.TypeOf((*jobs.CredentialSource)(nil)).Elem()
	ot := reflect.TypeOf(prove.Options{})
	for i := 0; i < ot.NumField(); i++ {
		f := ot.Field(i)
		if f.Type.Implements(credType) || reflect.PointerTo(f.Type).Implements(credType) {
			t.Fatalf("prove.Options.%s (%s) satisfies jobs.CredentialSource — the proving lane must take its "+
				"credential as an explicit value, never through the worker's credential seam", f.Name, f.Type)
		}
	}
	// And the credential it DOES take is a plain string.
	f, ok := ot.FieldByName("FoundryAPIKey")
	if !ok || f.Type.Kind() != reflect.String {
		t.Fatalf("prove.Options.FoundryAPIKey must exist and be a string, got %+v (ok=%v)", f.Type, ok)
	}
}

// TestProveIgnoresTheWorkerCredentialEnv is the RUNTIME half: with the
// production worker's key present in the environment (and resolving through
// jobs.StaticCredentials, exactly as the worker would), a proving run still
// dispatches with its own explicit key and the worker's key never reaches the
// wire.
func TestProveIgnoresTheWorkerCredentialEnv(t *testing.T) {
	t.Setenv("SBCI_FOUNDRY_API_KEY", workerKey)

	// The worker's seam would resolve this env into a present credential...
	if key, ok, _ := (jobs.StaticCredentials{Key: workerKey}).ProviderKey(context.Background(), routeID); !ok || key != workerKey {
		t.Fatalf("precondition: the worker seam should resolve the poison key, got %q ok=%v", key, ok)
	}

	fake := newFakeFoundry(t, resultJSON("SYNTHETIC FIXTURE session", []string{"metrics"}))
	rep, err := prove.Run(context.Background(), prove.Options{
		FoundryAPIKey: proveKey, RouteID: routeID,
		Control:  &fakeControl{route: activeRoute(t, fake.srv.URL, string(foundry.DialectChatCompletions))},
		Attestor: &fakeAttestor{verified: true, reason: "ok"},
		Provider: &foundry.AzureClient{}, Fixtures: prove.Catalog()[:1],
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !rep.Passed() {
		t.Fatal("run did not pass")
	}
	apiKeys, _, _, _ := fake.snapshot()
	if len(apiKeys) != 1 || apiKeys[0] != proveKey {
		t.Fatalf("wire carried %v, want exactly the explicit prove key", apiKeys)
	}
	for _, k := range apiKeys {
		if k == workerKey {
			t.Fatal("ADVERSARIAL FAILURE: the production worker's credential reached the provider through the proving lane")
		}
	}

	// ...and the worker's own default is STILL absence: nothing the proving lane
	// did provisioned a credential for the worker.
	if _, ok, _ := (jobs.AbsentCredentials{}).ProviderKey(context.Background(), routeID); ok {
		t.Fatal("the worker's credential-absence default reports a credential after a proving run")
	}
}

// TestProveWritesNoTenantState pins that a proving run is not a job: the only
// seams it is given are two control-table READS and one audit append. There is
// no queue, no blob store, and no store write in its dependency surface.
func TestProveWritesNoTenantState(t *testing.T) {
	ct := reflect.TypeOf((*prove.ControlPlane)(nil)).Elem()
	if ct.NumMethod() != 2 {
		t.Fatalf("prove.ControlPlane grew to %d methods — the lane's store surface must stay two READS "+
			"(RouteByID, DialectVerified); anything else risks touching tenant state", ct.NumMethod())
	}
	for i := 0; i < ct.NumMethod(); i++ {
		switch name := ct.Method(i).Name; name {
		case "RouteByID", "DialectVerified":
		default:
			t.Fatalf("prove.ControlPlane has an unexpected method %q", name)
		}
	}
	// *store.Store satisfies it (the production wiring compiles).
	var _ prove.ControlPlane = (*store.Store)(nil)
}

// TestProveRunIsNotAJobBySource is the belt to TestProveWritesNoTenantState's
// braces: no file in the package may name a queue/reservation/job/result write.
func TestProveRunIsNotAJobBySource(t *testing.T) {
	forbidden := []string{
		"SubmitJob", "Lease(", "NewPGQueue", "CompleteJobWithResult", "ParkJob", "FailJob",
		"MarkJobRunning", "RecordProviderAttempt", "BlobStore", "GetEvidence",
	}
	for _, file := range packageGoFiles(t, ".") {
		src := readFile(t, file)
		for _, bad := range forbidden {
			if strings.Contains(src, bad) {
				t.Fatalf("%s references %q — a proving run must never touch the queue, a reservation, "+
					"evidence, or a result row", file, bad)
			}
		}
	}
}

// TestProveNeverConsultsWorkerCredentialSource is the SOURCE-level half of the
// credential-separation property.
//
// Two teeth, and the first is the sharp one: the package reads NO environment
// at all (no "os" import, no os.Getenv). That makes it impossible for the lane
// to pick up the worker's credential variable — or any other — regardless of
// what any comment claims. The second bans the worker's credential seam by
// name, so a future refactor cannot quietly route the lane through it.
func TestProveNeverConsultsWorkerCredentialSource(t *testing.T) {
	forbidden := map[string]string{
		"CredentialSource":  "the lane must take its credential as an explicit parameter, not through the worker's seam",
		"AbsentCredentials": "the worker's absence boundary is not this package's business",
		"StaticCredentials": "the lane must not construct a worker credential source",
		"chooseCredentials": "the worker's credential chooser is not reachable from the lane",
		"os.Getenv":         "the lane reads no environment at all — every input is an explicit parameter",
		"os.LookupEnv":      "the lane reads no environment at all — every input is an explicit parameter",
	}
	for _, file := range packageGoFiles(t, ".") {
		src := readFile(t, file)
		for bad, why := range forbidden {
			if strings.Contains(src, bad) {
				t.Fatalf("%s contains %q — %s", file, bad, why)
			}
		}
		if importsPackage(t, file, "os") {
			t.Fatalf("%s imports \"os\" — the proving lane must not be able to read ANY environment variable; "+
				"its credential is an explicit parameter", file)
		}
	}
}

// TestBoundaryImports pins the same module discipline the jobs package keeps
// (CLAUDE.md #2/#4): the proving lane composes seams, it owns no HTTP surface
// and no SQL. Its store access is the two-method ControlPlane interface.
func TestBoundaryImports(t *testing.T) {
	forbidden := map[string]string{
		"net/http":                "the lane owns no HTTP surface — the provider client does",
		"database/sql":            "SQL belongs in internal/cloudserver/store",
		"github.com/jackc/pgx/v5": "pgx belongs in internal/cloudserver/store",
	}
	for _, file := range packageGoFiles(t, ".") {
		for path, why := range forbidden {
			if importsPackage(t, file, path) {
				t.Errorf("%s imports %q — %s", file, path, why)
			}
		}
	}
}

// --- test helpers ----------------------------------------------------------

// packageGoFiles lists the package's non-test .go files.
func packageGoFiles(t *testing.T, dir string) []string {
	t.Helper()
	all, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	out := make([]string, 0, len(all))
	for _, f := range all {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		out = append(out, f)
	}
	if len(out) == 0 {
		t.Fatal("no package files found — the source scan would be vacuous")
	}
	return out
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func importsPackage(t *testing.T, path, want string) bool {
	t.Helper()
	af, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	for _, imp := range af.Imports {
		if strings.Trim(imp.Path.Value, `"`) == want {
			return true
		}
	}
	return false
}
