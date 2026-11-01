package jobs_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/anthropic"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/attest"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/inference"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// The Anthropic route through the FULL execution lease: the real worker, the
// real store (Postgres), the real attestation gate over the disclosed
// attestor, the real anthropic.Client, and an in-process fake transport in
// place of api.anthropic.com, so no socket is ever opened.

const (
	haikuRoute    = "session_enrichment.claude-haiku-5-5.v1"
	haikuResource = "anthropic:messages:claude-haiku-5-5"
	anthropicKey  = "sk-ant-test-family-key"
)

type fakeAnthropicAPI struct {
	mu      sync.Mutex
	content string
	keys    []string
	bodies  []map[string]any
}

func (f *fakeAnthropicAPI) RoundTrip(r *http.Request) (*http.Response, error) {
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	f.mu.Lock()
	f.keys = append(f.keys, r.Header.Get("X-Api-Key"))
	f.bodies = append(f.bodies, body)
	content := f.content
	f.mu.Unlock()
	text, _ := json.Marshal(content)
	resp := `{"id":"msg_1","type":"message","role":"assistant","model":"claude-haiku-5-5",` +
		`"content":[{"type":"thinking","thinking":"","signature":"s"},{"type":"text","text":` + string(text) + `}],` +
		`"stop_reason":"end_turn","usage":{"input_tokens":900,"output_tokens":120,"cache_read_input_tokens":3000,"cache_creation_input_tokens":0}}`
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(resp)),
		Request:    r,
	}, nil
}

func (f *fakeAnthropicAPI) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.keys)
}

// bindHaiku moves migration 0042's route from its shipped state (inactive,
// unbound) to the state `observer-cloud route bind-anthropic --activate`
// leaves it in.
func bindHaiku(t *testing.T, s *store.Store) {
	t.Helper()
	ctx := context.Background()
	if err := s.SetRouteBinding(ctx, haikuRoute, store.RouteBinding{
		TenantID: "anthropic", SubscriptionID: "default", ARMResourceID: haikuResource,
		EndpointAudience: anthropic.DefaultBaseURL, Endpoint: anthropic.DefaultBaseURL, APIVersion: anthropic.APIVersion,
	}); err != nil {
		t.Fatalf("SetRouteBinding: %v", err)
	}
	if err := s.SetRoutePrice(ctx, haikuRoute, 0.10, 0.50, "pricing-table:test"); err != nil {
		t.Fatalf("SetRoutePrice: %v", err)
	}
	if err := s.SetRouteActive(ctx, haikuRoute, true); err != nil {
		t.Fatalf("SetRouteActive: %v", err)
	}
}

func submitOnRoute(t *testing.T, s *store.Store, acct, key, routeID string, routeVersion int64, now time.Time) {
	t.Helper()
	evidence := []byte(`{"schema_version":"x","actions":[]}`)
	if _, err := s.SubmitJob(context.Background(), store.SubmitJobInput{
		AccountID: acct, CloudProjectID: "p", CloudSessionID: "cs-" + key,
		Tool: "claude-code", ModelFamily: "claude", Feature: store.FeatureSessionEnrichment,
		RouteID: routeID, RouteVersion: routeVersion, PromptVersion: 1,
		CanonicalKey: key, UploadDigest: "sha256:" + key, ContentDigest: "sha256:c",
		BlobRef: "evidence/" + key, SizeBytes: int64(len(evidence)), EvidenceBytes: evidence,
		ConsentGeneration: 0, Now: now,
	}); err != nil {
		t.Fatalf("SubmitJob: %v", err)
	}
}

type anthropicWiring struct {
	api       *fakeAnthropicAPI
	pricerHit int
}

// anthropicWorker wires the worker exactly as cmd/observer-cloud does for
// SBCI_INFERENCE_PROVIDER=anthropic: a router holding only the Anthropic
// client, FamilyCredentials holding only the Anthropic key, the attestation
// gate over the disclosed attestor, and a pricer.
func anthropicWorker(s *store.Store, disclosedResource string, creds jobs.CredentialSource) (*jobs.Worker, *anthropicWiring) {
	w := &anthropicWiring{api: &fakeAnthropicAPI{content: validResult("Wired the Anthropic provider", "did work", []string{"refactor"})}}
	client := &anthropic.Client{HTTPClient: &http.Client{Transport: w.api}}
	router := inference.NewRouter(map[inference.Dialect]inference.Provider{inference.DialectAnthropicMessages: client})
	pricer := func(route store.RouteInfo, res inference.Response, _ time.Time) (float64, string, bool) {
		w.pricerHit++
		if route.Deployment != "claude-haiku-5-5" {
			return 0, "", false
		}
		// 0.10 / 0.50 per MTok, cache read 0.01: the table's Haiku 5.5 row.
		usd := float64(res.Usage.Input)*0.10/1e6 + float64(res.Usage.Output)*0.50/1e6 + float64(res.Usage.CacheRead)*0.01/1e6
		return usd, "pricing-table:feed-vTEST", true
	}
	exec := jobs.NewLunaExecutor(s, store.NewPGBlobStore(s), router).WithPricer(pricer)
	gate := jobs.NewAttestationGate(s, attest.DisclosedAttestor{
		AttestedResourceID: disclosedResource, PolicyVersion: "2", AttestedBy: "test-operator",
	}, time.Minute)
	worker := jobs.NewWorker(jobs.Config{WorkerID: "w-anthropic", LeaseFor: time.Hour},
		jobs.NewPGQueue(s), s, gate, creds,
		map[string]jobs.Executor{store.FeatureSessionEnrichment: exec})
	return worker, w
}

func anthropicCreds() jobs.CredentialSource {
	return jobs.FamilyCredentials{Keys: map[inference.Family]string{inference.FamilyAnthropic: anthropicKey}}
}

func TestAnthropicRouteFullLease(t *testing.T) {
	s, _, acct := setup(t)
	ctx := context.Background()
	now := time.Now()
	bindHaiku(t, s)
	submitOnRoute(t, s, acct, "haiku-e2e", haikuRoute, 3, now)

	worker, w := anthropicWorker(s, haikuResource, anthropicCreds())
	out, err := worker.ProcessOnce(ctx, now)
	if err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}
	if out.State != "succeeded" {
		t.Fatalf("want succeeded, got %+v", out)
	}
	if w.api.calls() != 1 {
		t.Fatalf("provider calls = %d, want exactly 1", w.api.calls())
	}
	if w.api.keys[0] != anthropicKey {
		t.Fatalf("wire key = %q, want the family key", w.api.keys[0])
	}
	body := w.api.bodies[0]
	if body["model"] != "claude-haiku-5-5" || body["max_tokens"] != float64(4096) {
		t.Fatalf("request model/max_tokens = %v / %v (from migration 0042's route row)", body["model"], body["max_tokens"])
	}
	if oc, _ := body["output_config"].(map[string]any); oc["format"] == nil {
		t.Fatalf("no strict structured-output format on the wire: %v", body)
	}

	rows, err := s.ListResultsAfter(ctx, acct, 0, 50)
	if err != nil || len(rows) != 1 {
		t.Fatalf("results = %d, %v", len(rows), err)
	}
	p := rows[0].Provenance
	if p.ModelRouteID != haikuRoute || p.RouteVersion != 3 {
		t.Fatalf("provenance route = %s v%d", p.ModelRouteID, p.RouteVersion)
	}
	// tokens_in counts every prompt token the provider processed (900 uncached
	// + 3000 cache read); cost comes from the pricing-table pricer, not the
	// route's snapshot, and the provenance names the table's version.
	if p.TokensIn != 3900 || p.TokensOut != 120 {
		t.Fatalf("tokens in/out = %d/%d, want 3900/120", p.TokensIn, p.TokensOut)
	}
	wantCost := 900*0.10/1e6 + 120*0.50/1e6 + 3000*0.01/1e6
	if diff := p.CostUSD - wantCost; diff > 1e-12 || diff < -1e-12 {
		t.Fatalf("cost = %v, want %v (pricing table)", p.CostUSD, wantCost)
	}
	if p.PriceVersion != "pricing-table:feed-vTEST" {
		t.Fatalf("price_version = %q, want the pricer's", p.PriceVersion)
	}
	if w.pricerHit == 0 {
		t.Fatal("pricer never consulted for a DeploymentIsModelID route")
	}

	// The persisted attestation record says, in its own words, that provider
	// retention was NOT verified (disclosed mode).
	rec, err := s.LatestAttestation(ctx, haikuRoute)
	if err != nil {
		t.Fatalf("LatestAttestation: %v", err)
	}
	if !rec.Healthy || !strings.Contains(rec.Reason, "NOT verified") || !strings.Contains(rec.Reason, haikuResource) {
		t.Fatalf("attestation record = %+v", rec)
	}
	if strings.HasPrefix(rec.ContentLoggingValue, "false") {
		t.Fatalf("disclosed record must never claim ContentLogging=false: %q", rec.ContentLoggingValue)
	}
}

func TestAnthropicRouteParksWithoutProviderCall(t *testing.T) {
	cases := []struct {
		name       string
		bind       func(t *testing.T, s *store.Store)
		routeID    string
		routeVer   int64
		disclosed  string
		creds      jobs.CredentialSource
		wantReason string
	}{
		{
			// The Foundry route on an Anthropic-only deployment: the family
			// key is never handed to it, so the credential gate parks it.
			name: "foundry route on an anthropic-keyed worker",
			bind: func(t *testing.T, s *store.Store) {
				if err := s.SetRouteBinding(context.Background(), "session_enrichment.luna.v1", store.RouteBinding{
					TenantID: "t", SubscriptionID: "s", ARMResourceID: "/arm/luna", EndpointAudience: "aud",
					Endpoint: "https://x.openai.azure.com", APIVersion: "2024-10-21",
				}); err != nil {
					t.Fatal(err)
				}
			},
			routeID: "session_enrichment.luna.v1", routeVer: 1,
			disclosed: "/arm/luna", creds: anthropicCreds(),
			wantReason: store.ReasonProviderPolicyUnverified,
		},
		{
			name: "no anthropic key", bind: bindHaiku,
			routeID: haikuRoute, routeVer: 3, disclosed: haikuResource,
			creds:      jobs.AbsentCredentials{},
			wantReason: store.ReasonProviderPolicyUnverified,
		},
		{
			name: "disclosure covers a different model", bind: bindHaiku,
			routeID: haikuRoute, routeVer: 3, disclosed: "anthropic:messages:claude-opus-5-5",
			creds:      anthropicCreds(),
			wantReason: store.ReasonProviderPolicyUnverified,
		},
		{
			name:    "route never bound (migration 0042 default: inactive)",
			bind:    func(*testing.T, *store.Store) {},
			routeID: haikuRoute, routeVer: 3, disclosed: haikuResource,
			creds:      anthropicCreds(),
			wantReason: store.ReasonProviderPolicyUnverified,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _, acct := setup(t)
			now := time.Now()
			c.bind(t, s)
			submitOnRoute(t, s, acct, "park", c.routeID, c.routeVer, now)
			worker, w := anthropicWorker(s, c.disclosed, c.creds)
			out, err := worker.ProcessOnce(context.Background(), now)
			if err != nil {
				t.Fatalf("ProcessOnce: %v", err)
			}
			if out.State != "parked" || out.Reason != c.wantReason {
				t.Fatalf("got %+v, want parked %s", out, c.wantReason)
			}
			if w.api.calls() != 0 {
				t.Fatalf("provider calls = %d, want 0 (fail closed BEFORE dispatch)", w.api.calls())
			}
		})
	}
}

func TestFamilyCredentialsAnswerByDialectFamily(t *testing.T) {
	c := jobs.FamilyCredentials{Keys: map[inference.Family]string{inference.FamilyAnthropic: "ak"}}
	cases := []struct {
		dialect string
		key     string
		ok      bool
	}{
		{"anthropic_messages", "ak", true},
		{"chat_completions", "", false},
		{"responses_store_false", "", false},
		{"", "", false},
		{"unknown", "", false},
	}
	for _, tc := range cases {
		k, ok, err := c.ProviderKey(context.Background(), store.RouteInfo{RouteID: "r", Dialect: tc.dialect})
		if err != nil || k != tc.key || ok != tc.ok {
			t.Errorf("dialect %q: key=%q ok=%v err=%v, want %q %v", tc.dialect, k, ok, err, tc.key, tc.ok)
		}
	}
	empty := jobs.FamilyCredentials{Keys: map[inference.Family]string{inference.FamilyAnthropic: ""}}
	if _, ok, _ := empty.ProviderKey(context.Background(), store.RouteInfo{Dialect: "anthropic_messages"}); ok {
		t.Error("an empty family key must report absent")
	}
}

func TestInvalidOutputDetailNamesRefusal(t *testing.T) {
	got := jobs.InvalidOutputDetail(inference.Response{FinishReason: "refusal:cyber"}, "unparseable output")
	if !strings.Contains(got, "provider refused") || !strings.Contains(got, "refusal:cyber") {
		t.Errorf("detail = %q", got)
	}
}
