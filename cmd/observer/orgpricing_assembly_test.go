package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// THE REAL-ASSEMBLY GATE (enterprise-pricing plan §5, criteria 4a and 4b).
//
// Everything else in this wave is unit-testable and unit-tested: the ladder,
// the signature, the HTTP rungs, the store round-trip. None of that proves the
// thing the arc actually promises, which is that a rate an admin negotiates
// reaches BOTH numbers a budget is enforced against on a real developer's
// machine — and those two numbers are stamped by two different subsystems,
// through two different code paths, that until this wave built two different
// price tables.
//
// So this test goes through the REAL composition: buildProxy the way `observer
// start` calls it, and the org-push pricer the way buildOrgBundle wires it. A
// hand-built engine would pass while the daemon shipped list prices, which is
// exactly the failure mode finding F3 describes.
//
// 4a: the next PROXIED turn's api_turns.cost_usd is the ORG rate x tokens.
// 4b: a hook/watcher-captured token_usage row leaves on the org wire priced at
//     the ORG rate.

const assemblyPricedModel = "claude-opus-4-8"

// The org's negotiated rates. Deliberately absurd round numbers that no seed
// entry could produce, so an assertion cannot pass by coincidence.
const (
	assemblyOrgInput  = 100.0 // $/1M input
	assemblyOrgOutput = 500.0 // $/1M output
)

// writeAssemblyConfig stages a node that has opted into the org's budget rail
// (ruling R2 — pricing rides that switch) and proxies to a fake upstream.
func writeAssemblyConfig(t *testing.T, dbPath, upstream string) string {
	t.Helper()
	dir := filepath.Dir(dbPath)
	configPath := filepath.Join(dir, "config.toml")
	body := fmt.Sprintf(`
[observer]
db_path = %q
log_level = "warn"

[proxy]
enabled = true
port = 8820
anthropic_upstream = %q
openai_upstream = "http://127.0.0.1:1"
chatgpt_upstream = "http://127.0.0.1:2"
prewarm_targets = []

[guard.budget]
from_org = true

[cachetrack]
enabled = false

[codeintel]
enabled = false
`, dbPath, upstream)
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return configPath
}

// seedOrgPricingDocument writes the node-local copy of a VERIFIED org price
// document, exactly as orgclient.FetchPricingPolicy's 200 branch does. Going
// through store.SaveOrgPricing rather than an INSERT is the point: the one
// writer is what every constructor reads back.
//
// It ALSO writes an enrolment row (finding F6): an org price document only
// applies to an ENROLLED node, which is the real shape a fleet machine is in —
// the org rail that delivered the document is the same enrolment the loader now
// checks FIRST. Before F6 these tests passed with no enrolment row because the
// loader applied the stored document on from_org alone; that is exactly the
// un-enrolment precedence defect, so the fixture now carries the row.
func seedOrgPricingDocument(t *testing.T, ctx context.Context, dbPath string) {
	t.Helper()
	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = database.Close() }()
	if err := store.New(database).WriteEnrolment(ctx, store.Enrolment{
		OrgID: "org-1", OrgName: "Acme", OrgServerURL: "https://org.example",
		UserID: "u", UserEmail: "dev@example.com", BearerKeyID: "k",
	}); err != nil {
		t.Fatalf("WriteEnrolment: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := store.New(database).UpsertOrgRoutingPolicy(ctx, store.OrgRoutingPolicyRow{
		Version: 1, Body: "[routing]\n", BodyHash: "hash", Signature: "sig",
		ServerPubkey: base64.StdEncoding.EncodeToString(pub), ReceivedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertOrgRoutingPolicy: %v", err)
	}
	in := assemblyOrgInput
	out := assemblyOrgOutput
	doc, err := orgcontract.SignPricingPolicy(priv, "org-1", orgcontract.PricingPolicyBody{
		Version:     12,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Rows: []orgcontract.PricingPolicyRow{{
			Model:         assemblyPricedModel,
			InputPerMTok:  &in,
			OutputPerMTok: &out,
			Source:        "negotiated",
		}},
	})
	if err != nil {
		t.Fatalf("SignPricingPolicy: %v", err)
	}
	st := store.New(database)
	identity, active, err := orgclient.CurrentBudgetIdentity(ctx, st)
	if err != nil || !active {
		t.Fatalf("CurrentBudgetIdentity: active=%v err=%v", active, err)
	}
	if err := st.SaveOrgPricing(ctx, doc,
		orgcontract.PublicKeyPinHash(pub), orgcontract.PricingFetchVerified, identity); err != nil {
		t.Fatalf("SaveOrgPricing: %v", err)
	}
}

// TestAssembly_OrgRateReachesTheProxiedTurnCost is criterion 4a.
func TestAssembly_OrgRateReachesTheProxiedTurnCost(t *testing.T) {
	ctx := context.Background()

	// A fake Anthropic upstream returning a turn with round token counts, so
	// the expected dollar figure is exact rather than approximate.
	const inputTokens, outputTokens = 1_000_000, 100_000
	sse := strings.Join([]string{
		`event: message_start`,
		fmt.Sprintf(`data: {"type":"message_start","message":{"id":"msg_pricing_assembly","model":%q,"usage":{"input_tokens":%d,"cache_read_input_tokens":0,"cache_creation_input_tokens":0,"output_tokens":1}}}`,
			assemblyPricedModel, inputTokens),
		``,
		`event: message_delta`,
		fmt.Sprintf(`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":%d}}`, outputTokens),
		``,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n")
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		if f, ok := w.(http.Flusher); ok {
			_, _ = w.Write([]byte(sse))
			f.Flush()
		}
	}))
	t.Cleanup(up.Close)

	dbPath := filepath.Join(t.TempDir(), "observer.db")
	configPath := writeAssemblyConfig(t, dbPath, up.URL)
	seedOrgPricingDocument(t, ctx, dbPath)

	// THE REAL COMPOSITION.
	p, cleanup, _, _, _, _, _, err := buildProxy(ctx, configPath, "", 0, "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("buildProxy: %v", err)
	}
	t.Cleanup(cleanup)
	if p == nil {
		t.Fatal("buildProxy returned nil proxy")
	}

	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)

	reqBody := fmt.Sprintf(`{"model":%q,"stream":true,"messages":[{"role":"user","content":"hi"}]}`, assemblyPricedModel)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		srv.URL+"/v1/messages", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "test")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	_ = resp.Body.Close()

	// The proxy inserts the turn on a DETACHED context, so poll rather than
	// assume it has landed.
	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	wantUSD := float64(inputTokens)*assemblyOrgInput/1e6 + float64(outputTokens)*assemblyOrgOutput/1e6
	var gotUSD float64
	var found bool
	for i := 0; i < 100; i++ {
		row := database.QueryRowContext(ctx,
			`SELECT cost_usd FROM api_turns WHERE model = ? ORDER BY id DESC LIMIT 1`, assemblyPricedModel)
		if err := row.Scan(&gotUSD); err == nil {
			found = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !found {
		t.Fatal("no api_turns row was captured through the real proxy assembly")
	}
	if diff := gotUSD - wantUSD; diff > 0.0001 || diff < -0.0001 {
		t.Fatalf("api_turns.cost_usd = %v, want %v (the ORG rate) — the proxy is pricing from a different table than the one the org document composed into",
			gotUSD, wantUSD)
	}
}

// TestAssembly_OrgRateReachesTheOrgPushWire is criterion 4b.
//
// It matters INDEPENDENTLY of 4a because the two numbers are stamped by
// different subsystems and the node's own guard reads
// MAX(SUM(api_turns.cost_usd), SUM(token_usage.estimated_cost_usd)): a fleet
// where only one of them carried the org's rates would enforce whichever
// happened to be larger, which for a discounted org rate means the budget
// silently keeps biting at list prices.
func TestAssembly_OrgRateReachesTheOrgPushWire(t *testing.T) {
	ctx := context.Background()

	dbPath := filepath.Join(t.TempDir(), "observer.db")
	configPath := writeAssemblyConfig(t, dbPath, "http://127.0.0.1:1")
	seedOrgPricingDocument(t, ctx, dbPath)

	// A hook/watcher-captured session that stored $0 — the shape most
	// non-proxied adapters produce, and the whole reason the push-time pricer
	// exists.
	const inputTokens, outputTokens = 2_000_000, 50_000
	seed, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	stamp := time.Now().UTC().Format(time.RFC3339)
	if _, err := seed.ExecContext(ctx,
		`INSERT INTO projects (root_path, name, created_at) VALUES ('/tmp/assembly-proj', 'assembly', ?)`, stamp); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if _, err := seed.ExecContext(ctx, `
INSERT INTO sessions (id, project_id, tool, model, started_at)
VALUES ('assembly-s1', (SELECT id FROM projects WHERE root_path = '/tmp/assembly-proj'), 'claude-code', ?, ?)`,
		assemblyPricedModel, stamp); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if _, err := seed.ExecContext(ctx, `
INSERT INTO token_usage(session_id, timestamp, tool, model, input_tokens, output_tokens,
    cache_read_tokens, cache_creation_tokens, cache_creation_1h_tokens, reasoning_tokens,
    web_search_requests, estimated_cost_usd, fast, source, source_file, source_event_id)
VALUES('assembly-s1', ?, 'claude-code', ?, ?, ?, 0, 0, 0, 0, 0, 0, 0, 'jsonl', 'f.jsonl', 'tu-assembly')`,
		stamp, assemblyPricedModel, inputTokens, outputTokens); err != nil {
		t.Fatalf("seed token_usage: %v", err)
	}
	_ = seed.Close()

	// THE REAL COMPOSITION: buildOrgBundle is what installs the push pricer.
	bundle, err := buildOrgBundle(ctx, configPath)
	if err != nil {
		t.Skipf("buildOrgBundle unavailable in this environment (%v) — the 4b path needs the org bundle's own handles", err)
	}

	batch, err := bundle.store.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20,
		"org-1", "dev@example.com", store.ShareOptions{}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	var gotUSD float64
	var found bool
	for _, r := range batch.TokenUsage {
		if r.SourceEventID == "tu-assembly" {
			gotUSD, found = r.EstimatedCostUSD, true
		}
	}
	if !found {
		t.Fatalf("the seeded token_usage row did not reach the wire (%d rows)", len(batch.TokenUsage))
	}
	wantUSD := float64(inputTokens)*assemblyOrgInput/1e6 + float64(outputTokens)*assemblyOrgOutput/1e6
	if diff := gotUSD - wantUSD; diff > 0.0001 || diff < -0.0001 {
		t.Fatalf("token_usage.estimated_cost_usd on the wire = %v, want %v (the ORG rate) — the push-time pricer is on a different table than the proxy",
			gotUSD, wantUSD)
	}
}

// TestAssembly_ProxyAndPushPricerShareOneEngine is the structural half of the
// same claim, and it is worth its own assertion: the two tests above could
// both pass with two engines that happen to have loaded the same document,
// and would then start disagreeing the moment one of them was Reloaded.
func TestAssembly_ProxyAndPushPricerShareOneEngine(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "observer.db")
	configPath := writeAssemblyConfig(t, dbPath, "http://127.0.0.1:1")
	seedOrgPricingDocument(t, ctx, dbPath)

	_, cleanup, _, _, _, _, _, err := buildProxy(ctx, configPath, "", 0, "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("buildProxy: %v", err)
	}
	t.Cleanup(cleanup)

	first := lookupProcessCostEngine(dbPath)
	if first == nil {
		t.Fatal("buildProxy did not register the shared cost engine")
	}
	if _, err := buildOrgBundle(ctx, configPath); err != nil {
		t.Skipf("buildOrgBundle unavailable in this environment: %v", err)
	}
	second := lookupProcessCostEngine(dbPath)
	if first != second {
		t.Fatal("the org bundle built its own cost engine — the proxy and the push pricer would then price from two tables")
	}
	if first.OrgPricingVersion() != 12 {
		t.Errorf("shared engine org version = %d, want the seeded 12", first.OrgPricingVersion())
	}
	p, src, ok := first.LookupWithSource(assemblyPricedModel)
	if !ok || p.Input != assemblyOrgInput || string(src) != "org" {
		t.Errorf("shared engine lookup = %v %q %v, want the org rate", p, src, ok)
	}
}
