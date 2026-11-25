package invariant

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"

	"github.com/marmutapp/superbased-observer/internal/aggregate"
	"github.com/marmutapp/superbased-observer/internal/aggregateclient"
	"github.com/marmutapp/superbased-observer/internal/aggregatesource"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// envelopeAllowlist / cellAllowlist are the ONLY JSON keys the aggregate wire
// shape may carry (design §3, §6.4 #2). Adding a field to Submission
// or Cell without updating these fails loudly — the allow-list is the guard,
// not a denylist of known sentinels.
var envelopeAllowlist = map[string]bool{
	"schema_version": true, "observer_version": true, "pricing_version": true,
	"cost_method_version": true, "tool_registry_version": true, "submission_id": true,
	"month": true, "cells": true,
}

var cellAllowlist = map[string]bool{
	"model_family": true, "tool": true,
	"turns_acc": true, "turns_est": true,
	"input_tokens_acc": true, "input_tokens_est": true,
	"output_tokens_acc": true, "output_tokens_est": true,
	"cache_read_tokens_acc": true, "cache_read_tokens_est": true,
	"cache_creation_tokens_acc": true, "cache_creation_tokens_est": true,
	"cache_creation_1h_tokens_acc": true, "cache_creation_1h_tokens_est": true,
	"reasoning_tokens_acc": true, "reasoning_tokens_est": true,
	"web_search_requests_acc": true, "web_search_requests_est": true,
	"fast_turns_acc": true, "fast_turns_est": true,
	"cost_usd_acc": true, "cost_usd_est": true,
	"cache_observable": true, "fast_observable": true,
}

func jsonFieldNames(t *testing.T, typ reflect.Type) []string {
	t.Helper()
	var out []string
	for i := 0; i < typ.NumField(); i++ {
		tag := typ.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			t.Errorf("%s.%s has no json tag — every wire field must be explicitly tagged", typ.Name(), typ.Field(i).Name)
			continue
		}
		name := tag
		if c := indexByte(tag, ','); c >= 0 {
			name = tag[:c]
		}
		out = append(out, name)
	}
	return out
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// TestAggregatePayloadIsAllowlistOnly is the structural allow-list guard over
// the wire types (design §6.4 #2). Mirrors TestRoutingSummaryWireShapeIsAggregateOnly.
func TestAggregatePayloadIsAllowlistOnly(t *testing.T) {
	t.Parallel()
	for _, name := range jsonFieldNames(t, reflect.TypeOf(aggregate.Submission{})) {
		if !envelopeAllowlist[name] {
			t.Errorf("Submission gained non-allowlisted field %q — the wire envelope is a fixed shape", name)
		}
	}
	for _, name := range jsonFieldNames(t, reflect.TypeOf(aggregate.Cell{})) {
		if !cellAllowlist[name] {
			t.Errorf("Cell gained non-allowlisted field %q — the wire cell carries only per-(family,tool) aggregates", name)
		}
	}
}

// TestAggregateSerializationPositive is the positive schema test (design §6.4
// #8): a fully-populated submission serializes to EXACTLY the allow-listed key
// set — every allow-listed key present, none extra — catching a renamed/added
// field the denylist would miss.
func TestAggregateSerializationPositive(t *testing.T) {
	t.Parallel()
	// One stat that populates every metric, above the coarsening floor.
	sub := aggregate.Build(
		aggregate.Meta{ObserverVersion: "1.20", SubmissionID: "fixed", Month: "2026-06"},
		[]aggregate.ModelToolStat{{
			Model: "claude-opus-4-8", Tool: "claude-code", Accurate: true,
			Turns: 100, InputTokens: 1, OutputTokens: 2, CacheReadTokens: 3,
			CacheCreation: 4, CacheCreation1h: 5, ReasoningTokens: 6,
			WebSearchRequests: 7, FastTurns: 8, CostUSD: 9.99,
			CacheObservable: true, FastObservable: true,
		}},
	)
	raw, err := json.Marshal(sub)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	assertKeySetEquals(t, "envelope", envelope, envelopeAllowlist)

	var cells []map[string]json.RawMessage
	if err := json.Unmarshal(envelope["cells"], &cells); err != nil {
		t.Fatalf("unmarshal cells: %v", err)
	}
	if len(cells) != 1 {
		t.Fatalf("want 1 cell, got %d", len(cells))
	}
	assertKeySetEquals(t, "cell", cells[0], cellAllowlist)
}

func assertKeySetEquals(t *testing.T, what string, got map[string]json.RawMessage, allow map[string]bool) {
	t.Helper()
	for k := range got {
		if !allow[k] {
			t.Errorf("%s carries unexpected key %q", what, k)
		}
	}
	for k := range allow {
		if _, ok := got[k]; !ok {
			t.Errorf("%s missing expected key %q (positive-serialization: every allow-listed field must serialize)", what, k)
		}
	}
}

// TestAggregateModelFamilyTotalCoverage pins model-family totality at the
// invariant layer (design §6.4 #7): every input — representative or exotic —
// maps to a member of the closed Families set, and the map version is stable.
func TestAggregateModelFamilyTotalCoverage(t *testing.T) {
	t.Parallel()
	inSet := map[string]bool{}
	for _, f := range aggregate.Families {
		inSet[f] = true
	}
	samples := []string{
		"claude-opus-4-8", "claude-sonnet-5", "claude-haiku-4-5",
		"gpt-5", "gpt-5-mini", "gpt-5.4-nano", "gemini-3.1-pro-preview",
		"gemini-3.5-flash", "grok-4.5", "openai/gpt-oss-120b",
		"nvidia/nemotron-3-super-120b-a12b", "moonshotai/kimi-k2.6",
		// exotic / must collapse to "other"
		"", "<unknown>", "gpt-4o", "composer-2.5", "kilo-auto/free",
		"SECRET_EXOTIC_MODEL_zzz_9000", "some.random/thing:free",
	}
	for _, m := range samples {
		if !inSet[aggregate.Family(m)] {
			t.Errorf("Family(%q) = %q is outside the closed vocabulary", m, aggregate.Family(m))
		}
	}
	if aggregate.FamilyMapVersion == "" {
		t.Error("FamilyMapVersion must be non-empty (it travels on the wire)")
	}
}

// aggregate leak sentinels — distinctive strings stuffed into content-bearing
// columns that the read+map path can in principle touch. NONE may appear in
// the serialized submission.
const (
	aggSecRoot   = "AGG_SECRET_ROOTPATH_flibberflop_11"
	aggSecRemote = "AGG_SECRET_GITREMOTE_wibblewob_22"
	aggSecBranch = "AGG_SECRET_GITBRANCH_snickersnack_33"
	aggSecSource = "AGG_SECRET_SOURCEFILE_bandersnatch_44"
	aggSecModel  = "AGG_SECRET_MODEL_jabberwock_55"
	aggSecTool   = "AGG_SECRET_TOOL_frumious_66"
)

// finalizedTestMonth is a clearly-past month so IsFinalizedMonth is always
// true regardless of the machine clock; seed timestamps land inside it.
const finalizedTestMonth = "2020-06"

func finalizedTestTS() time.Time { return time.Date(2020, 6, 15, 12, 0, 0, 0, time.UTC) }

func newAggregateStore(t *testing.T) (*store.Store, *sql.DB, func()) {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "agg.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	return store.New(database), database, func() { _ = database.Close() }
}

// TestAggregatePayloadCarriesNoContent is the leak sentinel for the rail
// (design §6.4 #3): seed real projects/sessions/api_turns/token_usage with
// sentinel roots/remotes/branches/source files + an exotic model + an exotic
// tool, build a submission through the REAL read+map+build path, gzip it, and
// assert not one sentinel — nor any content-bearing key — crossed into the
// bytes. Exotic model/tool must have collapsed to "other".
func TestAggregatePayloadCarriesNoContent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st, database, cleanup := newAggregateStore(t)
	defer cleanup()

	// A benign accurate cell so the payload is non-vacuous (a real registry
	// tool + a real model that maps to a family).
	projID, err := st.UpsertProject(ctx, aggSecRoot, aggSecRemote)
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	if err := st.UpsertSession(ctx, models.Session{
		ID: "sess-acc", ProjectID: projID, Tool: "claude-code",
		Model: "claude-opus-4-8", GitBranch: aggSecBranch, StartedAt: finalizedTestTS(),
	}); err != nil {
		t.Fatalf("UpsertSession: %v", err)
	}
	if _, err := st.InsertAPITurn(ctx, models.APITurn{
		SessionID: "sess-acc", ProjectID: projID, Timestamp: finalizedTestTS(),
		Provider: "anthropic", Model: "claude-opus-4-8", RequestID: "req-acc",
		InputTokens: 1200, OutputTokens: 800, CacheReadTokens: 4000, CostUSD: 0.5,
	}); err != nil {
		t.Fatalf("InsertAPITurn: %v", err)
	}

	// An estimated cell carrying the exotic model + exotic tool + a sentinel
	// source file, via the JSONL token path. (The estimated cell's tool comes
	// from token_usage.tool; the session's own tool is irrelevant but the row
	// must exist for the FK.)
	if err := st.UpsertSession(ctx, models.Session{
		ID: "sess-est", ProjectID: projID, Tool: "codex",
		Model: aggSecModel, GitBranch: aggSecBranch, StartedAt: finalizedTestTS(),
	}); err != nil {
		t.Fatalf("UpsertSession est: %v", err)
	}
	if _, err := st.InsertTokenEvents(ctx, []models.TokenEvent{{
		SourceFile: aggSecSource, SourceEventID: "tok-1", SessionID: "sess-est",
		ProjectRoot: aggSecRoot, GitBranch: aggSecBranch, Timestamp: finalizedTestTS(),
		Tool: aggSecTool, Model: aggSecModel, InputTokens: 500, OutputTokens: 300,
		Source: "jsonl", Reliability: "unreliable",
	}}); err != nil {
		t.Fatalf("InsertTokenEvents: %v", err)
	}

	engine := cost.NewEngine(config.IntelligenceConfig{})
	sub, err := aggregatesource.BuildSubmission(ctx, database, engine, aggregate.Meta{
		ObserverVersion: "1.20", SubmissionID: "fixed-id", Month: finalizedTestMonth,
	})
	if err != nil {
		t.Fatalf("BuildSubmission: %v", err)
	}
	if len(sub.Cells) == 0 {
		t.Fatal("no cells built — the sentinel scan would be vacuous")
	}

	// Serialize (raw + gzipped, mirroring the eventual wire) and scan.
	raw, err := json.Marshal(sub)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(raw); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	for _, s := range []string{aggSecRoot, aggSecRemote, aggSecBranch, aggSecSource, aggSecModel, aggSecTool} {
		if bytes.Contains(raw, []byte(s)) {
			t.Errorf("sentinel %q leaked into the aggregate payload", s)
		}
	}
	// Forbidden JSON keys: no path/identity/content keys may exist.
	for _, k := range []string{`"project`, `"root`, `"path`, `"git`, `"remote`, `"branch`, `"session`, `"source_file`, `"target`, `"model_id`, `"user`, `"host`, `"node`} {
		if bytes.Contains(raw, []byte(k)) {
			t.Errorf("forbidden key %q present in the aggregate payload", k)
		}
	}
	// The exotic model + tool must have collapsed to the "other" buckets.
	var sawOther bool
	for _, c := range sub.Cells {
		if c.ModelFamily == aggregate.FamilyOther && c.Tool == aggregate.FamilyOther {
			sawOther = true
		}
	}
	if !sawOther {
		t.Error("expected the exotic (model,tool) to collapse to an (other,other) cell")
	}
}

// TestAggregateDataLineage proves every numeric output derives only from the
// allowed source columns, by exact sums, and that the _acc/_est split follows
// provenance (design §6.4 #9).
func TestAggregateDataLineage(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st, database, cleanup := newAggregateStore(t)
	defer cleanup()

	projID, err := st.UpsertProject(ctx, "/lineage/proj", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	if err := st.UpsertSession(ctx, models.Session{
		ID: "sess-acc", ProjectID: projID, Tool: "claude-code",
		Model: "claude-opus-4-8", StartedAt: finalizedTestTS(),
	}); err != nil {
		t.Fatalf("UpsertSession: %v", err)
	}
	// Two accurate proxy turns in the same (family,tool) cell — sums must add.
	for i, in := range []int64{1000, 2000} {
		if _, err := st.InsertAPITurn(ctx, models.APITurn{
			SessionID: "sess-acc", ProjectID: projID, Timestamp: finalizedTestTS(),
			Provider: "anthropic", Model: "claude-opus-4-8", RequestID: "req-acc-" + string(rune('a'+i)),
			InputTokens: in, OutputTokens: in / 2, CacheReadTokens: in * 10, CostUSD: 1.00,
		}); err != nil {
			t.Fatalf("InsertAPITurn: %v", err)
		}
	}
	// One estimated jsonl turn in a different (family,tool) cell.
	if err := st.UpsertSession(ctx, models.Session{
		ID: "sess-est", ProjectID: projID, Tool: "codex",
		Model: "gpt-5-codex", StartedAt: finalizedTestTS(),
	}); err != nil {
		t.Fatalf("UpsertSession est: %v", err)
	}
	// Tokens well above the rare-cell coarsening floor so the gpt-5 family
	// survives as its own cell (a sparse cell would legitimately collapse to
	// "other" — that path is covered by the no-content test).
	if _, err := st.InsertTokenEvents(ctx, []models.TokenEvent{{
		SourceFile: "codex.jsonl", SourceEventID: "tok-1", SessionID: "sess-est",
		Timestamp: finalizedTestTS(), Tool: "codex", Model: "gpt-5-codex",
		InputTokens: 200000, OutputTokens: 200000, Source: "jsonl", Reliability: "unreliable",
	}}); err != nil {
		t.Fatalf("InsertTokenEvents: %v", err)
	}

	engine := cost.NewEngine(config.IntelligenceConfig{})
	sub, err := aggregatesource.BuildSubmission(ctx, database, engine, aggregate.Meta{
		ObserverVersion: "1.20", SubmissionID: "fixed", Month: finalizedTestMonth,
	})
	if err != nil {
		t.Fatalf("BuildSubmission: %v", err)
	}

	byKey := map[string]aggregate.Cell{}
	for _, c := range sub.Cells {
		byKey[c.ModelFamily+"|"+c.Tool] = c
	}
	acc, ok := byKey["claude-opus|claude-code"]
	if !ok {
		t.Fatalf("missing accurate cell; cells=%+v", sub.Cells)
	}
	// Exact sums: input 1000+2000, output 500+1000, cache_read 10000+20000.
	if acc.TurnsAcc != 2 || acc.InputTokensAcc != 3000 || acc.OutputTokensAcc != 1500 || acc.CacheReadTokensAcc != 30000 {
		t.Errorf("accurate cell sums wrong: %+v", acc)
	}
	if acc.TurnsEst != 0 || acc.InputTokensEst != 0 {
		t.Errorf("accurate cell must have empty _est twins: %+v", acc)
	}
	if acc.CostUSDAcc != 2.00 {
		t.Errorf("accurate cost = %v, want 2.00 (recorded per-turn)", acc.CostUSDAcc)
	}

	est, ok := byKey["gpt-5|codex"]
	if !ok {
		t.Fatalf("missing estimated cell; cells=%+v", sub.Cells)
	}
	if est.TurnsEst != 1 || est.InputTokensEst != 200000 || est.OutputTokensEst != 200000 {
		t.Errorf("estimated cell sums wrong: %+v", est)
	}
	if est.TurnsAcc != 0 || est.InputTokensAcc != 0 {
		t.Errorf("estimated cell must have empty _acc twins: %+v", est)
	}
}

// TestAggregateConfigDefaultsOff pins the off-by-default invariant (design
// §6.4 #1): the rail is inert in EVERY path unless the operator opts in.
//   - the zero-value AggregateShareConfig has Enabled == false,
//   - the loader's partial-merge default (config.Default) has Enabled == false
//     (only Endpoint is seeded), and
//   - a default config yields ConsentDisabled with no receipt, so
//     aggregateclient.Authorize refuses to mint a Gate.
func TestAggregateConfigDefaultsOff(t *testing.T) {
	t.Parallel()
	var zero config.AggregateShareConfig
	if zero.Enabled {
		t.Error("zero-value AggregateShareConfig.Enabled must be false")
	}
	def := config.Default()
	if def.AggregateShare.Enabled {
		t.Error("config.Default().AggregateShare.Enabled must be false (opt-in, unlike CacheTrack/Predict)")
	}
	if def.AggregateShare.Endpoint == "" {
		t.Error("config.Default() should seed the published endpoint so a consenting operator inherits it")
	}
	if def.AggregateShare.AllowCustomEndpoint {
		t.Error("config.Default().AggregateShare.AllowCustomEndpoint must be false")
	}
	// A default (off) config authorizes NO submission, receipt or not.
	live := aggregate.LiveState{
		Enabled:             def.AggregateShare.Enabled,
		SchemaVersion:       aggregate.SchemaVersion,
		Endpoint:            def.AggregateShare.Endpoint,
		ToolRegistryVersion: integration.RegistryVersion,
	}
	if got := aggregate.CheckConsent(live, nil); got != aggregate.ConsentDisabled {
		t.Errorf("default config consent = %q, want %q", got, aggregate.ConsentDisabled)
	}
	if _, err := aggregateclient.Authorize(aggregate.CheckConsent(live, nil)); err == nil {
		t.Error("Authorize must refuse a Gate when the rail is disabled — no submission is possible off-by-default")
	}
}

// TestAggregateConsentMaterialChange pins the re-consent semantics (design
// §9.1, finding #16): a receipt is valid only while its pinned versions still
// match the live ones. A schema-version bump, an endpoint change, or a
// tool-registry-version bump each suspends submission until re-consent.
func TestAggregateConsentMaterialChange(t *testing.T) {
	t.Parallel()
	base := aggregate.LiveState{
		Enabled:             true,
		SchemaVersion:       aggregate.SchemaVersion,
		Endpoint:            config.DefaultAggregateEndpoint,
		ToolRegistryVersion: integration.RegistryVersion,
	}
	good := &aggregate.Receipt{
		SchemaVersion:       aggregate.SchemaVersion,
		Endpoint:            aggregate.NormalizeEndpoint(config.DefaultAggregateEndpoint),
		ToolRegistryVersion: integration.RegistryVersion,
	}
	if got := aggregate.CheckConsent(base, good); got != aggregate.ConsentValid {
		t.Fatalf("matching receipt should be valid, got %q", got)
	}
	cases := []struct {
		name    string
		mutate  func(r aggregate.Receipt) aggregate.Receipt
		wantOut aggregate.ConsentStatus
	}{
		{"schema bump", func(r aggregate.Receipt) aggregate.Receipt { r.SchemaVersion = aggregate.SchemaVersion + 1; return r }, aggregate.ConsentSchemaChanged},
		{"endpoint change", func(r aggregate.Receipt) aggregate.Receipt {
			r.Endpoint = "https://aggregate.superbased.app/v2/submit"
			return r
		}, aggregate.ConsentEndpointChanged},
		{"registry bump", func(r aggregate.Receipt) aggregate.Receipt {
			r.ToolRegistryVersion = integration.RegistryVersion + 1
			return r
		}, aggregate.ConsentRegistryChanged},
	}
	for _, tc := range cases {
		r := tc.mutate(*good)
		if got := aggregate.CheckConsent(base, &r); got != tc.wantOut {
			t.Errorf("%s: consent = %q, want %q", tc.name, got, tc.wantOut)
		}
	}
	// Disabled beats everything; missing receipt while enabled is inert.
	off := base
	off.Enabled = false
	if got := aggregate.CheckConsent(off, good); got != aggregate.ConsentDisabled {
		t.Errorf("disabled rail = %q, want %q", got, aggregate.ConsentDisabled)
	}
	if got := aggregate.CheckConsent(base, nil); got != aggregate.ConsentMissing {
		t.Errorf("enabled + no receipt = %q, want %q", got, aggregate.ConsentMissing)
	}
}

// TestAggregateEgressSeamSeparate pins the module-boundary rule (design §6.3 /
// §6.4 #5): the aggregate rail's egress seam and org-push must not entangle.
// internal/aggregateclient must not import internal/orgclient, and
// internal/orgclient must not import internal/aggregateclient.
func TestAggregateEgressSeamSeparate(t *testing.T) {
	t.Parallel()
	assertNoImport(t,
		filepath.Join("..", "..", "internal", "aggregateclient"),
		"github.com/marmutapp/superbased-observer/internal/orgclient")
	assertNoImport(t,
		filepath.Join("..", "..", "internal", "orgclient"),
		"github.com/marmutapp/superbased-observer/internal/aggregateclient")
	// The pure package must not reach the egress seam either.
	assertNoImport(t,
		filepath.Join("..", "..", "internal", "aggregate"),
		"github.com/marmutapp/superbased-observer/internal/aggregateclient")
	// The Phase-4 collector must not entangle with org-push either: no
	// internal/orgclient import in either direction. Its only egress door
	// stays internal/aggregateclient (raw net/http is pinned off by the
	// package's own imports_test.go).
	assertNoImport(t,
		filepath.Join("..", "..", "internal", "aggregatesvc"),
		"github.com/marmutapp/superbased-observer/internal/orgclient")
	assertNoImport(t,
		filepath.Join("..", "..", "internal", "orgclient"),
		"github.com/marmutapp/superbased-observer/internal/aggregatesvc")
}

// assertNoImport fails if any non-test .go file in pkgDir imports forbidden
// or a package below it. It runs on importpin, the shared scanner: every
// import literal is decoded (a raw-string literal cannot slip past) and a
// scan that finds no file fails instead of passing vacuously.
func assertNoImport(t *testing.T, pkgDir, forbidden string) {
	t.Helper()
	importpin.Check(t, importpin.Spec{
		Dirs:           []string{pkgDir},
		ForbiddenTrees: []string{forbidden},
	})
}

// TestAggregateRequestShape captures the complete outbound request via httptest
// (design §6.4 #10, finding #22): a real gated Submit must POST gzip to the
// pinned host, follow no redirect, send no cookie, and carry no identifying
// header. It also proves a zero-value Gate cannot submit and that Authorize
// refuses a non-valid status.
func TestAggregateRequestShape(t *testing.T) {
	t.Parallel()

	var (
		gotMethod   string
		gotEncoding string
		gotCookie   string
		gotAuth     string
		gotBody     []byte
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotEncoding = r.Header.Get("Content-Encoding")
		gotCookie = r.Header.Get("Cookie")
		gotAuth = r.Header.Get("Authorization")
		gz, err := gzip.NewReader(r.Body)
		if err == nil {
			gotBody, _ = io.ReadAll(gz)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	client, err := aggregateclient.New(srv.URL) // httptest.NewTLSServer is https
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	client.SetHTTPClientForTest(srv.Client()) // trust the test server's cert

	// A valid gate is required; a zero Gate must be refused.
	if err := client.Submit(context.Background(), aggregateclient.Gate{}, aggregate.Submission{}); err == nil {
		t.Error("zero-value Gate must not submit")
	}
	gate, err := aggregateclient.Authorize(aggregate.ConsentValid)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	sub := aggregate.Build(
		aggregate.Meta{ObserverVersion: "1.20", SubmissionID: "fixed", Month: "2026-06"},
		[]aggregate.ModelToolStat{{Model: "claude-opus-4-8", Tool: "claude-code", Accurate: true, Turns: 100, CostUSD: 1.0}},
	)
	if err := client.Submit(context.Background(), gate, sub); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotEncoding != "gzip" {
		t.Errorf("Content-Encoding = %q, want gzip", gotEncoding)
	}
	if gotCookie != "" {
		t.Errorf("Cookie header present: %q — the client must send no cookies", gotCookie)
	}
	if gotAuth != "" {
		t.Errorf("Authorization header present: %q — the rail carries no bearer", gotAuth)
	}
	if len(gotBody) == 0 || !bytes.Contains(gotBody, []byte(`"schema_version"`)) {
		t.Errorf("server did not receive the gzipped submission body")
	}
	// Non-valid status must never mint a Gate.
	if _, err := aggregateclient.Authorize(aggregate.ConsentSchemaChanged); err == nil {
		t.Error("Authorize must refuse a non-valid status")
	}
}
