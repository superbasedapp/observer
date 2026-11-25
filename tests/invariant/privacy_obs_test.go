package invariant

import (
	"context"
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestObsSummaryWireShapeIsAggregateOnly pins the T1 obs rollup wire shape
// (obs-org-tier plan §1): ObsSummaryRow may carry ONLY attribution + the
// content-free dimensions (day/model/provider/project_hash/source) + numeric
// counts/sums. A new free-text/topology field would fail loudly — the T1 floor
// is content-free by construction.
func TestObsSummaryWireShapeIsAggregateOnly(t *testing.T) {
	t.Parallel()
	allowed := map[string]bool{
		"OrgID": true, "UserEmail": true,
		"Day": true, "Model": true, "Provider": true, "ProjectHash": true, "Source": true,
		"Traces": true, "Spans": true, "InputTokens": true, "OutputTokens": true,
		"CacheReadTokens": true, "CacheWriteTokens": true, "ReasoningTokens": true,
		"TotalTokens": true, "CostUSD": true, "ErrorTraces": true,
		"DurationMsSum": true, "DurationMsCount": true,
		"TracesPrimary": true, "ErrorTracesPrimary": true, // F17 primary-bucket counts
	}
	typ := reflect.TypeOf(orgcontract.ObsSummaryRow{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if !allowed[name] {
			t.Errorf("ObsSummaryRow gained non-aggregate field %q — the T1 obs rollup is content-free counts/sums by closed dimensions ONLY", name)
		}
	}
}

// TestObsTraceWireShapeCarriesNoBody pins the T2 structure tier: ObsSpanRow /
// ObsTraceRow / ObsContentRow must not grow a raw prompt/response/tool body
// field on the STRUCTURE rows. Bodies live ONLY on ObsContentRow.Content
// (gated). A field literally named for content on a structure row fails.
func TestObsTraceWireShapeCarriesNoBody(t *testing.T) {
	t.Parallel()
	forbiddenOnStructure := []string{"Content", "Prompt", "Response", "Input", "Output", "Body", "Messages", "Attributes"}
	for _, typ := range []reflect.Type{reflect.TypeOf(orgcontract.ObsTraceRow{}), reflect.TypeOf(orgcontract.ObsSpanRow{}), reflect.TypeOf(orgcontract.ObsSpanEventRow{})} {
		for i := 0; i < typ.NumField(); i++ {
			name := typ.Field(i).Name
			for _, bad := range forbiddenOnStructure {
				if name == bad {
					t.Errorf("%s gained body-bearing field %q — T2 structure ships hashes/labels only; bodies belong on ObsContentRow (T3, gated)", typ.Name(), name)
				}
			}
		}
	}
}

// TestObsTraceWireShape pins the T2 trace row's identity contract (plan
// W1a-2, finding F11): every ObsTraceRow field is classified content-free-
// always or gated (ships ONLY under shipsRawContent(), stripped by
// ObsTraceRow.PrepareForWire), never both and never unclassified, so a new
// identity or PII field cannot silently ride the always-ships path. The end
// user is PII, and so is its unkeyed org-bound hash (an org can test a guess),
// so both hashes are gated too (operator ruling D23, review R-A02).
func TestObsTraceWireShape(t *testing.T) {
	t.Parallel()
	contentFree := map[string]bool{
		"OrgID": true, "UserEmail": true, // agent-stamped attribution (the pushing developer)
		"TraceID": true, "SessionID": true, "ThreadID": true, "RootSpanID": true, // structure ids
		"Source": true, "Status": true, "StartedAt": true, "EndedAt": true,
		"ProjectHash": true, "SpanCount": true, "TotalTokens": true, "CostUSD": true,
		"Service": true, "Environment": true, "Release": true, // the app's deployment labels
	}
	gated := map[string]bool{
		"ProjectRoot": true, "EndUser": true, "Tenant": true, "Tags": true, "Metadata": true,
		"EndUserHash": true, "TenantHash": true, // testable pseudonyms of the gated raw values (D23)
	}
	typ := reflect.TypeOf(orgcontract.ObsTraceRow{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		switch {
		case contentFree[name] && gated[name]:
			t.Errorf("ObsTraceRow field %q classified as BOTH content-free and gated — pick one", name)
		case !contentFree[name] && !gated[name]:
			t.Errorf("ObsTraceRow gained UNCLASSIFIED field %q — classify it content-free-always or gated (and strip it in ObsTraceRow.PrepareForWire)", name)
		}
	}
	// Dynamic half: PrepareForWire must zero every gated field.
	r := orgcontract.ObsTraceRow{
		ProjectRoot: "p", EndUser: "u", Tenant: "t", Tags: []string{"x"}, Metadata: map[string]string{"k": "v"},
		EndUserHash: "eh", TenantHash: "th",
	}
	r.PrepareForWire("org", "dev", false)
	rv := reflect.ValueOf(r)
	for name := range gated {
		if !rv.FieldByName(name).IsZero() {
			t.Errorf("PrepareForWire(raw=false) left gated field %q set", name)
		}
	}
}

// TestObsAdmissionWireShape pins the T6 admission wire contract structurally
// (Plane-A admission org tier, gap-audit §2.1 / #1a): every ObsAdmissionRow
// field must be classified as either content-free-always (ships in
// metadata-only mode) or gated (ships ONLY under shipsRawContent()), and no
// field may be both or unclassified — so a new content-bearing column can't
// silently ride the always-ships path. ObsAdmissionPolicyRow carries only
// admin-authored config fields (Body always ships, like RoutingPolicyDoc.Body).
// Mirrors TestRoutingSummaryWireShapeIsAggregateOnly.
func TestObsAdmissionWireShape(t *testing.T) {
	t.Parallel()
	// Content-free-always: verdict metadata + hashes + soft-join ids + the
	// node hash-chain links. These ride even in the default metadata-only mode.
	contentFree := map[string]bool{
		"OrgID": true, "UserEmail": true, // agent-stamped attribution
		"TS": true, "Mode": true, "Decision": true, "Severity": true, // verdict enums
		"CriterionID": true, "PolicyHash": true, // criterion + soft join
		"JudgeUsed": true, "JudgeHosting": true, "Degraded": true, "LatencyMS": true, // judge facts
		"MessageHash": true,                                       // content-free request provenance (raw text never stored)
		"TraceID":     true, "SessionID": true, "RequestID": true, // content-free soft join keys
		"PrevHash": true, "RowHash": true, // tamper-evidence hash-chain links
		// R-A06: org SDK verdict records only (server-published, never set by
		// a node, ignored on a node push): non-secret credential ids.
		"CredID": true, "WorkspaceID": true, "EnvironmentID": true, "VerdictID": true,
	}
	// Gated: PII / prose — ship ONLY under shipsRawContent() (stripped in
	// composeObsTiers otherwise).
	gated := map[string]bool{
		"Tenant": true, "EndUser": true, "ReasonExcerpt": true,
	}
	typ := reflect.TypeOf(orgcontract.ObsAdmissionRow{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		switch {
		case contentFree[name] && gated[name]:
			t.Errorf("ObsAdmissionRow field %q classified as BOTH content-free and gated — pick one", name)
		case !contentFree[name] && !gated[name]:
			t.Errorf("ObsAdmissionRow gained UNCLASSIFIED field %q — classify it content-free-always or gated (shipsRawContent) so the strip in composeObsTiers stays exhaustive", name)
		}
	}
	// The policy snapshot carries only admin-authored config — every field
	// always ships (Body included, like RoutingPolicyDoc.Body).
	policyAllowed := map[string]bool{
		"OrgID": true, "UserEmail": true,
		"PolicyHash": true, "CreatedAt": true, "Mode": true, "Scope": true,
		"CriteriaCount": true, "Body": true,
	}
	ptyp := reflect.TypeOf(orgcontract.ObsAdmissionPolicyRow{})
	for i := 0; i < ptyp.NumField(); i++ {
		name := ptyp.Field(i).Name
		if !policyAllowed[name] {
			t.Errorf("ObsAdmissionPolicyRow gained unexpected field %q — the policy snapshot is admin config only (hash/created_at/mode/scope/criteria_count/body)", name)
		}
	}
}

// TestObsEvalItemWireShape pins the T7 per-item eval wire contract structurally
// (Plane-A eval-run detail org tier, gap-audit §1 / §2.2 / §6): every
// ObsEvalItemRow field must be classified as either content-free-always (ships
// in metadata-only mode) or gated (ships ONLY under shipsRawContent()), and no
// field may be both or unclassified — so a new content-bearing column can't
// silently ride the always-ships path. Mirrors TestObsAdmissionWireShape.
func TestObsEvalItemWireShape(t *testing.T) {
	t.Parallel()
	// Content-free-always: attribution + run/dataset identity + span/trace soft
	// joins + the score verdict + duration/ts + the dataset item's content_hash.
	contentFree := map[string]bool{
		"OrgID": true, "UserEmail": true, // agent-stamped attribution
		"RunID": true, "RunName": true, "DatasetID": true, "DatasetName": true, // run/dataset identity
		"ItemID": true, "SpanID": true, "TraceID": true, // item + content-free soft joins
		"Scorer": true, "Score": true, "Passed": true, "Source": true, // verdict
		"DurationMs": true, "TS": true, // span duration + score instant
		"ContentHash": true, // content-free signal (raw bodies gated below)
	}
	// Gated: bounded content excerpts + scorer prose — ship ONLY under
	// shipsRawContent() (stripped in composeObsTiers otherwise).
	gated := map[string]bool{
		"InputExcerpt": true, "ExpectedExcerpt": true, "OutputExcerpt": true, "Rationale": true,
	}
	typ := reflect.TypeOf(orgcontract.ObsEvalItemRow{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		switch {
		case contentFree[name] && gated[name]:
			t.Errorf("ObsEvalItemRow field %q classified as BOTH content-free and gated — pick one", name)
		case !contentFree[name] && !gated[name]:
			t.Errorf("ObsEvalItemRow gained UNCLASSIFIED field %q — classify it content-free-always or gated (shipsRawContent) so the strip in composeObsTiers stays exhaustive", name)
		}
	}
}

// fakeObsProviders returns one row per tier so the gating logic in
// composeObsTiers can be exercised. The content row carries a raw body so the
// content-strip path is observable.
func fakeObsProviders() store.ObsOrgProviders {
	return store.ObsOrgProviders{
		Summaries: func(_ context.Context, _ int) ([]orgcontract.ObsSummaryRow, error) {
			return []orgcontract.ObsSummaryRow{{Day: "2026-06-29", Model: "gpt-4o", Traces: 1, CostUSD: 0.01}}, nil
		},
		Spans: func(_ context.Context, _ orgcontract.ObsCursor, _ int) (orgcontract.ObsSpanBatch, error) {
			return orgcontract.ObsSpanBatch{
				Traces: []orgcontract.ObsTraceRow{{
					TraceID: "t1", StartedAt: "2026-06-29T00:00:00Z", ProjectHash: "ph", ProjectRoot: "/secret/path",
					Service: "svc", EndUser: "SECRET_ENDUSER", Tenant: "SECRET_TENANT",
					Tags: []string{"SECRET_TAG"}, Metadata: map[string]string{"k": "SECRET_META"},
				}},
				Spans: []orgcontract.ObsSpanRow{{TraceID: "t1", SpanID: "s1", Kind: "llm", Name: "chat"}},
			}, nil
		},
		Content: func(_ context.Context, _ orgcontract.ObsCursor, _ int) ([]orgcontract.ObsContentRow, error) {
			return []orgcontract.ObsContentRow{{SpanID: "s1", Kind: "prompt", ContentHash: "h1", Content: "SECRET BODY"}}, nil
		},
		EvalRuns: func(_ context.Context, _ int) ([]orgcontract.ObsEvalRow, error) {
			return []orgcontract.ObsEvalRow{{Day: "2026-06-29", RunName: "r1", ScorerName: "json_valid", Total: 2, Passed: 1}}, nil
		},
	}
}

// TestObsTiersGatedOffByDefault pins the consent posture for all four obs
// tiers (obs-org-tier plan §1): the zero ShareOptions attaches NO obs rows even
// when the providers would yield them; each tier ships ONLY under its own flag;
// and T2 project_root + T3 content are stripped unless the node shares full
// content (content_hash / project_hash always survive).
func TestObsTiersGatedOffByDefault(t *testing.T) {
	t.Parallel()
	s, _ := newInvariantStore(t)
	s.SetObsOrgProviders(fakeObsProviders())
	ctx := context.Background()

	// Default share → nothing obs.
	def, err := s.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@x", store.ShareOptions{}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("select default: %v", err)
	}
	if len(def.ObsSummaries)+len(def.ObsTraces)+len(def.ObsSpans)+len(def.ObsContent)+len(def.ObsEvalRuns) != 0 {
		t.Fatalf("default share shipped obs rows: summaries=%d traces=%d spans=%d content=%d evals=%d",
			len(def.ObsSummaries), len(def.ObsTraces), len(def.ObsSpans), len(def.ObsContent), len(def.ObsEvalRuns))
	}

	// Each flag independently gates its tier; content/path stripped (metadata-only).
	opt, err := s.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@x",
		store.ShareOptions{ObsSummary: true, ObsTraces: true, ObsContent: true, ObsEvalSummary: true}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("select opted: %v", err)
	}
	if len(opt.ObsSummaries) == 0 || len(opt.ObsTraces) == 0 || len(opt.ObsSpans) == 0 || len(opt.ObsContent) == 0 || len(opt.ObsEvalRuns) == 0 {
		t.Fatalf("opt-in dropped a tier: summaries=%d traces=%d spans=%d content=%d evals=%d",
			len(opt.ObsSummaries), len(opt.ObsTraces), len(opt.ObsSpans), len(opt.ObsContent), len(opt.ObsEvalRuns))
	}
	if opt.ObsSummaries[0].OrgID != "org-1" {
		t.Errorf("attribution not stamped: %+v", opt.ObsSummaries[0])
	}
	// Metadata-only (no full_content): raw project_root + content MUST be stripped; hashes survive.
	if opt.ObsTraces[0].ProjectRoot != "" {
		t.Errorf("project_root leaked without full_content: %q", opt.ObsTraces[0].ProjectRoot)
	}
	if opt.ObsTraces[0].ProjectHash == "" {
		t.Error("project_hash was stripped — it must always ride")
	}
	// End user (PII), tenant, tags and metadata: raw values AND their hashes
	// stripped (D23); the service label rides (identity contract, W1a-2).
	if tr := opt.ObsTraces[0]; tr.EndUser != "" || tr.Tenant != "" || tr.Tags != nil || tr.Metadata != nil {
		t.Errorf("trace identity leaked without full_content: %+v", tr)
	}
	if tr := opt.ObsTraces[0]; tr.EndUserHash != "" || tr.TenantHash != "" {
		t.Errorf("end_user_hash / tenant_hash shipped metadata-only (D23): %+v", tr)
	}
	if tr := opt.ObsTraces[0]; tr.Service != "svc" {
		t.Errorf("service must always ride: %+v", tr)
	}
	if opt.ObsContent[0].Content != "" {
		t.Errorf("raw content leaked without full_content: %q", opt.ObsContent[0].Content)
	}
	if opt.ObsContent[0].ContentHash == "" {
		t.Error("content_hash was stripped — it must always ride")
	}

	// With full_content, the raw body + path DO ride.
	full, err := s.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@x",
		store.ShareOptions{FullContent: true, ObsTraces: true, ObsContent: true}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("select full: %v", err)
	}
	if tr := full.ObsTraces[0]; tr.EndUser != "SECRET_ENDUSER" || tr.Tenant != "SECRET_TENANT" || len(tr.Tags) != 1 || tr.Metadata["k"] != "SECRET_META" {
		t.Errorf("full_content did not ship the trace identity: %+v", tr)
	}
	if tr := full.ObsTraces[0]; tr.EndUserHash == "" || tr.TenantHash == "" {
		t.Errorf("full_content did not ship the identity hashes: %+v", tr)
	}
	if full.ObsContent[0].Content != "SECRET BODY" || full.ObsTraces[0].ProjectRoot != "/secret/path" {
		t.Errorf("full_content did not ship raw body/path: content=%q root=%q", full.ObsContent[0].Content, full.ObsTraces[0].ProjectRoot)
	}
}
