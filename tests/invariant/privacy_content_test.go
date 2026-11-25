package invariant

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestPushPayloadCarriesNoContent is the privacy invariant: a push must ship
// only the content-free rollup shapes. It seeds the corpus, then stuffs a
// distinctive secret string into EVERY agent-side string column that the
// push seam can in principle read (raw_tool_input, raw_tool_output,
// preceding_reasoning, error_message, target, source_file, projects.root_path,
// projects.git_remote, token_usage.source_file), runs one real push cycle
// against an in-process server, and asserts that not one of those secrets
// appears anywhere in the bytes that crossed the wire.
//
// This guards the structural privacy posture end to end: the orgcontract row
// types carry no content fields, store.SelectUnpushedSince selects no content
// columns when share.full_content=false (the default), and this test fails
// loudly if either ever regresses.
//
// Pre-v1.8.0: this test FAILS — the seam at internal/store/orgpush.go ships
// `target`, `source_file`, `root_path`, `git_remote` raw. That's the leak the
// 2026-06-02 teams test caught. The fix (M1.1–M1.3 + M1.5 of the remediation
// plan at docs/plans/teams-test-findings-remediation-plan-2026-06-03.md) ships only
// the corresponding *_hash columns by default and gates the raw fields behind
// an opt-in node config.
func TestPushPayloadCarriesNoContent(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)

	// Stuff the secret-bearing columns. Order matters: we update the agent
	// DB AFTER the benign seed has gone in via Ingest, so the secrets land
	// in the same rows the push seam will read.
	// actions has no UNIQUE on target/source_file, so blanket-update is fine.
	if _, err := database.ExecContext(ctx,
		`UPDATE actions SET raw_tool_input = ?, raw_tool_output = ?, preceding_reasoning = ?, error_message = ?, target = ?, source_file = ?, user_attachments = ?`,
		secRawInput, secRawOutput, secReasoning, secErrMsg, secTarget, secSourceFile, secUserAttachments); err != nil {
		t.Fatalf("stuff actions: %v", err)
	}
	// projects has UNIQUE(root_path) — per-id update with the same prefix so
	// `bytes.Contains(raw, secRootPath)` still triggers regardless of which
	// project's row leaks.
	rows, err := database.QueryContext(ctx, `SELECT id FROM projects ORDER BY id`)
	if err != nil {
		t.Fatalf("list projects: %v", err)
	}
	var projectIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			t.Fatalf("scan project id: %v", err)
		}
		projectIDs = append(projectIDs, id)
	}
	if err := rows.Close(); err != nil {
		t.Fatalf("close projects rows: %v", err)
	}
	for _, id := range projectIDs {
		if _, err := database.ExecContext(ctx,
			`UPDATE projects SET root_path = ?, git_remote = ?,
			    git_upstream_remote = ?, git_upstream_remote_hash = 'sha256:upstream-remote-canary',
			    git_remote_owner_hash = 'sha256:remote-owner-canary',
			    git_upstream_owner_hash = 'sha256:upstream-owner-canary',
			    root_commit_hash = 'sha256:root-commit-canary',
			    content_fingerprint_hash = 'sha256:content-fingerprint-canary'
			  WHERE id = ?`,
			secRootPath+"-p"+itoa(id), secGitRemote,
			secUpstreamRemote+"-p"+itoa(id), id); err != nil {
			t.Fatalf("stuff project %d: %v", id, err)
		}
	}
	// source_file is the SENTINEL (stripped in metadata-only mode);
	// is_sidechain is the W1 CANARY on the same table — METADATA that must
	// ship in every posture, set to 1 here so the positive assertion below is
	// non-vacuous (the seeded rows are all sidechain=0 by default). turn_id
	// is the §7 follow-up CANARY (server migration 160 / pg 0026) — the same
	// posture, an opaque grouping id that must ship unconditionally. gen_ms/
	// gen_basis are the S10-SPEED CANARY (server migration 174 / pg 0040) —
	// the same posture, a duration + closed enum that must ship
	// unconditionally.
	if _, err := database.ExecContext(ctx,
		`UPDATE token_usage SET source_file = ?, is_sidechain = 1, turn_id = ?, gen_ms = ?, gen_basis = ?`,
		secSourceFile, canaryTurnID, canaryGenMs, canaryGenBasis); err != nil {
		t.Fatalf("stuff token_usage: %v", err)
	}
	if _, err := database.ExecContext(ctx,
		`UPDATE sessions SET git_branch = ?, forked_from_id = ?, parent_thread_id = ?, thread_source = ?,
		    workspace = ?, workspace_hash = 'sha256:workspace-canary', is_worktree = 1,
		                     surface = ?, surface_host = ?, tool_version = ?, tool_version_last = ?,
		                     execution_location = 'customer_worker', vendor_session_ref = ?,
		                     reported_via_token = ?`,
		secGitBranch, secForkedFrom, canaryParentThreadID, secThreadSource, secWorkspace, canarySurface, canarySurfaceHost, canaryToolVersion, canaryToolVersionLast,
		canaryVendorSessionRef, secReportedVia); err != nil {
		t.Fatalf("stuff sessions git_branch + lineage + identity v2 + surface + tool_version: %v", err)
	}
	// Plane B per-turn authority stamps (Sol S5 / Luna L15, migration 095):
	// route / routing_generation / authority_source are CONTENT-FREE enum +
	// integer metadata and must ALWAYS ship (never gated by shipsRawContent).
	// Stamp the seeded api_turns so the positive assertion below is
	// non-vacuous — there is no secret counterpart because these columns
	// can never carry request text.
	if _, err := database.ExecContext(ctx,
		`UPDATE api_turns SET route = 'gateway', routing_generation = 4242, authority_source = 'gateway', request_class = 'compaction'`); err != nil {
		t.Fatalf("stamp api_turns authority: %v", err)
	}
	// Guard events go through the one-owner store helper (the only
	// legal write path — a direct INSERT would also have to fake the
	// §10.4 hash chain). The three content-bearing columns carry their
	// sentinels; target_hash is the content-free counterpart that must
	// still ship.
	if _, err := st.InsertGuardEvents(ctx, []store.GuardEventRow{{
		TS: time.Now().UTC(), SessionID: "sess-cc-1",
		Tool: "claude-code", EventKind: "shell_exec",
		RuleID: "R-101", Category: "destructive", Severity: "critical",
		Decision: "flag", Source: "builtin",
		Reason:        secGuardReason,
		TargetHash:    "sha256:guard-target-canary",
		TargetExcerpt: secGuardExcerpt,
		TaintOrigin:   secGuardTaint,
		ProjectRoot:   secGuardProjectRoot,
	}}); err != nil {
		t.Fatalf("seed guard event: %v", err)
	}
	// Native-OTel content (migration 048): the body carries the sentinel; its
	// content_hash is the content-free counterpart that must still ship.
	if _, err := st.InsertOTelContent(ctx, []models.OTelContent{{
		RequestID: "req-cc-1", SessionID: "sess-cc-1", Kind: "prompt",
		Content: secOTelContent, Timestamp: time.Now().UTC(), Source: "cc_otel",
	}}); err != nil {
		t.Fatalf("seed otel_content: %v", err)
	}

	// Enrol directly (leave the push cursor at zero so the whole corpus is a
	// push candidate — we want maximum surface for a leak to show).
	if err := st.WriteEnrolment(ctx, store.Enrolment{
		OrgID: "org-1", OrgName: "Acme", OrgServerURL: "PLACEHOLDER",
		UserID: "scim-1", UserEmail: "dev@acme.example", BearerKeyID: "k",
	}); err != nil {
		t.Fatalf("WriteEnrolment: %v", err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	bs := &memBearer{bearer: "bearer-xyz", key: priv}

	// In-process server: capture the exact wire bytes, ACK 200.
	var wire []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wire, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int64{"accepted_rows": 1, "deduped_rows": 0, "next_cursor": 1})
	}))
	defer srv.Close()
	// Point the enrolment at the test server.
	if err := st.WriteEnrolment(ctx, store.Enrolment{
		OrgID: "org-1", OrgName: "Acme", OrgServerURL: srv.URL,
		UserID: "scim-1", UserEmail: "dev@acme.example", BearerKeyID: "k",
	}); err != nil {
		t.Fatalf("WriteEnrolment (url): %v", err)
	}
	// Org attribution (agent migration 250, D-43): the corpus above was
	// captured before this enrolment, so it is stamped personal and none of
	// it would ship. Key it to the enrolled org so every assertion below
	// scans a full payload, then add one session of ANOTHER org, with a token
	// row, that must never reach the wire.
	destOrgKey := orgclient.OrgKey(srv.URL, "org-1")
	if _, err := database.ExecContext(ctx, `UPDATE sessions SET authority_org_key = ?`, destOrgKey); err != nil {
		t.Fatalf("key the corpus to the enrolled org: %v", err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, project_id, tool, started_at, authority, authority_org_key)
		 VALUES (?, ?, 'claude-code', ?, 'org', ?)`,
		secForeignOrgSession, projectIDs[0], time.Now().UTC().Format(time.RFC3339), secForeignOrgKey); err != nil {
		t.Fatalf("seed the other org's session: %v", err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO token_usage(session_id, timestamp, tool, model, input_tokens, output_tokens, source, source_file, source_event_id)
		 VALUES(?, ?, 'claude-code', 'claude', 1, 1, 'jsonl', 'foreign.jsonl', ?)`,
		secForeignOrgSession, time.Now().UTC().Format(time.RFC3339), secForeignOrgEvent); err != nil {
		t.Fatalf("seed the other org's token row: %v", err)
	}

	// Obs input-admission (T6): wire a fake obs provider that yields one verdict
	// carrying the content-bearing sentinels (tenant/user/reason_excerpt) plus
	// content-free canaries (decision/message_hash/row_hash). With
	// full_content OFF the composeObsTiers strip must zero the sentinels while
	// the metadata rides — the raw obs_admission_events table doesn't exist in
	// the plain agent DB, so the provider seam (like fakeObsProviders) is the
	// legal source. The policy body is admin config → benign, always ships.
	st.SetObsOrgProviders(store.ObsOrgProviders{
		Admission: func(_ context.Context, _ orgcontract.ObsCursor, _ int) (orgcontract.ObsAdmissionBatch, error) {
			return orgcontract.ObsAdmissionBatch{
				Events: []orgcontract.ObsAdmissionRow{{
					TS: time.Now().UTC().Format(time.RFC3339), Mode: "enforce",
					Decision: "deny", Severity: "critical", PolicyHash: "adm-policy-canary",
					MessageHash: "sha256:adm-msg-canary", RowHash: "adm-rowhash-canary",
					Tenant: secAdmTenant, EndUser: secAdmUser, ReasonExcerpt: secAdmReason,
				}},
				Policies: []orgcontract.ObsAdmissionPolicyRow{{
					PolicyHash: "adm-policy-canary", CreatedAt: time.Now().UTC().Format(time.RFC3339),
					Mode: "enforce", Scope: "all", CriteriaCount: 1, Body: "criterion = benign-policy-body",
				}},
			}, nil
		},
		// T7 per-item eval: one item carrying the content-bearing sentinels
		// (input/expected/output excerpts + rationale) plus content-free canaries
		// (run identity, scorer, content_hash). With full_content OFF the
		// composeObsTiers strip must zero the sentinels while the metadata rides.
		EvalItems: func(_ context.Context, _ orgcontract.ObsCursor, _ int) (orgcontract.ObsEvalItemBatch, error) {
			return orgcontract.ObsEvalItemBatch{
				Items: []orgcontract.ObsEvalItemRow{{
					RunID: 7, RunName: "eval-canary-run", DatasetID: 3, DatasetName: "eval-canary-ds",
					ItemID: 11, SpanID: "eval-span-canary", TraceID: "eval-trace-canary",
					Scorer: "json_valid", Score: 0.5, Passed: false, Source: "run",
					TS: time.Now().UTC().Format(time.RFC3339), ContentHash: "sha256:eval-hash-canary",
					InputExcerpt: secEvalInput, ExpectedExcerpt: secEvalExpected,
					OutputExcerpt: secEvalOutput, Rationale: secEvalRational,
				}},
			}, nil
		},
	})

	// Default config: share.full_content is OFF — the seam should ship hashes
	// only. The [org_client.share.obs] admission opt-in is ON so the T6 arm
	// runs (and its content-bearing verdict columns get exercised by the
	// strip); every other content column stays metadata-only.
	c := orgclient.New(config.OrgClientConfig{
		Enabled: true, MaxPushBytes: config.DefaultMaxPushBytes, KeychainID: "k",
		Share: config.OrgClientShareConfig{
			Obs: config.OrgClientShareObsConfig{Admission: true, EvalItems: true},
		},
	}, st, bs, "inv-test", http.DefaultClient, nil)

	res, err := c.PushOnce(ctx)
	if err != nil {
		t.Fatalf("PushOnce: %v", err)
	}
	if res.Empty || res.RowCount == 0 {
		t.Fatalf("expected a non-empty push, got %+v", res)
	}
	if len(wire) == 0 {
		t.Fatal("server received no body")
	}

	// Decompress and scan the actual transmitted bytes.
	zr, err := gzip.NewReader(bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	for _, s := range allSentinels {
		if bytes.Contains(raw, []byte(s)) {
			t.Errorf("content secret %q leaked into the push payload", s)
		}
	}
	// D-43: no row of another org's session, and no attribution key, ships.
	for _, s := range []string{secForeignOrgSession, secForeignOrgEvent, secForeignOrgKey, destOrgKey} {
		if bytes.Contains(raw, []byte(s)) {
			t.Errorf("org attribution marker %q reached the push payload", s)
		}
	}

	// Sanity: the rollup must carry the hashed counterpart of the columns
	// it stripped — otherwise the wire could be empty and the leak-check
	// would trivially pass. target_hash is the canary: it's present on
	// every action and is the M1.1 contract addition that proves the new
	// (hash-only) shape is in effect.
	if !bytes.Contains(raw, []byte(`"target_hash"`)) {
		t.Errorf("expected hashed counterpart (target_hash) in the payload; scan may be vacuous or the M1.1 wire-shape change hasn't landed")
	}

	// Project Identity Resolver v2 canaries (§3.2): the two gated raws
	// (secUpstreamRemote/secWorkspace) must be absent (checked by the
	// allSentinels scan above) while their hash counterparts DO ship —
	// otherwise the sentinel scan could trivially pass because the whole
	// resolver-v2 bundle failed to ship at all.
	if !bytes.Contains(raw, []byte(`sha256:upstream-remote-canary`)) {
		t.Errorf("expected the session's git_upstream_remote_hash in the payload; the content-free counterpart must always ship")
	}
	if !bytes.Contains(raw, []byte(`sha256:workspace-canary`)) {
		t.Errorf("expected the session's workspace_hash in the payload; the content-free counterpart must always ship")
	}
	if !bytes.Contains(raw, []byte(`sha256:remote-owner-canary`)) {
		t.Errorf("expected the session's git_remote_owner_hash in the payload; it has no raw counterpart and must always ship")
	}
	if !bytes.Contains(raw, []byte(`sha256:upstream-owner-canary`)) {
		t.Errorf("expected the session's git_upstream_owner_hash in the payload; it has no raw counterpart and must always ship")
	}
	if !bytes.Contains(raw, []byte(`sha256:root-commit-canary`)) {
		t.Errorf("expected the session's root_commit_hash in the payload; it has no raw counterpart and must always ship")
	}
	if !bytes.Contains(raw, []byte(`sha256:content-fingerprint-canary`)) {
		t.Errorf("expected the session's content_fingerprint_hash in the payload; it has no raw counterpart and must always ship")
	}
	if !bytes.Contains(raw, []byte(`"is_worktree":true`)) {
		t.Errorf("expected the session's is_worktree bool in the payload; it is content-free and must always ship")
	}

	// W1 capture-surface + sub-agent-token canaries (server migration 139).
	// These are the deliberate polarity FLIP of the old migration-107
	// sentinel: surface / surface_host / token_usage.is_sidechain are
	// METADATA (a closed vocabulary, a bounded host token, a bool), so the
	// DEFAULT metadata-only posture — this very test's posture — must ship
	// them. If a future change re-gates them behind shipsRawContent(), these
	// three assertions fail while the sentinel scan above stays green, which
	// is exactly the signal we want.
	if !bytes.Contains(raw, []byte(canarySurface)) {
		t.Errorf("expected the session's surface (%q) in the payload; W1 made it unconditional metadata, not gated content", canarySurface)
	}
	if !bytes.Contains(raw, []byte(canarySurfaceHost)) {
		t.Errorf("expected the session's surface_host (%q) in the payload; W1 made it unconditional metadata, not gated content", canarySurfaceHost)
	}
	if !bytes.Contains(raw, []byte(`"is_sidechain":true`)) {
		t.Errorf("expected token_usage.is_sidechain on the wire; W1 ships the sub-agent flag unconditionally, like actions.is_sidechain")
	}
	if !bytes.Contains(raw, []byte(canaryTurnID)) {
		t.Errorf("expected token_usage.turn_id (%q) on the wire; the §7 follow-up ships the opaque grouping id unconditionally, like is_sidechain", canaryTurnID)
	}
	// S10-SPEED generation-timing canary (server migration 174 / pg 0040):
	// gen_ms/gen_basis must ship unconditionally, the same posture as
	// turn_id above. gen_timing_v has NO wire counterpart by design (a
	// node-local upsert-precedence input) and must NEVER appear.
	if !bytes.Contains(raw, []byte(`"gen_ms":424242`)) {
		t.Errorf("expected token_usage.gen_ms (424242) on the wire; the S10-SPEED follow-up ships the generation duration unconditionally, like turn_id")
	}
	if !bytes.Contains(raw, []byte(`"gen_basis":"`+canaryGenBasis+`"`)) {
		t.Errorf("expected token_usage.gen_basis (%q) on the wire; the S10-SPEED follow-up ships the closed basis enum unconditionally, like turn_id", canaryGenBasis)
	}
	if bytes.Contains(raw, []byte("gen_timing_v")) {
		t.Errorf("gen_timing_v must never appear on the wire; it is a node-local upsert-precedence input with no wire counterpart")
	}
	// Tool-version trickle-up canary (server migration 161 / pg 0027): this
	// RECLASSIFIES sessions.tool_version from "never ships" to unconditional
	// METADATA, the same polarity flip W1 did for surface/surface_host. If a
	// future change re-gates it behind shipsRawContent(), this assertion
	// fails while the (now tool-version-free) sentinel scan above stays
	// green — exactly the signal we want.
	if !bytes.Contains(raw, []byte(canaryToolVersion)) {
		t.Errorf("expected the session's tool_version (%q) in the payload; this change made it unconditional metadata, not gated content", canaryToolVersion)
	}
	if !bytes.Contains(raw, []byte(canaryToolVersionLast)) {
		t.Errorf("expected the session's tool_version_last (%q) in the payload; it is unconditional metadata like tool_version", canaryToolVersionLast)
	}
	// Parent-thread-id trickle-up canary (server migration 162 / pg 0028):
	// this RECLASSIFIES sessions.parent_thread_id from "never ships" to
	// unconditional METADATA, the same polarity flip as tool_version above —
	// while forked_from_id / thread_source (secForkedFrom / secThreadSource)
	// stay sentinels and must still be absent from the scan above.
	if !bytes.Contains(raw, []byte(canaryParentThreadID)) {
		t.Errorf("expected the session's parent_thread_id (%q) in the payload; this change made it unconditional metadata, not gated content", canaryParentThreadID)
	}
	// Cloud-agents canaries (agent 240 / server 300 / pg 0170): where the
	// session ran and its vendor reference are unconditional METADATA.
	if !bytes.Contains(raw, []byte(canaryVendorSessionRef)) {
		t.Errorf("expected the session's vendor_session_ref (%q) in the payload; it is unconditional metadata like parent_thread_id", canaryVendorSessionRef)
	}
	if !bytes.Contains(raw, []byte(`"execution_location":"customer_worker"`)) {
		t.Errorf("expected the session's execution_location in the payload; it is closed-vocabulary metadata like surface")
	}

	// Guard-layer canaries (G2, guard spec §10.2): the guard event must
	// have SHIPPED (metadata) for the guard sentinel scan above to be
	// non-vacuous, and its content-free hash counterpart must be on the
	// wire — proving the seam shipped the row but stripped the verdict
	// prose rather than dropping the table or shipping it whole.
	if !bytes.Contains(raw, []byte(`"guard_events"`)) {
		t.Errorf("expected guard_events in the payload; the guard push arm may be missing and the guard sentinel scan vacuous")
	}
	if !bytes.Contains(raw, []byte(`"R-101"`)) {
		t.Errorf("expected the guard event's rule_id (R-101) in the payload; guard metadata should ship even in metadata-only mode")
	}
	if !bytes.Contains(raw, []byte(`sha256:guard-target-canary`)) {
		t.Errorf("expected the guard event's target_hash in the payload; the content-free counterpart must always ship")
	}

	// Obs admission canaries (T6): the verdict must have SHIPPED (metadata) for
	// the admission sentinel scan above to be non-vacuous, and its content-free
	// hash-chain link + message_hash must be on the wire — proving the seam
	// shipped the row but stripped the PII/prose (tenant/user/reason_excerpt)
	// rather than dropping the tier or shipping it whole. The decision must
	// ride VERBATIM (no wire translation to "would_block").
	if !bytes.Contains(raw, []byte(`"obs_admission_events"`)) {
		t.Errorf("expected obs_admission_events in the payload; the T6 admission push arm may be missing and the admission sentinel scan vacuous")
	}
	if !bytes.Contains(raw, []byte(`adm-rowhash-canary`)) {
		t.Errorf("expected the admission verdict's row_hash (dedup key) in the payload; the content-free hash-chain link must always ship")
	}
	if !bytes.Contains(raw, []byte(`sha256:adm-msg-canary`)) {
		t.Errorf("expected the admission verdict's message_hash in the payload; the content-free request provenance must always ship")
	}
	if !bytes.Contains(raw, []byte(`"decision":"deny"`)) {
		t.Errorf("expected the admission verdict decision to ship VERBATIM (allow|flag|ask|deny); the node ships the stored decision, the server does any would_block display mapping")
	}

	// Obs per-item eval canaries (T7): the score must have SHIPPED (metadata)
	// for the eval sentinel scan above to be non-vacuous, and its content-free
	// content_hash + run identity must be on the wire — proving the seam shipped
	// the row but stripped the item excerpts/rationale rather than dropping the
	// tier or shipping it whole.
	if !bytes.Contains(raw, []byte(`"obs_eval_items"`)) {
		t.Errorf("expected obs_eval_items in the payload; the T7 per-item eval push arm may be missing and the eval sentinel scan vacuous")
	}
	if !bytes.Contains(raw, []byte(`sha256:eval-hash-canary`)) {
		t.Errorf("expected the eval item's content_hash in the payload; the content-free signal must always ship")
	}
	if !bytes.Contains(raw, []byte(`eval-canary-run`)) {
		t.Errorf("expected the eval item's run_name in the payload; the content-free run identity must ship even in metadata-only mode")
	}

	// Plane B per-turn authority stamps (Sol S5 / Luna L15): the three
	// content-free api_turns stamps must ALWAYS ship — even in the default
	// metadata-only posture — because a mixed-mode fleet's org rollup needs
	// them to single-count a turn and know which source owns its usage
	// authority. There is no secret counterpart (enum + integer only), so
	// this positive canary is how the invariant is pinned in this suite.
	if !bytes.Contains(raw, []byte(`"route":"gateway"`)) {
		t.Errorf("expected the api_turn's route stamp in the payload; the content-free per-turn authority stamp must always ship")
	}
	if !bytes.Contains(raw, []byte(`"authority_source":"gateway"`)) {
		t.Errorf("expected the api_turn's authority_source stamp in the payload; the content-free per-turn authority stamp must always ship")
	}
	if !bytes.Contains(raw, []byte(`"routing_generation":4242`)) {
		t.Errorf("expected the api_turn's routing_generation stamp in the payload; the content-free per-turn authority stamp must always ship")
	}
	// The client-declared request class (agent 144 / server 188, lane
	// G-WIRE2) is a closed enum with no request text: it ships in the
	// default posture too.
	if !bytes.Contains(raw, []byte(`"request_class":"compaction"`)) {
		t.Errorf("expected the api_turn's request_class in the payload; the closed-enum request class must always ship")
	}
}

// TestPushPayloadCarriesContentWhenOptedIn is the inverse guard: when the
// node operator has explicitly enabled share.full_content, the seam must
// ship the raw target/source_file/project_root/git_remote columns. Without
// this test the opt-in path could silently regress to metadata-only without
// any signal.
//
// Pre-M1.2 the OrgClientConfig.Share field doesn't exist; the test is
// marked skipped until the config plumbing lands, so it documents the
// expected behavior without blocking the M1.4 RED-to-GREEN flow.
func TestPushPayloadCarriesContentWhenOptedIn(t *testing.T) {
	// All three cases route through ShareOptions.shipsRawContent(): the node's
	// own full_content opt-in and the native-console admin-managed default-flip
	// are the TEAMS-posture paths (admin authors admin_managed via the node's
	// provisioning; still node-side, no remote force); enterprise_granted is the
	// structurally distinct ENTERPRISE-posture path (Plane B dual-mode gateway /
	// RBAC-IA design, 2026-08-29 §5.3) — set from a node's own managed enrolment
	// grant (govern.Effective.GrantsEnterpriseContent()), minted once at
	// enrolment under the org's chosen product_posture, never a live remote
	// command or a governance-body directive (see TestOrgPushUnchangedByGovernance
	// in governance_phase1b_test.go, which pins that the governance-body merge
	// specifically cannot reach this predicate). Each must ship the GATED
	// path/excerpt columns raw — while the never-read body columns
	// (raw_tool_input/output, reasoning, error_message) stay off the wire even
	// then (they are not selected by the seam at all).
	gatedShouldShip := []string{
		secTarget, secSourceFile, secRootPath, secGitRemote, secGitBranch,
		secGuardReason, secGuardExcerpt, secGuardTaint,
		secOTelContent,
		// Project Identity Resolver v2's two raw fields (§3.2) — same gate.
		secUpstreamRemote, secWorkspace,
	}
	bodiesNeverShip := []string{
		secRawInput, secRawOutput, secReasoning, secErrMsg,
		// Codex fork/subagent lineage (forked_from_id / thread_source) is
		// node-local in EVERY share mode — it must not ship even under
		// full_content / admin_managed. parent_thread_id is no longer in
		// this bucket (server migration 162 / pg 0028): it ships
		// unconditionally, in every posture including this one — see
		// canaryParentThreadID.
		secForkedFrom, secThreadSource,
		// The cloud-session sandbox tag (agent 245) is node-local in EVERY
		// share mode.
		secReportedVia,
		// User-attachment metadata (migration 126) is node-local in EVERY
		// share mode — org-wire promotion is a documented follow-up.
		secUserAttachments,
		// The gate's matched project root on guard_events (agent 253) is
		// node-local in EVERY share mode.
		secGuardProjectRoot,
	}

	for _, tc := range []struct {
		name  string
		share store.ShareOptions
	}{
		{"full_content", store.ShareOptions{FullContent: true}},
		{"admin_managed", store.ShareOptions{AdminManaged: true}},
		{"enterprise_granted", store.ShareOptions{EnterpriseGranted: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
			if err != nil {
				t.Fatalf("db.Open: %v", err)
			}
			defer func() { _ = database.Close() }()
			st := store.New(database)
			seed(ctx, t, st)

			if _, err := database.ExecContext(ctx,
				`UPDATE actions SET raw_tool_input = ?, raw_tool_output = ?, preceding_reasoning = ?, error_message = ?, target = ?, source_file = ?, user_attachments = ?`,
				secRawInput, secRawOutput, secReasoning, secErrMsg, secTarget, secSourceFile, secUserAttachments); err != nil {
				t.Fatalf("stuff actions: %v", err)
			}
			// projects has UNIQUE(root_path): per-id update with the sentinel as a
			// prefix so bytes.Contains still triggers on whichever row ships.
			prows, err := database.QueryContext(ctx, `SELECT id FROM projects ORDER BY id`)
			if err != nil {
				t.Fatalf("list projects: %v", err)
			}
			var projectIDs []int64
			for prows.Next() {
				var id int64
				if err := prows.Scan(&id); err != nil {
					_ = prows.Close()
					t.Fatalf("scan project id: %v", err)
				}
				projectIDs = append(projectIDs, id)
			}
			if err := prows.Close(); err != nil {
				t.Fatalf("close projects rows: %v", err)
			}
			for _, id := range projectIDs {
				if _, err := database.ExecContext(ctx,
					`UPDATE projects SET root_path = ?, git_remote = ?, git_upstream_remote = ? WHERE id = ?`,
					secRootPath+"-p"+itoa(id), secGitRemote, secUpstreamRemote+"-p"+itoa(id), id); err != nil {
					t.Fatalf("stuff project %d: %v", id, err)
				}
			}
			if _, err := database.ExecContext(ctx,
				`UPDATE token_usage SET source_file = ?`, secSourceFile); err != nil {
				t.Fatalf("stuff token_usage: %v", err)
			}
			if _, err := database.ExecContext(ctx,
				`UPDATE sessions SET git_branch = ?, forked_from_id = ?, parent_thread_id = ?, thread_source = ?, workspace = ?, reported_via_token = ?`,
				secGitBranch, secForkedFrom, canaryParentThreadID, secThreadSource, secWorkspace, secReportedVia); err != nil {
				t.Fatalf("stuff sessions git_branch + lineage + workspace: %v", err)
			}
			if _, err := st.InsertGuardEvents(ctx, []store.GuardEventRow{{
				TS: time.Now().UTC(), SessionID: "sess-cc-1",
				Tool: "claude-code", EventKind: "shell_exec",
				RuleID: "R-101", Category: "destructive", Severity: "critical",
				Decision: "flag", Source: "builtin",
				Reason:        secGuardReason,
				TargetHash:    "sha256:guard-target-canary",
				TargetExcerpt: secGuardExcerpt,
				TaintOrigin:   secGuardTaint,
				ProjectRoot:   secGuardProjectRoot,
			}}); err != nil {
				t.Fatalf("seed guard event: %v", err)
			}
			if _, err := st.InsertOTelContent(ctx, []models.OTelContent{{
				RequestID: "req-cc-1", SessionID: "sess-cc-1", Kind: "prompt",
				Content: secOTelContent, Timestamp: time.Now().UTC(), Source: "cc_otel",
			}}); err != nil {
				t.Fatalf("seed otel_content: %v", err)
			}

			batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example", tc.share, store.ScopeOptions{})
			if err != nil {
				t.Fatalf("SelectUnpushedSince: %v", err)
			}
			raw, err := json.Marshal(batch)
			if err != nil {
				t.Fatalf("marshal batch: %v", err)
			}

			for _, s := range gatedShouldShip {
				if !bytes.Contains(raw, []byte(s)) {
					t.Errorf("[%s] gated content %q did NOT ship — the opt-in/flip failed to flip the seam", tc.name, s)
				}
			}
			for _, s := range bodiesNeverShip {
				if bytes.Contains(raw, []byte(s)) {
					t.Errorf("[%s] never-read body column %q leaked — these are not selected by the seam even under full content", tc.name, s)
				}
			}
		})
	}
}

// TestEnterpriseGrantedHasNoPerDeveloperOptOut is the operator's §5.3.6
// ruling made testable (design §5.3 item 6, review finding F7): under the
// enterprise posture no per-developer opt-in — and symmetrically no
// per-developer opt-out — exists or is expected. The consent gesture is the
// org's (posture chosen at org creation + the node's managed/IdP enrolment
// class), not the individual developer's, and no node-side edit is part of
// the flow.
//
// This is pinned two ways:
//
//  1. store.ShareOptions carries no field alongside EnterpriseGranted that a
//     developer could set locally to suppress it once the resolved grant says
//     true — EnterpriseGranted alone (every other field at its zero value)
//     must ship raw content, exactly like FullContent alone and AdminManaged
//     alone. If a future change added an "EnterpriseOptOut"-shaped field ANDed
//     against it, this proves it by construction: shipsRawContent() would
//     then require a SECOND field to also be true/false, and this assertion
//     (EnterpriseGranted:true, everything else zero) would start failing.
//  2. govern.Effective.GrantsEnterpriseContent() (internal/govern/enterprise_test.go
//     ::TestGrantsEnterpriseContent) takes no "local"/developer-supplied
//     input at all — it is a zero-argument method reading only the resolved
//     Managed + Authority fields, i.e. the org's enrolment grant. There is no
//     LowerBool-style call site for it anywhere (unlike full_content, which
//     is explicitly merged against a local value in
//     TestGovernanceCannotRaiseShare) — confirmed by grep: orgpush.go never
//     passes EnterpriseGranted through a merge function, it is read straight
//     off the resolved ShareOptions the ONE construction site built.
func TestEnterpriseGrantedHasNoPerDeveloperOptOut(t *testing.T) {
	opts := store.ShareOptions{EnterpriseGranted: true}
	if !opts.ShipsRawContent() {
		t.Fatal("EnterpriseGranted alone (every other ShareOptions field at its zero value) must ship raw content — " +
			"if this fails, a new field now gates EnterpriseGranted, which would reintroduce a per-developer opt-out/opt-in the §5.3.6 ruling forbids")
	}

	// Structural half of the proof: reflect over ShareOptions and confirm no
	// OTHER bool field is a plausible "enterprise opt-out/consent" companion
	// to EnterpriseGranted. This is a naming-convention guard, not a full
	// semantic proof, but it fails loud if someone adds
	// EnterpriseOptOut/EnterpriseConsent/DeveloperConsent-shaped fields that
	// the disjunct above wouldn't otherwise catch (a field that defaults to
	// true and must be explicitly set false would slip past case 1).
	suspectSubstrings := []string{"optout", "opt_out", "consent", "developerapproval", "developer_approval"}
	rt := reflect.TypeOf(store.ShareOptions{})
	for i := 0; i < rt.NumField(); i++ {
		name := strings.ToLower(rt.Field(i).Name)
		for _, s := range suspectSubstrings {
			if strings.Contains(name, s) {
				t.Fatalf("store.ShareOptions gained field %q, which looks like a per-developer opt-out/consent gate on the enterprise grant — "+
					"§5.3.6 rules this out: the consent gesture is the org's, not the individual developer's", rt.Field(i).Name)
			}
		}
	}
}

// TestPushPayloadCarriesToolBodiesWhenOptedIn is the Arc 4 P2 extraction tier:
// under the DISTINCT full_tool_bodies opt-in, the four actions body columns
// (raw_tool_input, raw_tool_output, preceding_reasoning, error_message) — which
// TestPushPayloadCarriesContentWhenOptedIn proves NEVER ship under
// full_content/admin_managed alone — DO ship. And because the tier is
// orthogonal to shipsRawContent(), the path/target columns must STILL be
// stripped (full_tool_bodies grants bodies, not paths). Together with the two
// tests above this pins the granularity: bodies ⟺ full_tool_bodies, paths ⟺
// full_content, and neither leaks the other.
//
// The managed remote-RAISE of this tier is exercised at the govern layer
// (RaiseBool gated on Effective.Managed) + cmd/observer (lowerShareOptions);
// here we pin the wire seam given the resolved ShareOptions, which is where the
// individual-plane guarantee ultimately lands.
func TestPushPayloadCarriesToolBodiesWhenOptedIn(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)

	if _, err := database.ExecContext(ctx,
		`UPDATE actions SET raw_tool_input = ?, raw_tool_output = ?, preceding_reasoning = ?, error_message = ?, target = ?, source_file = ?`,
		secRawInput, secRawOutput, secReasoning, secErrMsg, secTarget, secSourceFile); err != nil {
		t.Fatalf("stuff actions: %v", err)
	}

	batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example",
		store.ShareOptions{FullToolBodies: true}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}

	// The four body columns MUST ship under this tier.
	for _, s := range []string{secRawInput, secRawOutput, secReasoning, secErrMsg} {
		if !bytes.Contains(raw, []byte(s)) {
			t.Errorf("body column %q did NOT ship under full_tool_bodies — the tier failed to flip the seam", s)
		}
	}
	// Paths/targets are a DIFFERENT tier (shipsRawContent) — full_tool_bodies
	// must not leak them.
	for _, s := range []string{secTarget, secSourceFile} {
		if bytes.Contains(raw, []byte(s)) {
			t.Errorf("path/target %q leaked under full_tool_bodies — the tier is orthogonal to full_content and must not ship paths", s)
		}
	}
}
