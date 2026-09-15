package invariant

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// memBearer is a deterministic in-test orgclient.BearerStore (the production
// OpenBearerStore would probe — and on a developer machine, write to — the OS
// keychain, which a test must not do).
type memBearer struct {
	bearer string
	key    ed25519.PrivateKey
}

func (m *memBearer) SaveBearer(b string) error { m.bearer = b; return nil }
func (m *memBearer) LoadBearer() (string, error) {
	if m.bearer == "" {
		return "", orgclient.ErrNoSecret
	}
	return m.bearer, nil
}
func (m *memBearer) SaveAgentKey(k ed25519.PrivateKey) error { m.key = k; return nil }
func (m *memBearer) LoadAgentKey() (ed25519.PrivateKey, error) {
	if m.key == nil {
		return nil, orgclient.ErrNoSecret
	}
	return m.key, nil
}
func (m *memBearer) Clear() error    { m.bearer, m.key = "", nil; return nil }
func (m *memBearer) Backend() string { return "mem" }

// SaveVirtualKey / LoadVirtualKey satisfy the P5a virtual-key extension of
// orgclient.BearerStore (internal/orgclient/bearer_store.go). This fake does
// not exercise Gateway Mode, so the stubs are inert — added only to keep the
// shared invariant package compiling after the interface grew.
func (m *memBearer) SaveVirtualKey(string, uint64) error { return nil }

func (m *memBearer) LoadVirtualKey() (string, uint64, error) {
	return "", 0, orgclient.ErrNoSecret
}

func itoa(i int64) string { return strconv.FormatInt(i, 10) }

// privacy sentinels — distinct, unmistakable markers stuffed into every
// agent-side string column. None may appear in the pushed bytes when the
// node has NOT opted in to full-content sharing.
//
// First four (secRawInput ... secErrMsg): the original v1.5+ posture —
// content columns that have ALWAYS been forbidden on the wire.
// Next four (secTarget ... secGitRemote): the v1.8.0 additions covering
// the four columns the 2026-06-02 teams test found leaking
// (actions.target, actions.source_file, projects.root_path,
// projects.git_remote). Pre-M1.x these ship raw; post-M1.x the seam ships
// only the hashed counterparts (target_hash / source_file_hash /
// project_root_hash / git_remote_hash).
const (
	secRawInput  = "SECRET_RAW_INPUT_xyzzy_42"
	secRawOutput = "SECRET_RAW_OUTPUT_plugh_99"
	secReasoning = "SECRET_REASONING_hunter2_zz"
	secErrMsg    = "SECRET_ERRMSG_swordfish_qq"

	secTarget     = "SECRET_TARGET_correcthorsebatterystaple"
	secSourceFile = "SECRET_SOURCEFILE_tetragrammaton_ww"
	secRootPath   = "SECRET_ROOTPATH_voluptuous_qq"
	secGitRemote  = "SECRET_GITREMOTE_omphaloskepsis_uu"
	// sessions.git_branch: no hash counterpart and no server feature keys on
	// it, but branch names routinely encode client/codename/ticket ids, so it
	// ships raw ONLY under full_content / admin_managed (stripped by default).
	secGitBranch = "SECRET_GITBRANCH_antidisestablishment_bb"

	// Codex fork/subagent lineage (migration 069): forked_from_id /
	// parent_thread_id / thread_source are NODE-LOCAL — never selected by
	// the push seam, in ANY share mode (unlike git_branch, they don't ship
	// even under full_content). Written only via Store.SetSessionLineage.
	secForkedFrom   = "SECRET_FORKEDFROM_grandiloquent_ff"
	secParentThread = "SECRET_PARENTTHREAD_perspicacious_pp"
	secThreadSource = "SECRET_THREADSOURCE_sesquipedalian_ss"

	// Capture-surface attribution (agent migration 107 / server migration
	// 139). These are POSITIVE CANARIES, not sentinels — the opposite
	// polarity of everything else in this block.
	//
	// Until the node session-detail trickle-up wave W1 these were secrets:
	// surface / surface_host were NODE-LOCAL and the push seam selected
	// neither, in any share mode. W1 DELIBERATELY reclassified them as
	// METADATA and put them on the wire unconditionally: `surface` is a
	// closed vocabulary the node's Store.SetSessionSurface refuses to write
	// outside of (models.KnownSurface — cli | ide | desktop | sdk | web) and
	// `surface_host` a bounded host token (vscode | jetbrains |
	// claude-desktop | ...). Neither can carry a path, a prompt or a branch
	// name, so neither is gated — the org needs them to split IDE vs
	// terminal vs desktop spend.
	//
	// Still stuffed directly (bypassing the store's vocabulary check) so the
	// probe reads whatever the COLUMN holds rather than a value the store
	// would have blessed: if the seam ever stopped shipping the column, or
	// started substituting a default, these distinctive bytes would vanish
	// from the wire and TestPushPayloadCarriesNoContent's canary block fails.
	canarySurface     = "CANARY_SURFACE_pulchritudinous_uu"
	canarySurfaceHost = "CANARY_SURFACEHOST_tintinnabulation_hh"

	// Guard-layer additions (migration 040, guard spec §10.2): the
	// three content-bearing guard_events columns. guard_events rows DO
	// push (unlike the node-local cache_*/advisor_* tables) — these
	// columns must be stripped in Go at SelectUnpushedSince unless the
	// node opted into [org_client.share].full_content, while
	// target_hash always ships.
	secGuardReason  = "SECRET_GUARDREASON_balderdash_kk"
	secGuardExcerpt = "SECRET_GUARDEXCERPT_rigmarole_jj"
	secGuardTaint   = "SECRET_GUARDTAINT_skulduggery_mm"

	// Native-console (otel_content) addition: the captured content body is
	// content-bearing — it ships ONLY under full_content / admin_managed, with
	// content_hash always shipping. Migration 048 (agent) / 007 (server).
	secOTelContent = "SECRET_OTELCONTENT_flibbertigibbet_pp"

	// Obs input-admission (T6, obs migration 0005): the three content-bearing
	// verdict columns (tenant / user / reason_excerpt). They ride raw out of
	// the obs provider and are stripped in composeObsTiers unless the node
	// opted into full_content / admin_managed — while the content-free verdict
	// metadata (decision / message_hash / row_hash / hash-chain links) always
	// ships. Composed via the obs provider seam (orgpush.go names no obs_*
	// table); the raw request text is NEVER stored on the node at all.
	secAdmTenant = "SECRET_ADMTENANT_collywobbles_xx"
	secAdmUser   = "SECRET_ADMUSER_widdershins_vv"
	secAdmReason = "SECRET_ADMREASON_snollygoster_tt"

	// Obs per-item eval (T7, obs migration 0002 tables): the four
	// content-bearing item columns (input / expected / output excerpts +
	// scorer rationale). They ride raw out of the obs provider and are
	// stripped in composeObsTiers unless the node opted into
	// full_content / admin_managed — while the content-free score metadata
	// (run/dataset identity, scorer, score, pass, content_hash, ts) always
	// ships. Composed via the obs provider seam (orgpush.go names no obs_*
	// table); the raw bodies live on the node only under its ContentGate.
	secEvalInput    = "SECRET_EVALINPUT_borborygmus_aa"
	secEvalExpected = "SECRET_EVALEXPECTED_gongoozler_bb"
	secEvalOutput   = "SECRET_EVALOUTPUT_absquatulate_cc"
	secEvalRational = "SECRET_EVALRATIONALE_mumpsimus_dd"

	// Project Identity Resolver v2 (agent migration 102 / server migration
	// 121, docs/plans/project-identity-resolver-v2-plan-2026-09-06.md §3.2):
	// of the nine new columns, exactly TWO have a raw counterpart on the
	// wire — projects.git_upstream_remote and sessions.workspace. Like
	// git_remote/git_branch above, they ship ONLY under
	// ShareOptions.shipsRawContent() and are stripped in Go by
	// SelectUnpushedSince; the other seven fields in this bundle (the four
	// owner/root-commit/fingerprint hashes, WorkspaceHash,
	// GitUpstreamRemoteHash, IsWorktree) are content-free and always ship —
	// there is no sentinel for them, they're proven present by a positive
	// canary instead.
	secUpstreamRemote = "SECRET_UPSTREAMREMOTE_widdershins_oo"
	secWorkspace      = "SECRET_WORKSPACE_snickersnee_ee"
)

// allSentinels is the union of the original 4 content-column sentinels,
// the 4 v1.8.0 target/path sentinels, the 3 guard-layer verdict sentinels,
// and the 2 Project Identity Resolver v2 raw-field sentinels. Every push in
// the default (full_content=false) mode must ship NONE of these.
//
// canarySurface / canarySurfaceHost are deliberately NOT here: W1 moved the
// capture-surface columns from node-local to unconditional METADATA, so they
// are asserted PRESENT (see the canary block in TestPushPayloadCarriesNoContent
// and TestSessionSurfaceAndSidechainTokensShipAsMetadata) rather than absent.
var allSentinels = []string{
	secRawInput, secRawOutput, secReasoning, secErrMsg,
	secTarget, secSourceFile, secRootPath, secGitRemote, secGitBranch,
	secForkedFrom, secParentThread, secThreadSource,
	secGuardReason, secGuardExcerpt, secGuardTaint,
	secOTelContent,
	secAdmTenant, secAdmUser, secAdmReason,
	secEvalInput, secEvalExpected, secEvalOutput, secEvalRational,
	secUpstreamRemote, secWorkspace,
}

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
// plan at docs/teams-test-findings-remediation-plan-2026-06-03.md) ships only
// the corresponding *_hash columns by default and gates the raw fields behind
// an opt-in node config.
func TestPushPayloadCarriesNoContent(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
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
		`UPDATE actions SET raw_tool_input = ?, raw_tool_output = ?, preceding_reasoning = ?, error_message = ?, target = ?, source_file = ?`,
		secRawInput, secRawOutput, secReasoning, secErrMsg, secTarget, secSourceFile); err != nil {
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
	// non-vacuous (the seeded rows are all sidechain=0 by default).
	if _, err := database.ExecContext(ctx,
		`UPDATE token_usage SET source_file = ?, is_sidechain = 1`, secSourceFile); err != nil {
		t.Fatalf("stuff token_usage: %v", err)
	}
	if _, err := database.ExecContext(ctx,
		`UPDATE sessions SET git_branch = ?, forked_from_id = ?, parent_thread_id = ?, thread_source = ?,
		    workspace = ?, workspace_hash = 'sha256:workspace-canary', is_worktree = 1,
		                     surface = ?, surface_host = ?`,
		secGitBranch, secForkedFrom, secParentThread, secThreadSource, secWorkspace, canarySurface, canarySurfaceHost); err != nil {
		t.Fatalf("stuff sessions git_branch + lineage + identity v2 + surface: %v", err)
	}
	// Plane B per-turn authority stamps (Sol S5 / Luna L15, migration 095):
	// route / routing_generation / authority_source are CONTENT-FREE enum +
	// integer metadata and must ALWAYS ship (never gated by shipsRawContent).
	// Stamp the seeded api_turns so the positive assertion below is
	// non-vacuous — there is no secret counterpart because these columns
	// can never carry request text.
	if _, err := database.ExecContext(ctx,
		`UPDATE api_turns SET route = 'gateway', routing_generation = 4242, authority_source = 'gateway'`); err != nil {
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
		// Codex fork/subagent lineage is node-local in EVERY share mode —
		// it must not ship even under full_content / admin_managed.
		secForkedFrom, secParentThread, secThreadSource,
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
			database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
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
				`UPDATE sessions SET git_branch = ?, forked_from_id = ?, parent_thread_id = ?, thread_source = ?, workspace = ?`,
				secGitBranch, secForkedFrom, secParentThread, secThreadSource, secWorkspace); err != nil {
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
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
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

// seedCacheEvents inserts one cache_events row with a sentinel model, so a
// SelectUnpushedSince batch can be searched for whether the P5c cache aggregate
// shipped. cache_segments/entries/events stay NODE-LOCAL; only the content-free
// (day, model, kind) aggregate crosses the wire, and only under cache_detail.
func seedCacheEvents(ctx context.Context, t *testing.T, database *sql.DB, model string) {
	t.Helper()
	ts := time.Now().UTC().Format(time.RFC3339)
	if _, err := database.ExecContext(ctx,
		`INSERT INTO cache_events (session_id, tier, timestamp, model, kind, tokens_read, tokens_written, cost_delta_usd)
		 VALUES ('sess-cc-1', 'proxy', ?, ?, 'hit', 4000, 0, -0.012)`, ts, model); err != nil {
		t.Fatalf("seed cache_events: %v", err)
	}
}

// TestPushPayloadCarriesCacheWhenOptedIn is the Arc 4 P5c extraction tier: under
// the DISTINCT cache_detail opt-in, the node-local cache_events log ships as a
// content-free (day × model × kind) aggregate. The cache_* table NAMES still
// never appear in orgpush.go (SelectCacheSummaries owns the read in a separate
// file — TestSelectUnpushedSinceExcludesCacheTables guards that); this proves
// the aggregate itself flips onto the wire under the tier.
func TestPushPayloadCarriesCacheWhenOptedIn(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)
	const secCacheModel = "SENTINEL_CACHE_MODEL_pangram_zz"
	seedCacheEvents(ctx, t, database, secCacheModel)

	batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example",
		store.ShareOptions{CacheDetail: true}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	if len(batch.CacheSummaries) == 0 {
		t.Fatal("cache_detail opt-in shipped no CacheSummaries — the tier failed to flip the seam")
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}
	if !bytes.Contains(raw, []byte(secCacheModel)) {
		t.Error("cache aggregate did NOT ship under cache_detail — the tier failed to flip the seam")
	}
}

// TestPushPayloadStripsCacheWhenNotOptedIn is the other side of the tier: with
// cache_detail OFF, the fleet cache aggregate must NOT ship — not even under
// full_content (maximum path/content disclosure). cache_detail is a DISTINCT
// tier, orthogonal to shipsRawContent().
//
// Org-parity W2.1 nuance (plan §0/§3.1, 2026-08-24), extended by the per-event
// timeline (operator directive item 6): TWO session-scoped cache wires
// deliberately ride shipsRawContent() rather than cache_detail —
// SessionCacheSummaries (the bucket) and SessionCacheEvents (the per-event
// log). full_content / admin_managed nodes DO ship both, model included. So
// under full_content-only the batch-wide byte-scan for the sentinel model is
// scoped to exclude those two legitimate wires; the zero-value (metadata-only,
// TEAMS default) case still byte-scans the ENTIRE batch — nothing cache-shaped
// may cross there, which is the guard that actually protects the teams tier.
func TestPushPayloadStripsCacheWhenNotOptedIn(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)
	const secCacheModel = "SENTINEL_CACHE_MODEL_pangram_zz"
	seedCacheEvents(ctx, t, database, secCacheModel)

	for _, tc := range []struct {
		name  string
		share store.ShareOptions
	}{
		{"zero-value", store.ShareOptions{}},
		{"full_content-only", store.ShareOptions{FullContent: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example", tc.share, store.ScopeOptions{})
			if err != nil {
				t.Fatalf("SelectUnpushedSince: %v", err)
			}
			if len(batch.CacheSummaries) != 0 {
				t.Errorf("cache aggregate shipped under %s (cache_detail OFF) — the cache tier must be orthogonal and opt-in", tc.name)
			}
			if tc.share.FullContent {
				// full_content legitimately ships BOTH session-scoped cache
				// wires (model included) — scope the leak scan to the batch
				// WITHOUT them so the fleet cache_detail tier stays pinned
				// orthogonal.
				if len(batch.SessionCacheSummaries) == 0 {
					t.Error("full_content shipped no session cache wire — the W2.1 enterprise wire failed to flip")
				}
				if len(batch.SessionCacheEvents) == 0 {
					t.Error("full_content shipped no session cache EVENTS — the per-event timeline wire failed to flip")
				}
				batch.SessionCacheSummaries = nil
				batch.SessionCacheEvents = nil
			} else {
				if len(batch.SessionCacheSummaries) != 0 {
					t.Errorf("session cache wire shipped under %s (metadata-only) — it must ride shipsRawContent only", tc.name)
				}
				if len(batch.SessionCacheEvents) != 0 {
					t.Errorf("session cache EVENT wire shipped under %s (metadata-only) — it must ride shipsRawContent only", tc.name)
				}
			}
			raw, err := json.Marshal(batch)
			if err != nil {
				t.Fatalf("marshal batch: %v", err)
			}
			if bytes.Contains(raw, []byte(secCacheModel)) {
				t.Errorf("cache model leaked under %s without cache_detail", tc.name)
			}
		})
	}
}

// seedCacheEventTimeline inserts TWO cache_events rows shaped for the per-event
// timeline wire (operator directive item 6):
//
//   - a fully-populated anomaly carrying every optional column, including the
//     `detail` diagnostic JSON with its own sentinel and diverged_seq = 0 /
//     cost_delta_usd = 0 — the two values whose meaning would be destroyed by
//     a "zero means absent" mapping;
//   - a bare baseline row with cause / diverged_seq / diverged_level /
//     cost_delta_usd / predicted_kind / message_id all NULL.
//
// Together they let one test prove both directions of the NULL rule and the
// `detail` exclusion at once.
func seedCacheEventTimeline(ctx context.Context, t *testing.T, database *sql.DB, model, detailSentinel, msgSentinel string) {
	t.Helper()
	ts := time.Now().UTC().Format(time.RFC3339)
	if _, err := database.ExecContext(ctx,
		`INSERT INTO cache_events
		   (session_id, tier, timestamp, model, kind, cause,
		    diverged_seq, diverged_level,
		    tokens_read, tokens_written, tokens_written_1h,
		    cost_delta_usd, predicted_kind, message_id, detail)
		 VALUES ('sess-cc-1', 'proxy', ?, ?, 'mispredict', 'tools_changed',
		         0, 'tools', 4000, 1200, 300, 0, 'hit', ?, ?)`,
		ts, model, msgSentinel, `{"note":"`+detailSentinel+`"}`); err != nil {
		t.Fatalf("seed cache_events (anomaly): %v", err)
	}
	// A 0/0 token pair on this baseline hit lets one test also pin the
	// ZeroUsageOf rule: a hit with no token movement is NOT vacant (only a
	// mispredict with no tokens is), so ZeroUsageOf() must read false here.
	if _, err := database.ExecContext(ctx,
		`INSERT INTO cache_events
		   (session_id, tier, timestamp, model, kind, tokens_read, tokens_written)
		 VALUES ('sess-cc-1', 'proxy', ?, ?, 'hit', 0, 0)`, ts, model); err != nil {
		t.Fatalf("seed cache_events (baseline): %v", err)
	}
}

// TestSessionCacheEventsShipOnlyUnderRawContent is the wire-surface pin for the
// PER-EVENT cache timeline (server migration 142, operator directive item 6).
//
// WHAT CHANGED, AND WHAT DID NOT. "cache_events" STAYS in forbiddenCacheTables:
// that sentinel is a SOURCE-LEVEL rule about internal/store/orgpush.go — the
// table name may not appear there — and TestSelectUnpushedSinceExcludesCacheTables
// still enforces it, because the read lives in its own seam file
// (internal/store/cacheeventorgrows.go) exactly as the two existing cache wires
// already do. What this test pins is the DATA posture, which the enterprise-
// first ruling deliberately reverses: the per-event log may now cross, under
// the node's own raw-content posture.
//
// Four properties, in one table:
//
//	(a) the zero value ships NOTHING — the teams/metadata default is untouched;
//	(b) cache_detail ALONE ships nothing here either. That flag gates the
//	    CONTENT-FREE FLEET day aggregate and is ORTHOGONAL in both directions;
//	    the per-event log is not a louder version of it;
//	(c) full_content, and separately admin_managed, DO ship it — with every
//	    field cachetrack.TimelineEvent needs, and with the two NULLABLE numerics
//	    round-tripped honestly: 0 stays 0 (not nil) and NULL stays nil (not 0);
//	(d) the node's `detail` diagnostic JSON NEVER crosses — not even under
//	    full_content, which is the widest posture a node can be in. That is a
//	    policy exclusion made structural in the seam's SELECT list, and this is
//	    the case that keeps it that way.
func TestSessionCacheEventsShipOnlyUnderRawContent(t *testing.T) {
	const (
		secCacheModel  = "SENTINEL_CACHE_EVT_MODEL_pangram_gg"
		secCacheDetail = "SENTINEL_CACHE_EVT_DETAIL_pangram_hh"
		secCacheMsg    = "SENTINEL_CACHE_EVT_MSGID_pangram_ii"
	)
	for _, tc := range []struct {
		name     string
		share    store.ShareOptions
		wantRows bool
	}{
		{"zero-value", store.ShareOptions{}, false},
		{"cache_detail-only", store.ShareOptions{CacheDetail: true}, false},
		{"full_content", store.ShareOptions{FullContent: true}, true},
		{"admin_managed", store.ShareOptions{AdminManaged: true}, true},
		{"cache_detail+full_content", store.ShareOptions{CacheDetail: true, FullContent: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
			if err != nil {
				t.Fatalf("db.Open: %v", err)
			}
			defer func() { _ = database.Close() }()
			st := store.New(database)
			seed(ctx, t, st)
			seedCacheEventTimeline(ctx, t, database, secCacheModel, secCacheDetail, secCacheMsg)

			batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example",
				tc.share, store.ScopeOptions{})
			if err != nil {
				t.Fatalf("SelectUnpushedSince: %v", err)
			}

			if !tc.wantRows {
				if len(batch.SessionCacheEvents) != 0 {
					t.Errorf("per-event cache timeline shipped %d rows under %s — it rides shipsRawContent() "+
						"ONLY; cache_detail gates the content-free FLEET aggregate and is orthogonal",
						len(batch.SessionCacheEvents), tc.name)
				}
			} else {
				if len(batch.SessionCacheEvents) != 2 {
					t.Fatalf("per-event cache timeline shipped %d rows under %s, want 2 — the enterprise wire failed to flip",
						len(batch.SessionCacheEvents), tc.name)
				}
				var sawAnomaly, sawBaseline bool
				for _, r := range batch.SessionCacheEvents {
					if r.SessionID != "sess-cc-1" || r.Model != secCacheModel || r.Tier != "proxy" {
						t.Errorf("row identity = %q/%q/%q, want sess-cc-1/%s/proxy",
							r.SessionID, r.Model, r.Tier, secCacheModel)
					}
					if r.NodeEventID == 0 {
						t.Error("NodeEventID = 0 — the node's own cache_events.id is the idempotency key and must ship")
					}
					if r.Timestamp == "" {
						t.Error("Timestamp is empty — it is the timeline's ordering key")
					}
					switch r.Kind {
					case "mispredict":
						sawAnomaly = true
						if r.Cause != "tools_changed" || r.DivergedLevel != "tools" || r.PredictedKind != "hit" {
							t.Errorf("anomaly enums = cause %q / level %q / predicted %q, want tools_changed/tools/hit",
								r.Cause, r.DivergedLevel, r.PredictedKind)
						}
						if r.MessageID != secCacheMsg {
							t.Errorf("MessageID = %q, want the seeded sentinel — the drawer joins a cache event to its message on it", r.MessageID)
						}
						if r.TokensRead != 4000 || r.TokensWritten != 1200 || r.TokensWritten1H != 300 {
							t.Errorf("token movement = %d/%d/%d, want 4000/1200/300",
								r.TokensRead, r.TokensWritten, r.TokensWritten1H)
						}
						// The load-bearing half of the NULL rule: a stored 0
						// must arrive as a PRESENT zero, never as nil. 0 means
						// "the FIRST block diverged" / "a genuinely zero cost
						// delta", both real readings.
						if r.DivergedSeq == nil || *r.DivergedSeq != 0 {
							t.Errorf("DivergedSeq = %v, want a non-nil 0 — 0 means the FIRST block diverged, "+
								"and collapsing it onto nil would report it as \"not computed\"", r.DivergedSeq)
						}
						if r.CostDeltaUSD == nil || *r.CostDeltaUSD != 0 {
							t.Errorf("CostDeltaUSD = %v, want a non-nil 0 — 0 is a genuinely zero delta, not an absence", r.CostDeltaUSD)
						}
						if r.ZeroUsageOf() {
							t.Error("ZeroUsageOf() = true for an event with 4000 read — the derivation disagrees with its own tokens")
						}
					case "hit":
						sawBaseline = true
						// The other half: a stored NULL must arrive as nil, so
						// no reader can present "not computed" as a value.
						if r.DivergedSeq != nil {
							t.Errorf("DivergedSeq = %v for a row with NULL diverged_seq, want nil", *r.DivergedSeq)
						}
						if r.CostDeltaUSD != nil {
							t.Errorf("CostDeltaUSD = %v for a row with NULL cost_delta_usd, want nil", *r.CostDeltaUSD)
						}
						// A 0/0 hit is NOT vacant — only a mispredict with no
						// tokens is. ZeroUsageOf now delegates to
						// cachetrack.IsZeroUsage, so the two surfaces agree.
						if r.ZeroUsageOf() {
							t.Error("ZeroUsageOf() = true for a 0/0 HIT — a hit that moved no cache tokens is a real event, not vacant")
						}
						if r.Cause != "" || r.DivergedLevel != "" || r.PredictedKind != "" || r.MessageID != "" {
							t.Errorf("baseline row carried enums it was not seeded with: cause %q level %q predicted %q msg %q",
								r.Cause, r.DivergedLevel, r.PredictedKind, r.MessageID)
						}
					default:
						t.Errorf("unexpected kind %q", r.Kind)
					}
				}
				if !sawAnomaly || !sawBaseline {
					t.Error("both seeded events must ship — BuildTimeline needs the baseline runs as well as the anomalies")
				}
			}

			raw, err := json.Marshal(batch)
			if err != nil {
				t.Fatalf("marshal batch: %v", err)
			}
			// The `detail` diagnostic JSON is excluded BY POLICY at every
			// posture, including the widest one. This is the case that keeps
			// the seam's SELECT list honest.
			if bytes.Contains(raw, []byte(secCacheDetail)) {
				t.Errorf("cache_events.detail leaked under %s — the engine's diagnostic JSON is excluded by policy "+
					"at EVERY posture; it is not selected by internal/store/cacheeventorgrows.go and must never be", tc.name)
			}
			// The model and message id are per-event detail: present exactly
			// when the wire ships, absent otherwise. cache_detail-only must not
			// smuggle them through the fleet aggregate's message-id-less shape.
			if leaked := bytes.Contains(raw, []byte(secCacheMsg)); leaked != tc.wantRows {
				t.Errorf("message id present in the marshalled batch = %v, want %v under %s",
					leaked, tc.wantRows, tc.name)
			}
		})
	}
}

// seedCodeintel inserts one codeintel file + symbol + edge whose project path
// and symbol name are sentinels, so a SelectUnpushedSince batch can be searched
// both for whether the P5f codeintel-detail aggregate shipped AND for whether
// any raw source identity leaked. codeintel_* stays NODE-LOCAL; only the
// content-free per (project-HASH × lang) file/symbol/edge count aggregate
// crosses, and only under codeintel_detail — the project path is hashed and the
// symbol name is never shipped.
func seedCodeintel(ctx context.Context, t *testing.T, database *sql.DB, project, symbol string) {
	t.Helper()
	res, err := database.ExecContext(ctx,
		`INSERT INTO codeintel_files (project, path, lang, status) VALUES (?, ?, 'go', 'indexed')`,
		project, project+"/main.go")
	if err != nil {
		t.Fatalf("seed codeintel_files: %v", err)
	}
	fileID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("codeintel_files last id: %v", err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO codeintel_nodes (project, file_id, kind, name, fqn, lang) VALUES (?, ?, 'function', ?, ?, 'go')`,
		project, fileID, symbol, symbol); err != nil {
		t.Fatalf("seed codeintel_nodes: %v", err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO codeintel_edges (project, file_id, src_id, dst_id, kind) VALUES (?, ?, 0, 0, 'CALLS')`,
		project, fileID); err != nil {
		t.Fatalf("seed codeintel_edges: %v", err)
	}
}

// TestPushPayloadCarriesCodeintelWhenOptedIn is the Arc 4 P5f extraction tier:
// under the DISTINCT codeintel_detail opt-in, the node-local codeintel index
// ships as a content-free per (project-HASH × language) file/symbol/edge count
// aggregate. Two properties are proven together: (1) the tier FLIPS the seam
// (CodeintelSummaries is non-empty and the ProjectHash is a hash, not the raw
// path); and (2) even when it ships, NO raw source identity crosses — neither
// the project path nor the symbol name appears in the marshalled batch. The
// codeintel_* table NAMES still never appear in orgpush.go (SelectCodeintelSummaries
// owns the read in a separate file — TestSelectUnpushedSinceExcludesCacheTables
// guards that).
func TestPushPayloadCarriesCodeintelWhenOptedIn(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)
	const (
		secProject = "SENTINEL_CODEINTEL_PROJECT_pangram_zz"
		secSymbol  = "SENTINEL_CODEINTEL_SYMBOL_pangram_zz"
	)
	seedCodeintel(ctx, t, database, secProject, secSymbol)

	batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example",
		store.ShareOptions{CodeintelDetail: true}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	if len(batch.CodeintelSummaries) == 0 {
		t.Fatal("codeintel_detail opt-in shipped no CodeintelSummaries — the tier failed to flip the seam")
	}
	// The project path must be HASHED, never raw.
	for _, r := range batch.CodeintelSummaries {
		if r.ProjectHash == "" {
			t.Error("CodeintelSummaryRow.ProjectHash is empty — the project must ship as a hash")
		}
		if r.ProjectHash == secProject {
			t.Error("CodeintelSummaryRow.ProjectHash is the RAW project path — it must be hashed")
		}
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}
	// Content-free even when shipped: no raw path, no symbol name.
	if bytes.Contains(raw, []byte(secProject)) {
		t.Error("raw project path leaked into the codeintel aggregate — it must ship only as a hash")
	}
	if bytes.Contains(raw, []byte(secSymbol)) {
		t.Error("symbol name leaked into the codeintel aggregate — only structure counts may ship")
	}
}

// TestPushPayloadStripsCodeintelWhenNotOptedIn is the other side of the tier:
// with codeintel_detail OFF, the aggregate must NOT ship — not even under
// full_content (maximum path/content disclosure). codeintel_detail is a DISTINCT
// tier, orthogonal to shipsRawContent(), and raised only by the DISTINCT
// extract.codeintel authority on a managed node.
func TestPushPayloadStripsCodeintelWhenNotOptedIn(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)
	const (
		secProject = "SENTINEL_CODEINTEL_PROJECT_pangram_zz"
		secSymbol  = "SENTINEL_CODEINTEL_SYMBOL_pangram_zz"
	)
	seedCodeintel(ctx, t, database, secProject, secSymbol)

	for _, tc := range []struct {
		name  string
		share store.ShareOptions
	}{
		{"zero-value", store.ShareOptions{}},
		{"full_content-only", store.ShareOptions{FullContent: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example", tc.share, store.ScopeOptions{})
			if err != nil {
				t.Fatalf("SelectUnpushedSince: %v", err)
			}
			if len(batch.CodeintelSummaries) != 0 {
				t.Errorf("codeintel aggregate shipped under %s (codeintel_detail OFF) — the tier must be orthogonal and opt-in", tc.name)
			}
			if tc.share.FullContent {
				// Enterprise (org-parity W2.4): full_content legitimately
				// ships the per-dev codeintel wire, which carries the RAW
				// project root (operator ruling 2026-08-24) — scope the
				// leak scan past it. Symbol names still NEVER cross on any
				// wire, so secSymbol stays in the unscoped scan below.
				if len(batch.CodeintelDevRows) == 0 {
					t.Error("full_content shipped no codeintel dev rows — the W2.4 enterprise wire failed to flip")
				}
				batch.CodeintelDevRows = nil
			} else if len(batch.CodeintelDevRows) != 0 {
				t.Errorf("codeintel dev rows shipped under %s (metadata-only) — must ride shipsRawContent only", tc.name)
			}
			raw, err := json.Marshal(batch)
			if err != nil {
				t.Fatalf("marshal batch: %v", err)
			}
			if bytes.Contains(raw, []byte(secProject)) || bytes.Contains(raw, []byte(secSymbol)) {
				t.Errorf("codeintel identity leaked under %s without codeintel_detail", tc.name)
			}
		})
	}
}

// seedProcessRun inserts one process_runs row whose exe_path and argv are
// sentinels, so a SelectUnpushedSince batch can be searched both for whether the
// P5g process-detail aggregate shipped AND for whether any raw process identity
// leaked. process_* stays NODE-LOCAL; only the content-free per (day × tool)
// run/exit count aggregate crosses, and only under process_detail — the exe
// path and argv are never shipped.
func seedProcessRun(ctx context.Context, t *testing.T, database *sql.DB, tool, exePath, argv string) {
	t.Helper()
	ts := time.Now().UTC().Format(time.RFC3339)
	if _, err := database.ExecContext(ctx,
		`INSERT INTO process_runs
		   (process_key, pid, attribution_source, attribution_confidence, tool,
		    exe_path, argv_preview, started_at, last_seen_at, exited_at, exit_code, duration_ms)
		 VALUES (?, 4242, 'pidbridge', 'high', ?, ?, ?, ?, ?, ?, 0, 1500)`,
		"pk-"+exePath, tool, exePath, argv, ts, ts, ts); err != nil {
		t.Fatalf("seed process_runs: %v", err)
	}
}

// TestPushPayloadCarriesProcessWhenOptedIn is the Arc 4 P5g extraction tier:
// under the DISTINCT process_detail opt-in, the node-local process_runs log
// ships as a content-free per (day × tool) run/exit count aggregate. Two
// properties are proven together: (1) the tier FLIPS the seam (ProcessSummaries
// is non-empty); and (2) even when it ships, NO raw process identity crosses —
// neither the exe path nor the argv appears in the marshalled batch. The
// process_* table NAMES still never appear in orgpush.go (SelectProcessSummaries
// owns the read in a separate file — TestSelectUnpushedSinceExcludesCacheTables
// guards that).
func TestPushPayloadCarriesProcessWhenOptedIn(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)
	const (
		secExe  = "SENTINEL_PROCESS_EXE_pangram_zz"
		secArgv = "SENTINEL_PROCESS_ARGV_pangram_zz"
	)
	seedProcessRun(ctx, t, database, "claude-code", secExe, secArgv)

	batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example",
		store.ShareOptions{ProcessDetail: true}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	if len(batch.ProcessSummaries) == 0 {
		t.Fatal("process_detail opt-in shipped no ProcessSummaries — the tier failed to flip the seam")
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}
	// Content-free even when shipped: no exe path, no argv.
	if bytes.Contains(raw, []byte(secExe)) {
		t.Error("exe path leaked into the process aggregate — only run/exit counts may ship")
	}
	if bytes.Contains(raw, []byte(secArgv)) {
		t.Error("argv leaked into the process aggregate — only run/exit counts may ship")
	}
}

// TestPushPayloadStripsProcessWhenNotOptedIn is the other side of the tier: with
// process_detail OFF, the aggregate must NOT ship — not even under full_content
// (maximum disclosure). process_detail is a DISTINCT tier, orthogonal to
// shipsRawContent(), and raised only by the DISTINCT extract.process authority
// on a managed node.
func TestPushPayloadStripsProcessWhenNotOptedIn(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)
	const (
		secExe  = "SENTINEL_PROCESS_EXE_pangram_zz"
		secArgv = "SENTINEL_PROCESS_ARGV_pangram_zz"
	)
	seedProcessRun(ctx, t, database, "claude-code", secExe, secArgv)

	for _, tc := range []struct {
		name  string
		share store.ShareOptions
	}{
		{"zero-value", store.ShareOptions{}},
		{"full_content-only", store.ShareOptions{FullContent: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example", tc.share, store.ScopeOptions{})
			if err != nil {
				t.Fatalf("SelectUnpushedSince: %v", err)
			}
			if len(batch.ProcessSummaries) != 0 {
				t.Errorf("process aggregate shipped under %s (process_detail OFF) — the tier must be orthogonal and opt-in", tc.name)
			}
			raw, err := json.Marshal(batch)
			if err != nil {
				t.Fatalf("marshal batch: %v", err)
			}
			if bytes.Contains(raw, []byte(secExe)) || bytes.Contains(raw, []byte(secArgv)) {
				t.Errorf("process identity leaked under %s without process_detail", tc.name)
			}
		})
	}
}

// TestSessionProcessWireCarriesMetricsMessageIDAndCapsSamples is the W-A wire
// property (org session-detail parity): under shipsRawContent() the
// session-scoped process row carries the NON-CONTENT process metadata
// working_set_bytes / thread_count / message_id (resolved from the correlated
// action) / metric_samples_json alongside the rest of the raw row; a run that
// never captured them ships zero/empty (an honest absence, never a phantom
// zero); and the high-volume samples ring is capped so it can never dominate
// the envelope. process_runs stays NODE-LOCAL (its table name never appears in
// orgpush.go — pinned by TestSelectUnpushedSinceExcludesCacheTables); these are
// numeric counters / an opaque id, no new content surface.
func TestSessionProcessWireCarriesMetricsMessageIDAndCapsSamples(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st) // creates session sess-cc-1 + its project

	var projectID int64
	if err := database.QueryRowContext(ctx,
		`SELECT project_id FROM sessions WHERE id = 'sess-cc-1'`).Scan(&projectID); err != nil {
		t.Fatalf("resolve project id: %v", err)
	}

	ts := time.Now().UTC().Format(time.RFC3339)

	// An action carrying a message id, correlated to the metric-bearing run by
	// action_id (process_runs has no message_id column; the wire resolves it
	// through actions.message_id).
	res, err := database.ExecContext(ctx,
		`INSERT INTO actions (session_id, project_id, timestamp, tool, action_type, message_id, success, source_file, source_event_id)
		 VALUES ('sess-cc-1', ?, ?, 'claude-code', 'run_command', 'msg_proc_1', 1, 'p.jsonl', 'proc-ev-1')`,
		projectID, ts)
	if err != nil {
		t.Fatalf("insert correlated action: %v", err)
	}
	actionID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("LastInsertId: %v", err)
	}

	// A 90-sample ring (over the 60-sample cap) so the wire cap is exercised.
	var ring strings.Builder
	ring.WriteByte('[')
	for i := 0; i < 90; i++ {
		if i > 0 {
			ring.WriteByte(',')
		}
		ring.WriteString(`{"t":"2026-08-24T10:00:00Z","cpu_ms":`)
		ring.WriteString(strconv.Itoa(i))
		ring.WriteString(`,"ws":`)
		ring.WriteString(strconv.Itoa(i * 1024))
		ring.WriteByte('}')
	}
	ring.WriteByte(']')

	// A run WITH the metrics + correlated action.
	if _, err := database.ExecContext(ctx,
		`INSERT INTO process_runs
		   (process_key, pid, session_id, action_id, attribution_source, attribution_confidence, tool,
		    exe_path, argv_preview, started_at, last_seen_at,
		    working_set_bytes, thread_count, metric_samples_json)
		 VALUES ('pk-metrics', 700, 'sess-cc-1', ?, 'bridge', 'high', 'claude-code',
		         '/usr/bin/node', 'node x.js', ?, ?, ?, ?, ?)`,
		actionID, ts, ts, 6<<20, 15, ring.String()); err != nil {
		t.Fatalf("insert metric-bearing process_run: %v", err)
	}

	// A run WITHOUT the metrics (older / non-Windows capture) → zero/empty.
	if _, err := database.ExecContext(ctx,
		`INSERT INTO process_runs
		   (process_key, pid, session_id, attribution_source, attribution_confidence, tool,
		    exe_path, argv_preview, started_at, last_seen_at)
		 VALUES ('pk-bare', 701, 'sess-cc-1', 'bridge', 'high', 'claude-code',
		         '/usr/bin/git', 'git status', ?, ?)`,
		ts, ts); err != nil {
		t.Fatalf("insert bare process_run: %v", err)
	}

	batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example",
		store.ShareOptions{AdminManaged: true}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}

	var withMetrics, bare *orgcontract.SessionProcessRow
	for i := range batch.SessionProcesses {
		switch batch.SessionProcesses[i].RunKey {
		case "pk-metrics":
			withMetrics = &batch.SessionProcesses[i]
		case "pk-bare":
			bare = &batch.SessionProcesses[i]
		}
	}
	if withMetrics == nil || bare == nil {
		t.Fatalf("expected both process rows on the wire, got %+v", batch.SessionProcesses)
	}

	if withMetrics.WorkingSetBytes != 6<<20 {
		t.Errorf("WorkingSetBytes = %d, want %d", withMetrics.WorkingSetBytes, 6<<20)
	}
	if withMetrics.ThreadCount != 15 {
		t.Errorf("ThreadCount = %d, want 15", withMetrics.ThreadCount)
	}
	if withMetrics.MessageID != "msg_proc_1" {
		t.Errorf("MessageID = %q, want msg_proc_1 (resolved from the correlated action)", withMetrics.MessageID)
	}

	// The samples ring is present but capped: at most 60 samples, within the
	// byte ceiling.
	var kept []map[string]any
	if err := json.Unmarshal([]byte(withMetrics.MetricSamplesJSON), &kept); err != nil {
		t.Fatalf("metric_samples_json not a valid JSON array: %v (%q)", err, withMetrics.MetricSamplesJSON)
	}
	if len(kept) > 60 {
		t.Errorf("metric samples not capped: %d on the wire, want <= 60", len(kept))
	}
	if len(withMetrics.MetricSamplesJSON) > 8<<10 {
		t.Errorf("metric_samples_json = %d bytes, exceeds the 8 KiB wire ceiling", len(withMetrics.MetricSamplesJSON))
	}

	// The bare run carries honest zeros/empties, never a phantom value.
	if bare.WorkingSetBytes != 0 || bare.ThreadCount != 0 || bare.MessageID != "" || bare.MetricSamplesJSON != "" {
		t.Errorf("bare run carries phantom metrics: %+v", bare)
	}
}

// TestSessionSurfaceAndSidechainTokensShipAsMetadata is the W1 wire property
// (node session-detail trickle-up, server migration 139) and the deliberate
// REVERSAL of the migration-107 posture: sessions.surface / surface_host and
// token_usage.is_sidechain used to be pinned OUT of the push seam in every
// share mode, and now ship UNCONDITIONALLY — including in the zero-value,
// metadata-only posture that is every node's default.
//
// They are METADATA, not content: surface is a closed vocabulary
// (models.KnownSurface — cli | ide | desktop | sdk | web) the node's
// SetSessionSurface refuses to write outside of, surface_host is a bounded
// host token, and is_sidechain is a bool over a row that already ships (the
// exact disclosure class as ActionRow.IsSidechain, on the wire since the
// baseline). None can carry a path, a prompt or a branch name, so none is
// gated by shipsRawContent() and none gets a [org_client.share] key.
//
// The second half is the honesty half, and the reason this is an invariant
// rather than a unit test: a session the node never stamped (a pre-107 agent,
// or a transcript never re-scanned) must reach the org as EMPTY. The wire may
// never manufacture a default — "cli" is a real answer, not a fallback.
func TestSessionSurfaceAndSidechainTokensShipAsMetadata(t *testing.T) {
	for _, tc := range []struct {
		name  string
		share store.ShareOptions
	}{
		// The zero value IS the default metadata-only posture; the gated
		// postures must not change the answer, which is what "not gated" means.
		{"metadata_only", store.ShareOptions{}},
		{"full_content", store.ShareOptions{FullContent: true}},
		{"admin_managed", store.ShareOptions{AdminManaged: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
			if err != nil {
				t.Fatalf("db.Open: %v", err)
			}
			defer func() { _ = database.Close() }()
			st := store.New(database)
			seed(ctx, t, st) // sess-cc-1, sess-cur-1, sess-cdx-1 + their token rows

			// Exactly ONE session is stamped; the others stay unstamped so the
			// honest-absence half of the assertion is non-vacuous. Written
			// directly rather than through SetSessionSurface so the probe reads
			// the COLUMN, not the store's vocabulary check.
			if _, err := database.ExecContext(ctx,
				`UPDATE sessions SET surface = 'ide', surface_host = 'vscode' WHERE id = 'sess-cc-1'`); err != nil {
				t.Fatalf("stamp surface: %v", err)
			}
			// Likewise exactly ONE usage row is a sub-agent row.
			if _, err := database.ExecContext(ctx,
				`UPDATE token_usage SET is_sidechain = 1 WHERE source_event_id = 'cc-tok-1'`); err != nil {
				t.Fatalf("stamp is_sidechain: %v", err)
			}

			batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example",
				tc.share, store.ScopeOptions{})
			if err != nil {
				t.Fatalf("SelectUnpushedSince: %v", err)
			}

			var stamped, unstamped *orgcontract.SessionRow
			for i := range batch.Sessions {
				switch batch.Sessions[i].ID {
				case "sess-cc-1":
					stamped = &batch.Sessions[i]
				case "sess-cur-1":
					unstamped = &batch.Sessions[i]
				}
			}
			if stamped == nil || unstamped == nil {
				t.Fatalf("expected both sessions on the wire, got %+v", batch.Sessions)
			}
			if stamped.Surface != "ide" || stamped.SurfaceHost != "vscode" {
				t.Errorf("stamped session surface = %q/%q, want ide/vscode — W1 ships capture surface in every posture",
					stamped.Surface, stamped.SurfaceHost)
			}
			if unstamped.Surface != "" || unstamped.SurfaceHost != "" {
				t.Errorf("unstamped session carries a phantom surface %q/%q; an unknown surface must reach the org EMPTY, never defaulted to cli",
					unstamped.Surface, unstamped.SurfaceHost)
			}

			var sidechain, ordinary *orgcontract.TokenUsageRow
			for i := range batch.TokenUsage {
				switch batch.TokenUsage[i].SourceEventID {
				case "cc-tok-1":
					sidechain = &batch.TokenUsage[i]
				case "cur-tok-1":
					ordinary = &batch.TokenUsage[i]
				}
			}
			if sidechain == nil || ordinary == nil {
				t.Fatalf("expected both token_usage rows on the wire, got %+v", batch.TokenUsage)
			}
			if !sidechain.IsSidechain {
				t.Errorf("sub-agent usage row shipped IsSidechain=false; W1 carries the flag unconditionally, like actions.is_sidechain")
			}
			if ordinary.IsSidechain {
				t.Errorf("main-thread usage row shipped IsSidechain=true; the flag must reflect the node column, not a default")
			}
		})
	}
}

// seedSessionTasks writes one checklist item and one status transition for
// sess-cc-1 whose PROSE columns are sentinels but whose STATUS columns are the
// real closed vocabulary, so one SelectUnpushedSince batch can be searched both
// for whether the W2 task wire shipped AND for whether any plan text leaked.
//
// Written with direct SQL rather than through Store.applyTaskEvents so the
// fixture does not depend on the taskflow decoder's per-tool vocabulary — the
// wire Select reads these columns whatever wrote them.
func seedSessionTasks(ctx context.Context, t *testing.T, database *sql.DB, content, activeForm, owner string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := database.ExecContext(ctx,
		`INSERT INTO task_items
		   (session_id, tool, key, key_kind, content, active_form, owner,
		    raw_status, status, order_index, first_seen_at, last_seen_at, unmatched)
		 VALUES ('sess-cc-1', 'claude-code', 'task-1', 'native_id', ?, ?, ?,
		         'in_progress', 'in_progress', 0, ?, ?, 0)`,
		content, activeForm, owner, now, now); err != nil {
		t.Fatalf("seed task_items: %v", err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO task_transitions
		   (session_id, key, from_status, to_status, ts, action_id, source_event_id)
		 VALUES ('sess-cc-1', 'task-1', 'pending', 'in_progress', ?, 7, 'evt-task-1')`,
		now); err != nil {
		t.Fatalf("seed task_transitions: %v", err)
	}
}

// TestSessionTasksShipOnlyUnderTaskDetail is the W2 wire-surface pin, and the
// replacement for the blanket task_items/task_transitions entry this file's
// forbiddenCacheTables used to carry (agent migration 109 pinned them
// node-local "for this first slice"; docs/plans/
// node-session-detail-trickle-up-to-org-plan-2026-09-10.md §2 W2 is the
// reviewed reversal). It is STRICTLY STRONGER than the absence assertion it
// replaces, because it pins the GATE in all three postures rather than the
// silence in one:
//
//	(a) the ZERO-VALUE ShareOptions ships NOTHING — no item, no transition, and
//	    no sentinel anywhere in the marshalled batch. full_content ALONE does
//	    not unlock the tier either: task_detail is orthogonal, exactly like
//	    cache_detail.
//	(b) task_detail ALONE ships the STATUS half — status, the vendor raw_status
//	    spelling, key/key_kind, order/seen times and the transitions — while
//	    every PROSE sentinel (content / active_form / owner) is STRIPPED. This
//	    is the two-level tier: an org can render "in progress, 1 of N" without
//	    ever learning what the work was.
//	(c) task_detail + full_content, and task_detail + admin_managed, BOTH carry
//	    the prose. Two rows rather than one because shipsRawContent() is a
//	    three-way disjunction and a regression that dropped one of its terms
//	    would otherwise pass.
func TestSessionTasksShipOnlyUnderTaskDetail(t *testing.T) {
	const (
		secTaskContent    = "SENTINEL_TASK_PROSE_pangram_aa"
		secTaskActiveForm = "SENTINEL_TASK_ACTIVEFORM_pangram_bb"
		secTaskOwner      = "SENTINEL_TASK_OWNER_pangram_cc"
	)
	for _, tc := range []struct {
		name        string
		share       store.ShareOptions
		wantRows    bool
		wantContent bool
	}{
		{"zero-value", store.ShareOptions{}, false, false},
		{"full_content-only", store.ShareOptions{FullContent: true}, false, false},
		{"task_detail", store.ShareOptions{TaskDetail: true}, true, false},
		{"task_detail+full_content", store.ShareOptions{TaskDetail: true, FullContent: true}, true, true},
		{"task_detail+admin_managed", store.ShareOptions{TaskDetail: true, AdminManaged: true}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
			if err != nil {
				t.Fatalf("db.Open: %v", err)
			}
			defer func() { _ = database.Close() }()
			st := store.New(database)
			seed(ctx, t, st)
			seedSessionTasks(ctx, t, database, secTaskContent, secTaskActiveForm, secTaskOwner)

			batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example",
				tc.share, store.ScopeOptions{})
			if err != nil {
				t.Fatalf("SelectUnpushedSince: %v", err)
			}

			if !tc.wantRows {
				if len(batch.SessionTaskItems) != 0 || len(batch.SessionTaskTransitions) != 0 {
					t.Errorf("task wire shipped %d items / %d transitions under %s — task_detail is OFF, so the checklist must not cross at all",
						len(batch.SessionTaskItems), len(batch.SessionTaskTransitions), tc.name)
				}
			} else {
				if len(batch.SessionTaskItems) == 0 {
					t.Fatalf("task_detail shipped no items under %s — the W2 tier failed to flip", tc.name)
				}
				if len(batch.SessionTaskTransitions) == 0 {
					t.Errorf("task_detail shipped no transitions under %s — the status-change log rides the same tier as the items", tc.name)
				}
				item := batch.SessionTaskItems[0]
				if item.SessionID != "sess-cc-1" || item.Key != "task-1" || item.KeyKind != "native_id" {
					t.Errorf("item identity = %q/%q/%q, want sess-cc-1/task-1/native_id", item.SessionID, item.Key, item.KeyKind)
				}
				if item.Status != "in_progress" || item.RawStatus != "in_progress" {
					t.Errorf("status/raw_status = %q/%q, want in_progress/in_progress — the STATUS half ships under task_detail alone",
						item.Status, item.RawStatus)
				}
				if item.Tool != "claude-code" || item.FirstSeenAt == "" || item.LastSeenAt == "" {
					t.Errorf("metadata half incomplete: tool=%q first=%q last=%q", item.Tool, item.FirstSeenAt, item.LastSeenAt)
				}
				tr := batch.SessionTaskTransitions[0]
				if tr.FromStatus != "pending" || tr.ToStatus != "in_progress" || tr.ActionID != 7 || tr.SourceEventID != "evt-task-1" {
					t.Errorf("transition = %q->%q action=%d src=%q, want pending->in_progress action=7 src=evt-task-1",
						tr.FromStatus, tr.ToStatus, tr.ActionID, tr.SourceEventID)
				}

				gotContent := item.Content != "" || item.ActiveForm != "" || item.Owner != ""
				if gotContent != tc.wantContent {
					t.Errorf("prose present = %v, want %v under %s (content=%q active_form=%q owner=%q) — "+
						"the plan text is a SECOND gate on top of task_detail: it ships only under shipsRawContent()",
						gotContent, tc.wantContent, tc.name, item.Content, item.ActiveForm, item.Owner)
				}
				if tc.wantContent {
					if item.Content != secTaskContent || item.ActiveForm != secTaskActiveForm || item.Owner != secTaskOwner {
						t.Errorf("prose under %s = %q/%q/%q, want the seeded sentinels verbatim",
							tc.name, item.Content, item.ActiveForm, item.Owner)
					}
				}
			}

			raw, err := json.Marshal(batch)
			if err != nil {
				t.Fatalf("marshal batch: %v", err)
			}
			for _, sentinel := range []string{secTaskContent, secTaskActiveForm, secTaskOwner} {
				leaked := bytes.Contains(raw, []byte(sentinel))
				if leaked != tc.wantContent {
					t.Errorf("sentinel %q present in the marshalled batch = %v, want %v under %s",
						sentinel, leaked, tc.wantContent, tc.name)
				}
			}
		})
	}
}

// seedSessionToolAccounts writes two login observations for sess-cc-1: one
// whose IDENTITY columns are sentinels, and a SECOND with a different
// account_key for the same binding, so the fixture also exercises the
// conflict-retention shape (the node keeps both; the wire must too).
func seedSessionToolAccounts(ctx context.Context, t *testing.T, database *sql.DB, email, name, accountID string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	rows := []struct {
		accountKey string
		source     string
	}{
		{"acct-key-primary", "hook"},
		{"acct-key-other", "transcript"},
	}
	for _, r := range rows {
		if _, err := database.ExecContext(ctx,
			`INSERT INTO tool_account_observations
			   (session_id, tool, binding_kind, binding_id, role, account_key,
			    email, name, account_id, source, scope, stage, observed_at)
			 VALUES ('sess-cc-1', 'claude-code', 'message', 'msg-1', 'assistant', ?,
			         ?, ?, ?, ?, 'session', 'start', ?)`,
			r.accountKey, email, name, accountID, r.source, now); err != nil {
			t.Fatalf("seed tool_account_observations: %v", err)
		}
	}
}

// TestSessionToolAccountsShipOnlyUnderToolAccountDetail is the W3 wire-surface
// pin, replacing this file's former blanket tool_account_observations entry
// (agent migration 111: "Never copied by org push or foreign import"). Same
// three-posture shape as its W2 sibling, and the second gate here is the arc's
// one genuine developer-PII boundary (operator decision D2):
//
//	(a) zero-value ships nothing, and full_content ALONE does not unlock the
//	    tier — tool_account_detail is orthogonal.
//	(b) tool_account_detail ALONE ships the BINDING half: binding_kind /
//	    binding_id / role / source / scope / stage, the OPAQUE account_key and
//	    observed_at. That is enough to render "account changed / conflict /
//	    unknown" and count distinct accounts — while email / name / account_id
//	    are STRIPPED, so no developer is named.
//	(c) with full_content, and separately with admin_managed, the raw identity
//	    crosses.
//
// It additionally pins CONFLICT RETENTION: both differing observations for the
// same binding ship, because a surface that saw only one could not honestly say
// "conflict".
func TestSessionToolAccountsShipOnlyUnderToolAccountDetail(t *testing.T) {
	const (
		secAcctEmail = "SENTINEL_ACCOUNT_EMAIL_pangram_dd@example.invalid"
		secAcctName  = "SENTINEL_ACCOUNT_NAME_pangram_ee"
		secAcctID    = "SENTINEL_ACCOUNT_ID_pangram_ff"
	)
	for _, tc := range []struct {
		name        string
		share       store.ShareOptions
		wantRows    bool
		wantContent bool
	}{
		{"zero-value", store.ShareOptions{}, false, false},
		{"full_content-only", store.ShareOptions{FullContent: true}, false, false},
		{"tool_account_detail", store.ShareOptions{ToolAccountDetail: true}, true, false},
		{"tool_account_detail+full_content", store.ShareOptions{ToolAccountDetail: true, FullContent: true}, true, true},
		{"tool_account_detail+admin_managed", store.ShareOptions{ToolAccountDetail: true, AdminManaged: true}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
			if err != nil {
				t.Fatalf("db.Open: %v", err)
			}
			defer func() { _ = database.Close() }()
			st := store.New(database)
			seed(ctx, t, st)
			seedSessionToolAccounts(ctx, t, database, secAcctEmail, secAcctName, secAcctID)

			batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example",
				tc.share, store.ScopeOptions{})
			if err != nil {
				t.Fatalf("SelectUnpushedSince: %v", err)
			}

			if !tc.wantRows {
				if len(batch.SessionToolAccounts) != 0 {
					t.Errorf("tool-account wire shipped %d rows under %s — tool_account_detail is OFF, so login evidence must not cross at all",
						len(batch.SessionToolAccounts), tc.name)
				}
			} else {
				if len(batch.SessionToolAccounts) != 2 {
					t.Fatalf("tool_account_detail shipped %d rows under %s, want 2 — a CONFLICTING observation must ride along, never be resolved away",
						len(batch.SessionToolAccounts), tc.name)
				}
				keys := map[string]bool{}
				for _, r := range batch.SessionToolAccounts {
					keys[r.AccountKey] = true
					if r.SessionID != "sess-cc-1" || r.BindingKind != "message" || r.BindingID != "msg-1" || r.Role != "assistant" {
						t.Errorf("binding half = %q/%q/%q/%q, want sess-cc-1/message/msg-1/assistant",
							r.SessionID, r.BindingKind, r.BindingID, r.Role)
					}
					if r.Scope != "session" || r.Stage != "start" || r.ObservedAt == "" || r.Tool != "claude-code" {
						t.Errorf("provenance half incomplete: tool=%q scope=%q stage=%q observed_at=%q",
							r.Tool, r.Scope, r.Stage, r.ObservedAt)
					}
					gotContent := r.Email != "" || r.Name != "" || r.AccountID != ""
					if gotContent != tc.wantContent {
						t.Errorf("identity present = %v, want %v under %s (email=%q name=%q account_id=%q) — "+
							"the raw vendor identity is a SECOND gate on top of tool_account_detail (decision D2)",
							gotContent, tc.wantContent, tc.name, r.Email, r.Name, r.AccountID)
					}
					if tc.wantContent && (r.Email != secAcctEmail || r.Name != secAcctName || r.AccountID != secAcctID) {
						t.Errorf("identity under %s = %q/%q/%q, want the seeded sentinels verbatim",
							tc.name, r.Email, r.Name, r.AccountID)
					}
				}
				if !keys["acct-key-primary"] || !keys["acct-key-other"] {
					t.Errorf("account keys shipped = %v, want BOTH observed keys — the opaque key is what makes "+
						"\"same account or not\" answerable without the e-mail", keys)
				}
			}

			raw, err := json.Marshal(batch)
			if err != nil {
				t.Fatalf("marshal batch: %v", err)
			}
			for _, sentinel := range []string{secAcctEmail, secAcctName, secAcctID} {
				leaked := bytes.Contains(raw, []byte(sentinel))
				if leaked != tc.wantContent {
					t.Errorf("sentinel %q present in the marshalled batch = %v, want %v under %s",
						sentinel, leaked, tc.wantContent, tc.name)
				}
			}
		})
	}
}

// seedTerminalActivity inserts one terminal_run (+ command) and one remote_audit
// row whose SENSITIVE columns are sentinels but whose public enums (tool, kind,
// decision, principal) are benign, so a SelectUnpushedSince batch can be
// searched both for whether the P5h terminal-detail aggregate shipped AND for
// whether any raw terminal/remote identity leaked. terminal_* / remote_audit
// stay pinned ENTIRELY out of the wire otherwise (the dedicated
// TestTerminalRunTablesPinnedOutOfPush / TestRemoteAuditTablePinnedOutOfPush);
// only the content-free count aggregate crosses, and only under terminal_detail.
func seedTerminalActivity(ctx context.Context, t *testing.T, st *store.Store, sentinel string) {
	t.Helper()
	if err := st.InsertTerminalRun(ctx, store.TerminalRun{
		RunID: "run-" + sentinel, Tool: "claude-code", Kind: "handoff",
		SourceSessionID: sentinel, ProjectRootHash: sentinel, CorrelationTokenHash: sentinel,
	}); err != nil {
		t.Fatalf("InsertTerminalRun: %v", err)
	}
	if err := st.InsertTerminalCommand(ctx, store.TerminalCommand{
		RunID: "run-" + sentinel, TurnSeq: 1, Trust: "hint", CmdHash: sentinel,
	}); err != nil {
		t.Fatalf("InsertTerminalCommand: %v", err)
	}
	if err := st.InsertRemoteAudit(ctx, store.RemoteAuditEvent{
		Kind: "session_paired", SessionID: sentinel, Principal: "view",
		RemoteAddr: sentinel, Route: sentinel, Decision: "ok", Detail: sentinel,
	}); err != nil {
		t.Fatalf("InsertRemoteAudit: %v", err)
	}
}

// TestPushPayloadCarriesTerminalWhenOptedIn is the Arc 4 P5h extraction tier:
// under the DISTINCT terminal_detail opt-in, the node-local terminal_run +
// remote_audit logs ship as content-free count aggregates. Two properties are
// proven together: (1) the tier FLIPS the seam (both TerminalSummaries and
// RemoteAuditSummaries are non-empty); and (2) even when it ships, NO raw
// terminal/remote identity crosses — no project/correlation/command hash, no
// source session id, no remote session id, no peer address, no route, no detail.
// The raw table NAMES still never appear in orgpush.go (SelectTerminalSummaries
// / SelectRemoteAuditSummaries own the reads in a separate file), and the
// pre-existing never-ships tests (which assert absence under full_content) stay
// true because this aggregate is orthogonal to full_content.
func TestPushPayloadCarriesTerminalWhenOptedIn(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)
	const secTerm = "SENTINEL_TERMINAL_grandiloquent_zz"
	seedTerminalActivity(ctx, t, st, secTerm)

	batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example",
		store.ShareOptions{TerminalDetail: true}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	if len(batch.TerminalSummaries) == 0 {
		t.Fatal("terminal_detail opt-in shipped no TerminalSummaries — the tier failed to flip the seam")
	}
	if len(batch.RemoteAuditSummaries) == 0 {
		t.Fatal("terminal_detail opt-in shipped no RemoteAuditSummaries — the tier failed to flip the seam")
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}
	// Content-free even when shipped: none of the sensitive columns cross.
	if bytes.Contains(raw, []byte(secTerm)) {
		t.Error("terminal/remote identity leaked into the aggregate — only counts + public enums may ship")
	}
}

// TestPushPayloadStripsTerminalWhenNotOptedIn is the other side of the tier:
// with terminal_detail OFF, neither aggregate ships — not even under
// full_content (maximum disclosure). terminal_detail is a DISTINCT tier,
// orthogonal to shipsRawContent(), raised only by the DISTINCT extract.terminal
// authority on a managed node. This is what keeps the raw-table never-ships
// pins intact: the ONLY way terminal/remote data crosses at all is this
// content-free aggregate under this explicit tier.
func TestPushPayloadStripsTerminalWhenNotOptedIn(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)
	const secTerm = "SENTINEL_TERMINAL_grandiloquent_zz"
	seedTerminalActivity(ctx, t, st, secTerm)

	for _, tc := range []struct {
		name  string
		share store.ShareOptions
	}{
		{"zero-value", store.ShareOptions{}},
		{"full_content-only", store.ShareOptions{FullContent: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example", tc.share, store.ScopeOptions{})
			if err != nil {
				t.Fatalf("SelectUnpushedSince: %v", err)
			}
			if len(batch.TerminalSummaries) != 0 || len(batch.RemoteAuditSummaries) != 0 {
				t.Errorf("terminal aggregate shipped under %s (terminal_detail OFF) — the tier must be orthogonal and opt-in", tc.name)
			}
			if tc.share.FullContent {
				// Enterprise (org-parity W2.6): full_content legitimately
				// ships the per-dev terminal/remote visibility wires —
				// scope the leak scan past them; the teams-tier aggregates
				// above stay flag-gated.
				if len(batch.TerminalRuns) == 0 {
					t.Error("full_content shipped no terminal runs — the W2.6 enterprise wire failed to flip")
				}
				batch.TerminalRuns, batch.TerminalCommands, batch.RemoteAudit = nil, nil, nil
			} else if len(batch.TerminalRuns) != 0 || len(batch.TerminalCommands) != 0 || len(batch.RemoteAudit) != 0 {
				t.Errorf("terminal/remote dev wires shipped under %s (metadata-only) — must ride shipsRawContent only", tc.name)
			}
			raw, err := json.Marshal(batch)
			if err != nil {
				t.Fatalf("marshal batch: %v", err)
			}
			if bytes.Contains(raw, []byte(secTerm)) {
				t.Errorf("terminal/remote identity leaked under %s without terminal_detail", tc.name)
			}
		})
	}
}

// seedRouterDecision inserts one router_decisions row with a sentinel model, so
// a SelectUnpushedSince batch can be searched for whether the P5d routing-detail
// aggregate shipped. router_decisions stays NODE-LOCAL; only the content-free
// (day, model→model, turn_kind, mode) aggregate crosses, and only under
// routing_detail.
func seedRouterDecision(ctx context.Context, t *testing.T, database *sql.DB, selectedModel string) {
	t.Helper()
	ts := time.Now().UTC().Format(time.RFC3339)
	if _, err := database.ExecContext(ctx,
		`INSERT INTO router_decisions (session_id, ts, mode, channel, original_model, selected_model, turn_kind, policy_hash, applied, est_savings_usd)
		 VALUES ('sess-cc-1', ?, 'enforce', 'proxy', 'claude-opus-4-8', ?, 'edit', 'ph', 1, 0.03)`, ts, selectedModel); err != nil {
		t.Fatalf("seed router_decisions: %v", err)
	}
}

// TestPushPayloadCarriesRoutingDetailWhenOptedIn is the Arc 4 P5d extraction
// tier: under the DISTINCT routing_detail opt-in, the node-local
// router_decisions log ships as a content-free but MODEL-ID-BEARING aggregate.
// The router_decisions table NAME still never appears in orgpush.go
// (SelectRoutingDetail owns the read in a separate file); this proves the
// aggregate itself flips onto the wire under the tier.
func TestPushPayloadCarriesRoutingDetailWhenOptedIn(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)
	const secRouteModel = "SENTINEL_ROUTE_MODEL_pangram_zz"
	seedRouterDecision(ctx, t, database, secRouteModel)

	batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example",
		store.ShareOptions{RoutingDetail: true}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	if len(batch.RoutingDetails) == 0 {
		t.Fatal("routing_detail opt-in shipped no RoutingDetails — the tier failed to flip the seam")
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}
	if !bytes.Contains(raw, []byte(secRouteModel)) {
		t.Error("routing detail did NOT ship the selected model under routing_detail — the tier failed to flip the seam")
	}
}

// TestPushPayloadStripsRoutingDetailWhenNotOptedIn is the other side of the
// tier: with routing_detail OFF, the routing detail must NOT ship — not even
// under full_content, and not under the model-id-FREE routing_summary tier
// (which ships a DIFFERENT aggregate). routing_detail is a DISTINCT tier.
func TestPushPayloadStripsRoutingDetailWhenNotOptedIn(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)
	const secRouteModel = "SENTINEL_ROUTE_MODEL_pangram_zz"
	seedRouterDecision(ctx, t, database, secRouteModel)

	for _, tc := range []struct {
		name  string
		share store.ShareOptions
	}{
		{"zero-value", store.ShareOptions{}},
		{"full_content-only", store.ShareOptions{FullContent: true}},
		{"routing_summary-only", store.ShareOptions{RoutingSummary: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example", tc.share, store.ScopeOptions{})
			if err != nil {
				t.Fatalf("SelectUnpushedSince: %v", err)
			}
			if len(batch.RoutingDetails) != 0 {
				t.Errorf("routing detail shipped under %s (routing_detail OFF) — the tier must be distinct and opt-in", tc.name)
			}
			if tc.share.FullContent {
				// Enterprise (org-parity W2.3): full_content legitimately
				// ships the per-dev routing wire, which MAY carry the
				// model (plan §0.1) — scope the leak scan past it. The
				// routing_summary-only and zero-value cases stay fully
				// clean (the teams posture).
				if len(batch.RoutingDevRows) == 0 {
					t.Error("full_content shipped no routing dev rows — the W2.3 enterprise wire failed to flip")
				}
				batch.RoutingDevRows = nil
			} else if len(batch.RoutingDevRows) != 0 {
				t.Errorf("routing dev rows shipped under %s (no raw-content tier) — must ride shipsRawContent only", tc.name)
			}
			raw, err := json.Marshal(batch)
			if err != nil {
				t.Fatalf("marshal batch: %v", err)
			}
			if bytes.Contains(raw, []byte(secRouteModel)) {
				t.Errorf("selected model leaked under %s without routing_detail", tc.name)
			}
		})
	}
}

// seedLimitSnapshot inserts one limit_snapshots row with a sentinel scope_hash,
// so a SelectUnpushedSince batch can be searched to prove the P5e aggregate
// ships utilization stats but NEVER the raw scope hash. limit_snapshots stays
// NODE-LOCAL; only the content-free (day, provider) utilization aggregate
// crosses, and only under limit_gauge.
func seedLimitSnapshot(ctx context.Context, t *testing.T, database *sql.DB, scopeHash string) {
	t.Helper()
	if _, err := database.ExecContext(ctx,
		`INSERT INTO limit_snapshots (scope_hash, provider, observed_at, window_5h_util, window_7d_util)
		 VALUES (?, 'anthropic', ?, 0.73, 0.41)`, scopeHash, time.Now().UTC().Unix()); err != nil {
		t.Fatalf("seed limit_snapshots: %v", err)
	}
}

// TestPushPayloadCarriesLimitGaugeWhenOptedIn is the Arc 4 P5e extraction tier:
// under the DISTINCT limit_gauge opt-in, the node-local limit_snapshots log
// ships as a content-free per (day, provider) utilization aggregate — and the
// raw scope_hash (auth identity) is NEVER on the wire. The limit_snapshots table
// NAME still never appears in orgpush.go (SelectLimitGauges owns the read in a
// separate file).
func TestPushPayloadCarriesLimitGaugeWhenOptedIn(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)
	const secScopeHash = "SENTINEL_LIMIT_SCOPE_pangram_zz"
	seedLimitSnapshot(ctx, t, database, secScopeHash)

	batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example",
		store.ShareOptions{LimitGauge: true}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	if len(batch.LimitGauges) == 0 {
		t.Fatal("limit_gauge opt-in shipped no LimitGauges — the tier failed to flip the seam")
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}
	// The aggregate rides, but the raw auth-scope hash must NOT.
	if bytes.Contains(raw, []byte(secScopeHash)) {
		t.Error("limit gauge leaked the raw scope_hash — only the (day, provider) utilization aggregate may ship")
	}
	if batch.LimitGauges[0].Provider != "anthropic" || batch.LimitGauges[0].Max5hUtil <= 0 {
		t.Errorf("limit gauge = %+v, want anthropic with a positive 5h util", batch.LimitGauges[0])
	}
}

// TestPushPayloadStripsLimitGaugeWhenNotOptedIn is the other side of the tier:
// with limit_gauge OFF, the aggregate must NOT ship — not even under
// full_content. It is a DISTINCT tier.
func TestPushPayloadStripsLimitGaugeWhenNotOptedIn(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)
	const secScopeHash = "SENTINEL_LIMIT_SCOPE_pangram_zz"
	seedLimitSnapshot(ctx, t, database, secScopeHash)

	for _, tc := range []struct {
		name  string
		share store.ShareOptions
	}{
		{"zero-value", store.ShareOptions{}},
		{"full_content-only", store.ShareOptions{FullContent: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example", tc.share, store.ScopeOptions{})
			if err != nil {
				t.Fatalf("SelectUnpushedSince: %v", err)
			}
			if len(batch.LimitGauges) != 0 {
				t.Errorf("limit gauge shipped under %s (limit_gauge OFF) — the tier must be distinct and opt-in", tc.name)
			}
		})
	}
}

// forbiddenCacheTables names the three node-local cachetrack tables
// that MUST NEVER appear in the org-push wire path. Spec §11:
// cachetrack data (segments, entries, events) is local, passive,
// node-side telemetry — it never leaves the agent. Adding any
// of them to internal/store/orgpush.go::SelectUnpushedSince (or
// any helper in that file) is a privacy regression — even though
// the rows themselves carry no raw text content, they reveal
// per-turn cache-hit patterns that the operator may treat as
// private even when they've opted into full-content sharing on
// the existing wire surfaces.
//
// Pinned by [TestSelectUnpushedSinceExcludesCacheTables] at the
// SOURCE level so the regression fires before any row is even
// constructed.
var forbiddenCacheTables = []string{
	"cache_segments",
	"cache_entries",
	// cache_events STAYS here after the enterprise-first per-event timeline
	// landed (server migration 142, operator directive item 6) — deliberately,
	// and unlike task_items / tool_account_observations, which LEFT this set
	// when their wires landed. The difference is what each pin was doing. Those
	// two were blanket "never crosses" pins whose reversal had to be recorded
	// by removing them. This entry is a SOURCE-LEVEL module-boundary rule about
	// ONE FILE: the cache_* names may not appear in internal/store/orgpush.go,
	// so every cache read stays with its one owner in a seam file
	// (cachesummary.go, cachesessionorgrows.go, cacheeventorgrows.go). That
	// rule is unchanged and still worth enforcing. The DATA posture — which of
	// those reads may cross, and under what tier — is pinned by the named
	// tests instead: TestPushPayloadCarriesCacheWhenOptedIn (fleet aggregate,
	// cache_detail), TestPushPayloadStripsCacheWhenNotOptedIn (orthogonality)
	// and TestSessionCacheEventsShipOnlyUnderRawContent (the per-event
	// timeline, shipsRawContent(), plus the `detail`-column exclusion).
	"cache_events",
	// Advisor (suggestions engine, spec §15.7) tables are node-local
	// for the same reason and more: suggestion state + the digest
	// snapshot embed file paths and command summaries. Migration 039.
	"advisor_state",
	"advisor_digest",
	// Model-routing tables (model-routing spec §R9.1 + §R20) are
	// node-local: decision rows reveal per-turn model-selection
	// patterns and policy state; calibration rows reveal per-project
	// outcome aggregates. The §R19.4 org rollup pushes a separate
	// AGGREGATE wire shape when it ships — never these rows.
	// Migrations 041 + 042.
	"router_decisions",
	"model_calibration",
	// The agent-side org routing-policy CACHE (migration 043) is
	// received state — its body may describe org-internal projects —
	// and must never round-trip back onto the wire. The §R19.4
	// rollup that IS allowed on the wire is the routing_summaries
	// AGGREGATE, computed in store/routingsummary.go and composed
	// into the push via a function call precisely so this sentinel
	// can keep forbidding the underlying table names here.
	"org_routing_policies",
	// project_patterns (W3.3 Discovery/Patterns) is NODE-LOCAL by table
	// name: orgpush.go must never reference it directly. A derived,
	// capped, enterprise-raw wire row (ProjectPatternRow) DOES ship under
	// shipsRawContent(), computed in store/patternsorgrows.go and
	// composed into the push via a function call — precisely so this
	// sentinel can keep forbidding the underlying table name here, same
	// pattern as org_routing_policies/router_decisions above.
	"project_patterns",
	// Guard-layer tables (migration 040, guard spec §10.2): pins,
	// policy state and approvals are NODE-LOCAL until the G13/G14
	// teams arc deliberately adds their wire surfaces (pins ship
	// hash-only, approvals ship granted_by — per guard spec §14.3)
	// and consciously updates this sentinel. guard_events is
	// deliberately ABSENT from this list — it DOES push, with its
	// content-bearing columns (reason / target_excerpt / taint_origin)
	// stripped in Go unless [org_client.share].full_content; that
	// posture is pinned data-side by TestPushPayloadCarriesNoContent's
	// guard sentinels + canaries above.
	"guard_pins",
	"guard_policy_state",
	"guard_approvals",
	// The prompt-submit intervention's "reconsider-once" grant table
	// (migration 110, docs/plans/prompt-submit-intervention-exploration-
	// 2026-09-07.md §5.4) is NODE-LOCAL for the same reason as the guard
	// block above: even though the matched secret/PII value is NEVER
	// stored anywhere in this table (or anywhere else — only a
	// composite sha256 fingerprint over detector-id/span-hash pairs is
	// persisted, §5.2), the row's `detectors` + `session_id` still
	// reveal WHICH KIND of sensitive content a developer typed and WHEN
	// — provenance-of-a-near-miss that the node operator should control
	// disclosure of, same posture as guard_pins/guard_policy_state/
	// guard_approvals immediately above. It gets NO paired org-server
	// migration, by design — same posture as limit_snapshots.
	"guard_prompt_reconsider",
	// Process-observability tables (migration 044,
	// docs/process-observability.md §10.1) are NODE-LOCAL: they record
	// OS-level process trees, argv previews, executable identity, and
	// side-effect events for AI sessions — far higher privacy surface than
	// the metadata that DOES push. They never enter the wire path until a
	// separate privacy review designs hash-only rollups. No paired
	// orgserver migration exists, by the same design.
	"process_runs",
	"process_events",
	"process_network_bodies",
	// Rate-limit snapshots (migration 049, the Next-Message Cost & Limit
	// Predictor's limit half) are NODE-LOCAL: per-account subscription-
	// window utilization + reset timestamps are personal usage telemetry
	// (same class as the cache tables). No paired orgserver migration; a
	// team-level "who's near their cap" view, if ever built, is a separate
	// opt-in AGGREGATE wire shape, never this table.
	"limit_snapshots",
	// Plane-A P0-5 unified policy resource, agent-side scoped persistence
	// (migration 081, docs/plans/plane-a-p0-5-unified-policy-resource-v1-plan.md
	// §6.2/§6.9/§6.10): org_enrolment_generation is the durable
	// cross-process enrolment fence (survives unenrol, carries a tombstone
	// bit) and org_policy_resource_state is the per-(org_key, family)
	// replay floor + last-verified-envelope identity. Both are RECEIVED,
	// generation-scoped control-plane state — like org_routing_policies
	// above, round-tripping either back onto the wire is pure noise even
	// setting aside that a generation counter and a replay floor reveal
	// nothing useful to the server it didn't already know, but the
	// underlying resource content (family bodies) could. internal/store/
	// policyresource.go is their one owner; orgpush.go must never read
	// them.
	"org_enrolment_generation",
	"org_policy_resource_state",
	// Admin-controlled Plane B, the ENROLMENT GRANT (migration 082,
	// docs/plans/admin-controlled-plane-b-spec-2026-08-15.md §2.4). It
	// records the bounded authority THIS machine handed to the
	// organization: consent mode, the consenting local actor, the signed
	// offer, the key pin. The org already knows what it offered; what it
	// must never receive back on the push wire is the node's own consent
	// record, which names a local user and is the developer's evidence of
	// what they agreed to — evidence whose whole value is that it lives on
	// their machine, under their control, deletable by `observer unenroll`.
	// internal/store/orggrant.go is its one owner.
	"org_enrolment_grant",
	// Session-handoff records (migration 055,
	// docs/plans/session-handoff-plan-2026-07-03.md §5) are NODE-LOCAL:
	// which tool a user moved a session to, when, at what fork point and
	// estimated cost is personal workflow telemetry. The rendered
	// HandoverDoc is never stored at all (delivered and forgotten); the
	// row holds counts/enums/hashes/paths only. Cross-machine handoff, if
	// ever built, is a separate opt-in wire shape behind
	// shipsRawContent(), never this table.
	"handoffs",
	// The Terminal Workspace dock-grid layout (migration 073,
	// docs/plans/terminal-dock-grid-design-2026-07-20.md) is NODE-LOCAL:
	// the blob maps terminal handles / session ids to grid cells — the
	// operator's personal screen arrangement, meaningless and unwanted
	// off-node. No paired orgserver migration, by design.
	"workspace_layouts",
	// The org-announcement CACHE (migration 076, rail R3 of
	// docs/plans/dashboard-announcements-banner-plan-2026-07-31.md §4)
	// is NODE-LOCAL and must stay that way for a reason specific to
	// this feature: the rail is ONE-WAY by design. Pushing the cached
	// document (or its version) back would tell the server which of its
	// own announcements this node holds — a read receipt, which plan §6
	// rules out as telemetry. The banner has no acknowledgment wire and
	// must never grow one by accident; the row is also RECEIVED state,
	// like org_routing_policies above, so round-tripping it is pure
	// noise even setting the receipt problem aside.
	"org_announcements",
	// Code-intelligence tables (internal/codeintel, migrations 050+,
	// docs/codeintel/) are NODE-LOCAL: they hold a project's source
	// paths, symbol names, signatures, import specifiers, and the
	// call/import graph — a structural map of private code that must
	// never leave the agent. [codeintel] config is local-only (like
	// [routing]/[cachewarm]); these tables are pre-registered here
	// before the schema lands so any attempt to add one to the push
	// seam fails loudly. If a team-level code-graph rollup is ever
	// built it would be a separate opt-in AGGREGATE wire shape, never
	// these tables.
	"codeintel_files",
	"codeintel_nodes",
	"codeintel_edges",
	"codeintel_sites",
	"codeintel_fts",
	"codeintel_embeddings",
	"codeintel_minhash",
	// Corpus-archival tables (docs/plans/observer-corpus-archival-lazyload-
	// design-2026-08-26.md). Two distinct things are pinned here:
	//
	//   - codeintel_archived_projects (migration 092) is a HOT-DB table
	//     naming private project paths, node-local for exactly the same
	//     reason as the codeintel_* rows above.
	//   - the archive_* names live in a DIFFERENT FILE entirely
	//     (~/.observer/archive.db, owned by internal/archivestore with its
	//     own *sql.DB and its own migration lineage), so they are already
	//     unreachable from the push seam BY CONSTRUCTION: orgpush.go builds
	//     wire rows from the single hot handle it is given and has no code
	//     path to a second database. They are listed anyway because "by
	//     construction" is an argument, and this sentinel is a check —
	//     if a future refactor ever hands orgpush.go a second handle, the
	//     failure should be a red test rather than a review someone had to
	//     remember to do. Cold storage never becomes a wire surface: it
	//     holds the same node-local rows, only older.
	"codeintel_archived_projects",
	// Bucket B (process capture) archival, migration 093 + archive
	// migration 002. Same two-part posture as Bucket A above: the marker
	// is a hot-DB table, the archive_process_* rows live in the separate
	// archive file. Bucket B's hot tables carry raw command lines, cwds
	// and scrubbed network bodies, so their cold mirrors are at least as
	// sensitive as the originals — cold storage never becomes a wire
	// surface, it holds the same node-local rows, only older.
	"process_archived_windows",
	"archive_process_runs",
	"archive_process_events",
	"archive_process_network_bodies",
	"archive_codeintel_files",
	"archive_codeintel_nodes",
	"archive_codeintel_edges",
	"archive_codeintel_sites",
	"archive_codeintel_embeddings",
	"archive_codeintel_minhash",
	// Generalized-observability subsystem tables (internal/obs, plan
	// docs/plans/generalized-observability-custom-app-plan-2026-06-27.md
	// §10, decision D3). These are the obs subsystem's OWN tables, read
	// ONLY by internal/obs/store. Their org-tier disclosure IS a real
	// data flow — the obs-org-tier subsystem (docs/plans/
	// obs-org-tier-plan-2026-06-29.md) pushes trace/span STRUCTURE (T2),
	// eval-run SUMMARIES (T4), per-end-user SPEND (T5), and — gated by
	// shipsRawContent() — raw span bodies (T3), each under its own
	// [org_client.share] obs_* opt-in (default OFF; on in the hosted-app
	// admin_managed deployment). What this sentinel enforces is the
	// MODULE BOUNDARY, not "never pushed": orgpush.go must NEVER name an
	// obs_* table directly — the disclosure is composed through the
	// injected obs func seam (store.ObsOrgProviders), exactly like
	// RoutingSummaries. So these names must not appear as literals in
	// orgpush.go even though the data they hold does (selectively) ship.
	"obs_traces",
	"obs_spans",
	"obs_span_events",
	"obs_span_links",
	"obs_span_content",
	// obs eval plane (migration 0002, plan §8): datasets, dataset items
	// (snapshot input/output bodies), eval runs and scores are obs-owned.
	// Eval HEALTH ships as the T4 aggregate (obs_eval_summaries server
	// side) via the EvalRuns func seam; these raw tables are never NAMED
	// in orgpush.go (module boundary — same rule as above).
	"obs_datasets",
	"obs_dataset_items",
	"obs_eval_runs",
	"obs_eval_scores",

	// Benchmarks Harness tables (migration 061,
	// docs/plans/benchmarks-harness-plan-2026-07-11.md §3.3) are NODE-LOCAL:
	// they hold repo paths, task prompts, final-answer excerpts, and judge
	// rationales — far higher privacy surface than the metadata that DOES
	// push, and personal benchmarking telemetry besides. They never enter the
	// wire path: no paired orgserver migration exists, and orgpush.go names an
	// explicit table allow-list these are not in. A future team-level
	// leaderboard, if ever built, would be a separate opt-in AGGREGATE wire
	// shape (per-config success-rate + cost, no prompts/paths), composed via a
	// function seam — never these tables (the routing_summary precedent).
	"benchmark_runs",
	"benchmark_attempts",
	"benchmark_session_members",
	"benchmark_scores",
	// obs input-admission audit (migration 0005, admission spec §7): the
	// verdict event log (raw request NEVER stored — only message_hash; the
	// reason_excerpt is gated by ContentGate) and the content-addressed policy
	// snapshots are NODE-LOCAL like the rest of obs_* — never on the org-push
	// wire, no server pair. (Org-level admission rollups, if ever wanted, are a
	// separate opt-in decision — obs plan §15 Q5.)
	"obs_admission_events",
	"obs_admission_policy_versions",

	// Opt-in aggregate rail state (migration 062,
	// docs/plans/g25-optin-aggregate-rail-design-2026-07-11.md §6.5). Both
	// tables are NODE-LOCAL by construction: aggregate_submissions is a
	// per-month submission ledger (month/hash/state/attempt bookkeeping + a
	// bounded snapshot of the CONTENT-FREE allow-listed payload), and
	// aggregate_consent is the single-row consent receipt. The aggregate rail
	// is an org-INDEPENDENT sibling of org-push, never an extension of it: it
	// has its OWN egress seam (internal/aggregateclient), its own consent gate,
	// and it does not round-trip through SelectUnpushedSince at all. These
	// literal sentinels keep both table names out of orgpush.go — the wire that
	// DOES leave under this rail is the aggregate.Submission (24-field
	// allow-list), pinned separately by tests/invariant/aggregate_test.go.
	"aggregate_submissions",
	"aggregate_consent",

	// Remote-access audit log (migration 063, remote-dashboard-access plan
	// §4.8) is NODE-LOCAL: it records remote-exposure events (paired session
	// ids, resolved capability, matched route, decision) for the operator's own
	// `observer remote status`. It never leaves the machine — no paired
	// orgserver migration, and orgpush.go names an explicit table allow-list
	// this is never in. Same posture as cachetrack / limit_snapshots. If a
	// team-level "who accessed my node remotely" view is ever wanted it is a
	// separate opt-in AGGREGATE wire shape, never this raw table.
	"remote_audit",

	// obs Plane-A egress-routing audit (migration 0007, G22 design §7). The
	// raw request is NEVER stored (only message_hash). Since 2026-08-24
	// (org-parity W5.3) an egress org tier DOES exist — exactly the "future
	// opt-in wire shape + share key + sentinel update" the original G22 §8
	// deferral prescribed: composed as orgcontract.ObsEgressRow via the
	// store.ObsOrgProviders.Egress FUNC SEAM, gated on the node-side
	// [org_client.share.obs].egress opt-in (ShareOptions.ObsEgress, default
	// false), with the Tenant/User content columns additionally stripped
	// under !shipsRawContent(). This literal sentinel therefore still holds:
	// the table NAME never appears in orgpush.go (module-boundary
	// discipline, same as every obs_* table); the tier contract itself is
	// pinned by TestObsEgressTierContract + the compose gating test in
	// internal/store/orgpush_obs_test.go.
	"obs_egress_decisions",

	// Terminal-run identity + correlation (migration 064, terminal-product-
	// exploitation plan §2.1a / §7 — Phase 0 item S0b). Both tables are
	// NODE-LOCAL: they record which tool a dashboard terminal launched, when, at
	// what (hashed) project root, and which agent sessions the launch was
	// confidently correlated to — personal workflow telemetry. They never enter
	// the wire path: no paired orgserver migration exists, and orgpush.go names
	// an explicit table allow-list neither is in. A future team-level "who ran
	// what" view, if ever built, is a separate opt-in AGGREGATE wire shape,
	// never these raw tables. Same posture as the remote_audit / limit_snapshots
	// node-local tables.
	"terminal_run",
	"terminal_run_session",
	// Terminal command/turn boundaries (migration 065, terminal-product-
	// exploitation plan §7 / F3). NODE-LOCAL: command/turn boundary
	// coordinates + exit codes + provenance for a dashboard terminal launch,
	// metadata/coordinates only (never command text or output). Never on the
	// wire — no server pair; same posture as terminal_run.
	"terminal_commands",
	// Persisted remote device sessions (migration 066, persist-remote-sessions
	// plan 2026-07-14). NODE-LOCAL: remote_sessions holds the sha256 hash of a
	// paired device's bearer cookie (never the raw token) + its generation and
	// idle clock; remote_session_state holds the single-row durable generation
	// fence. These let a paired phone survive a daemon restart without weakening
	// the revoke/rotate/disable invariant. They never leave the machine — no
	// paired orgserver migration, and orgpush.go names an explicit table
	// allow-list neither is in. Same posture as remote_audit / limit_snapshots.
	"remote_sessions",
	"remote_session_state",

	// Session classification (migration 075,
	// docs/plans/session-classification-tags-plan-2026-07-31.md §1). Tag names
	// and notes are the SAME PRIVACY CLASS as sessions.git_branch, which was
	// gated off the org wire on 2026-07-02 (security review M2) precisely
	// because free-text labels a developer authors encode client names,
	// codenames and ticket ids. A tag vocabulary is that failure mode by
	// construction ("acme-migration", "PROJ-1421", "junk"), and the note field
	// is unbounded prose about why a run mattered.
	//
	// Both tables are therefore NODE-LOCAL under EVERY share mode — including
	// admin_managed, which flips content-bearing columns raw for the other
	// surfaces. There is no share key for them and no paired orgserver
	// migration, by design; an org-shared taxonomy would need an explicit new
	// [org_client.share] key plus its own privacy review (plan §0, deferred).
	// session_tags additionally carries the end-to-end pin below
	// (TestSessionClassificationPinnedOutOfPush).
	"session_tags",
	"session_annotations",
	// tag_definitions (migration 101) — the optional human-readable
	// explanation + category attached to a tag name in the vocabulary above.
	// Same privacy class as session_tags/session_annotations (a definition
	// can itself restate the client/codename/ticket meaning a tag encodes),
	// same posture: no share key, no paired orgserver migration.
	"tag_definitions",
	// Node-local cloud-intelligence persistence (migration 097, CI-P2 Lane D —
	// cloud-intelligence Azure Foundry plan of record §6 CI-P2 + §7 invariant
	// 2). These are the SIGNED-IN FREE / PERSONAL cloud plane's own node-side
	// tables, and the personal plane is a SEPARATE destination from the org
	// push wire by construction (plan §7 invariant 3, plane separation). None
	// may ever appear in orgpush.go: consent receipts and the random
	// local<->cloud pseudonym maps are the developer's private evidence of what
	// they agreed to and which local ids they mapped; the outbox names sessions
	// + confirmed digests + retry state; cloud_results (and its overrides) hold
	// the enrichment product plus the user's own edits — all node-local under
	// EVERY share mode. There is no org share key for any of them and no paired
	// orgserver migration. TestCloudLocalTablesPinnedOutOfPush adds the
	// seeded-value end-to-end pin (STRENGTHENED sentinel, Sol SB3): distinctive
	// sentinels stuffed into every text column of every one of these tables,
	// asserted absent from a real SelectUnpushedSince serialization under
	// metadata-only, full_content, AND admin_managed.
	"cloud_consent_receipts",
	"cloud_session_map",
	"cloud_project_map",
	"cloud_outbox",
	"cloud_results",
	"cloud_result_overrides",
	// Migration 098 (W2 structural-insights rail, divergence-remediation plan
	// rev 4.1 §3 W2): the node's own record of which per-day windows it
	// snapshotted, at which revision, with which digest. Same posture as the
	// 097 five — node-local, no org share key, no paired orgserver migration.
	"cloud_structural_windows",
	// Migration 100 (Sol re-review N2, the cross-process dispatch lease for the
	// standing rails): receipt ids, a purpose label, a generation and
	// timestamps — the node's own record of which sends were in flight under
	// which receipt. Same posture as the 097/098 tables.
	"cloud_dispatch_leases",
	// Migration 115 (W2 value-upgrade plan: the developer's own standing
	// enrichment INTENT — which level the background path may mint
	// per-session receipts under, and whether background runs at all). It
	// binds nothing and authorizes no upload by itself (a consent receipt
	// still gates every send), but it is still node-local developer-recorded
	// state with no org share key and no paired orgserver migration — same
	// posture as every other cloud_* table.
	"cloud_enrich_policy",
	// Migration 117 (W3 value-upgrade plan: the outcome of the most recent
	// `observer cloud sync` run — content-free counts and a closed error
	// class only, never a session id or raw output). Same posture as every
	// other cloud_* table: no org share key, no paired orgserver migration.
	"cloud_sync_last",
	// Migration 118 (W5 value-upgrade plan: the weekly project digest a
	// pulled result kind="project_digest" record carries — headline/themes/
	// cost trend/recurring error classes/unfinished threads/suggested next
	// session for one project's own already-uploaded session_enrichment
	// results). NO new content ever left this node to produce a digest — it
	// is a RECEIVED product, the same posture as cloud_results for a session
	// enrichment. Node-local: no org share key, no paired orgserver
	// migration.
	"cloud_digests",
	// Migration 120 (2026-09-16 background-by-default follow-up: the
	// durable backoff for the auto-enrich sweep's permanently-failing
	// candidates — session id, attempt count, next-eligible time, and a
	// short fixed error CLASS token, never subprocess output). Same
	// posture as every other cloud_* table: no org share key, no paired
	// orgserver migration.
	"cloud_enrich_skips",
	// file_changes (migration 103, Lines-of-Code tracking) is NODE-LOCAL BY
	// TABLE NAME: orgpush.go must never reference it. Its grain is ONE ROW
	// PER FILE — a file-level activity map of the developer's working tree,
	// a strictly deeper disclosure than "this session's agent wrote N lines
	// of code", even though every path in it is already a hash.
	//
	// What DOES ship is the SUM over it: the SessionLOCRow / LOCDayRow
	// aggregates, computed in store/locsummary.go and composed into the push
	// via a FUNCTION CALL — precisely so this sentinel can keep forbidding the
	// underlying table name here, the same pattern as
	// router_decisions/routing_summaries and project_patterns above. Adding a
	// per-file wire row is not a matter of widening this list: it would need
	// its own share key and its own privacy review.
	// TestSessionLOCWireShapeIsAggregateOnly pins the wire types' shape;
	// TestFileChangesNeverOnTheWire is the end-to-end seeded-value pin.
	"file_changes",
	// Enterprise Update Management, node side (agent migration 105,
	// docs/plans/enterprise-update-management-plan-2026-09-07.md §3.4). Both
	// tables are NODE-LOCAL BY TABLE NAME: orgpush.go must never reference
	// them.
	//
	// update_state stores three LOCAL PATHS — the preserved rollback binary,
	// the staged download and the pre-apply VACUUM INTO snapshot — plus the
	// bytes of the manifest this node accepted. update_events.detail is
	// deliberately free text (which snapshot was restored, which directory
	// was not writable), which is what makes `observer update history`
	// usable and exactly what ruling R10 keeps off the wire: an error STRING
	// can leak a path, an error CLASS cannot.
	//
	// What DOES ship is orgcontract.UpdatePostureRow — a version string, a
	// coarse platform token, four closed enums and two booleans — composed
	// in internal/store/updateposture.go and reached from the push seam by a
	// FUNCTION CALL, precisely so this sentinel can keep forbidding the
	// underlying names here. That row's field set is pinned separately by
	// TestUpdatePostureRowWireShapeIsEnumOnly, so widening the disclosure is
	// not a matter of widening this list.
	"update_state",
	"update_events",
	// Enterprise pricing, node side (agent migration 106,
	// docs/plans/enterprise-pricing-and-admin-assistant-plan-2026-09-08.md
	// §3.3). org_pricing_cache is NODE-LOCAL BY TABLE NAME: orgpush.go must
	// never reference it.
	//
	// It holds the ORG's own signed price document as the node last accepted
	// it — the server's bytes coming BACK, not node data going out — plus the
	// key fingerprint that verified them and the ladder state of the last
	// fetch. It is persisted rather than kept in memory (the sibling budget
	// rail's choice) because a mis-priced captured turn is permanent, so a
	// restart must not silently drop the fleet to seed prices.
	//
	// What DOES ship in the other direction is the enum-only PricingSource /
	// PricingVersion pair on orgcontract.BudgetPostureRow — an envelope field
	// composed by internal/store's posture seam, never a selected wire row —
	// which is precisely why this sentinel can keep forbidding the table name
	// here. Same posture as update_state / update_events above.
	"org_pricing_cache",
	// Org BUDGET rail, node side (agent migration 119, org-observer
	// fundamentals plan 2026-09-13 finding H3). org_budget_cache is NODE-LOCAL
	// BY TABLE NAME: orgpush.go must never reference it.
	//
	// It holds the ORG's own signed PER-CALLER budget document as the node
	// last accepted it — the server's bytes coming BACK, not node data going
	// out — plus the ETag and the key fingerprint that verified them. The
	// direction is the org_pricing_cache posture exactly, one rail over, and
	// the body it stores was resolved and signed BY the server, so echoing it
	// on the push wire would add no information and only widen what a
	// compromised node could assert.
	//
	// What DOES ship in the other direction is the enum-only
	// orgcontract.BudgetPostureRow — composed by internal/store's posture
	// seam, never a selected wire row — which is why this sentinel can keep
	// forbidding the table name here.
	"org_budget_cache",
	// Org-served Cloud Intelligence, node side (agent migration 112,
	// docs/plans/org-served-cloud-intelligence-plan-2026-09-10.md §1.3/§2.4,
	// W3, INV-3). org_intel_cache is NODE-LOCAL BY TABLE NAME: orgpush.go must
	// never reference it.
	//
	// It holds the ORG server's OWN derived per-session enrichment results as
	// the node last PULLED them over GET /api/agent/intel/results — the org's
	// product coming BACK, not node data going out, exactly the posture of
	// org_pricing_cache above. The results are model-generated prose about the
	// developer's own session; they are rendered on the node dashboard and
	// never travel the node→server push wire (that direction is the push
	// envelope). There is no org share key for it and no paired orgserver
	// migration on the push side — the org DERIVES its own result rows from
	// data the node already pushed (B2), so nothing new goes out to produce
	// them. The single store seam is internal/store/intelcache.go.
	"org_intel_cache",
	// Standalone-node public pricing feed, node side (agent migration 113,
	// docs/plans/pricing-sync-tokenomics-to-platform-plan-2026-09-11.md §C.3,
	// Wave N). pricing_feed_cache is NODE-LOCAL BY TABLE NAME: orgpush.go must
	// never reference it.
	//
	// It holds the PUBLIC Tokenomics feed's OWN signed document as the node
	// last pulled it over GET /api/pricing/v1/observer-pricing — a publisher's
	// bytes coming BACK, and a body that names no org and no subject (the SAME
	// document for every consumer on earth), not node data going out. Exactly
	// the org_pricing_cache posture above, for the standalone case instead of
	// the enrolled one: an enrolled node ignores the public feed entirely, so
	// this table is inert while enrolled and never carries anything worth
	// pushing. The single store seam is internal/store/pricingfeed.go; there is
	// no org share key for it and no paired server migration (the org server
	// consumes the feed through its own importer, a separate wave).
	"pricing_feed_cache",
	// DELIBERATELY NO LONGER HERE — task_items / task_transitions (agent
	// migration 109) and tool_account_observations (agent 111). Migration
	// 109 pinned the task tables node-local "for this first slice" and 111
	// said "Never copied by org push"; the node session-detail trickle-up
	// arc's W2/W3 waves (docs/plans/
	// node-session-detail-trickle-up-to-org-plan-2026-09-10.md, server
	// migrations 140/141) are the deliberate, reviewed reversal of exactly
	// that first slice — the G22 s8 pattern this file has applied before
	// (terminal_run / remote_audit moved the same way under
	// terminal_detail).
	//
	// The one-owner discipline is UNCHANGED and still enforced: orgpush.go
	// names none of the three tables. The reads live in their own files
	// (internal/store/taskflowsummary.go, toolaccountsummary.go), reached
	// from the push seam by a FUNCTION CALL — the same arrangement
	// cache_events, router_decisions and file_changes already use, all of
	// which likewise ship an opt-in wire while their table names stay
	// forbidden here.
	//
	// What replaces the blanket forbid is a pair of NAMED wire-surface
	// tests, which are strictly stronger than the old absence assertion
	// because they pin the GATE rather than the silence:
	// TestSessionTasksShipOnlyUnderTaskDetail and
	// TestSessionToolAccountsShipOnlyUnderToolAccountDetail prove nothing
	// ships under the zero-value posture, that the status/enum halves ship
	// under their own tier, and that the content halves (plan prose;
	// developer identity) stay STRIPPED until the node ALSO ships raw
	// content.
}

// forbiddenGatewayTables names the SERVER-SIDE gateway tables that MUST NEVER be
// referenced as a string literal in internal/store/orgpush.go. Unlike the
// node-local forbiddenCacheTables above, these live in the ORG SERVER's DB — but
// the same source-level sentinel applies: the node→server push seam
// (SelectUnpushedSince) must never name them, because they are SERVER-ONLY ingest
// state the node never possesses. gateway_wal is the P0-9 durable-edge WAL — a
// server-only ingest queue whose payload holds mapped telemetry the node never
// possesses; naming it on the push wire would be nonsensical AND a boundary
// violation. Walked by TestSelectUnpushedSinceExcludesCacheTables alongside
// forbiddenCacheTables.
var forbiddenGatewayTables = []string{
	"gateway_wal",
	// The P1-2/P1-10 generic trace/span attribute-retention tier (server
	// migration 033) makes gateway_span carry retained OTLP attributes, and it
	// references the content-addressed gateway_resource/gateway_scope envelopes;
	// gateway_trace holds synthesized trace summaries. All four are SERVER-ONLY
	// gateway ingest tables (mig 026/027) that the NODE never possesses, so their
	// names must never appear on the org-push wire either.
	"gateway_resource",
	"gateway_scope",
	"gateway_span",
	"gateway_trace",
	// Plane B AI Gateway v1 (design §2, tracker Phase P4; server migrations
	// 108-111). The seven gw_* tables are the inference data plane's SERVER-ONLY
	// state — the per-developer virtual-key registry (stored as hashes only),
	// the org's registered upstreams (credential referenced only by a sealed
	// org_secret ref), the durable worst-case reservation ledger, and the
	// metadata-ONLY audit. The node never possesses any of them, so their names
	// must never appear as a string literal in orgpush.go's push seam. Named
	// gw_* rather than gateway_* deliberately (design §2.1 — grep-space disjoint
	// from the OTLP-ingest gateway_* tables above). Pinned as a fixed expected
	// set by TestForbiddenGatewayTablesExpectedSet.
	"gw_virtual_key",
	"gw_revocation_watermark",
	"gw_upstream",
	"gw_budget_cap",
	"gw_reservation",
	"gw_reservation_scope",
	// 120 (2026-09-02, G1-RESIDUALS): admin-authored model policy + rate card
	// documents and the per_developer dial-time secret-ref mapping.
	"gw_model_policy",
	"gw_rate_card",
	"gw_upstream_member_credential",
	"gw_audit",
	// Provider-billing reconciliation runs (server migration 117, P6, HG5):
	// imported provider billing reconciled against gw_audit. SERVER-ONLY gateway
	// data, never on the push wire.
	"gw_reconciliation_run",
	// Stateless-collectors + durable-log data plane (server migration 136,
	// docs/plans/stateless-collectors-durable-log-plan-2026-09-08.md §4.3/§4.4).
	// ingest_quarantine holds TERMINATED durable-log records - push envelopes or
	// mapped OTLP batches that the log's consumers (applyworker / sorwriter /
	// otlpapplier) could not apply and parked instead of losing. It is
	// SERVER-ONLY ingest state the node never possesses (the node has no concept
	// of the collector's log, let alone a record that failed to apply on the
	// server), so its name must never appear as a string literal in orgpush.go's
	// push seam. Pinned as a fixed expected-set member by
	// TestForbiddenGatewayTablesExpectedSet.
	"ingest_quarantine",
	// Server-only occurrence fences (migration 137), never node push state.
	"ingest_apply_receipt",
}

// forbiddenOrgControlPlaneTables are SERVER-ONLY P1-4/P1-7/P1-9 control-plane
// tables that must never appear in orgpush.go string literals.
var forbiddenOrgControlPlaneTables = []string{
	"org_intelligence_config",
	"insight_playbook",
	"insight_run",
	"insight_recommendation",
	"org_fleet_upgrade_cohorts",
	"org_fleet_cohort_members",
	"org_fleet_self_telemetry",
	"org_fleet_remote_config",
	"org_fleet_cert_events",
	"org_deployment_wizard",
	"org_deployment_connectors",
	// Plane B mode-switch plane (server migration 114, P5b): the routing-mode
	// singleton, the per-node mode-capability fleet-ACK registry that gates
	// Gateway-Mode activation, and the seven §8 preflight gate results. All
	// SERVER-ONLY — the node never sees the org's activation machinery.
	"org_plane_b_mode",
	"org_plane_b_mode_ack",
	"org_plane_b_preflight",
	// Break-glass credential-lease ledger (server migration 115, P6 §4.2 rung 3).
	// The admin request and the minted per-machine leases are SERVER-ONLY: the
	// LEASE is delivered server->node on the push RESPONSE (orgcontract, not a
	// selected wire row), never built by orgpush.go's node->server SELECT.
	"break_glass_request",
	"break_glass_lease",
	"break_glass_seal_key",
	// Recorded-acceptance ledger (server migration 116, P6, HG10): dated admin
	// acknowledgments of convention-grade enforcement. SERVER-ONLY.
	"org_plane_b_acceptance",
	// org_agent_policy_attributes (server migration 044) is the AUTHORITATIVE
	// per-subject policy-targeting binding: it decides which policy version a
	// node is served, and it exists precisely BECAUSE the node must not be the
	// one asserting those attributes. It is control-plane state the node never
	// possesses, so naming it on the node->server push wire would be both
	// nonsensical and a boundary violation. Pinned as a fixed expected member
	// by TestForbiddenOrgControlPlaneTablesExpectedSet below.
	"org_agent_policy_attributes",
	// The WS3 insight-harness trio (server migration 045). org_llm_provider is
	// the org's registered LLM connections and org_secret holds the SEALED
	// credential bodies those connections resolve — a credential store that the
	// node neither possesses nor may ever be shipped. insight_run_step is the
	// server-side audited step trace of an insight run (which query the agent
	// asked for, which model answered, what it cost). All three are org
	// control-plane state with no agent counterpart, so naming any of them on
	// the node->server push wire would be both nonsensical and a boundary
	// violation. Pinned as fixed expected members by
	// TestForbiddenOrgControlPlaneTablesExpectedSet below.
	"org_llm_provider",
	"org_secret",
	"insight_run_step",
	// Enterprise-Managed Tenancy machine-identity binding (server migration
	// 074, Arc 4 P6a): server-only, and the fingerprint rides the managed-bind
	// REQUEST, never the push wire. Pinned as a fixed expected member by
	// TestForbiddenOrgControlPlaneTablesExpectedSet.
	"managed_node",
	// The managed-integrity probe posture store (server migration 075, Arc 4
	// P6b): server-only, and the integrity signal rides the managed-integrity
	// REQUEST, never the push wire. Same posture as managed_node. Pinned as a
	// fixed expected member by TestForbiddenOrgControlPlaneTablesExpectedSet.
	"managed_integrity",
	// The ACP-P6c IdP device-code enrolment pairing store (server migration
	// 076): server-only, holding the device-code digest and the human-typed
	// user code of an in-flight browser pairing. Both live ONLY on the two
	// agent-facing idp-enrol endpoints, never on the node->server push wire.
	// Same posture as managed_node / managed_integrity. Pinned as a fixed
	// expected member by TestForbiddenOrgControlPlaneTablesExpectedSet.
	"idp_enrol_requests",
	// The fleet remote-config mutation trail (server migration 046). It
	// records WHICH ADMIN changed a collector's remote config, in which org —
	// server-side attribution for a control-plane mutation the node never
	// makes and never sees. Naming it on the node->server push wire would be
	// both nonsensical and a boundary violation. Pinned as a fixed expected
	// member by TestForbiddenOrgControlPlaneTablesExpectedSet below.
	"org_fleet_config_events",
	// The WS2 guided-setup settings store (server migration 047). Its rows
	// hold the org's storage-connection settings and a secretref pointing at a
	// SEALED credential body in org_secret — org control-plane configuration
	// the node neither possesses nor may ever be shipped. Naming it on the
	// node->server push wire would be both nonsensical and a boundary
	// violation. Pinned as a fixed expected member by
	// TestForbiddenOrgControlPlaneTablesExpectedSet below.
	"org_setup_setting",
	// The WS1.4 project display-label store (server migration 048). Rows are
	// ADMIN-AUTHORED display strings for a project hash — org-side naming the
	// node never possesses and must never be asked for. The node ships the
	// hash and only the hash; a seam in orgpush.go that named this table would
	// mean the label had become node data (or, worse, that the wire had grown
	// a raw-path counterpart), which is exactly the inversion the hash posture
	// exists to prevent. Pinned as a fixed expected member by
	// TestForbiddenOrgControlPlaneTablesExpectedSet below.
	"org_project_labels",
	// The dashboard-registered external harness agent registry (server
	// migration 049). Rows are org control-plane configuration (an admin's
	// choice of which pre-placed binary answers an agent id) with no agent
	// counterpart — the node never registers, resolves, or executes these,
	// it only ever sees the resulting "external:<id>" agent id the same way
	// it would a TOML entry. Naming it on the node->server push wire would be
	// both nonsensical and a boundary violation. Pinned as a fixed expected
	// member by TestForbiddenOrgControlPlaneTablesExpectedSet below.
	"org_external_agent",
	// Datasets foundation (server migration 051, wave item B): reference-only
	// trace/span membership for evals and experiments. Org control-plane
	// state with no agent counterpart — the node neither builds nor reads
	// datasets. Pinned as fixed expected members below.
	"org_dataset",
	"org_dataset_item",
	// LLM job runner + annotations (server migration 052, wave items C/D):
	// deterministic single-shot job state and metadata-class trace labels,
	// org control-plane only — the node never runs or reads these.
	"org_trace_annotation",
	"org_llm_job",
	"org_llm_job_item",
	// Guardrailed chat (server migration 053, wave item F): chat transcripts
	// and proposal state are org control-plane content with no agent
	// counterpart — the node never sees the assistant conversation.
	"org_chat_session",
	"org_chat_message",
	// Plane-B admin intelligence (server migrations 057-059 + the P2 harness
	// trio reserved by the spec's §2.3 nine-table pin;
	// docs/plans/plane-b-admin-intelligence-and-enforcement-spec-2026-08-15.md).
	// All are org control-plane state with no agent counterpart: the coding
	// intelligence config document, session-referencing dataset membership,
	// the single-shot job runner's state, session annotations, and the
	// Plane-B playbook/run tables. The node never builds, runs, or reads any
	// of them; naming one on the node->server push wire would be a boundary
	// violation. The content-adjacent trio (job, job_item, annotation) is
	// additionally pinned as fixed expected members below.
	"org_coding_intel_config",
	"org_coding_dataset",
	"org_coding_dataset_item",
	"org_coding_job",
	"org_coding_job_item",
	"org_coding_annotation",
	"org_coding_playbook",
	"org_coding_run",
	"org_coding_run_step",
	// Self-Improving Policy Plane P0 (server migrations 061-065;
	// docs/plans/self-improving-policy-evolution-p0-build-plan-2026-08-16.md).
	// All five are org control-plane state with no agent counterpart: the
	// per-(org,family,target) evolution config, the review-run ledger, the
	// candidate-proposal store (proposed_body + LLM-authored rationale), the
	// hash-chained approve/reject audit, and the manual-Apply outcome record.
	// The node never builds, runs, or reads any of them; naming one on the
	// node->server push wire would be a boundary violation. The two
	// content-bearing tables (proposal, decision — where LLM-authored text
	// lands) are additionally pinned as fixed expected members below.
	"org_policy_evolution_config",
	"org_policy_evolution_run",
	"org_policy_evolution_proposal",
	"org_policy_evolution_decision",
	"org_policy_evolution_applied",
	// Team Project Identity Mapping Wave B (server migration 083;
	// docs/plans/team-project-identity-mapping-plan-2026-08-21.md §1 L2/L4).
	// org_projects is the admin-authored team-level project identity (name +
	// client_label); org_project_members maps many project_root_hash-derived
	// ids onto one org_projects row. Both are org-side grouping/naming data
	// layered on top of the hash the node already ships — naming either on
	// the node->server push wire would be both nonsensical and a boundary
	// violation, the same posture as org_project_labels (048) above.
	"org_projects",
	"org_project_members",
	// Org Dashboard RBAC Wave A (server migration 084;
	// docs/plans/org-dashboard-rbac-plan-2026-08-21.md §1, §5 Wave A).
	// org_roles/org_role_permissions/org_member_roles are the role/
	// permission model (who may see which slice of the org's already-pushed
	// data), and org_role_bootstrap_applied is the bootstrap-marker gating
	// the one-time builtin-permission seed and the config-email member-role
	// backfill. All four are pure org-server authorization state with no
	// agent counterpart — the node never builds, grants, or reads roles or
	// permissions; naming any of them on the node->server push wire would be
	// both nonsensical and a boundary violation, the same posture as
	// org_project_labels (048) / org_projects (083) above.
	"org_roles",
	"org_role_permissions",
	"org_member_roles",
	"org_role_bootstrap_applied",
	// Pre-045-convention control-plane tables (C1 fix wave, slice A). These
	// predate the migration-file-comment convention the entries above follow,
	// but are the same posture: server-only state the node never possesses.
	// budgets/budget_alert_events (server migrations 002 base +
	// 080_budgets_multilevel widen) are the org-authored spend caps and the
	// evaluator's threshold-crossing audit trail — the node has no budget
	// concept and never fires an alert itself. issued_bearers/revoked_bearers
	// (server migration 001/002) are the bearer-token mint/revoke ledger — a
	// credential store, never shipped. enrolment_tokens (server migration
	// 001) and invite_attempts (server migration 024) are the enrolment/
	// invite rails' own state (who was offered a token, who attempted an
	// invite) — org control-plane bookkeeping about the node, not data from
	// it.
	"budgets",
	"budget_alert_events",
	"issued_bearers",
	"revoked_bearers",
	"enrolment_tokens",
	"invite_attempts",
	// Evals plane versioning/scheduling (server migrations 082_org_eval_run +
	// 085_org_eval_versioning_scheduling). org_eval_run/org_eval_score are the
	// eval-run ledger and its per-item scores; org_eval_run_item/
	// org_eval_schedule (085) added per-run item detail and the recurring-
	// schedule config. All four are org control-plane eval state with no
	// agent counterpart — the node never runs, schedules, or scores an eval.
	"org_eval_run",
	"org_eval_score",
	"org_eval_run_item",
	"org_eval_schedule",
	// Product-posture plane (server migration 112, P2b). org_product_posture
	// is the teams|enterprise singleton + fleet replacement generation;
	// org_grant_replacement is the signed grant-replacement issuance ledger;
	// org_grant_replacement_ack is the per-node fleet-ACK registry that gates
	// enterprise activation; org_collection_settings is the org-side per-
	// share-tier collection toggle. All four are org control-plane state with
	// no agent counterpart -- the node never issues a replacement, records a
	// fleet ACK server-side (it reports its own via a push HEADER, never a
	// wire row), or authors collection toggles. Pinned as fixed expected
	// members by TestForbiddenOrgControlPlaneTablesExpectedSet below.
	"org_product_posture",
	"org_grant_replacement",
	"org_grant_replacement_ack",
	"org_collection_settings",
	// Project Identity Resolver v2 server-only tables (server migration 122,
	// docs/plans/project-identity-resolver-v2-plan-2026-09-06.md §3.3/§3.4).
	// project_identity_signals is the materialized per-project identity
	// bundle (ingest-writer, replaces the per-read loadProjectOrigins scan);
	// org_repositories is the canonical-repo table keyed by remote hash;
	// org_project_rules is the admin's permanent assign/exclude rule ledger;
	// org_identity_settings holds the admin-authored enterprise owner
	// prefixes + auto-apply threshold. All four are server-side resolver
	// state with no agent counterpart — the node never builds, runs, or
	// reads any of them; naming one on the node->server push wire would be
	// both nonsensical and a boundary violation, the same posture as
	// org_project_labels/048 and org_projects/083 above.
	"project_identity_signals",
	"org_repositories",
	"org_project_rules",
	"org_identity_settings",
	// Org budget enforcement + token display server-only tables (server
	// migration 125, docs/plans/org-budget-enforcement-and-token-display-
	// plan-2026-09-07.md §3.1). org_display_settings holds the admin's
	// cosmetic cost_display / tokens_percent_scope choice (rendering only —
	// it changes nothing stored, computed, pushed or enforced);
	// org_budget_policy_version is the per-org counter the agent
	// budget-policy endpoint serves as an ETag. Both are admin/server
	// authored with no agent counterpart — the node RECEIVES budget policy on
	// the agent policy rail, it never PUSHES a budget row — so naming either
	// on the node->server push wire would be both nonsensical and a boundary
	// violation, the same posture as org_identity_settings/122 above.
	"org_display_settings",
	"org_budget_policy_version",
	// Enterprise Update Management server-only tables (server migration 127,
	// docs/plans/enterprise-update-management-plan-2026-09-07.md §3.3).
	// org_update_manifests is the signed publication registry served on the
	// bearer-gated agent rail; org_update_artifacts is the mirror's index of
	// artifact bytes on the SERVER's own disk; org_update_rollouts is the ring
	// ledger the shared rollout engine drives; org_node_versions is the node
	// inventory board upserted at INGEST from the envelope the node pushed.
	// The direction is what matters: a node RECEIVES a manifest and FETCHES
	// bytes, and its only contribution is the enum-only UpdatePosture field on
	// the push ENVELOPE — never a selected wire row. So naming any of these
	// four in internal/store/orgpush.go would be both nonsensical and a
	// boundary violation, the same posture as org_budget_policy_version/125
	// above.
	"org_update_manifests",
	"org_update_artifacts",
	"org_update_rollouts",
	"org_node_versions",
	// The node BUDGET posture board (server migration 130, gap
	// G1-BUDGET-POSTURE). It is upserted at INGEST from the enum-only
	// budget_posture field on the push ENVELOPE, exactly as org_node_versions
	// is from update_posture: the node's contribution is an envelope field,
	// never a selected wire row, so naming this table in
	// internal/store/orgpush.go would be both nonsensical and a boundary
	// violation.
	"org_node_budget_posture",
	// Org Dashboard Enterprise Sign-In server-only tables (server migration
	// 128, docs/plans/org-enterprise-sign-in-plan-2026-09-07.md §3.6).
	// org_auth_settings is the dashboard-editable identity singleton (enabled
	// rails, session policy, the org-wide sign-out epoch, ruling R8's
	// provisioning allow-list, the M3 seed marker); org_auth_rail_setting is
	// the per-rail key/value store and is the LOAD-BEARING one -- it is the
	// table carrying secret_ref, so a `store:` reference into the SEALED
	// org_secret body lives here; org_auth_group_role_map is the IdP-group ->
	// role rule set; org_auth_failures is the failed-sign-in counter keyed by
	// attempted email. All four are the configuration of a DASHBOARD HUMAN
	// session, a thing the node has no concept of and can neither produce nor
	// consume, so naming any of them in internal/store/orgpush.go would be
	// both nonsensical and a boundary violation -- the same posture as
	// org_setup_setting/047, whose shape org_auth_rail_setting copies.
	"org_auth_settings",
	"org_auth_rail_setting",
	"org_auth_group_role_map",
	"org_auth_failures",
	// Enterprise pricing server-only tables (server migration 132,
	// docs/plans/enterprise-pricing-and-admin-assistant-plan-2026-09-08.md
	// §3.1). org_model_prices is the org's ONE authored per-model price table
	// and org_pricing_version its monotonic document version. Both are
	// ADMIN-AUTHORED on the server and travel server -> node on a signed
	// policy rail (GET /api/agent/pricing, W2): the node RECEIVES prices, it
	// never PUSHES one, so naming either on the node -> server push wire would
	// be both nonsensical and a boundary violation — the same posture as
	// org_budget_policy_version/125 above. Pinned as fixed expected members by
	// TestForbiddenOrgControlPlaneTablesExpectedSet.
	"org_model_prices",
	"org_pricing_version",
	// org_pricing_feed_state is the pricing-FEED importer's server-side
	// bookkeeping (server migration 144): the last feed version/digest the
	// leader-only importer saw and the parked diff awaiting approval. It is
	// control-plane (it drives writes to org_model_prices through the same
	// handle) and purely server-side — the node RECEIVES feed-fed prices on the
	// signed GET /api/agent/pricing rail, it never pushes this. Pinned as a
	// fixed expected member by TestForbiddenOrgControlPlaneTablesExpectedSet.
	"org_pricing_feed_state",
	// control_schema_data_applied is the Postgres-only ONE-SHOT marker for the
	// DATA retrofits in controlstore/schema.go (that file is replayed on every
	// server start, so a data statement needs a marker or it runs forever). It
	// is server-side bookkeeping about the control schema itself: the node has
	// no concept of it, so naming it in internal/store/orgpush.go would be both
	// nonsensical and a boundary violation. Pinned as a fixed expected member
	// by TestForbiddenOrgControlPlaneTablesExpectedSet.
	"control_schema_data_applied",
}

// TestForbiddenOrgControlPlaneTablesExpectedSet is the NON-GAMEABLE membership
// pin for the org control-plane sentinel, mirroring
// TestForbiddenGatewayTablesExpectedSet. Merely APPENDING a name to
// forbiddenOrgControlPlaneTables is trivially removable without any test
// failing, which would silently stop TestSelectUnpushedSinceExcludesCacheTables
// from guarding that name out of orgpush.go. A FIXED expected subset must
// therefore remain present: deleting any of these names fails HERE, by name.
func TestForbiddenOrgControlPlaneTablesExpectedSet(t *testing.T) {
	want := []string{
		"org_agent_policy_attributes",
		"org_intelligence_config",
		"org_fleet_upgrade_cohorts",
		"org_fleet_remote_config",
		"org_deployment_wizard",
		// WS3 insight harness (server migration 045). org_secret in particular
		// is a SEALED CREDENTIAL store: dropping it from the sentinel would
		// stop the orgpush.go guard from ever noticing a seam that named it.
		"org_llm_provider",
		"org_secret",
		"insight_run_step",
		// Fleet mutation attribution (server migration 046): the audit trail
		// of who reconfigured which collector. Server-only control-plane
		// state with no agent counterpart.
		"org_fleet_config_events",
		// WS2 guided setup (server migration 047): the settings store whose
		// secret_ref column points at a SEALED org_secret body. Dropping it
		// from the sentinel would stop the orgpush.go guard from ever noticing
		// a seam that named it.
		"org_setup_setting",
		// WS1.4 project labels (server migration 048): org-side display names
		// for hashed project identities. Dropping it from the sentinel would
		// stop the orgpush.go guard from noticing a seam that tried to carry
		// project naming — in either direction — on the agent wire.
		"org_project_labels",
		// Dashboard-registered external harness agents (server migration
		// 049): org control-plane configuration with no agent counterpart.
		// Dropping it from the sentinel would stop the orgpush.go guard from
		// noticing a seam that named it.
		"org_external_agent",
		// Datasets foundation (server migration 051): dataset membership is
		// org-side only; dropping these would stop the guard from noticing a
		// seam that tried to carry dataset state on the agent wire.
		"org_dataset",
		"org_dataset_item",
		// LLM jobs + annotations (server migration 052): job/annotation
		// state stays org-side; dropping these would stop the guard from
		// noticing a seam that named them.
		"org_trace_annotation",
		"org_llm_job",
		"org_llm_job_item",
		// Guardrailed chat (server migration 053): transcripts stay
		// org-side; dropping these would stop the guard from noticing a
		// seam that named them.
		"org_chat_session",
		"org_chat_message",
		// Plane-B admin intelligence (server migrations 057-059): the
		// content-adjacent trio — job state, per-item results, and session
		// annotations are the rows an LLM's output lands in. Dropping any of
		// them from the sentinel would stop the orgpush.go guard from
		// noticing a seam that named them.
		"org_coding_job",
		"org_coding_job_item",
		"org_coding_annotation",
		// Self-Improving Policy Plane P0 (server migrations 061-065): the
		// content-bearing pair. org_policy_evolution_proposal holds the
		// candidate proposed_body + LLM-authored rationale, and
		// org_policy_evolution_decision holds the approve/reject reason —
		// the rows an LLM's output lands in. Dropping either from the
		// sentinel would stop the orgpush.go guard from noticing a seam
		// that named them.
		"org_policy_evolution_proposal",
		"org_policy_evolution_decision",
		// Enterprise-Managed Tenancy machine-identity binding (server
		// migration 074, Arc 4 P6a). managed_node binds one managed node to
		// one machine; the fingerprint rides the bearer-authed managed-bind
		// REQUEST, never the node->server push wire, so naming it in
		// orgpush.go would be both nonsensical and a boundary violation.
		"managed_node",
		// The managed-integrity probe posture store (server migration 075,
		// Arc 4 P6b). managed_integrity records per-(org, machine)
		// tamper-evidence; the signal rides the bearer-authed
		// managed-integrity REQUEST, never the node->server push wire. Same
		// boundary as managed_node.
		"managed_integrity",
		// The IdP device-code enrolment pairing store (server migration 076,
		// ACP-P6c). idp_enrol_requests holds the device-code digest and the
		// user code of an in-flight pairing — enrolment-credential-adjacent
		// material that rides the two agent-facing idp-enrol REQUESTS, never
		// the node->server push wire. Dropping it from the sentinel would stop
		// the orgpush.go guard from noticing a seam that named it.
		"idp_enrol_requests",
		// Team Project Identity Mapping Wave B (server migration 083): the
		// admin-authored project-grouping pair. org_projects names a team-
		// level project identity (with an optional client_label);
		// org_project_members maps hash-derived ids onto it. Dropping either
		// from the sentinel would stop the orgpush.go guard from noticing a
		// seam that tried to carry project grouping/naming on the agent wire.
		"org_projects",
		"org_project_members",
		// Org Dashboard RBAC Wave A (server migration 084): the role/
		// permission model (org_roles, org_role_permissions,
		// org_member_roles) plus its bootstrap-marker
		// (org_role_bootstrap_applied). Dropping any of these from the
		// sentinel would stop the orgpush.go guard from noticing a seam that
		// tried to carry role/permission grant state on the agent wire.
		"org_roles",
		"org_role_permissions",
		"org_member_roles",
		"org_role_bootstrap_applied",
		// Product-posture plane (server migration 112, P2b): the posture
		// singleton, the signed grant-replacement issuance ledger, the per-node
		// fleet-ACK registry, and the org-side collection toggle. Dropping any of
		// these from the sentinel would stop the orgpush.go guard from noticing a
		// seam that named them.
		"org_product_posture",
		"org_grant_replacement",
		"org_grant_replacement_ack",
		"org_collection_settings",
		// Plane B mode-switch plane (server migration 114, P5b).
		"org_plane_b_mode",
		"org_plane_b_mode_ack",
		"org_plane_b_preflight",
		// Break-glass credential-lease ledger (server migration 115, P6).
		"break_glass_request",
		"break_glass_lease",
		// Recorded-acceptance ledger (server migration 116, P6, HG10).
		"org_plane_b_acceptance",
		// Project Identity Resolver v2 server-only tables (server migration
		// 122). Dropping any of these from the sentinel would stop the
		// orgpush.go guard from noticing a seam that named them.
		"project_identity_signals",
		"org_repositories",
		"org_project_rules",
		"org_identity_settings",
		// Org budget enforcement + token display server-only tables (server
		// migration 125). Dropping either from the sentinel would stop the
		// orgpush.go guard from noticing a seam that named them.
		"org_display_settings",
		"org_budget_policy_version",
		// Enterprise Update Management server-only tables (server migration
		// 127). Dropping any of these from the sentinel would stop the
		// orgpush.go guard from noticing a seam that named them.
		"org_update_manifests",
		"org_update_artifacts",
		"org_update_rollouts",
		"org_node_versions",
		// The node budget posture board (server migration 130). Dropping it
		// from the sentinel would stop the orgpush.go guard from noticing a
		// seam that named it.
		"org_node_budget_posture",
		// Org Dashboard Enterprise Sign-In server-only tables (server
		// migration 128). org_auth_rail_setting in particular carries
		// secret_ref, pointing at a SEALED org_secret body: dropping it from
		// the sentinel would stop the orgpush.go guard from ever noticing a
		// seam that named it.
		"org_auth_settings",
		"org_auth_rail_setting",
		"org_auth_group_role_map",
		"org_auth_failures",
		// Enterprise pricing server-only tables (server migration 132). The
		// org's authored per-model rates and their monotonic document
		// version: authored on the SERVER and distributed server -> node on a
		// signed rail, never pushed. Dropping either from the sentinel would
		// stop the orgpush.go guard from noticing a seam that named them.
		"org_model_prices",
		"org_pricing_version",
		// The pricing-FEED importer bookkeeping (server migration 144):
		// control-plane, server-side only, distributed to nodes only on the
		// signed pricing rail — never pushed node -> server.
		"org_pricing_feed_state",
		// The Postgres-only one-shot DATA marker for controlstore/schema.go's
		// retrofits: server-side bookkeeping the node has no concept of.
		"control_schema_data_applied",
	}
	have := make(map[string]struct{}, len(forbiddenOrgControlPlaneTables))
	for _, n := range forbiddenOrgControlPlaneTables {
		have[n] = struct{}{}
	}
	for _, w := range want {
		if _, ok := have[w]; !ok {
			t.Errorf("expected server-side control-plane table %q is missing from forbiddenOrgControlPlaneTables — "+
				"the privacy sentinel would no longer guard it out of orgpush.go", w)
		}
	}
}

// TestForbiddenGatewayTablesExpectedSet is the NON-GAMEABLE membership pin: a
// FIXED expected set (gateway_wal + the four gateway ingest tables the P1-2/P1-10
// retention tier touches) must be a SUBSET of forbiddenGatewayTables. Merely
// APPENDING a name is removable without a failure (the original TestGatewayWAL…
// only checked gateway_wal), so REMOVING any of these names from
// forbiddenGatewayTables fails HERE — which in turn would stop
// TestSelectUnpushedSinceExcludesCacheTables from guarding that name in
// orgpush.go. Mut 10 (drop gateway_span from forbiddenGatewayTables) fails this
// assertion by name.
func TestForbiddenGatewayTablesExpectedSet(t *testing.T) {
	want := []string{
		"gateway_wal",
		"gateway_resource",
		"gateway_scope",
		"gateway_span",
		"gateway_trace",
		// Plane B AI Gateway v1 (server migrations 108-111): removing any of
		// these from forbiddenGatewayTables fails HERE, which in turn would stop
		// TestSelectUnpushedSinceExcludesCacheTables from guarding the name out
		// of orgpush.go.
		"gw_virtual_key",
		"gw_revocation_watermark",
		"gw_upstream",
		"gw_budget_cap",
		"gw_reservation",
		"gw_reservation_scope",
		"gw_audit",
		// Stateless-collectors durable-log terminal-quarantine table (server
		// migration 136): removing it from forbiddenGatewayTables fails HERE,
		// which in turn would stop TestSelectUnpushedSinceExcludesCacheTables
		// from guarding the name out of orgpush.go.
		"ingest_quarantine",
		"ingest_apply_receipt",
	}
	have := make(map[string]struct{}, len(forbiddenGatewayTables))
	for _, n := range forbiddenGatewayTables {
		have[n] = struct{}{}
	}
	for _, w := range want {
		if _, ok := have[w]; !ok {
			t.Errorf("expected server-side gateway table %q is missing from forbiddenGatewayTables — "+
				"the privacy sentinel would no longer guard it out of orgpush.go", w)
		}
	}
}

// TestGatewayWALPinnedOutOfPush pins gateway_wal (server migration 032, Plane-A
// P0-9 durable-edge WAL) at the source level: its name is in the
// forbiddenGatewayTables sentinel, so TestSelectUnpushedSinceExcludesCacheTables
// fails the build if it ever appears as a string literal in orgpush.go. There is
// no end-to-end seed arm because the table lives in the ORG SERVER's DB, not the
// agent store the push seam reads — the source-level pin is the guarantee.
func TestGatewayWALPinnedOutOfPush(t *testing.T) {
	found := false
	for _, n := range forbiddenGatewayTables {
		if n == "gateway_wal" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("gateway_wal is not in forbiddenGatewayTables — the source-level sentinel is missing")
	}
}

// TestGuardPromptReconsiderPinnedOutOfPush pins the prompt-submit
// intervention's "reconsider-once" grant table (migration 110, F6
// round-2 review) out of the org-push wire two ways: (1) the table
// name is in the forbidden-name sentinel set (so
// TestSelectUnpushedSinceExcludesCacheTables fails the build if it
// ever appears as a string literal in orgpush.go), and (2) an
// end-to-end assertion that a seeded guard_prompt_reconsider row never
// crosses the wire — even under full_content (maximum disclosure
// surface). Unlike remote_audit (which DOES ship under full_content
// via a dedicated composed slice), this table has NO wire
// representation at all, by design (same posture as limit_snapshots /
// cache_segments) — so the assertion is simply "this canary never
// appears anywhere in the marshaled batch."
func TestGuardPromptReconsiderPinnedOutOfPush(t *testing.T) {
	// (1) name pinned in the sentinel set.
	found := false
	for _, n := range forbiddenCacheTables {
		if n == "guard_prompt_reconsider" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("guard_prompt_reconsider is not in forbiddenCacheTables — the source-level sentinel is missing")
	}

	// (2) end-to-end: a seeded guard_prompt_reconsider row never rides
	// the wire, even under full_content.
	const secGPR = "SECRET_GUARDPROMPTRECONSIDER_grandiloquent_zz"
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)

	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	if err := st.RecordPromptWarned(ctx, store.PromptReconsiderRow{
		Fingerprint: secGPR,
		SessionID:   secGPR,
		Tool:        secGPR,
		Detectors:   secGPR,
		WarnedAt:    now,
		ExpiresAt:   now.Add(30 * time.Minute),
	}); err != nil {
		t.Fatalf("RecordPromptWarned: %v", err)
	}

	batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@x",
		store.ShareOptions{FullContent: true}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}
	if bytes.Contains(raw, []byte(secGPR)) {
		t.Error("guard_prompt_reconsider content leaked onto the org-push wire under full_content")
	}
}

// TestRemoteAuditTablePinnedOutOfPush pins the remote-access audit log
// (migration 063, remote-dashboard-access plan §4.8) out of the org-push wire
// two ways: (1) the table name is in the forbidden-name sentinel set (so
// TestSelectUnpushedSinceExcludesCacheTables fails the build if it ever appears
// as a string literal in orgpush.go), and (2) an end-to-end assertion that a
// seeded remote_audit row never crosses the wire — even under full_content
// (maximum disclosure surface). The row carries no *_hash counterpart because
// it is never pushed at all.
func TestRemoteAuditTablePinnedOutOfPush(t *testing.T) {
	// (1) name pinned in the sentinel set.
	found := false
	for _, n := range forbiddenCacheTables {
		if n == "remote_audit" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("remote_audit is not in forbiddenCacheTables — the source-level sentinel is missing")
	}

	// (2) end-to-end: a seeded remote_audit row never rides the wire.
	const secRemoteAudit = "SECRET_REMOTEAUDIT_grandiloquent_zz"
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)

	if err := st.InsertRemoteAudit(ctx, store.RemoteAuditEvent{
		Kind: "session_paired", SessionID: secRemoteAudit, Principal: "view",
		RemoteAddr: secRemoteAudit, Route: "/api/remote/pair", Decision: "ok",
		Detail: secRemoteAudit,
	}); err != nil {
		t.Fatalf("InsertRemoteAudit: %v", err)
	}
	// Also seed the Phase-4 execute-tier audit kinds (writer-lease + terminal-
	// control lifecycle) — new kinds ride the SAME node-local table, so the
	// table-level exclusion must still hold with a canary in every column.
	for _, k := range []string{
		"terminal_writer_acquire", "terminal_writer_release", "terminal_writer_revoke",
		"terminal_local_takeover", "terminal_remote_takeover",
		"terminal_control_local_approval", "terminal_control_request",
		"terminal_control_capability_consume", "terminal_control_denied", "terminal_denied_frame",
	} {
		if err := st.InsertRemoteAudit(ctx, store.RemoteAuditEvent{
			Kind: k, SessionID: secRemoteAudit, Principal: "execute",
			RemoteAddr: secRemoteAudit, Route: secRemoteAudit, Decision: "ok",
			Detail: secRemoteAudit,
		}); err != nil {
			t.Fatalf("InsertRemoteAudit(%s): %v", k, err)
		}
	}

	// TEAMS posture (zero-value, metadata-only): remote_audit ships nothing.
	teams, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@x",
		store.ShareOptions{}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince (teams): %v", err)
	}
	rawTeams, err := json.Marshal(teams)
	if err != nil {
		t.Fatalf("marshal teams batch: %v", err)
	}
	if bytes.Contains(rawTeams, []byte(secRemoteAudit)) {
		t.Error("remote_audit content leaked under metadata-only — the teams tier must never push it")
	}

	// ENTERPRISE posture (org-parity W2.6, plan §0 — deliberate reversal of
	// the pre-2026-08-24 "never pushed" pin): under full_content /
	// admin_managed the remote-access audit DOES ship, via the composed
	// SelectRemoteAuditRows seam (orgpush.go still never names the table).
	// The sentinel's remaining job: it ships ONLY in that slice.
	batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@x",
		store.ShareOptions{FullContent: true}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	if len(batch.RemoteAudit) == 0 {
		t.Error("full_content shipped no remote-audit rows — the W2.6 enterprise wire failed to flip")
	}
	batch.RemoteAudit = nil
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}
	if bytes.Contains(raw, []byte(secRemoteAudit)) {
		t.Error("remote_audit content leaked OUTSIDE the RemoteAudit slice — only the composed wire may carry it")
	}
}

// TestTerminalRunTablesPinnedOutOfPush pins the terminal-run identity tables
// (migration 064, terminal-product-exploitation plan §2.1a / §7) out of the
// org-push wire two ways: (1) both table names are in the forbidden-name
// sentinel set (so TestSelectUnpushedSinceExcludesCacheTables fails the build if
// either appears as a string literal in orgpush.go), and (2) an end-to-end
// assertion that a seeded terminal_run + terminal_run_session row never crosses
// the wire — even under full_content (maximum disclosure surface). The rows
// carry no *_hash counterpart because they are never pushed at all.
func TestTerminalRunTablesPinnedOutOfPush(t *testing.T) {
	// (1) both names pinned in the sentinel set.
	for _, name := range []string{"terminal_run", "terminal_run_session", "terminal_commands"} {
		found := false
		for _, n := range forbiddenCacheTables {
			if n == name {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s is not in forbiddenCacheTables — the source-level sentinel is missing", name)
		}
	}

	// (2) end-to-end: a seeded terminal-run row never rides the wire.
	const secTermRun = "SECRET_TERMRUN_pusillanimous_zz"
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)

	if err := st.InsertTerminalRun(ctx, store.TerminalRun{
		RunID: secTermRun, Tool: secTermRun, Kind: "handoff",
		SourceSessionID: secTermRun, ProjectRootHash: secTermRun,
		CorrelationTokenHash: secTermRun,
	}); err != nil {
		t.Fatalf("InsertTerminalRun: %v", err)
	}
	if err := st.UpsertCorrelation(ctx, store.TerminalCorrelation{
		RunID: secTermRun, SessionID: secTermRun, Confidence: 0.95, Source: "oob",
	}); err != nil {
		t.Fatalf("UpsertCorrelation: %v", err)
	}
	if err := st.InsertTerminalCommand(ctx, store.TerminalCommand{
		RunID: secTermRun, TurnSeq: 1, Trust: "hint", CmdHash: secTermRun,
	}); err != nil {
		t.Fatalf("InsertTerminalCommand: %v", err)
	}

	// TEAMS posture (zero-value, metadata-only): nothing terminal-shaped ships.
	teams, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@x",
		store.ShareOptions{}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince (teams): %v", err)
	}
	rawTeams, err := json.Marshal(teams)
	if err != nil {
		t.Fatalf("marshal teams batch: %v", err)
	}
	if bytes.Contains(rawTeams, []byte(secTermRun)) {
		t.Error("terminal_run content leaked under metadata-only — the teams tier must never push it")
	}

	// ENTERPRISE posture (org-parity W2.6, plan §0 — deliberate reversal of
	// the pre-2026-08-24 "never pushed" pin): under full_content /
	// admin_managed the per-dev terminal visibility wire DOES ship, via the
	// composed SelectTerminalRunRows/SelectTerminalCommandRows seam
	// (orgpush.go still never names the tables — part (1) above stays the
	// source-level guard). Remaining job: it ships ONLY in those slices.
	batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@x",
		store.ShareOptions{FullContent: true}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	if len(batch.TerminalRuns) == 0 {
		t.Error("full_content shipped no terminal runs — the W2.6 enterprise wire failed to flip")
	}
	batch.TerminalRuns, batch.TerminalCommands = nil, nil
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}
	if bytes.Contains(raw, []byte(secTermRun)) {
		t.Error("terminal_run content leaked OUTSIDE the terminal wire slices — only the composed wire may carry it")
	}
}

// TestSessionClassificationPinnedOutOfPush pins the session-classification
// tables (migration 075, plan §1) out of the org-push wire two ways: (1) both
// table names are in the forbidden-name sentinel set (so
// TestSelectUnpushedSinceExcludesCacheTables fails the build if either ever
// appears as a string literal in orgpush.go), and (2) an end-to-end assertion
// that a seeded tag AND a seeded note never cross the wire — even under
// full_content, the maximum disclosure surface. The rows carry no *_hash
// counterpart because they are never pushed at all.
//
// PROOF SCOPE — what this test does and does not establish. It proves absence
// from the CURRENT SelectUnpushedSince payload (one seeded canary tag + note on
// a session the push actually visits, marshalled and byte-searched) and it
// proves the source-level sentinel covers both table names inside orgpush.go.
// It does NOT prove the tables are unreachable by any future egress path: a new
// wire-building query added ELSEWHERE — a second push seam, an export handler,
// an org-side pull — would not be caught here. That case is held by CONVENTION,
// not by this test: the single-SQL-seam rule (CLAUDE.md "Teams / org-server
// invariants" — SelectUnpushedSince is the only place wire rows are built) plus
// the review requirement that any new content-bearing wire column be gated at
// that seam AND added to the sentinel set. Widening egress therefore requires
// touching the one file this test watches; a reviewer who accepts a second seam
// has stepped outside what any of these invariants can see.
func TestSessionClassificationPinnedOutOfPush(t *testing.T) {
	// (1) both names pinned in the sentinel set.
	for _, name := range []string{"session_tags", "session_annotations"} {
		found := false
		for _, n := range forbiddenCacheTables {
			if n == name {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s is not in forbiddenCacheTables — the source-level sentinel is missing", name)
		}
	}

	// (2) end-to-end: a seeded tag + note never ride the wire. The tag must
	// survive NormalizeTag's charset, so the canary is lowercase/hyphenated —
	// exactly the shape a real client codename would take.
	const (
		secTag   = "secret-sessiontag-obstreperous-zz"
		secNote  = "SECRET_SESSIONNOTE_obstreperous_zz"
		secTitle = "SECRET_SESSIONTITLE_obstreperous_zz"
	)
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)

	// Tag a session that DOES ride the wire, so the exclusion is proven for a
	// row the push actually visits — not merely for an orphan id.
	if err := st.MutateSessionTags(ctx, "sess-cc-1", []string{secTag}, nil); err != nil {
		t.Fatalf("MutateSessionTags: %v", err)
	}
	fav := true
	note := secNote
	rating := 9       // the overall rating (migration 080) rides the same node-local row.
	title := secTitle // the developer's own session title (migration 116) rides the same node-local row.
	if err := st.SetSessionAnnotation(ctx, "sess-cc-1", &fav, &note, &rating, &title); err != nil {
		t.Fatalf("SetSessionAnnotation: %v", err)
	}

	// Full-content = maximum surface; the classification tables must STILL be
	// absent.
	batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@x",
		store.ShareOptions{FullContent: true}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}
	if bytes.Contains(raw, []byte(secTag)) {
		t.Error("session_tags content leaked into the push payload — the table must never be pushed")
	}
	if bytes.Contains(raw, []byte(secNote)) {
		t.Error("session_annotations note leaked into the push payload — the table must never be pushed")
	}
	if bytes.Contains(raw, []byte(secTitle)) {
		t.Error("session_annotations title leaked into the push payload — the table must never be pushed")
	}

	// The same must hold under admin_managed, which deliberately flips the
	// OTHER content-bearing columns raw (CLAUDE.md native-console carve-out).
	batch, err = st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@x",
		store.ShareOptions{AdminManaged: true}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince(admin_managed): %v", err)
	}
	raw, err = json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal admin_managed batch: %v", err)
	}
	if bytes.Contains(raw, []byte(secTag)) || bytes.Contains(raw, []byte(secNote)) || bytes.Contains(raw, []byte(secTitle)) {
		t.Error("session classification leaked under admin_managed — the tables are node-local under EVERY share mode")
	}
}

// TestPolicyResourceTablesPinnedOutOfPush pins the Plane-A P0-5 unified
// policy resource tables (migration 081, plan §6.2/§6.9/§6.10) out of the
// org-push wire two ways: (1) both table names are in the forbidden-name
// sentinel set (so TestSelectUnpushedSinceExcludesCacheTables fails the
// build if either appears as a string literal in orgpush.go), and (2) an
// end-to-end assertion that seeded rows in both tables never cross the wire
// — even under full_content, the maximum disclosure surface. The rows carry
// no *_hash counterpart because they are never pushed at all.
func TestPolicyResourceTablesPinnedOutOfPush(t *testing.T) {
	// (1) both names pinned in the sentinel set.
	for _, name := range []string{"org_enrolment_generation", "org_policy_resource_state"} {
		found := false
		for _, n := range forbiddenCacheTables {
			if n == name {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s is not in forbiddenCacheTables — the source-level sentinel is missing", name)
		}
	}

	// (2) end-to-end: seeded generation + state rows never ride the wire.
	const secOrgKey = "secret-orgkey-perspicacious-zz"
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)

	if _, err := st.BumpEnrolmentGeneration(ctx, secOrgKey, false); err != nil {
		t.Fatalf("BumpEnrolmentGeneration: %v", err)
	}
	err = st.WithPolicyResourceFence(ctx, secOrgKey, "admission.input", func(_ context.Context, fence store.PolicyResourceFence) (*store.PolicyResourceCommit, error) {
		return &store.PolicyResourceCommit{
			Generation: fence.Generation, FloorVersion: 1, LastVersion: 1,
			BodyHash: secOrgKey, MsgDigest: secOrgKey,
		}, nil
	})
	if err != nil {
		t.Fatalf("WithPolicyResourceFence: %v", err)
	}

	batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@x",
		store.ShareOptions{FullContent: true}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}
	if bytes.Contains(raw, []byte(secOrgKey)) {
		t.Error("policy-resource state leaked into the push payload — the tables must never be pushed")
	}
}

// TestCloudLocalTablesPinnedOutOfPush is the STRENGTHENED cloud privacy
// sentinel (CI-P2 Lane D / Sol SB3, plan §6 CI-P2 + §7 invariant 2). The
// node-local cloud-intelligence tables (migration 097) belong to the PERSONAL
// cloud plane, a separate destination from the org push wire. This proves that
// two ways:
//
//	(1) all six table names are in the forbidden-name sentinel set (so
//	    TestSelectUnpushedSinceExcludesCacheTables — the AST scan of orgpush.go
//	    — fails the build if any ever appears as a string literal there, which
//	    is the composition-boundary import pin); and
//	(2) a SEEDED-VALUE wire test: a distinctive sentinel is stuffed into every
//	    text column of every one of the six tables, then the REAL
//	    SelectUnpushedSince serialization is byte-searched for the sentinel
//	    under ALL THREE share postures — metadata-only, full_content, and
//	    admin_managed (the maximum disclosure surface, which deliberately flips
//	    the OTHER content columns raw). The sentinel must never appear.
//
// The rows carry no *_hash counterpart because they are never pushed at all.
// PROOF SCOPE matches TestSessionClassificationPinnedOutOfPush: it establishes
// absence from the CURRENT SelectUnpushedSince payload plus source-level
// coverage in orgpush.go; the single-SQL-seam convention (CLAUDE.md Teams
// invariants) holds any future egress path.
func TestCloudLocalTablesPinnedOutOfPush(t *testing.T) {
	cloudTables := []string{
		"cloud_consent_receipts",
		"cloud_session_map",
		"cloud_project_map",
		"cloud_outbox",
		"cloud_results",
		"cloud_result_overrides",
		"cloud_structural_windows",
		"cloud_dispatch_leases",
		"cloud_enrich_policy",
		"cloud_sync_last",
		"cloud_digests",
		"cloud_enrich_skips",
	}

	// (1) every name pinned in the sentinel set the AST scan walks.
	for _, name := range cloudTables {
		found := false
		for _, n := range forbiddenCacheTables {
			if n == name {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s is not in forbiddenCacheTables — the source-level sentinel is missing", name)
		}
	}

	// (2) seeded-value wire test. Every text column of every table gets a value
	// carrying this prefix; the marshaled push payload must never contain it.
	const sentinel = "SBCLOUDSENT" // unmistakable; appears nowhere legitimate

	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st) // seeds sessions that DO ride the wire (e.g. sess-cc-1)

	// s builds a per-column sentinel value so a leak names the exact column.
	s := func(table, col string) string { return sentinel + "_" + table + "_" + col }

	execSeed := func(query string, args ...any) {
		if _, err := database.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("seed cloud table: %v\nquery: %s", err, query)
		}
	}

	execSeed(`INSERT INTO cloud_consent_receipts
		  (id, account_pseudonym, device_label_ref, purpose, field_classes_json,
		   envelope_schema_version, scrubber_version, endpoint,
		   retention_policy_version, upload_digest, created_at, invalidated_at,
		   grant_mode, data_dictionary_digest, declared_timezone,
		   source_window_rule, review_at, consent_generation)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
		s("cloud_consent_receipts", "id"), s("cloud_consent_receipts", "account_pseudonym"),
		s("cloud_consent_receipts", "device_label_ref"), s("cloud_consent_receipts", "purpose"),
		s("cloud_consent_receipts", "field_classes_json"), s("cloud_consent_receipts", "envelope_schema_version"),
		s("cloud_consent_receipts", "scrubber_version"), s("cloud_consent_receipts", "endpoint"),
		s("cloud_consent_receipts", "retention_policy_version"), s("cloud_consent_receipts", "upload_digest"),
		s("cloud_consent_receipts", "created_at"), s("cloud_consent_receipts", "invalidated_at"),
		s("cloud_consent_receipts", "grant_mode"), s("cloud_consent_receipts", "data_dictionary_digest"),
		s("cloud_consent_receipts", "declared_timezone"), s("cloud_consent_receipts", "source_window_rule"),
		s("cloud_consent_receipts", "review_at"))

	execSeed(`INSERT INTO cloud_session_map (local_session_id, cloud_pseudonym, created_at) VALUES (?, ?, ?)`,
		s("cloud_session_map", "local_session_id"), s("cloud_session_map", "cloud_pseudonym"),
		s("cloud_session_map", "created_at"))

	execSeed(`INSERT INTO cloud_project_map (local_project_id, cloud_pseudonym, created_at) VALUES (?, ?, ?)`,
		s("cloud_project_map", "local_project_id"), s("cloud_project_map", "cloud_pseudonym"),
		s("cloud_project_map", "created_at"))

	// Two outbox rows so BOTH migration-098 columns are covered. Row 1 stuffs
	// the sentinel into `kind` (and carries no payload — the 098 trigger
	// forbids payload on any kind but structural_insights). Row 2 is a real
	// structural row whose payload_bytes BLOB is the sentinel, proving the one
	// place the outbox is allowed to hold bytes also never reaches the wire.
	execSeed(`INSERT INTO cloud_outbox
		  (id, session_id, feature_set_json, evidence_content_digest, upload_digest,
		   receipt_id, state, retry_count, last_error, created_at, updated_at, kind)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)`,
		s("cloud_outbox", "id"), s("cloud_outbox", "session_id"), s("cloud_outbox", "feature_set_json"),
		s("cloud_outbox", "evidence_content_digest"), s("cloud_outbox", "upload_digest"),
		s("cloud_outbox", "receipt_id"), s("cloud_outbox", "state"), s("cloud_outbox", "last_error"),
		s("cloud_outbox", "created_at"), s("cloud_outbox", "updated_at"), s("cloud_outbox", "kind"))

	execSeed(`INSERT INTO cloud_outbox
		  (id, session_id, feature_set_json, evidence_content_digest, upload_digest,
		   receipt_id, state, retry_count, last_error, created_at, updated_at,
		   kind, payload_bytes)
		VALUES (?, '', ?, ?, ?, ?, 'pending', 0, '', ?, ?, 'structural_insights', ?)`,
		s("cloud_outbox", "id")+"_structural", s("cloud_outbox", "feature_set_json_structural"),
		s("cloud_outbox", "evidence_content_digest_structural"), s("cloud_outbox", "upload_digest_structural"),
		s("cloud_outbox", "receipt_id_structural"),
		s("cloud_outbox", "created_at_structural"), s("cloud_outbox", "updated_at_structural"),
		[]byte(s("cloud_outbox", "payload_bytes")))

	execSeed(`INSERT INTO cloud_structural_windows
		  (period, period_rule_version, schema_version, revision, outbox_id, digest, created_at)
		VALUES (?, 1, ?, 1, ?, ?, ?)`,
		s("cloud_structural_windows", "period"), s("cloud_structural_windows", "schema_version"),
		s("cloud_structural_windows", "outbox_id"), s("cloud_structural_windows", "digest"),
		s("cloud_structural_windows", "created_at"))

	execSeed(`INSERT INTO cloud_dispatch_leases
		  (id, receipt_id, purpose, consent_generation, acquired_at, expires_at, released_at, cancelled_at)
		VALUES (?, ?, ?, 1, ?, ?, ?, ?)`,
		s("cloud_dispatch_leases", "id"), s("cloud_dispatch_leases", "receipt_id"),
		s("cloud_dispatch_leases", "purpose"), s("cloud_dispatch_leases", "acquired_at"),
		s("cloud_dispatch_leases", "expires_at"), s("cloud_dispatch_leases", "released_at"),
		s("cloud_dispatch_leases", "cancelled_at"))

	// cloud_enrich_policy.level is CHECK-constrained to off/titles/excerpts (a
	// closed, content-free vocabulary — no sentinel needed there); every other
	// column, including migration 117's `since`, is free text and gets the
	// sentinel treatment like the rest.
	execSeed(`INSERT INTO cloud_enrich_policy (id, level, background, policy_version, source, updated_at, since)
		VALUES (1, 'titles', 1, ?, ?, ?, ?)`,
		s("cloud_enrich_policy", "policy_version"), s("cloud_enrich_policy", "source"),
		s("cloud_enrich_policy", "updated_at"), s("cloud_enrich_policy", "since"))

	// Migration 117/118: cloud_sync_last, the outcome of the most recent
	// `observer cloud sync` run plus (118) the account plan it observed via
	// GET /v1/usage. started_at/finished_at/error_class/plan_name/plan_label
	// are the free-text columns; ok/sent/waiting_provider/reconfirm/failed/
	// results/sign_in_expired/digest_weekly/results_retention_days/
	// daily_cap/monthly_cap are plain integers with a closed or numeric
	// meaning — no sentinel needed there.
	execSeed(`INSERT INTO cloud_sync_last
		  (id, started_at, finished_at, ok, sent, waiting_provider, reconfirm, failed, results,
		   sign_in_expired, error_class, plan_name, plan_label, digest_weekly,
		   results_retention_days, daily_cap, monthly_cap)
		VALUES (1, ?, ?, 1, 0, 0, 0, 0, 0, 0, ?, ?, ?, 1, 30, 50, 500)`,
		s("cloud_sync_last", "started_at"), s("cloud_sync_last", "finished_at"),
		s("cloud_sync_last", "error_class"), s("cloud_sync_last", "plan_name"),
		s("cloud_sync_last", "plan_label"))

	// Migration 118: cloud_digests, the weekly project digest a pulled
	// result kind="project_digest" record carries. cloud_project_id/
	// local_project_id/period_start/period_end/schema_version/result_json/
	// received_at/superseded_by are all free text (result_json in
	// particular is the digest body itself) and get the sentinel treatment.
	execSeed(`INSERT INTO cloud_digests
		  (id, cloud_project_id, local_project_id, period_start, period_end,
		   schema_version, result_json, received_at, superseded_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s("cloud_digests", "id"), s("cloud_digests", "cloud_project_id"),
		s("cloud_digests", "local_project_id"), s("cloud_digests", "period_start"),
		s("cloud_digests", "period_end"), s("cloud_digests", "schema_version"),
		s("cloud_digests", "result_json"), s("cloud_digests", "received_at"),
		s("cloud_digests", "superseded_by"))

	execSeed(`INSERT INTO cloud_results
		  (id, session_id, schema_version, result_json, model_route, prompt_hash,
		   tokens, cost_usd, received_at, superseded_by)
		VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?, ?)`,
		s("cloud_results", "id"), s("cloud_results", "session_id"), s("cloud_results", "schema_version"),
		s("cloud_results", "result_json"), s("cloud_results", "model_route"), s("cloud_results", "prompt_hash"),
		s("cloud_results", "received_at"), s("cloud_results", "superseded_by"))

	execSeed(`INSERT INTO cloud_result_overrides (result_id, field, user_value, updated_at) VALUES (?, ?, ?, ?)`,
		s("cloud_result_overrides", "result_id"), s("cloud_result_overrides", "field"),
		s("cloud_result_overrides", "user_value"), s("cloud_result_overrides", "updated_at"))

	postures := []struct {
		name  string
		share store.ShareOptions
	}{
		{"metadata_only", store.ShareOptions{}},
		{"full_content", store.ShareOptions{FullContent: true}},
		{"admin_managed", store.ShareOptions{AdminManaged: true}},
	}
	// Positive canary (FD6): a KNOWN non-cloud seed value that DOES ride the
	// wire in every posture. Its presence proves the org batch is non-empty, so
	// the sentinel-absence assertion below is not vacuously true (a silently
	// empty batch would otherwise "pass" the absence check). seed() ingests a
	// codex session whose model rides the wire as plain metadata under all three
	// postures.
	const wireCanary = "gpt-5-codex"
	for _, p := range postures {
		batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@x", p.share, store.ScopeOptions{})
		if err != nil {
			t.Fatalf("SelectUnpushedSince(%s): %v", p.name, err)
		}
		raw, err := json.Marshal(batch)
		if err != nil {
			t.Fatalf("marshal batch(%s): %v", p.name, err)
		}
		if !bytes.Contains(raw, []byte(wireCanary)) {
			t.Fatalf("positive canary %q missing from the %s push payload — the batch is empty/degenerate, "+
				"so the cloud-absence assertion would be vacuous", wireCanary, p.name)
		}
		if bytes.Contains(raw, []byte(sentinel)) {
			t.Errorf("cloud-local table content leaked into the push payload under %s — the personal "+
				"cloud plane is node-local and must never enter the org-push wire", p.name)
		}
	}
}

// TestCloudOutboxPayloadOnlyOnStructuralKind pins migration 098's NAMED
// EXCEPTION to the "the outbox stores no content" rule, at the storage layer.
//
// The rule guards session CONTENT — excerpts, paths, command strings. A
// structural-insights snapshot has none of those (it is bounded deterministic
// aggregates over a time window, and cloudcontract.StructuralSnapshot has no
// field in which a path or an excerpt could be expressed), so it is permitted
// to store its exact canonical bytes — which is what makes a resend replay the
// digested bytes instead of re-aggregating.
//
// The exception is narrow, and this test proves the narrowness is ENFORCED
// rather than merely documented: migration 098's BEFORE INSERT / BEFORE UPDATE
// triggers reject payload_bytes on every other kind, so a future code path that
// forgets the rule — or a raw SQL writer that never knew it — fails loudly
// instead of quietly parking session content in the outbox. The assertions go
// through the raw *sql.DB deliberately: a Go-level guard in the store seam
// (store.ErrCloudPayloadKindForbidden) would not catch a writer that bypasses
// the seam, and the trigger does.
func TestCloudOutboxPayloadOnlyOnStructuralKind(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()

	insert := func(id, kind string, payload []byte) error {
		var p any
		if payload != nil {
			p = payload
		}
		_, err := database.ExecContext(ctx, `
			INSERT INTO cloud_outbox
			  (id, session_id, feature_set_json, evidence_content_digest, upload_digest,
			   receipt_id, state, retry_count, last_error, created_at, updated_at,
			   kind, payload_bytes)
			VALUES (?, 's', '[]', 'sha256:a', 'sha256:a', 'r', 'pending', 0, '', 't', 't', ?, ?)`,
			id, kind, p)
		return err
	}

	// A structural item MAY carry bytes — the named exception itself.
	if err := insert("ok-structural", "structural_insights", []byte("canonical-snapshot-bytes")); err != nil {
		t.Fatalf("a structural_insights row must be allowed to carry payload_bytes: %v", err)
	}
	// Every other kind may NOT.
	for _, kind := range []string{"session_evidence", "", "something_new"} {
		if err := insert("reject-"+kind, kind, []byte("session content")); err == nil {
			t.Errorf("cloud_outbox accepted payload_bytes on kind %q — migration 098's exception is "+
				"narrow by design: only structural_insights items may store bytes", kind)
		}
	}
	// A payload-free row of another kind stays perfectly legal.
	if err := insert("ok-evidence", "session_evidence", nil); err != nil {
		t.Fatalf("a payload-free session_evidence row must still insert: %v", err)
	}
	// And the rule cannot be dodged by inserting empty and updating after.
	if _, err := database.ExecContext(ctx,
		`UPDATE cloud_outbox SET payload_bytes = ? WHERE id = 'ok-evidence'`, []byte("session content")); err == nil {
		t.Error("cloud_outbox accepted an UPDATE attaching payload_bytes to a session_evidence row — " +
			"the INSERT trigger alone would leave insert-then-update as an open door")
	}
	// Nor by flipping a structural row's kind while keeping its bytes.
	if _, err := database.ExecContext(ctx,
		`UPDATE cloud_outbox SET kind = 'session_evidence' WHERE id = 'ok-structural'`); err == nil {
		t.Error("cloud_outbox accepted re-labelling a payload-carrying row as session_evidence — " +
			"the guard must hold on the row's resulting state, not only on the bytes being written")
	}
}

// TestObsEgressTierContract pins the T8 egress org tier's shape (org-parity
// W5.3, 2026-08-24 — the conscious change the retired
// TestObsEgressHasNoOrgProviderSeam sentinel demanded: G22 design §8 deferred
// an egress org tier to "its own wire shape + share key + sentinel update",
// which is exactly what shipped). Structurally: the tier is reachable ONLY
// through the store.ObsOrgProviders.Egress func seam (never SQL against
// obs_egress_decisions inside orgpush.go — the literal table-name sentinel
// above still enforces that), and it is gated by its OWN node-side share key
// ShareOptions.ObsEgress (default false; zero value ships nothing). The
// behavioral gating — absent without the opt-in, Tenant/User stripped under
// !shipsRawContent() — is pinned by TestObsEgressComposeGating in
// internal/store/orgpush_obs_test.go.
func TestObsEgressTierContract(t *testing.T) {
	t.Parallel()
	pt := reflect.TypeOf(store.ObsOrgProviders{})
	if _, ok := pt.FieldByName("Egress"); !ok {
		t.Errorf("store.ObsOrgProviders lost its Egress provider func — the T8 egress tier must be composed through the func seam, never inline SQL in orgpush.go")
	}
	st := reflect.TypeOf(store.ShareOptions{})
	f, ok := st.FieldByName("ObsEgress")
	if !ok {
		t.Fatalf("store.ShareOptions lost ObsEgress — the T8 egress tier must be gated by its own node-side share key ([org_client.share.obs].egress), default false")
	}
	if f.Type.Kind() != reflect.Bool {
		t.Errorf("ShareOptions.ObsEgress is %s, want bool (a node-side opt-in flag, never a server-driven value)", f.Type)
	}
	if (store.ShareOptions{}).ObsEgress {
		t.Errorf("ShareOptions zero value has ObsEgress=true — the egress tier must default OFF")
	}
}

// TestSelectUnpushedSinceExcludesCacheTables is the structural
// privacy sentinel for the cachetrack arc. Walks every string
// literal in internal/store/orgpush.go (the single SQL seam
// for the push path per CLAUDE.md "Single SQL seam" Teams
// invariant) and fails if any contains a cachetrack table name.
//
// Strict-source check rather than data-side: catches the
// regression at the moment someone writes the JOIN/SELECT,
// before any row even exists. Pairs with
// TestPushPayloadCarriesNoContent which catches the
// alternative-path case (someone exports cache_* via a separate
// seam).
//
// orgpush.go also contains a long list of `*_hash` allowed
// columns — the regex deliberately matches the table NAMES, not
// "cache" substrings — so future "cache_read_hash" / "cache_*"
// column names on api_turns don't trigger a false positive.
func TestSelectUnpushedSinceExcludesCacheTables(t *testing.T) {
	t.Parallel()
	path := filepath.Join("..", "..", "internal", "store", "orgpush.go")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		for _, name := range forbiddenCacheTables {
			if strings.Contains(lit.Value, name) {
				pos := fset.Position(lit.Pos())
				t.Errorf("%s:%d: forbidden cachetrack table name %q appears in string literal — "+
					"cache_* tables are NODE-LOCAL per spec §11; they MUST NOT enter the push wire path",
					pos.Filename, pos.Line, name)
			}
		}
		for _, name := range forbiddenGatewayTables {
			if strings.Contains(lit.Value, name) {
				pos := fset.Position(lit.Pos())
				t.Errorf("%s:%d: forbidden server-side gateway table name %q appears in string literal — "+
					"gateway_wal is a SERVER-ONLY ingest queue (P0-9 durable-edge WAL); it MUST NOT enter the push wire path",
					pos.Filename, pos.Line, name)
			}
		}
		for _, name := range forbiddenOrgControlPlaneTables {
			if strings.Contains(lit.Value, name) {
				pos := fset.Position(lit.Pos())
				t.Errorf("%s:%d: forbidden org control-plane table name %q appears in string literal — "+
					"P1-4/P1-7/P1-9 control-plane tables are SERVER-ONLY and MUST NOT enter the push wire path",
					pos.Filename, pos.Line, name)
			}
		}
		return true
	})

	// Cold storage is a SECOND DATABASE FILE, so a forbidden-name scan alone
	// would not catch the way it could actually leak: orgpush.go importing
	// the archive packages and reading the archive handle directly, never
	// naming a table in a literal because internal/archivestore does that for
	// it. The single-database assumption the whole sentinel rests on is worth
	// asserting outright.
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		for _, bad := range []string{
			"github.com/marmutapp/superbased-observer/internal/archivestore",
			"github.com/marmutapp/superbased-observer/internal/archivesvc",
		} {
			if path == bad {
				pos := fset.Position(imp.Pos())
				t.Errorf("%s:%d: orgpush.go imports %q — the push seam must read the ONE hot "+
					"database it is given; cold storage (~/.observer/archive.db) holds the same "+
					"node-local rows, only older, and must never become a wire surface",
					pos.Filename, pos.Line, bad)
			}
		}
	}
}

// TestPushPayloadHasOnlyAllowlistedKeys is the structural-allowlist guard:
// in metadata-only mode (the default), the actions / sessions / api_turns /
// token_usage objects must contain ONLY keys from a fixed allowlist. Adding
// a new content-bearing field anywhere would silently break this invariant
// and the test fails loudly rather than relying on a denylist of known
// sentinels.
//
// Pre-M1.1 the allowlist would have to include `target`, `source_file`,
// `project_root`, `git_remote` (since those currently ship raw); the
// post-M1.1 allowlist drops those names in favor of their *_hash equivalents.
// Marked skipped until M1.1 lands so we don't have to bake a stale shape
// into the assertion.
func TestPushPayloadHasOnlyAllowlistedKeys(t *testing.T) {
	t.Skip("structural allowlist covered by M1.1 (orgcontract hash columns); test will activate once the wire shape stabilises")
	// Intentional placeholder: once M1.1 lands, the body decodes the
	// payload, walks each row in sessions/actions/api_turns/token_usage,
	// and t.Errorf on any unexpected key. The allowlist set is the final
	// list of JSON tag names declared on each orgcontract row type AFTER
	// the M1.1 change.
}

// TestRoutingSummaryWireShapeIsAggregateOnly pins the §R19.4 rollup
// contract structurally: the RoutingSummaryRow wire type may carry
// ONLY the allow-listed aggregate keys (attribution, date, enums,
// counts, dollars) — no model ids, no session ids, no paths. A new
// field on the type fails here before it can ship.
func TestRoutingSummaryWireShapeIsAggregateOnly(t *testing.T) {
	t.Parallel()
	allowed := map[string]bool{
		"OrgID": true, "UserEmail": true, // agent-stamped attribution
		"Day": true, "Tier": true, "Reason": true, "Mode": true, // date + closed enums
		"Decisions": true, "Applied": true, // counts
		"EstSavingsUSD": true, "CacheForfeitUSD": true, // dollars
	}
	typ := reflect.TypeOf(orgcontract.RoutingSummaryRow{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if !allowed[name] {
			t.Errorf("RoutingSummaryRow gained non-aggregate field %q — the §R19.4 wire shape is counts + dollars by tier/reason ONLY", name)
		}
	}
}

// TestUpdatePostureRowWireShapeIsEnumOnly pins the Enterprise Update
// Management posture row (plan §2.1, ruling R10): the ONLY thing a node
// discloses about updating itself may be version strings, coarse platform
// tokens, closed enums and one boolean. A field named Host/Hostname/User/
// Path/Dir/File/Message/Detail/Error(text)/Progress/Bytes — anything that
// could carry a path, an identity or a progress percentage — fails HERE,
// before it can ship.
//
// Modeled on TestRoutingSummaryWireShapeIsAggregateOnly and
// TestPolicyStateRowWireShapeIsHashOnly, including the exact-count assertion:
// merely allow-listing a name is not enough, the SET must match, so a field
// cannot be added without a deliberate edit to this list.
//
// AutoApply is the one field beyond §2.1's own table. It is included because
// org_node_versions carries the column and the Updates board must answer
// "which of my fleet is actually zero-touch" — a boolean configuration fact
// the server cannot otherwise know, since [update].auto_apply is node-owned
// and there is deliberately no remote toggle. Reason is likewise a CLOSED
// vocabulary (update.Reason), not free text: it is the difference between
// "this fleet needs MDM" and "this fleet is broken".
func TestUpdatePostureRowWireShapeIsEnumOnly(t *testing.T) {
	t.Parallel()
	allowed := map[string]bool{
		"Version": true, "Channel": true, // version string + closed channel enum
		"OS": true, "Arch": true, // coarse platform tokens
		"State": true, "Reason": true, // closed update.State / update.Reason
		"TargetVersion": true, "ManifestVersion": true, // version string + ordinal
		"ErrorClass":       true, // closed update.ErrorClass, NEVER a message
		"InstallMethod":    true, // closed update.Method
		"AutoApply":        true, // boolean configuration fact
		"ExtensionVersion": true, // version string, empty = "not reported"
	}
	typ := reflect.TypeOf(orgcontract.UpdatePostureRow{})
	if typ.NumField() != len(allowed) {
		t.Errorf("UpdatePostureRow has %d fields, want exactly %d (§2.1 allow-list)", typ.NumField(), len(allowed))
	}
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if !allowed[name] {
			t.Errorf("UpdatePostureRow gained non-allow-listed field %q — the §2.1 wire shape is "+
				"version/platform/enum/boolean ONLY: no hostname, no username, no path, no progress, "+
				"no free-text error (ruling R10)", name)
		}
	}
}

// TestPolicyStateRowWireShapeIsHashOnly pins the P0-6 effective-state row
// (docs/plans/plane-a-p0-6-effective-policy-state-plan.md §2.1/§5.1): the
// PolicyStateRow that rides POST /api/agent/policy-ack may carry ONLY the 15
// allow-listed hash/version/enum/timestamp fields — no Body/TOML/Path/Detail/
// Message/Excerpt/Tenant/EndUser/Prompt or any free-text field, forever. A new
// field fails loudly. Modeled on TestRoutingSummaryWireShapeIsAggregateOnly.
//
// gen2 (P4-2) widened the allow-list by exactly three CLOSED-VOCABULARY
// fields — AcceptedAuthority/ExtractionEffective are govern.KnownAuthority /
// govern.ExtractionAuthority token slices, and DroppedClasses is a closed
// directive-class-name -> closed drop-reason map — still enum shape, never
// free text.
func TestPolicyStateRowWireShapeIsHashOnly(t *testing.T) {
	t.Parallel()
	allowed := map[string]bool{
		"OrgID": true, "UserEmail": true, // server-stamped attribution (empty-on-wire)
		"Family": true, "EnforcementPoint": true, // closed enums
		"DesiredVersion": true, "RunningVersion": true, // integer versions
		"EffectiveHash": true,                 // per-point hex digest
		"Status":        true, "Reason": true, // closed enums (Reason a typed code, never Detail)
		"RestartRequired": true, "Mode": true, // bool + closed enum
		"LastSeen":            true, // RFC3339 liveness
		"AcceptedAuthority":   true, // gen2 — closed authority-token slice
		"ExtractionEffective": true, // gen2 — closed authority-token slice
		"DroppedClasses":      true, // gen2 — closed class-name -> closed reason map
	}
	typ := reflect.TypeOf(orgcontract.PolicyStateRow{})
	if typ.NumField() != len(allowed) {
		t.Errorf("PolicyStateRow has %d fields, want exactly %d (§2.1 allow-list + gen2 P4-2 widening)", typ.NumField(), len(allowed))
	}
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if !allowed[name] {
			t.Errorf("PolicyStateRow gained non-allow-listed field %q — the P0-6 §2.1 wire shape is hash/version/enum/timestamp ONLY", name)
		}
	}
}

// newInvariantStore opens a fresh migrated agent DB for the routing
// wire-shape tests.
func newInvariantStore(t *testing.T) (*store.Store, func()) {
	t.Helper()
	database, err := db.Open(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return store.New(database), func() { _ = database.Close() }
}

// TestRoutingSummaryGatedOffByDefault pins the consent posture: the
// zero-valued ShareOptions (the default) attaches NO routing summaries
// to a push batch, even when decision rows exist.
func TestRoutingSummaryGatedOffByDefault(t *testing.T) {
	t.Parallel()
	s, _ := newInvariantStore(t)
	ctx := context.Background()
	if err := s.InsertRouterDecisions(ctx, []store.RouterDecisionRow{{
		SessionID: "s1", Timestamp: time.Now().UTC(), Mode: "advise", Channel: "B",
		OriginalModel: "claude-opus-4-8", SelectedModel: "claude-haiku-4-5",
		TurnKind: "read_only", PolicyName: "value", PolicyHash: "h",
		ReasonCodes: []string{"overpowered_read"}, EstSavingsUSD: 1, EstimateVersion: "p1-v1",
	}}); err != nil {
		t.Fatalf("seed decision: %v", err)
	}

	batch, err := s.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@x", store.ShareOptions{}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if len(batch.RoutingSummaries) != 0 {
		t.Fatalf("default share shipped %d routing summaries — the §R26.4 consent toggle must gate them", len(batch.RoutingSummaries))
	}

	opted, err := s.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@x", store.ShareOptions{RoutingSummary: true}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("select opted: %v", err)
	}
	if len(opted.RoutingSummaries) == 0 {
		t.Fatal("opt-in shipped no summaries despite decision rows")
	}
	row := opted.RoutingSummaries[0]
	if row.Tier != "opus-class" || row.Decisions != 1 || row.OrgID != "org-1" {
		t.Errorf("summary row = %+v", row)
	}
}

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
				Traces: []orgcontract.ObsTraceRow{{TraceID: "t1", StartedAt: "2026-06-29T00:00:00Z", ProjectHash: "ph", ProjectRoot: "/secret/path"}},
				Spans:  []orgcontract.ObsSpanRow{{TraceID: "t1", SpanID: "s1", Kind: "llm", Name: "chat"}},
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
	if full.ObsContent[0].Content != "SECRET BODY" || full.ObsTraces[0].ProjectRoot != "/secret/path" {
		t.Errorf("full_content did not ship raw body/path: content=%q root=%q", full.ObsContent[0].Content, full.ObsTraces[0].ProjectRoot)
	}
}

// TestPushPayloadNeverCarriesOrgIntelCache is the DYNAMIC complement to the
// org_intel_cache forbidden-name sentinel (INV-3, finding 11): the name check
// proves orgpush.go never references the table by literal, but a leak could
// still reach the wire through a helper that reads the table without naming it.
// This seeds distinctive sentinel strings into org_intel_cache and asserts none
// of them appear in the ACTUAL pushed bytes (the SelectUnpushedSince envelope,
// JSON-marshalled) under EVERY sharing posture — metadata-only, full_content,
// and admin_managed. The node-local org-served intelligence result cache is the
// org's product coming BACK to the node; it must never go out on the push wire.
func TestPushPayloadNeverCarriesOrgIntelCache(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)

	const (
		secTitle = "SENTINEL_INTEL_TITLE_pangram_zz"
		secDesc  = "SENTINEL_INTEL_DESC_pangram_zz"
		secTag   = "SENTINEL_INTEL_TAG_pangram_zz"
		secLim   = "SENTINEL_INTEL_LIM_pangram_zz"
	)
	if _, err := database.ExecContext(ctx, `
		INSERT INTO org_intel_cache
		  (org_id, session_id, job_id, title, taxonomy_tags, suggested_tags,
		   description, confidence, limitations, schema_version, fetched_at)
		VALUES ('org-1','sess-intel-1','j1', ?, ?, '[]', ?, 'high', ?, 'v2', ?)`,
		secTitle, `["`+secTag+`"]`, secDesc, `["`+secLim+`"]`,
		time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("seed org_intel_cache: %v", err)
	}

	for _, tc := range []struct {
		name  string
		share store.ShareOptions
	}{
		{"metadata-only", store.ShareOptions{}},
		{"full_content", store.ShareOptions{FullContent: true}},
		{"admin_managed", store.ShareOptions{AdminManaged: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example", tc.share, store.ScopeOptions{})
			if err != nil {
				t.Fatalf("SelectUnpushedSince: %v", err)
			}
			raw, err := json.Marshal(batch)
			if err != nil {
				t.Fatalf("marshal batch: %v", err)
			}
			for _, s := range []string{secTitle, secDesc, secTag, secLim} {
				if bytes.Contains(raw, []byte(s)) {
					t.Errorf("org_intel_cache sentinel %q leaked into the push envelope under %s — INV-3: the "+
						"node-local intel result cache must NEVER cross the push wire", s, tc.name)
				}
			}
		})
	}
}
