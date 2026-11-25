package invariant

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/store"
)

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
// representation at all, by design (same posture as cache_segments) — so
// the assertion is simply "this canary never
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
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
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
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
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
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
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
		// The G19 isolation evidence (migration 179) is per-run: it rides
		// only on the TerminalRunRow, so it obeys the same two postures.
		Isolation: store.TerminalRunIsolation{
			Class: secTermRun + "_class", CaptureLevel: secTermRun + "_capture",
			CaptureOrigin: secTermRun + "_origin", EvidenceDigest: secTermRun + "_digest",
			// The digest's producer inputs (migration 181) ride the same row.
			EvidenceProducer: secTermRun + "_producer", EvidenceComponent: secTermRun + "_component",
			EvidenceComponentVersion: secTermRun + "_version",
		},
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
	} else if batch.TerminalRuns[0].EvidenceDigest != secTermRun+"_digest" {
		t.Error("the run's isolation evidence did not ride on its TerminalRunRow under full_content")
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
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
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
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
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
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
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
	// meaning — no sentinel needed there. Migration 254 adds two more text
	// columns (budget_unit, enrichment_tier) that get the sentinel, and the
	// token-budget integers (evidence_token_budget and the token windows).
	execSeed(`INSERT INTO cloud_sync_last
		  (id, started_at, finished_at, ok, sent, waiting_provider, reconfirm, failed, results,
		   sign_in_expired, error_class, plan_name, plan_label, digest_weekly,
		   results_retention_days, daily_cap, monthly_cap,
		   budget_unit, enrichment_tier, evidence_token_budget, session_token_budget,
		   daily_tokens_used, daily_token_budget, monthly_tokens_used, monthly_token_budget)
		VALUES (1, ?, ?, 1, 0, 0, 0, 0, 0, 0, ?, ?, ?, 1, 30, 50, 500, ?, ?, 4000, 60000, 10, 250000, 20, 3000000)`,
		s("cloud_sync_last", "started_at"), s("cloud_sync_last", "finished_at"),
		s("cloud_sync_last", "error_class"), s("cloud_sync_last", "plan_name"),
		s("cloud_sync_last", "plan_label"), s("cloud_sync_last", "budget_unit"),
		s("cloud_sync_last", "enrichment_tier"))

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

// TestCloudAgentTablesPinnedOutOfPush is the cloud-agents sibling of
// TestCloudLocalTablesPinnedOutOfPush (agent migration 241, lane CA-A1). It
// proves both halves of the posture: (1) the three table names are in the
// source-level sentinel forbiddenCacheTables; (2) a sentinel planted in every
// free-text column of all three tables never appears in a marshaled push
// payload under any of the three share postures, because there is no wire
// surface for connector accounts, checkpoints or the native-unit ledger.
// The CHECK-constrained vocabulary columns (stream, measurement_source,
// value_type, monetary_status) carry closed values, not sentinels.
func TestCloudAgentTablesPinnedOutOfPush(t *testing.T) {
	for _, name := range []string{"cloud_connector_accounts", "cloud_sync_checkpoints", "cloud_usage_ledger"} {
		found := false
		for _, n := range forbiddenCacheTables {
			if n == name {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s is not in forbiddenCacheTables: the source-level sentinel is missing", name)
		}
	}

	const sentinel = "SBCLOUDAGENTSENT" // unmistakable; appears nowhere legitimate
	s := func(table, col string) string { return sentinel + "_" + table + "_" + col }

	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st) // seeds sessions that DO ride the wire

	execSeed := func(query string, args ...any) {
		if _, err := database.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("seed cloud-agent table: %v\nquery: %s", err, query)
		}
	}
	execSeed(`INSERT INTO cloud_connector_accounts
		  (id, connector, provider, issuer, account_id, display_email, coverage_state, last_error_class, created_at, updated_at)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s("acct", "connector"), s("acct", "provider"), s("acct", "issuer"), s("acct", "account_id"),
		s("acct", "display_email"), s("acct", "coverage_state"), s("acct", "last_error_class"),
		s("acct", "created_at"), s("acct", "updated_at"))
	execSeed(`INSERT INTO cloud_sync_checkpoints
		  (account_pk, stream, scope, cursor, overlap_seconds, last_attempt_at, last_success_at, gaps_json, updated_at)
		VALUES (1, 'session_history', ?, ?, 60, ?, ?, ?, ?)`,
		s("cp", "scope"), s("cp", "cursor"), s("cp", "last_attempt_at"), s("cp", "last_success_at"),
		s("cp", "gaps_json"), s("cp", "updated_at"))
	execSeed(`INSERT INTO cloud_usage_ledger
		  (connector, source_record_id, measurement_source, value_type, unit, value, monetary_status,
		   scope_run, scope_session, scope_user, scope_account, scope_org, scope_model,
		   interval_start, interval_end, includes_children, reported_at, observed_at)
		VALUES (?, ?, 'provider_run_total', 'interval', ?, 4.5, 'reported_charge',
		        ?, 'sess-cc-1', ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
		s("ledger", "connector"), s("ledger", "source_record_id"), s("ledger", "unit"),
		s("ledger", "scope_run"), s("ledger", "scope_user"), s("ledger", "scope_account"),
		s("ledger", "scope_org"), s("ledger", "scope_model"), s("ledger", "interval_start"),
		s("ledger", "interval_end"), s("ledger", "reported_at"), s("ledger", "observed_at"))

	const wireCanary = "gpt-5-codex" // rides the wire in every posture (see TestCloudLocalTablesPinnedOutOfPush)
	for _, p := range []struct {
		name  string
		share store.ShareOptions
	}{
		{"metadata_only", store.ShareOptions{}},
		{"full_content", store.ShareOptions{FullContent: true}},
		{"admin_managed", store.ShareOptions{AdminManaged: true}},
	} {
		batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@x", p.share, store.ScopeOptions{})
		if err != nil {
			t.Fatalf("SelectUnpushedSince(%s): %v", p.name, err)
		}
		raw, err := json.Marshal(batch)
		if err != nil {
			t.Fatalf("marshal batch(%s): %v", p.name, err)
		}
		if !bytes.Contains(raw, []byte(wireCanary)) {
			t.Fatalf("positive canary %q missing from the %s push payload: the absence check would be vacuous", wireCanary, p.name)
		}
		if bytes.Contains(raw, []byte(sentinel)) {
			t.Errorf("cloud-agent table content leaked into the push payload under %s", p.name)
		}
	}
}

// TestCloudSessionLinksPinnedOutOfPush (agent migration 246, lane CA-C5):
// the table is in the source-level sentinel, and a sentinel planted in every
// free-text column, against a session that DOES ride the wire, never appears
// in a marshaled push payload under any of the three share postures.
func TestCloudSessionLinksPinnedOutOfPush(t *testing.T) {
	found := false
	for _, n := range forbiddenCacheTables {
		found = found || n == "cloud_session_links"
	}
	if !found {
		t.Fatal("cloud_session_links is not in forbiddenCacheTables: the source-level sentinel is missing")
	}
	const sentinel = "SBCLOUDLINKSENT" // unmistakable; appears nowhere legitimate
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)
	if _, err := database.ExecContext(ctx, `INSERT INTO cloud_session_links
		  (session_id, connector, remote, pr_number, branch, first_seen_at, last_seen_at)
		VALUES ('sess-cc-1', ?, ?, 7, ?, ?, ?)`,
		sentinel+"_connector", sentinel+"_remote", sentinel+"_branch", sentinel+"_first", sentinel+"_last"); err != nil {
		t.Fatalf("seed cloud_session_links: %v", err)
	}
	const wireCanary = "gpt-5-codex"
	for _, p := range []struct {
		name  string
		share store.ShareOptions
	}{
		{"metadata_only", store.ShareOptions{}},
		{"full_content", store.ShareOptions{FullContent: true}},
		{"admin_managed", store.ShareOptions{AdminManaged: true}},
	} {
		batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@x", p.share, store.ScopeOptions{})
		if err != nil {
			t.Fatalf("SelectUnpushedSince(%s): %v", p.name, err)
		}
		raw, err := json.Marshal(batch)
		if err != nil {
			t.Fatalf("marshal batch(%s): %v", p.name, err)
		}
		if !bytes.Contains(raw, []byte(wireCanary)) {
			t.Fatalf("positive canary %q missing from the %s push payload: the absence check would be vacuous", wireCanary, p.name)
		}
		if bytes.Contains(raw, []byte(sentinel)) {
			t.Errorf("cloud_session_links content leaked into the push payload under %s", p.name)
		}
	}
}

// TestProjectCommitTablesPinnedOutOfPush is the commit-capture sibling of
// TestCloudLocalTablesPinnedOutOfPush (projects-page-roi-and-commit-
// alignment plan, agent migration 127). It proves both halves of the
// posture: (1) the three table names are present in the source-level AST
// sentinel forbiddenCacheTables, which TestSelectUnpushedSinceExcludesCacheTables
// walks against internal/store/orgpush.go's string literals; and (2) a
// seeded sentinel value planted in every free-text column of all three
// tables never appears in a marshaled push payload, under all three
// ShareOptions postures (zero-value / full_content / admin_managed) — so
// even the enterprise "ships full content" posture (CLAUDE.md "Teams /
// org-server invariants") does not carry commit data, because there is no
// wire surface for it at all yet (R1: an org projection is a documented,
// additive, shipsRawContent()-gated follow-up).
func TestProjectCommitTablesPinnedOutOfPush(t *testing.T) {
	commitTables := []string{
		"project_commits",
		"project_commit_files",
		"project_commit_scan",
	}
	for _, name := range commitTables {
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

	const sentinel = "SBCOMMITSENT" // unmistakable; appears nowhere legitimate
	s := func(table, col string) string { return sentinel + "_" + table + "_" + col }

	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st) // seeds sessions that DO ride the wire (e.g. sess-cc-1)

	projectID, err := st.UpsertProject(ctx, s("project_commits", "root_path"), "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}

	execSeed := func(query string, args ...any) {
		if _, err := database.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("seed commit table: %v\nquery: %s", err, query)
		}
	}

	execSeed(`INSERT INTO project_commits
		  (id, project_id, sha, parents_json, author_hash, authored_at, committed_at,
		   subject, is_merge, reachable, files_count, added, deleted, scanned_at)
		VALUES (1, ?, ?, ?, ?, '2026-09-21T00:00:00Z', '2026-09-21T00:00:00Z', ?, 0, 1, 1, 1, 0, '2026-09-21T00:00:00Z')`,
		projectID, s("project_commits", "sha"), s("project_commits", "parents_json"),
		s("project_commits", "author_hash"), s("project_commits", "subject"))

	execSeed(`INSERT INTO project_commit_files
		  (commit_id, rel_path, path_hash, status, added, deleted, binary)
		VALUES (1, ?, ?, ?, 1, 0, 0)`,
		s("project_commit_files", "rel_path"), s("project_commit_files", "path_hash"),
		s("project_commit_files", "status"))

	execSeed(`INSERT INTO project_commit_scan
		  (project_id, last_sha, last_committed_at, last_scan_at, last_error, consecutive_failures)
		VALUES (?, ?, '2026-09-21T00:00:00Z', '2026-09-21T00:00:00Z', ?, 0)`,
		projectID, s("project_commit_scan", "last_sha"), s("project_commit_scan", "last_error"))

	postures := []struct {
		name  string
		share store.ShareOptions
	}{
		{"metadata_only", store.ShareOptions{}},
		{"full_content", store.ShareOptions{FullContent: true}},
		{"admin_managed", store.ShareOptions{AdminManaged: true}},
	}
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
				"so the commit-table-absence assertion would be vacuous", wireCanary, p.name)
		}
		if bytes.Contains(raw, []byte(sentinel)) {
			t.Errorf("project_commit_* table content leaked into the push payload under %s — commit "+
				"capture is node-local (R1/R12) and has no wire surface yet", p.name)
		}
	}
}

// TestLocalSessionHoldsPinnedOutOfPush (agent migration 251, plan 07 M8.8):
// local_session_holds is in forbiddenCacheTables, and a hold's note never
// reaches a marshaled push payload in any share posture. The hold is the
// developer's choice about THIS machine's retention, never org data.
func TestLocalSessionHoldsPinnedOutOfPush(t *testing.T) {
	found := false
	for _, n := range forbiddenCacheTables {
		found = found || n == "local_session_holds"
	}
	if !found {
		t.Fatal("local_session_holds is not in forbiddenCacheTables — the source-level sentinel is missing")
	}
	const sentinel = "SBLOCALHOLDSENT"
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)
	if _, err := st.HoldSession(ctx, "sess-cc-1", sentinel, time.Now().UTC()); err != nil {
		t.Fatalf("HoldSession: %v", err)
	}
	for _, p := range []struct {
		name  string
		share store.ShareOptions
	}{
		{"metadata_only", store.ShareOptions{}},
		{"full_content", store.ShareOptions{FullContent: true}},
		{"admin_managed", store.ShareOptions{AdminManaged: true}},
	} {
		batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@x", p.share, store.ScopeOptions{})
		if err != nil {
			t.Fatalf("SelectUnpushedSince(%s): %v", p.name, err)
		}
		raw, err := json.Marshal(batch)
		if err != nil {
			t.Fatalf("marshal batch(%s): %v", p.name, err)
		}
		if !bytes.Contains(raw, []byte("sess-cc-1")) {
			t.Fatalf("the held session is missing from the %s payload — the absence assertion would be vacuous", p.name)
		}
		if bytes.Contains(raw, []byte(sentinel)) {
			t.Errorf("a local hold leaked into the push payload under %s", p.name)
		}
	}
}

// TestDeliveryTablesPinnedOutOfPush is the delivery (commit to PR to merge,
// D-689) sibling of TestProjectCommitTablesPinnedOutOfPush. Same two halves:
// (1) all eight node tables are in forbiddenCacheTables, and (2) a seeded
// sentinel in every TEXT column never reaches a marshaled push payload in the
// metadata posture. Under the raw-content postures ONLY a PR's own title,
// URL and repo slug may ship (PullRequestRow); the remote URL, the branch
// name, the keychain entry name, the mirror path and the raw commit id
// never do.
func TestDeliveryTablesPinnedOutOfPush(t *testing.T) {
	deliveryTables := []string{
		"project_remotes", "commit_landings", "provider_links", "pull_requests",
		"pull_request_commits", "delivery_mirrors", "delivery_project_settings", "delivery_branch_tips",
	}
	for _, name := range deliveryTables {
		found := false
		for _, n := range forbiddenCacheTables {
			if n == name {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s is not in forbiddenCacheTables: the source-level sentinel is missing", name)
		}
	}

	const sentinel = "SBDELIVSENT"
	s := func(table, col string) string { return sentinel + "_" + table + "_" + col }

	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)

	projectID, err := st.UpsertProject(ctx, "/repo/delivery-sentinel", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	execSeed := func(query string, args ...any) {
		if _, err := database.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("seed delivery table: %v\nquery: %s", err, query)
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	execSeed(`INSERT INTO project_commits
		  (id, project_id, sha, parents_json, author_hash, authored_at, committed_at,
		   subject, is_merge, reachable, files_count, added, deleted, scanned_at, patch_fp, patch_fp_state)
		VALUES (9001, ?, ?, '[]', '', ?, ?, '', 0, 1, 1, 1, 0, ?, ?, 'ok')`,
		projectID, s("project_commits", "sha"), now, now, now, s("project_commits", "patch_fp"))
	execSeed(`INSERT INTO project_remotes
		  (project_id, remote_name, url, host, provider, repo_slug, default_branch, default_ref_sha, fetch_head_at, observed_at)
		VALUES (?, ?, ?, ?, 'github', ?, ?, ?, ?, ?)`,
		projectID, s("project_remotes", "remote_name"), s("project_remotes", "url"), s("project_remotes", "host"),
		s("project_remotes", "repo_slug"), s("project_remotes", "default_branch"), s("project_remotes", "default_ref_sha"), now, now)
	execSeed(`INSERT INTO provider_links
		  (id, provider, host, auth_mode, key_name, account_login, scopes_seen, status, last_error_kind, last_error, created_at)
		VALUES (1, 'github', ?, 'token', ?, ?, ?, 'ok', ?, ?, ?)`,
		s("provider_links", "host"), s("provider_links", "key_name"), s("provider_links", "account_login"),
		s("provider_links", "scopes_seen"), s("provider_links", "last_error_kind"), s("provider_links", "last_error"), now)
	execSeed(`INSERT INTO pull_requests
		  (id, provider_link_id, provider, host, repo_slug, number, title, url, author_login, pr_state, merge_readiness,
		   facets_json, provider_raw_state, head_sha, base_ref, merge_commit_sha, merge_method, created_at, merged_at, fetched_at,
		   head_ref)
		VALUES (1, 1, 'github', 'github.com', ?, 5, ?, ?, ?, 'merged', '', '{}', ?, ?, ?, ?, 'squash', ?, ?, ?, ?)`,
		s("pull_requests", "repo_slug"), s("pull_requests", "title"), s("pull_requests", "url"), s("pull_requests", "author_login"),
		s("pull_requests", "provider_raw_state"), s("pull_requests", "head_sha"), s("pull_requests", "base_ref"),
		s("pull_requests", "merge_commit_sha"), now, now, now, s("pull_requests", "head_ref"))
	execSeed(`INSERT INTO pull_request_commits (pr_id, sha, position, patch_fp) VALUES (1, ?, 0, ?)`,
		s("project_commits", "sha"), s("pull_request_commits", "patch_fp"))
	execSeed(`INSERT INTO commit_landings
		  (commit_id, project_id, status, kind, confidence, rule_id, rule_version, landing_sha, pr_id, pr_number,
		   abandon_reason, source, evaluated_at, contributors_json)
		VALUES (9001, ?, 'landed', 'squash', 'exact', 'P1', 1, ?, 1, 5, '', 'provider', ?, ?)`,
		projectID, s("commit_landings", "landing_sha"), now, `["`+s("commit_landings", "contributors_json")+`"]`)
	execSeed(`INSERT INTO delivery_mirrors (url_hash, url, path, default_branch, tip_sha, status, last_error, created_at)
		VALUES (?, ?, ?, ?, ?, 'ok', ?, ?)`,
		s("delivery_mirrors", "url_hash"), s("delivery_mirrors", "url"), s("delivery_mirrors", "path"),
		s("delivery_mirrors", "default_branch"), s("delivery_mirrors", "tip_sha"), s("delivery_mirrors", "last_error"), now)
	execSeed(`INSERT INTO delivery_project_settings (project_id, mirror_enabled, schedule_minutes, updated_at) VALUES (?, 1, 30, ?)`,
		projectID, now)
	execSeed(`INSERT INTO delivery_branch_tips
		  (project_id, ref_name_hash, ref_name, tip_sha, merge_base_sha, range_fp, range_fp_state, member_shas_json, files_json, observed_at)
		VALUES (?, ?, ?, ?, ?, ?, 'ok', ?, ?, ?)`,
		projectID, s("delivery_branch_tips", "ref_name_hash"), s("delivery_branch_tips", "ref_name"),
		s("delivery_branch_tips", "tip_sha"), s("delivery_branch_tips", "merge_base_sha"), s("delivery_branch_tips", "range_fp"),
		`["`+s("delivery_branch_tips", "member_shas_json")+`"]`, `["`+s("delivery_branch_tips", "files_json")+`"]`, now)

	// Under the raw posture, these three may ship inside a PullRequestRow.
	rawAllowed := map[string]bool{
		s("pull_requests", "repo_slug"): true,
		s("pull_requests", "title"):     true,
		s("pull_requests", "url"):       true,
	}
	postures := []struct {
		name  string
		share store.ShareOptions
		raw   bool
	}{
		{"metadata_only", store.ShareOptions{}, false},
		{"full_content", store.ShareOptions{FullContent: true}, true},
		{"admin_managed", store.ShareOptions{AdminManaged: true}, true},
	}
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
			t.Fatalf("positive canary %q missing from the %s push payload", wireCanary, p.name)
		}
		if len(batch.DeliveryDays) == 0 {
			t.Fatalf("%s: no delivery day rows: the absence assertion would be vacuous", p.name)
		}
		if p.raw && (len(batch.PullRequests) != 1 || batch.PullRequests[0].Title != s("pull_requests", "title")) {
			t.Fatalf("%s: raw posture PR rows = %+v", p.name, batch.PullRequests)
		}
		if !p.raw && len(batch.PullRequests) != 0 {
			t.Fatalf("%s: metadata posture shipped PR rows", p.name)
		}
		for _, table := range deliveryTables {
			for _, col := range []string{
				"remote_name", "url", "host", "repo_slug", "default_branch", "default_ref_sha",
				"key_name", "account_login", "scopes_seen", "last_error_kind", "last_error", "title", "author_login",
				"provider_raw_state", "head_sha", "base_ref", "merge_commit_sha", "patch_fp", "landing_sha",
				"contributors_json", "url_hash", "path", "tip_sha", "ref_name_hash", "ref_name", "merge_base_sha",
				"range_fp", "member_shas_json", "files_json", "head_ref",
			} {
				v := s(table, col)
				if p.raw && rawAllowed[v] {
					continue
				}
				if bytes.Contains(raw, []byte(v)) {
					t.Errorf("%s leaked into the %s push payload", v, p.name)
				}
			}
		}
		if bytes.Contains(raw, []byte(s("project_commits", "sha"))) {
			t.Errorf("the raw commit id leaked into the %s push payload", p.name)
		}
	}
}

// TestSkillHistoryTablesPinnedOutOfPush is the skills-history sibling of
// TestProjectCommitTablesPinnedOutOfPush (agent migration 135, S10-SKILLS).
// Same two halves: (1) all seven table names are in the source-level AST
// sentinel forbiddenCacheTables, and (2) a seeded sentinel value planted in
// every TEXT column of every table never appears in a marshaled push
// payload under all three ShareOptions postures. The snapshot rows are
// planted against sess-cc-1, a session that DOES ride the wire, so a join
// that dragged snapshot content onto a session row would be caught.
func TestSkillHistoryTablesPinnedOutOfPush(t *testing.T) {
	skillTables := []string{
		"skill_snapshot_members",
		"session_skill_snapshots",
		"project_head_moves",
		"project_skill_trees",
		"project_skill_tree_files",
		"project_skill_worktree",
		"project_skill_scan",
	}
	for _, name := range skillTables {
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

	const sentinel = "SBSKILLSENT" // unmistakable; appears nowhere legitimate
	s := func(table, col string) string { return sentinel + "_" + table + "_" + col }

	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st) // seeds sessions that DO ride the wire (e.g. sess-cc-1)

	projectID, err := st.UpsertProject(ctx, s("projects", "root_path"), "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	execSeed := func(query string, args ...any) {
		if _, err := database.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("seed skill table: %v\nquery: %s", err, query)
		}
	}
	const ts = "2026-09-23T00:00:00.000000000Z"
	m := "skill_snapshot_members"
	execSeed(`INSERT INTO skill_snapshot_members
		  (set_hash, scope, rel_path, dir_key, name, state, content_hash, blob_oid, blob_oid_lf, size_bytes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`,
		s(m, "set_hash"), s(m, "scope"), s(m, "rel_path"), s(m, "dir_key"), s(m, "name"),
		s(m, "state"), s(m, "content_hash"), s(m, "blob_oid"), s(m, "blob_oid_lf"))
	n := "session_skill_snapshots"
	execSeed(`INSERT INTO session_skill_snapshots
		  (session_id, tool, event, source, tool_use_id, invoked_name, observed_at, project_root, set_hash, complete, home_resolved)
		VALUES ('sess-cc-1', ?, ?, ?, ?, ?, ?, ?, ?, 1, 1)`,
		s(n, "tool"), s(n, "event"), s(n, "source"), s(n, "tool_use_id"), s(n, "invoked_name"),
		ts, s(n, "project_root"), s(m, "set_hash"))
	execSeed(`INSERT INTO project_head_moves (project_id, moved_at, sha, kind) VALUES (?, ?, ?, ?)`,
		projectID, ts, s("project_head_moves", "sha"), s("project_head_moves", "kind"))
	execSeed(`INSERT INTO project_skill_trees (project_id, sha, state, resolved_at) VALUES (?, ?, ?, ?)`,
		projectID, s("project_skill_trees", "sha"), s("project_skill_trees", "state"), ts)
	execSeed(`INSERT INTO project_skill_tree_files (project_id, sha, rel_path, mode, blob_oid) VALUES (?, ?, ?, ?, ?)`,
		projectID, s("project_skill_tree_files", "sha"), s("project_skill_tree_files", "rel_path"),
		s("project_skill_tree_files", "mode"), s("project_skill_tree_files", "blob_oid"))
	execSeed(`INSERT INTO project_skill_worktree (project_id, rel_path, state) VALUES (?, ?, ?)`,
		projectID, s("project_skill_worktree", "rel_path"), s("project_skill_worktree", "state"))
	execSeed(`INSERT INTO project_skill_scan
		  (project_id, last_scan_at, head_sha, reflog_since, ignorecase, object_format, shallow, last_error, consecutive_failures)
		VALUES (?, ?, ?, ?, 0, ?, 0, ?, 0)`,
		projectID, ts, s("project_skill_scan", "head_sha"), ts,
		s("project_skill_scan", "object_format"), s("project_skill_scan", "last_error"))

	postures := []struct {
		name  string
		share store.ShareOptions
	}{
		{"metadata_only", store.ShareOptions{}},
		{"full_content", store.ShareOptions{FullContent: true}},
		{"admin_managed", store.ShareOptions{AdminManaged: true}},
	}
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
				"so the skill-table-absence assertion would be vacuous", wireCanary, p.name)
		}
		if bytes.Contains(raw, []byte(sentinel)) {
			t.Errorf("skill-history table content leaked into the push payload under %s — skills "+
				"history is node-local and has no wire surface", p.name)
		}
	}
}

// TestProjectPromptGradesTableIsPinnedOutOfPush is the alignment-grading
// sibling of TestProjectCommitTablesPinnedOutOfPush (agent migration 128,
// projects-page-roi-and-commit-alignment plan §2 R6/§3.6/§4 W5a). Same two
// halves: (1) the table name is present in the source-level AST sentinel
// forbiddenCacheTables, and (2) a seeded sentinel value planted in every
// free-text column never appears in a marshaled push payload, under all
// three ShareOptions postures — a grading verdict is a derived disclosure
// of the prompt/commit evidence it was built from, and has no wire surface
// at all yet.
func TestProjectPromptGradesTableIsPinnedOutOfPush(t *testing.T) {
	const tableName = "project_prompt_grades"
	found := false
	for _, n := range forbiddenCacheTables {
		if n == tableName {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("%s is not in forbiddenCacheTables — the source-level sentinel is missing", tableName)
	}

	const sentinel = "SBGRADESENT" // unmistakable; appears nowhere legitimate
	s := func(col string) string { return sentinel + "_" + tableName + "_" + col }

	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st) // seeds sessions that DO ride the wire (e.g. sess-cc-1)

	projectID, err := st.UpsertProject(ctx, s("root_path"), "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}

	resultJSON := `{"delivered":["` + s("delivered") + `"],"missed":["` + s("missed") + `"],` +
		`"extra":["` + s("extra") + `"],"confidence":0.5,"notes":"` + s("notes") + `"}`
	if _, err := database.ExecContext(ctx, `
		INSERT INTO project_prompt_grades (project_id, action_id, tier, model, result_json, graded_at)
		VALUES (?, 1, 'judge', ?, ?, '2026-09-21T00:00:00Z')`,
		projectID, s("model"), resultJSON); err != nil {
		t.Fatalf("seed project_prompt_grades: %v", err)
	}

	postures := []struct {
		name  string
		share store.ShareOptions
	}{
		{"metadata_only", store.ShareOptions{}},
		{"full_content", store.ShareOptions{FullContent: true}},
		{"admin_managed", store.ShareOptions{AdminManaged: true}},
	}
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
				"so the grade-table-absence assertion would be vacuous", wireCanary, p.name)
		}
		if bytes.Contains(raw, []byte(sentinel)) {
			t.Errorf("project_prompt_grades content leaked into the push payload under %s — alignment "+
				"grading is node-local and has no wire surface yet", p.name)
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
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
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
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
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
		// The five NARRATIVE columns (agent migration 124). Each gets its OWN
		// sentinel: a single shared value would let four of the five columns be
		// added to the push seam undetected, and these carry the most revealing
		// prose on the row — "what failed", "what to do next" — so they are the
		// LAST thing that may cross the wire.
		secWork  = "SENTINEL_INTEL_WORKDONE_pangram_zz"
		secPlans = "SENTINEL_INTEL_PLANS_pangram_zz"
		secIssue = "SENTINEL_INTEL_ISSUES_pangram_zz"
		secFail  = "SENTINEL_INTEL_FAILURES_pangram_zz"
		secNext  = "SENTINEL_INTEL_NEXTSTEPS_pangram_zz"
	)
	if _, err := database.ExecContext(ctx, `
		INSERT INTO org_intel_cache
		  (org_id, session_id, job_id, title, taxonomy_tags, suggested_tags,
		   description, confidence, limitations, schema_version, fetched_at,
		   work_done, plans_implemented, issues_found, failures, next_steps)
		VALUES ('org-1','sess-intel-1','j1', ?, ?, '[]', ?, 'high', ?, 'v2', ?, ?, ?, ?, ?, ?)`,
		secTitle, `["`+secTag+`"]`, secDesc, `["`+secLim+`"]`,
		time.Now().UTC().Format(time.RFC3339),
		`["`+secWork+`"]`, `["`+secPlans+`"]`, `["`+secIssue+`"]`,
		`["`+secFail+`"]`, `["`+secNext+`"]`); err != nil {
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
			for _, s := range []string{
				secTitle, secDesc, secTag, secLim,
				secWork, secPlans, secIssue, secFail, secNext,
			} {
				if bytes.Contains(raw, []byte(s)) {
					t.Errorf("org_intel_cache sentinel %q leaked into the push envelope under %s — INV-3: the "+
						"node-local intel result cache must NEVER cross the push wire", s, tc.name)
				}
			}
		})
	}
}

// TestProjectQualityDailyPinnedOutOfPush is the quality-trend sibling of
// TestProjectCommitTablesPinnedOutOfPush (agent migration 219,
// docs/projects-page.md "Quality metrics"): the table is in
// forbiddenCacheTables, and a seeded sentinel in every TEXT column (and an
// unmistakable number in the counts) never reaches a marshaled push payload
// in any share posture.
func TestProjectQualityDailyPinnedOutOfPush(t *testing.T) {
	found := false
	for _, n := range forbiddenCacheTables {
		if n == "project_quality_daily" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("project_quality_daily is not in forbiddenCacheTables: the source-level sentinel is missing")
	}

	const sentinel = "SBQUALITYSENT"
	const number = 918273645
	s := func(col string) string { return sentinel + "_" + col }

	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)

	projectID, err := st.UpsertProject(ctx, "/repo/quality-pin", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO project_quality_daily
		  (project_id, day, measured_at, coverage_state, coverage_lines, coverage_covered, coverage_reports, coverage_report_at,
		   dup_state, dup_eligible_symbols, dup_cloned_symbols, dup_eligible_lines, dup_cloned_lines, dup_groups, dup_indexed_at)
		VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, 1, ?)`,
		projectID, s("day"), s("measured_at"), s("coverage_state"), number, number, s("coverage_report_at"),
		s("dup_state"), number, number, number, number, s("dup_indexed_at")); err != nil {
		t.Fatalf("seed project_quality_daily: %v", err)
	}

	postures := []struct {
		name  string
		share store.ShareOptions
	}{
		{"metadata_only", store.ShareOptions{}},
		{"full_content", store.ShareOptions{FullContent: true}},
		{"admin_managed", store.ShareOptions{AdminManaged: true}},
	}
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
			t.Fatalf("positive canary %q missing from the %s push payload: the absence assertion would be vacuous", wireCanary, p.name)
		}
		if bytes.Contains(raw, []byte(sentinel)) || bytes.Contains(raw, []byte("918273645")) {
			t.Errorf("project_quality_daily content leaked into the push payload under %s: the quality trend is node-local", p.name)
		}
	}
}
