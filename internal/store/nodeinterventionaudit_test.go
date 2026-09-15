package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func nodeProcessControlAuditFixture(ts time.Time) NodeProcessControlAudit {
	return NodeProcessControlAudit{
		TS:                         ts,
		Surface:                    "claude/native",
		Tool:                       "claude-code",
		SessionID:                  "session-existing-1",
		PID:                        3210,
		UID:                        1000,
		BootID:                     "boot-2026-09-14",
		StartTicks:                 987654,
		ExecutableDevice:           11,
		ExecutableInode:            22,
		RuleID:                     "B-625",
		Reason:                     "managed budget requires process control",
		AuthorityFingerprint:       "authority-fingerprint",
		BudgetFingerprint:          "budget-fingerprint",
		PolicyRevision:             17,
		MetadataHash:               "metadata-fingerprint",
		PricingDocumentRequired:    true,
		PricingDocumentKnown:       true,
		PricingDocumentPresent:     true,
		PricingDocumentFingerprint: "pricing-document-fingerprint",
	}
}

func TestInsertNodeProcessControlAudit_OutcomesAndChain(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	baseTS := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name          string
		status        string
		term          bool
		kill          bool
		observed      bool
		stopped       bool
		alreadyExited bool
		verified      bool
		errPresent    bool
	}{
		{name: "terminated", status: "terminated", term: true, observed: true, stopped: true, verified: true},
		{name: "killed", status: "killed", term: true, kill: true, observed: true, stopped: true, verified: true},
		{name: "fence refused", status: "fence_refused", errPresent: true},
		{name: "unverified", status: "termination_unverified", term: true, errPresent: true, verified: true},
		// AlreadyExited itself implies an observed exit. Leave Observed false
		// here to ensure the store projection preserves that invariant.
		{name: "already exited", status: "already_exited", term: true, alreadyExited: true, verified: true},
	}

	for i, tc := range cases {
		audit := nodeProcessControlAuditFixture(baseTS.Add(time.Duration(i) * time.Second))
		audit.Status = tc.status
		audit.TermAttempted = tc.term
		audit.KillAttempted = tc.kill
		audit.Observed = tc.observed
		audit.Stopped = tc.stopped
		audit.AlreadyExited = tc.alreadyExited
		audit.ControlVerified = tc.verified
		audit.ErrorPresent = tc.errPresent
		if err := s.InsertNodeProcessControlAudit(ctx, audit); err != nil {
			t.Fatalf("%s: InsertNodeProcessControlAudit: %v", tc.name, err)
		}
	}

	rows, err := s.LoadGuardEventsForSession(ctx, "session-existing-1")
	if err != nil {
		t.Fatalf("LoadGuardEventsForSession: %v", err)
	}
	if len(rows) != len(cases) {
		t.Fatalf("rows = %d, want %d", len(rows), len(cases))
	}
	var previousHash string
	for i, tc := range cases {
		row := rows[i]
		if row.EventKind != NodeProcessControlEventKind {
			t.Errorf("%s: EventKind = %q, want %q", tc.name, row.EventKind, NodeProcessControlEventKind)
		}
		if row.Decision != tc.status || row.Enforced != tc.stopped {
			t.Errorf("%s: decision/enforced = (%q, %t), want (%q, %t)", tc.name, row.Decision, row.Enforced, tc.status, tc.stopped)
		}
		if row.ActionID != nil || row.APITurnID != nil {
			t.Errorf("%s: process-control event invented an action/API-turn anchor: action=%v api_turn=%v", tc.name, row.ActionID, row.APITurnID)
		}
		if row.ChainPrev != previousHash || len(row.ChainHash) != sha256.Size*2 {
			t.Errorf("%s: chain linkage = (%q, %q), want previous %q and a SHA-256 hash", tc.name, row.ChainPrev, row.ChainHash, previousHash)
		}
		previousHash = row.ChainHash
		if !row.TS.Equal(baseTS.Add(time.Duration(i) * time.Second)) {
			t.Errorf("%s: TS = %s", tc.name, row.TS)
		}
		if len(row.Reason) > guardMaxReasonRunes || !json.Valid([]byte(row.Reason)) {
			t.Errorf("%s: reason is not valid bounded JSON: bytes=%d", tc.name, len(row.Reason))
		}
		if len(row.TargetExcerpt) > guardMaxExcerptRunes || !json.Valid([]byte(row.TargetExcerpt)) {
			t.Errorf("%s: outcome is not valid bounded JSON: bytes=%d", tc.name, len(row.TargetExcerpt))
		}

		var reason nodeProcessControlReasonMetadata
		if err := json.Unmarshal([]byte(row.Reason), &reason); err != nil {
			t.Fatalf("%s: unmarshal reason: %v", tc.name, err)
		}
		if reason.Surface != "claude/native" || reason.Tool != "claude-code" || reason.SessionID != "session-existing-1" ||
			reason.PID != 3210 || reason.UID != 1000 || reason.BootID != "boot-2026-09-14" ||
			reason.StartTicks != 987654 || reason.ExecutableDevice != 11 || reason.ExecutableInode != 22 {
			t.Errorf("%s: stable metadata lost: %+v", tc.name, reason)
		}
		if reason.AuthorityFingerprint != canonicalNodeControlHash("authority-fingerprint") ||
			reason.BudgetFingerprint != canonicalNodeControlHash("budget-fingerprint") ||
			reason.MetadataHash != canonicalNodeControlHash("metadata-fingerprint") || reason.PolicyRevision != 17 ||
			!reason.PricingDocumentRequired || !reason.PricingDocumentKnown || !reason.PricingDocumentPresent ||
			reason.PricingDocumentFingerprint != canonicalNodeControlHash("pricing-document-fingerprint") {
			t.Errorf("%s: fingerprint metadata = %+v", tc.name, reason)
		}

		var outcome nodeProcessControlOutcomeMetadata
		if err := json.Unmarshal([]byte(row.TargetExcerpt), &outcome); err != nil {
			t.Fatalf("%s: unmarshal outcome: %v", tc.name, err)
		}
		wantObserved := tc.observed || tc.stopped || tc.alreadyExited
		if outcome.Status != tc.status || outcome.TermAttempted != tc.term || outcome.KillAttempted != tc.kill ||
			outcome.Observed != wantObserved || outcome.AlreadyExited != tc.alreadyExited ||
			outcome.ControlVerified != tc.verified || outcome.ErrorPresent != tc.errPresent || outcome.Stopped != tc.stopped {
			t.Errorf("%s: outcome = %+v", tc.name, outcome)
		}
	}

	report, err := s.VerifyGuardChain(ctx)
	if err != nil {
		t.Fatalf("VerifyGuardChain: %v", err)
	}
	if !report.OK || report.Checked != len(cases) {
		t.Fatalf("VerifyGuardChain = %+v, want %d verified rows", report, len(cases))
	}
}

func TestInsertNodeProcessControlAudit_BoundsAndPrivacy(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()
	const secret = "Bearer super-secret-value"

	audit := nodeProcessControlAuditFixture(time.Date(2026, 9, 14, 13, 0, 0, 0, time.UTC))
	audit.Surface = strings.Repeat("surface-", 100)
	audit.Tool = strings.Repeat("tool-", 100)
	audit.SessionID = strings.Repeat("session-", 100)
	audit.BootID = strings.Repeat("boot-", 100)
	audit.RuleID = strings.Repeat("rule-", 100)
	audit.Reason = strings.Repeat("policy explanation 理由 ", 200)
	audit.Status = "permission denied: /proc/3210 secret=" + secret
	audit.AuthorityFingerprint = secret
	audit.BudgetFingerprint = "{" + secret + "}"
	audit.MetadataHash = "raw OS error: permission denied /secret/path"
	audit.PricingDocumentFingerprint = secret
	audit.ErrorPresent = true
	if err := s.InsertNodeProcessControlAudit(ctx, audit); err != nil {
		t.Fatalf("InsertNodeProcessControlAudit: %v", err)
	}

	rows, err := s.LoadGuardEventsForSession(ctx, audit.SessionID[:256])
	if err != nil {
		t.Fatalf("LoadGuardEventsForSession: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	row := rows[0]
	if len(row.Reason) > guardMaxReasonRunes || !json.Valid([]byte(row.Reason)) {
		t.Fatalf("reason is not valid within %d bytes: %d", guardMaxReasonRunes, len(row.Reason))
	}
	if len(row.TargetExcerpt) > guardMaxExcerptRunes || !json.Valid([]byte(row.TargetExcerpt)) {
		t.Fatalf("outcome is not valid within %d bytes: %d", guardMaxExcerptRunes, len(row.TargetExcerpt))
	}
	if utf8.RuneCountInString(row.Tool) > 128 || utf8.RuneCountInString(row.SessionID) > 256 {
		t.Fatalf("direct metadata columns exceeded bounds: tool=%d session=%d", utf8.RuneCountInString(row.Tool), utf8.RuneCountInString(row.SessionID))
	}
	if row.Decision != "unknown" {
		t.Errorf("raw status was persisted as decision %q", row.Decision)
	}
	for _, stored := range []string{row.Reason, row.TargetExcerpt, row.Tool, row.SessionID, row.EventKind, row.TargetHash} {
		if strings.Contains(stored, secret) {
			t.Fatalf("credential-like input leaked into audit metadata: %q", secret)
		}
	}
	var reason nodeProcessControlReasonMetadata
	if err := json.Unmarshal([]byte(row.Reason), &reason); err != nil {
		t.Fatalf("unmarshal bounded reason: %v", err)
	}
	if reason.AuthorityFingerprint != canonicalNodeControlHash(secret) ||
		reason.BudgetFingerprint != canonicalNodeControlHash("{"+secret+"}") ||
		reason.MetadataHash != canonicalNodeControlHash("raw OS error: permission denied /secret/path") ||
		reason.PricingDocumentFingerprint != canonicalNodeControlHash(secret) {
		t.Errorf("fingerprints were not canonicalized: %+v", reason)
	}
	for _, fingerprint := range []string{reason.AuthorityFingerprint, reason.BudgetFingerprint, reason.MetadataHash, reason.PricingDocumentFingerprint} {
		decoded, decodeErr := hex.DecodeString(fingerprint)
		if decodeErr != nil || len(decoded) != sha256.Size {
			t.Errorf("fingerprint %q is not a SHA-256 hex value", fingerprint)
		}
	}

	var actionID, apiTurnID any
	if err := database.QueryRowContext(ctx, `SELECT action_id, api_turn_id FROM guard_events WHERE id = ?`, row.ID).Scan(&actionID, &apiTurnID); err != nil {
		t.Fatalf("read anchor columns: %v", err)
	}
	if actionID != nil || apiTurnID != nil {
		t.Fatalf("anchor columns were populated: action=%v api_turn=%v", actionID, apiTurnID)
	}
	report, err := s.VerifyGuardChain(ctx)
	if err != nil || !report.OK || report.Checked != 1 {
		t.Fatalf("VerifyGuardChain = (%+v, %v)", report, err)
	}
}
