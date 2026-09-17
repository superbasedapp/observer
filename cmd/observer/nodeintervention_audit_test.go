package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/intervention"
)

func TestNodeInterventionAuditPreservesObservedResultWithoutRawError(t *testing.T) {
	for _, tc := range []struct {
		status        string
		term, kill    bool
		stopped, gone bool
	}{
		{"policy_unavailable", false, false, false, false},
		{"termination_unverified", true, false, false, false},
		{"terminated", true, false, true, false},
		{"killed", true, true, true, false},
		{"already_exited", true, false, false, true},
	} {
		t.Run(tc.status, func(t *testing.T) {
			at := time.Now().UTC()
			outcome := intervention.Outcome{
				Workload: intervention.Workload{SurfaceID: "muse/cli", Identity: intervention.Identity{
					PID: 42, UID: 1000, BootID: "fixture-boot", StartTicks: 123,
					Executable: intervention.ExecutableIdentity{Device: 8, Inode: 99},
				}},
				Status: tc.status, RuleID: "B-625", Reason: "accounting unavailable",
				TermAttempted: tc.term, KillAttempted: tc.kill, Stopped: tc.stopped,
				AlreadyExited: tc.gone, ControlVerified: true,
				Authority: "authority-fixture", BudgetBinding: "budget-binding-fixture",
				BudgetDocumentSHA256: strings.Repeat("a", 64), PolicyRevision: 7,
				PricingDocumentRequired: true, PricingDocumentKnown: true, PricingDocumentPresent: true,
				PricingDocumentSHA256: strings.Repeat("b", 64),
				Err:                   errors.New("private OS error fixture - must never persist"),
			}
			audit := nodeInterventionAudit(outcome, at)
			if audit.Tool != "muse" || audit.Surface != "muse/cli" || audit.SessionID != "" || audit.TS != at {
				t.Fatalf("audit invented a session or lost surface: %+v", audit)
			}
			if audit.PID != 42 || audit.UID != 1000 || audit.BootID != "fixture-boot" || audit.StartTicks != 123 || audit.ExecutableDevice != 8 || audit.ExecutableInode != 99 {
				t.Fatalf("audit lost stable process identity: %+v", audit)
			}
			if audit.TermAttempted != tc.term || audit.KillAttempted != tc.kill || audit.Stopped != tc.stopped || audit.AlreadyExited != tc.gone || !audit.ErrorPresent {
				t.Fatalf("requested control became observed enforcement: %+v", audit)
			}
			if audit.AuthorityFingerprint != outcome.Authority || audit.BudgetFingerprint != outcome.BudgetBinding || audit.MetadataHash != outcome.BudgetDocumentSHA256 || audit.PolicyRevision != 7 {
				t.Fatalf("audit lost policy evidence: %+v", audit)
			}
			if !audit.PricingDocumentRequired || !audit.PricingDocumentKnown || !audit.PricingDocumentPresent || audit.PricingDocumentFingerprint != outcome.PricingDocumentSHA256 {
				t.Fatalf("audit lost pricing evidence: %+v", audit)
			}
			encoded, err := json.Marshal(audit)
			if err != nil || strings.Contains(string(encoded), "private OS error") {
				t.Fatalf("audit leaked an OS error: %s, %v", encoded, err)
			}
		})
	}
}

// TestNodeInterventionAuditPersistsRealSessionID pins the other half of
// P1-7: once a Workload DOES carry a real SessionID (nodeintervention_cycle.go
// now resolves one via nodeInterventionWorkloadSessionID/session_pid_bridge),
// the audit row must actually carry it through - not just leave it empty
// like the fixture above (which pins the honest "nothing known" case).
func TestNodeInterventionAuditPersistsRealSessionID(t *testing.T) {
	at := time.Now().UTC()
	outcome := intervention.Outcome{
		Workload: intervention.Workload{
			SurfaceID: "muse/cli", SessionID: "sess-real-1234",
			Identity: intervention.Identity{PID: 42, UID: 1000},
		},
		Status: "terminated", RuleID: "B-602", Reason: "cap exhausted",
		TermAttempted: true, Stopped: true, ControlVerified: true,
	}
	audit := nodeInterventionAudit(outcome, at)
	if audit.SessionID != "sess-real-1234" {
		t.Fatalf("audit dropped a real session id: got %q", audit.SessionID)
	}
}

func TestNodeInterventionAuditReportsStorageFailure(t *testing.T) {
	ctx := context.Background()
	if err := recordNodeInterventionOutcomes(ctx, nil, []intervention.Outcome{{Status: "allowed"}, {Status: "not_authorized"}}); err != nil {
		t.Fatal("ordinary inventory attempted an audit write", err)
	}
	if err := recordNodeInterventionOutcomes(ctx, nil, []intervention.Outcome{{Status: "policy_unavailable"}}); err == nil {
		t.Fatal("failed durable control audit was silently discarded")
	}
}
