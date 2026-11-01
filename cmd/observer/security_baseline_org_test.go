//go:build !sbo_omit_security

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestSecurityBaselineOrgFollower (lane LEFT-SHARED): an in-force pull
// carrying approvals stores them and the node's baseline reads "approved by
// the org"; a pull from an older server (no approved_baselines), an
// expired or refused pull and an unbound store all leave the baseline
// unlabelled and never fail.
func TestSecurityBaselineOrgFollower(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: t.TempDir() + "/observer.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	root := t.TempDir()
	hash := secposture.ProjectRootHash(root)
	ident := strings.Repeat("1", 64)
	f := secfinding.Finding{
		LocalKey: "k1", Rule: secfinding.Rule{ID: "secret.aws", Pack: "security.secrets"}, Category: policy.FindingSecret,
		Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceHigh, Status: policy.FindingStatusOpen,
		Project: secfinding.Project{RootHash: hash, IdentityHash: ident}, Baseline: policy.FindingBaselineNew,
	}
	if _, _, err := st.UpsertSecFinding(ctx, secfinding.Normalize(f), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := st.AddSecBaseline(ctx, store.SecBaseline{ProjectRootHash: hash, Kind: "commit", Ref: "c1", Approver: "cli", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	label := func() string {
		v, err := secsvc.LoadBaselineView(ctx, func(context.Context, string, int, time.Duration, ...string) ([]byte, bool, error) {
			return nil, false, context.Canceled
		}, st, root)
		if err != nil || v.Current == nil {
			t.Fatalf("view: %+v %v", v, err)
		}
		return securityBaselineOrgLine(v.Current)
	}
	approved := &orgcontract.SecurityManagedPolicyV1{Version: 1, ApprovedBaselines: []orgcontract.SecurityBaselineApproval{
		{Project: ident, RefKind: "commit", Ref: "c1", ApprovedAt: "2026-10-24T10:00:00Z"},
	}}
	inForce := orgclient.ManagedPullOutcome{InForce: true, Version: 7}

	// No store bound (a CLI process): nothing happens.
	bindSecurityBaselineOrg(nil)
	followSecurityBaselineApprovals(securityManagedState{Outcome: inForce, Policy: approved})
	if label() != "" {
		t.Fatal("an unbound follower stored approvals")
	}
	bindSecurityBaselineOrg(st)
	defer bindSecurityBaselineOrg(nil)
	followSecurityBaselineApprovals(securityManagedState{Outcome: inForce, Policy: approved})
	if got := label(); !strings.Contains(got, "Approved by the org on 2026-10-24T10:00:00Z") {
		t.Fatalf("label = %q", got)
	}
	// An older server serves no approved_baselines: the next applied pull
	// clears the label rather than keep a stale one.
	followSecurityBaselineApprovals(securityManagedState{Outcome: inForce, Policy: &orgcontract.SecurityManagedPolicyV1{Version: 1}})
	if label() != "" {
		t.Fatal("a pull without approvals must clear the label")
	}
	followSecurityBaselineApprovals(securityManagedState{Outcome: inForce, Policy: approved})
	// Not in force (expired, grant gone): cleared.
	followSecurityBaselineApprovals(securityManagedState{Outcome: orgclient.ManagedPullOutcome{Version: 7}, Policy: approved})
	if label() != "" {
		t.Fatal("a pull no longer in force must clear the label")
	}
}
