package store

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/update"
)

// keptOrgTables are the agent tables that hold org-related state but are NOT
// identity-bound caches cleared by ClearIdentityBoundDocs, each with the reason
// (T-393). A new table must be added either to identityBoundDocs or here.
var keptOrgTables = map[string]string{
	"org_enrolment":             "the enrolment row itself: DeleteEnrolment deletes it, Enroll overwrites it",
	"org_enrolment_generation":  "the identity fence: Enroll and Unenroll bump or tombstone it per org key",
	"org_enrolment_grant":       "keyed by org key and fenced by the enrolment generation (P0-5); Unenroll deletes it and the enrol flow replaces or refuses it",
	"org_policy_resource_state": "keyed by org key; Enroll and Unenroll run ClearPolicyResourceState for the old key",
	"org_push_log":              "the node's own push history, not an org document (T-373)",
	"org_push_changes":          "push re-send tracking: clearPushTracking on unenrol, the cursor reseed on enrol",
	"org_push_deletions":        "push re-send tracking: clearPushTracking on unenrol, the cursor reseed on enrol",
	"org_push_manifests":        "push re-send tracking: clearPushTracking on unenrol, the cursor reseed on enrol",
	"org_push_rev":              "push re-send tracking: clearPushTracking on unenrol, the cursor reseed on enrol",
	"org_intel_consent":         "the node's own consent ledger keyed by org id; the intel row appends a 'leave' event rather than deleting history",
	"org_intel_receipts":        "the node's own local audit of intel actions",
	"org_members":               "legacy migration 028 table with no node writer",
	"org_teams":                 "legacy migration 028 table with no node writer",
	"org_team_members":          "legacy migration 028 table with no node writer",
	"org_project_team":          "legacy migration 028 table with no node writer",
}

// TestIdentityBoundDocsCoverEveryOrgTable fails when an org_* table (or a
// listed non-prefixed one) exists with no clearing row and no recorded reason
// to keep it, and when a clearing row names a table the schema lacks.
func TestIdentityBoundDocsCoverEveryOrgTable(t *testing.T) {
	t.Parallel()
	_, database := newTestStore(t)
	ctx := context.Background()

	rows, err := database.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	exists := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		exists[n] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	cleared := map[string]IdentityBoundDoc{}
	for _, d := range identityBoundDocs {
		for _, tbl := range d.tables {
			if strings.HasPrefix(tbl, "schema_meta:") {
				continue
			}
			if !exists[tbl] {
				t.Errorf("identity row %q names table %q, which the schema does not have", d.doc, tbl)
			}
			cleared[tbl] = d.doc
		}
	}

	var missing []string
	for tbl := range exists {
		if !strings.HasPrefix(tbl, "org_") {
			continue
		}
		_, c := cleared[tbl]
		_, k := keptOrgTables[tbl]
		if c && k {
			t.Errorf("table %q is both cleared (%s) and kept", tbl, cleared[tbl])
		}
		if !c && !k {
			missing = append(missing, tbl)
		}
	}
	sort.Strings(missing)
	for _, tbl := range missing {
		t.Errorf("org table %q has no identity decision: add a row to identityBoundDocs (identitydocs.go) or a reason to keptOrgTables", tbl)
	}
	for tbl := range keptOrgTables {
		if !exists[tbl] {
			t.Errorf("keptOrgTables names %q, which the schema does not have", tbl)
		}
	}
}

// TestClearIdentityBoundDocs seeds the single-row caches and the update rail,
// clears, and checks each one is gone (T-393).
func TestClearIdentityBoundDocs(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	leaving := &Enrolment{OrgID: "org-a", OrgServerURL: "https://a.example", UserID: "u1"}

	if err := s.UpsertOrgAnnouncement(ctx, OrgAnnouncementRow{Version: 7, Body: `{"id":"x"}`, BodyHash: "h", Signature: "s", ServerPubkey: "k-a", ReceivedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertOrgRoutingPolicy(ctx, OrgRoutingPolicyRow{Version: 3, Body: "[routing]\n", BodyHash: "h", Signature: "s", ServerPubkey: "k-a", ReceivedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertOrgDisplayPolicy(ctx, OrgDisplayPolicyRow{OrgID: "org-a", Version: 4, Body: "{}", BodyHash: "h", Signature: "s", ServerPubkey: "k-a", DeveloperCostDisplay: "tokens", ReceivedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveOrgPolicyETag(ctx, `"etag-a"`); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveVerifiedManifest(ctx, VerifiedManifest{Channel: update.ChannelStable, ManifestVersion: 40, TargetVersion: "9.9.9", ManifestJSON: `{"m":1}`, State: update.StateAvailable}); err != nil {
		t.Fatal(err)
	}

	if err := s.ClearIdentityBoundDocs(ctx, leaving); err != nil {
		t.Fatalf("ClearIdentityBoundDocs: %v", err)
	}

	if _, ok, err := s.GetOrgAnnouncement(ctx); err != nil || ok {
		t.Errorf("announcement survived: ok=%v err=%v", ok, err)
	}
	if _, ok, err := s.GetOrgRoutingPolicy(ctx); err != nil || ok {
		t.Errorf("routing policy survived: ok=%v err=%v", ok, err)
	}
	if _, ok, err := s.GetOrgDisplayPolicy(ctx); err != nil || ok {
		t.Errorf("display policy survived: ok=%v err=%v", ok, err)
	}
	if etag, err := s.LoadOrgPolicyETag(ctx); err != nil || etag != "" {
		t.Errorf("guard bundle ETag survived: %q err=%v", etag, err)
	}
	st, err := s.LoadUpdateState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.State != update.StateIdle || st.LastManifestVersion != 0 || st.ManifestJSON != "" || st.TargetVersion != "" || st.Channel != "" {
		t.Errorf("update manifest survived: %+v", st)
	}
}

// TestClearIdentityBoundDocsKeepsAnApplyInFlight pins the one exception: an
// update apply in flight owns update_state until it finishes.
func TestClearIdentityBoundDocsKeepsAnApplyInFlight(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	row := UpdateStateRow{NodeState: update.NodeState{
		Channel: update.ChannelStable, LastManifestVersion: 40, TargetVersion: "9.9.9", State: update.StateApplying,
	}, ManifestJSON: `{"m":1}`}
	if err := s.SaveUpdateState(ctx, row); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearIdentityBoundDocs(ctx, nil); err != nil {
		t.Fatalf("ClearIdentityBoundDocs: %v", err)
	}
	st, err := s.LoadUpdateState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.State != update.StateApplying || st.LastManifestVersion != 40 || st.ManifestJSON == "" {
		t.Errorf("an apply in flight lost its row: %+v", st)
	}
}

// TestReEnrolmentClearsTheProjectAudienceFence is audit finding 9: the
// project audience's downgrade fence (a guard_policy_state row keyed by the
// server URL) goes with the enrolment identity, so a new identity starts a
// new fence; every other policy-state row stays.
func TestReEnrolmentClearsTheProjectAudienceFence(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for _, r := range []GuardPolicyStateRow{
		{Layer: "org", Path: "https://a.example" + ProjectAudienceFenceSuffix, Version: "9", ContentHash: "d9", LoadedAt: now},
		{Layer: "org", Path: "/home/u/.observer/org-bundle.json", Version: "12", ContentHash: "h12", LoadedAt: now},
	} {
		if _, err := s.RecordGuardPolicyState(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.ClearIdentityBoundDocs(ctx, &Enrolment{OrgID: "org-a", OrgServerURL: "https://a.example", UserID: "u1"}); err != nil {
		t.Fatalf("ClearIdentityBoundDocs: %v", err)
	}
	states, err := s.LatestGuardPolicyStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var fence, bundle bool
	for _, st := range states {
		if strings.HasSuffix(st.Path, ProjectAudienceFenceSuffix) {
			fence = true
		}
		if st.Version == "12" {
			bundle = true
		}
	}
	if fence {
		t.Fatal("the project audience downgrade fence survived a re-enrolment")
	}
	if !bundle {
		t.Fatal("the clear removed an unrelated policy-state row")
	}
}
