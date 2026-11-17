package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/orgintel"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// orgIntelFixture is an enrolled node with a cached, signed requirement and a
// temp config; the org client has no bearer, so nothing reaches a network.
type orgIntelFixture struct {
	st      *store.Store
	cfgPath string
	d       *orgIntelDashboard
	body    orgcontract.IntelRequirementBody
}

func newOrgIntelFixture(t *testing.T, tenancy string, required bool) *orgIntelFixture {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	st := idpTestStore(t)
	client := idpTestOrgClient(t, st)
	ctx := context.Background()
	if err := st.WriteEnrolment(ctx, store.Enrolment{
		OrgID: "org-1", OrgName: "Acme", OrgServerURL: "https://org.invalid", UserID: "u1", Tenancy: tenancy,
		// Enrolled a day ago: the seeded sessions start after it, as sessions
		// a real node captured under this enrolment do (the sweep floors at it).
		EnrolledAt: time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	body := orgcontract.IntelRequirementBody{
		OrgName: "Acme", Enabled: true, ProviderLabel: "Azure OpenAI", Model: "gpt-x", EvidenceLevel: "titles",
		Purposes: []string{"structural_activity_insights"}, DeveloperActions: true, PerDeveloperDailyCap: 20,
		RequireIndividualConsent: required, RequirementVersion: 1, RequiredSince: "2026-10-01T00:00:00Z", DeadlineDays: 7,
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	doc, err := orgcontract.SignIntelRequirement(priv, "org-1", "u1", 4, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertOrgIntelRequirement(ctx, store.OrgIntelRequirementRow{
		OrgID: doc.OrgID, Version: doc.Version, Body: doc.Body, BodyHash: doc.BodyHash, Signature: doc.Signature, ServerPubkey: doc.PublicKey,
	}); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\nlog_level = \"warn\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := newOrgIntelDashboard(cfgPath, nil)
	d.build = func(context.Context, string) (orgBundle, error) {
		cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
		if err != nil {
			return orgBundle{}, err
		}
		return orgBundle{client: client, store: st, cfg: cfg, cleanup: func() {}}, nil
	}
	return &orgIntelFixture{st: st, cfgPath: cfgPath, d: d, body: body}
}

// TestOrgIntelAcceptWithdrawRoundTrip: the dashboard accept records exactly
// the disclosed coverage, turns the config key on, clears PENDING; a withdraw
// returns to PENDING and turns the key off. A stale digest is a 409 conflict.
func TestOrgIntelAcceptWithdrawRoundTrip(t *testing.T) {
	f := newOrgIntelFixture(t, orgcontract.TenancyIndividual, true)
	r := httptest.NewRequest("GET", "/api/intel/status", nil)

	st, err := f.d.Status(r)
	if err != nil {
		t.Fatal(err)
	}
	if st.Class != orgintel.ClassIndividual || !st.Pending || st.PendingReason != orgintel.PendingNotAccepted || st.Disclosure == "" || len(st.DisclosureDigest) != 64 {
		t.Fatalf("initial status = %+v", st)
	}
	if strings.Contains(st.Disclosure, "\u2014") {
		t.Fatal("the disclosure carries an em dash")
	}

	if _, err := f.d.Accept(r, strings.Repeat("0", 64)); !errors.Is(err, dashapi.ErrOrgIntelConflict) {
		t.Fatalf("stale digest err = %v, want a conflict", err)
	}
	got, err := f.d.Accept(r, st.DisclosureDigest)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if got.Pending || !got.EffectiveOptIn || !got.Covered || got.Active == nil || got.Active.EvidenceLevel != "titles" || got.Active.DisclosureDigest != st.DisclosureDigest {
		t.Fatalf("after accept = %+v", got)
	}
	if on, _ := loadConfigOptIn(f.cfgPath); !on {
		t.Fatal("accept did not turn [intelligence].org_enrichment on")
	}

	got, err = f.d.Withdraw(r)
	if err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if !got.Pending || got.EffectiveOptIn || got.Active != nil || len(got.History) != 2 {
		t.Fatalf("after withdraw = %+v", got)
	}
	if on, _ := loadConfigOptIn(f.cfgPath); on {
		t.Fatal("withdraw left [intelligence].org_enrichment on")
	}
}

// TestOrgIntelManagedIsNoticeOnly: a managed node is shown a notice (written
// once per document version), and accept / withdraw are conflicts.
func TestOrgIntelManagedIsNoticeOnly(t *testing.T) {
	f := newOrgIntelFixture(t, orgcontract.TenancyManaged, false)
	r := httptest.NewRequest("GET", "/api/intel/status", nil)
	for i := 0; i < 2; i++ {
		st, err := f.d.Status(r)
		if err != nil {
			t.Fatal(err)
		}
		if !st.NoticeOnly || st.Pending || st.EffectiveOptIn {
			t.Fatalf("managed status = %+v", st)
		}
	}
	recs, _ := f.st.OrgIntelReceipts(context.Background(), 0)
	if len(recs) != 1 || recs[0].Kind != store.OrgIntelReceiptNoticeShown {
		t.Fatalf("notice receipts = %+v", recs)
	}
	if _, err := f.d.Accept(r, "x"); !errors.Is(err, dashapi.ErrOrgIntelConflict) {
		t.Fatalf("managed accept err = %v", err)
	}
	if _, err := f.d.Withdraw(r); !errors.Is(err, dashapi.ErrOrgIntelConflict) {
		t.Fatalf("managed withdraw err = %v", err)
	}
}

// TestOrgIntelLocalOptInNeedsConsent pins INV-13 at the rail gate: on an
// individual node a hand-edited config key alone does not open the org plane.
func TestOrgIntelLocalOptInNeedsConsent(t *testing.T) {
	ctx := context.Background()
	f := newOrgIntelFixture(t, orgcontract.TenancyIndividual, false)
	if orgIntelLocalOptIn(ctx, f.st, true) {
		t.Fatal("config key alone opened the individual org plane")
	}
	r := httptest.NewRequest("GET", "/api/intel/status", nil)
	st, _ := f.d.Status(r)
	if _, err := f.d.Accept(r, st.DisclosureDigest); err != nil {
		t.Fatal(err)
	}
	if !orgIntelLocalOptIn(ctx, f.st, true) {
		t.Fatal("config key + consent did not open the individual org plane")
	}
	if orgIntelLocalOptIn(ctx, f.st, false) {
		t.Fatal("consent without the config key opened the org plane")
	}
	// A managed node's input is the config key (the govern table merges it).
	m := newOrgIntelFixture(t, orgcontract.TenancyManaged, false)
	if !orgIntelLocalOptIn(ctx, m.st, true) || orgIntelLocalOptIn(ctx, m.st, false) {
		t.Fatal("managed local opt-in is not the config key")
	}
}

// TestLiveOrgEnrichmentFollowsTheFile: the daemon's live reader sees an
// accept written after start.
func TestLiveOrgEnrichmentFollowsTheFile(t *testing.T) {
	f := newOrgIntelFixture(t, orgcontract.TenancyIndividual, false)
	live := newLiveOrgEnrichment(f.cfgPath, false)
	if live.Get() {
		t.Fatal("initial value on")
	}
	if err := setOrgEnrichmentKey(f.cfgPath, true); err != nil {
		t.Fatal(err)
	}
	live.invalidate()
	if !live.Get() {
		t.Fatal("live reader missed the write")
	}
}

// TestIntelStatusCLI: `observer intel status` renders the pending line.
func TestIntelStatusCLI(t *testing.T) {
	f := newOrgIntelFixture(t, orgcontract.TenancyIndividual, true)
	snap, err := loadOrgIntelSnapshot(context.Background(), f.st, false, time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	printOrgIntelStatus(&out, snap, nil)
	s := out.String()
	for _, want := range []string{"Organization: Acme (individual tenancy)", "PENDING", "observer intel accept", "Deadline:"} {
		if !strings.Contains(s, want) {
			t.Fatalf("status output missing %q:\n%s", want, s)
		}
	}
}
