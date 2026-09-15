package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudgateway"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestComputeCommunityMonthMetrics pins the pure metric math: sessions per
// ACTIVE day (days with sessions), and verification coverage as a percentage.
func TestComputeCommunityMonthMetrics(t *testing.T) {
	tests := []struct {
		name      string
		daily     []store.StructuralDayFacts
		wantSPD   float64 // sessions_per_active_day; -1 = must be absent
		wantVerif float64 // verification_coverage_pct; -1 = must be absent
	}{
		{
			name:      "empty month contributes nothing",
			daily:     nil,
			wantSPD:   -1,
			wantVerif: -1,
		},
		{
			name: "all-idle days contribute nothing",
			daily: []store.StructuralDayFacts{
				{SessionCount: 0},
				{SessionCount: 0},
			},
			wantSPD:   -1,
			wantVerif: -1,
		},
		{
			name: "two active days, mixed verification",
			daily: []store.StructuralDayFacts{
				{SessionCount: 4, SessionsWithVerification: 2},
				{SessionCount: 0}, // idle day is NOT an active day
				{SessionCount: 6, SessionsWithVerification: 3},
			},
			// 10 sessions over 2 active days = 5.0; 5 verified of 10 = 50%.
			wantSPD:   5.0,
			wantVerif: 50.0,
		},
		{
			name: "single active day, no verification",
			daily: []store.StructuralDayFacts{
				{SessionCount: 3, SessionsWithVerification: 0},
			},
			wantSPD:   3.0,
			wantVerif: 0.0, // present (there were sessions), just zero
		},
		{
			// Sol review F11: the hosted registry's band edges are defined
			// against sessions_per_active_day ROUNDED to one decimal upstream,
			// so uploading the raw division risks landing a value on the wrong
			// side of an edge from where its rounded form belongs. 7 sessions
			// over 3 active days = 2.3333... which must round to 2.3, not ship
			// as the unrounded value.
			name: "non-terminating sessions-per-day division rounds to one decimal",
			daily: []store.StructuralDayFacts{
				{SessionCount: 3, SessionsWithVerification: 0},
				{SessionCount: 2, SessionsWithVerification: 0},
				{SessionCount: 2, SessionsWithVerification: 0},
			},
			wantSPD:   2.3,
			wantVerif: 0.0,
		},
		{
			// Sol review F11's second half: verification_coverage_pct is NOT
			// documented as rounded upstream (unlike sessions_per_active_day)
			// and its band edges are not sub-integer, so the raw non-terminating
			// division (1 of 3 = 33.333...%) must ship UNROUNDED — pinning this
			// distinguishes "we chose not to round" from "we forgot to".
			name: "verification coverage ships unrounded",
			daily: []store.StructuralDayFacts{
				{SessionCount: 3, SessionsWithVerification: 1},
			},
			wantSPD:   3.0,
			wantVerif: 100.0 / 3.0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := computeCommunityMonthMetrics(tc.daily)
			assertMetric(t, got, communityMetricSessionsPerDay, tc.wantSPD)
			assertMetric(t, got, communityMetricVerifCoverage, tc.wantVerif)
		})
	}
}

// TestCloudCommunityEligibleWindow is the "eligibility-window-skips-grant-month"
// regression for Sol review F6: a grant created on, say, 2026-09-20 must never
// authorize contributing THAT month's scalar, because days from 2026-09-01
// through 2026-09-19 — before the grant existed — would otherwise be folded
// into it. The first eligible month is the first one that STARTS AFTER the
// grant's own creation month.
func TestCloudCommunityEligibleWindow(t *testing.T) {
	tests := []struct {
		name      string
		grantedAt time.Time
		now       time.Time
		want      bool
	}{
		{
			name:      "grant's own creation month is never eligible",
			grantedAt: time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC),
			now:       time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC),
			want:      false,
		},
		{
			name:      "grant's own creation month, checked later in that same month",
			grantedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
			now:       time.Date(2026, 9, 30, 23, 59, 59, 0, time.UTC),
			want:      false,
		},
		{
			name:      "the immediately following month is eligible",
			grantedAt: time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC),
			now:       time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
			want:      true,
		},
		{
			name:      "a month further beyond the grant is eligible",
			grantedAt: time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC),
			now:       time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC),
			want:      true,
		},
		{
			name:      "year boundary: grant in December, check December itself is NOT eligible",
			grantedAt: time.Date(2026, 12, 15, 0, 0, 0, 0, time.UTC),
			now:       time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC),
			want:      false,
		},
		{
			name:      "year boundary: grant in December, January of the next year IS eligible",
			grantedAt: time.Date(2026, 12, 15, 0, 0, 0, 0, time.UTC),
			now:       time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
			want:      true,
		},
		{
			name:      "non-UTC input is normalized before comparing (same instant, offset clocks)",
			grantedAt: time.Date(2026, 9, 20, 23, 0, 0, 0, time.FixedZone("UTC-5", -5*3600)),
			now:       time.Date(2026, 9, 21, 6, 0, 0, 0, time.FixedZone("UTC+8", 8*3600)),
			want:      false, // both instants land in UTC September, still the grant month
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := cloudCommunityEligibleWindow(tc.grantedAt, tc.now)
			if got != tc.want {
				t.Errorf("cloudCommunityEligibleWindow(%s, %s) = %v, want %v",
					tc.grantedAt, tc.now, got, tc.want)
			}
		})
	}
}

func assertMetric(t *testing.T, got map[string]float64, id string, want float64) {
	t.Helper()
	v, ok := got[id]
	if want < 0 {
		if ok {
			t.Fatalf("%s: present (%v), want absent", id, v)
		}
		return
	}
	if !ok {
		t.Fatalf("%s: absent, want %v", id, want)
	}
	if v != want {
		t.Fatalf("%s = %v, want %v", id, v, want)
	}
}

// --- Sol re-review (2026-09-02) node fixes: N1 / N2 / N5 / N8 / F9 ----------

// cloudCommunityMonthAnchor is an instant safely inside the CURRENT UTC month
// (noon on the 1st), so a session seeded there is contributed this month
// regardless of when the test runs.
func cloudCommunityMonthAnchor() time.Time {
	now := time.Now().UTC()
	return time.Date(now.Year(), now.Month(), 1, 12, 0, 0, 0, time.UTC)
}

// seedCloudCommunityGrant records a live STANDING community grant created at
// createdAt, bound to the fake server's community endpoint, under the given
// source-window rule + data-dictionary digest (so a test can seed a receipt
// under RETIRED terms as well as current ones).
func seedCloudCommunityGrant(t *testing.T, st *store.Store, baseURL string, createdAt time.Time, rule, dict string) string {
	t.Helper()
	reviewAt := createdAt.AddDate(0, cloudStandingGrantReviewMonths, 0)
	id, err := st.InsertCloudConsentReceipt(context.Background(), store.CloudConsentReceipt{
		AccountPseudonym:       "acct-test",
		Purpose:                string(cloudcontract.PurposeCohortBenchmarking),
		FieldClassesJSON:       cloudStandingFieldClassesJSON(cloudcontract.PurposeCohortBenchmarking),
		EnvelopeSchemaVersion:  cloudcontract.CommunityContributionSchemaVersion,
		ScrubberVersion:        cloudScrubberVersion,
		Endpoint:               baseURL + "/v1/community/contribution",
		RetentionPolicyVersion: cloudRetentionPolicyVersion,
		UploadDigest:           dict,
		DataDictionaryDigest:   dict,
		CreatedAt:              createdAt,
		GrantMode:              store.CloudGrantStanding,
		DeclaredTimezone:       "UTC",
		SourceWindowRule:       rule,
		ReviewAt:               &reviewAt,
		ConsentGeneration:      1,
	})
	if err != nil {
		t.Fatalf("seed community grant: %v", err)
	}
	return id
}

// cloudCommunityFixture seeds a sendable community month: a grant created LAST
// month (so this month is eligible) under CURRENT terms, and one personal
// session this month. Returns (cfgPath, dbPath, receiptID).
func cloudCommunityFixture(t *testing.T, f *fakeCloudServer) (string, string, string) {
	t.Helper()
	cfgPath, dbPath, _ := writeCloudTestConfig(t)
	seedCloudSessionAt(t, dbPath, "s-this-month", cloudCommunityMonthAnchor())
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	id := seedCloudCommunityGrant(t, st, f.srv.URL, cloudCommunityMonthAnchor().AddDate(0, -1, 0),
		cloudCommunitySourceWindowRule, cloudcontract.CommunityDataDictionaryDigest())
	cloudTestLogin(t, f, cfgPath)
	return cfgPath, dbPath, id
}

// cloudTestLogin signs the CLI's credential store in against the fake server.
func cloudTestLogin(t *testing.T, f *fakeCloudServer, cfgPath string) {
	t.Helper()
	if out, err := runCloudCmd(t, "login", "--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "wtok"); err != nil {
		t.Fatalf("login: %v\n%s", err, out)
	}
}

// TestCloudSyncCommunityDeclaresTheSourceWindowRuleOnTheWire is the N1 wire
// half: the community upload must carry the receipt's source-window rule AND
// its (UTC-fixed) declared timezone as standing-grant binding headers, beside
// the generation + dictionary digest it already carried, and the rule must be
// the truthful in-progress-month one.
func TestCloudSyncCommunityDeclaresTheSourceWindowRuleOnTheWire(t *testing.T) {
	f := newFakeCloudServer(t)
	cfgPath, _, _ := cloudCommunityFixture(t, f)

	out, err := runCloudCmd(t, "sync", "--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "wtok")
	if err != nil {
		t.Fatalf("sync: %v\n%s", err, out)
	}
	if f.communityUploads != 2 {
		t.Fatalf("community uploads = %d, want 2 (one per metric)\n%s", f.communityUploads, out)
	}
	for i, h := range f.communityHeaders {
		for header, want := range map[string]string{
			"SBO-Consent-Generation":     "1",
			"SBO-Data-Dictionary-Digest": cloudcontract.CommunityDataDictionaryDigest(),
			"SBO-Source-Window-Rule":     "in_progress_utc_month_after_grant",
			"SBO-Declared-Timezone":      "UTC",
		} {
			if got := h.Get(header); got != want {
				t.Errorf("upload %d: %s = %q, want %q", i, header, got, want)
			}
		}
	}
	if cloudCommunitySourceWindowRule != "in_progress_utc_month_after_grant" {
		t.Errorf("cloudCommunitySourceWindowRule = %q — the rule id must say what egress does", cloudCommunitySourceWindowRule)
	}
}

// TestCloudSyncCommunityRefusesAReceiptUnderRetiredTerms is the N1 consent-
// terms bump: a community receipt recorded under the old
// "completed_utc_months_after_grant" rule (and the dictionary digest that
// rule was part of) is NOT live for community egress any more — sync must
// say it needs reconfirmation and send nothing.
func TestCloudSyncCommunityRefusesAReceiptUnderRetiredTerms(t *testing.T) {
	f := newFakeCloudServer(t)
	cfgPath, dbPath, _ := writeCloudTestConfig(t)
	seedCloudSessionAt(t, dbPath, "s-this-month", cloudCommunityMonthAnchor())
	st, cleanup := openCloudTestStore(t, dbPath)
	seedCloudCommunityGrant(t, st, f.srv.URL, cloudCommunityMonthAnchor().AddDate(0, -1, 0),
		"completed_utc_months_after_grant", "sha256:the-dictionary-the-old-rule-was-part-of")
	cleanup()
	cloudTestLogin(t, f, cfgPath)

	out, err := runCloudCmd(t, "sync", "--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "wtok")
	if err != nil {
		t.Fatalf("sync: %v\n%s", err, out)
	}
	if f.communityAttempts != 0 {
		t.Fatalf("a contribution left the machine under retired terms (%d attempt(s))\n%s", f.communityAttempts, out)
	}
	if !strings.Contains(out, "NEEDS RECONFIRMATION") || !strings.Contains(out, "consent grant --purpose community_cohort_benchmarking") {
		t.Fatalf("sync did not explain that the old-terms grant needs reconfirmation:\n%s", out)
	}
}

// TestCloudConsentGrantCommunityIsUTCFixed is N5: the community purpose refuses
// a non-UTC --timezone with a clear error, records "UTC" whatever the host's
// zone is, and says so on the binding screen.
func TestCloudConsentGrantCommunityIsUTCFixed(t *testing.T) {
	f := newFakeCloudServer(t)
	cfgPath, dbPath, _ := writeCloudTestConfig(t)
	t.Setenv("TZ", "Asia/Kolkata")

	out, err := runCloudCmd(t, "consent", "grant", "--config", cfgPath, "--base-url", f.srv.URL,
		"--purpose", string(cloudcontract.PurposeCohortBenchmarking), "--timezone", "Asia/Kolkata", "--yes")
	if err == nil {
		t.Fatalf("a non-UTC --timezone was accepted for the community purpose:\n%s", out)
	}
	if !strings.Contains(err.Error(), "UTC") || !strings.Contains(err.Error(), "Asia/Kolkata") {
		t.Fatalf("the refusal must name the zone and say the purpose is UTC-fixed: %v", err)
	}
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	if live, _ := st.ListLiveCloudConsentReceipts(context.Background(), string(cloudcontract.PurposeCohortBenchmarking)); len(live) != 0 {
		t.Fatalf("a refused grant still recorded %d receipt(s)", len(live))
	}

	// No --timezone on a non-UTC host: UTC is recorded, not the host zone.
	out, err = runCloudCmd(t, "consent", "grant", "--config", cfgPath, "--base-url", f.srv.URL,
		"--purpose", string(cloudcontract.PurposeCohortBenchmarking), "--yes")
	if err != nil {
		t.Fatalf("grant: %v\n%s", err, out)
	}
	if !strings.Contains(out, "declared timezone:        UTC") {
		t.Fatalf("the binding screen did not show UTC:\n%s", out)
	}
	if strings.Contains(out, "Asia/Kolkata") {
		t.Fatalf("the host zone leaked into a UTC-fixed binding:\n%s", out)
	}
	live, err := st.ListLiveCloudConsentReceipts(context.Background(), string(cloudcontract.PurposeCohortBenchmarking))
	if err != nil || len(live) != 1 {
		t.Fatalf("live community receipts = %d (err=%v), want 1", len(live), err)
	}
	if live[0].DeclaredTimezone != "UTC" {
		t.Fatalf("recorded declared timezone %q, want UTC", live[0].DeclaredTimezone)
	}
	if live[0].SourceWindowRule != "in_progress_utc_month_after_grant" {
		t.Fatalf("recorded source window rule %q, want the in-progress-month rule", live[0].SourceWindowRule)
	}
	// An explicit --timezone UTC is fine.
	if out, err := runCloudCmd(t, "consent", "grant", "--config", cfgPath, "--base-url", f.srv.URL,
		"--purpose", string(cloudcontract.PurposeCohortBenchmarking), "--timezone", "UTC", "--yes"); err != nil {
		t.Fatalf("--timezone UTC refused: %v\n%s", err, out)
	}
}

// TestCloudConsentGrantCommunityDisclosureSaysWhatEgressDoes pins the N1
// disclosure/binding copy: in-progress UTC month, re-sent each sync until close,
// frozen after, grant month never eligible — and never "completed month".
func TestCloudConsentGrantCommunityDisclosureSaysWhatEgressDoes(t *testing.T) {
	f := newFakeCloudServer(t)
	cfgPath, _, _ := writeCloudTestConfig(t)
	out, err := runCloudCmd(t, "consent", "grant", "--config", cfgPath, "--base-url", f.srv.URL,
		"--purpose", string(cloudcontract.PurposeCohortBenchmarking), "--yes")
	if err != nil {
		t.Fatalf("grant: %v\n%s", err, out)
	}
	for _, want := range []string{
		"in_progress_utc_month_after_grant",
		"IN-PROGRESS UTC calendar month",
		"re-sent on every sync until that month closes",
		"frozen",
		"month you grant in is never contributed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the community binding screen never said %q:\n%s", want, out)
		}
	}
	for _, never := range []string{"completed calendar month", "COMPLETE UTC month", "completed_utc_months"} {
		if strings.Contains(out, never) {
			t.Errorf("the community binding screen still says %q, which is not what egress does:\n%s", never, out)
		}
	}
}

// TestCloudSyncCommunityExplainsCrossDeviceConflict is F9's CLI half: a 409
// cross_device_conflict must be turned into a recovery action — sync from the
// owning device, or wait for the next window — using the hints the server
// carries in its body when present.
func TestCloudSyncCommunityExplainsCrossDeviceConflict(t *testing.T) {
	f := newFakeCloudServer(t)
	cfgPath, _, _ := cloudCommunityFixture(t, f)
	f.communityStatus = http.StatusConflict
	f.communityBody = `{"code":"cross_device_conflict","error":"this contribution window was already synced from a different device on this account","owner_device_hint":"dev-A1B2","next_window":"2099-01"}`

	out, err := runCloudCmd(t, "sync", "--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "wtok")
	if err != nil {
		t.Fatalf("sync: %v\n%s", err, out)
	}
	for _, want := range []string{
		"already synced from a different device",
		"dev-A1B2",
		"2099-01",
		"sync from that device",
		"wait for the next window",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the conflict report never said %q:\n%s", want, out)
		}
	}
	if f.communityUploads != 0 {
		t.Fatalf("a conflicted contribution was counted as accepted")
	}
}

// countingTransport counts the requests that actually reach the wire for one
// path — the "did bytes leave the machine?" counter for the barrier tests —
// and can hold a request at the socket (after the lease was taken) until the
// test releases it.
type countingTransport struct {
	base     http.RoundTripper
	path     string
	count    int
	holdAt   chan struct{} // closed by the transport when it reaches path (optional)
	resumeAt chan struct{} // the transport waits on this before dispatching (optional)
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path == c.path {
		if c.holdAt != nil {
			close(c.holdAt)
			c.holdAt = nil
			<-c.resumeAt
		}
		c.count++
	}
	return c.base.RoundTrip(r)
}

// cloudCommunityGatewayWithTransport builds a gateway over st whose network
// client uses rt, signed in against f.
func cloudCommunityGatewayWithTransport(t *testing.T, st *store.Store, f *fakeCloudServer, rt http.RoundTripper, retries int) *cloudgateway.Gateway {
	t.Helper()
	gw, err := cloudgateway.Open(cloudgateway.Options{
		Grants:     st,
		CredDir:    t.TempDir(),
		BaseURL:    f.srv.URL,
		DevToken:   "wtok",
		HTTPClient: &http.Client{Transport: rt},
		MaxRetries: retries,
		Backoff:    func(int) time.Duration { return 0 },
	})
	if err != nil {
		t.Fatalf("open gateway: %v", err)
	}
	if err := gw.BootstrapExchange(context.Background()); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	return gw
}

// cloudCommunityUploadFor builds the production-shaped community upload for a
// resolved grant, with the PRODUCTION lease hook and a caller-supplied
// PreAttempt (the barrier).
func cloudCommunityUploadFor(st *store.Store, grant cloudgateway.Grant, pre func() error) cloudgateway.CommunityUploadRequest {
	return cloudgateway.CommunityUploadRequest{
		Payload:              []byte(`{"x":1}`),
		Digest:               "sha256:x",
		ConsentGeneration:    grant.ConsentGeneration,
		DataDictionaryDigest: grant.DataDictionaryDigest,
		SourceWindowRule:     grant.SourceWindowRule,
		DeclaredTimezone:     grant.DeclaredTimezone,
		Endpoint:             grant.Endpoint,
		PreAttempt:           pre,
		DispatchLease:        cloudDispatchLeaseFor(st, grant.ReceiptID, cloudcontract.PurposeCohortBenchmarking, grant.ConsentGeneration),
	}
}

// TestCloudCommunityRevokeBetweenPreAttemptAndDispatchSendsNothing is the N2
// barrier test: the sender is PAUSED between its PreAttempt re-check and the
// physical send; `observer cloud consent revoke` runs meanwhile in the real
// CLI (its own DB handle — a separate process in production) and returns;
// the sender resumes — and NO bytes leave, because the dispatch lease it
// then asks for is refused under the revoked receipt.
func TestCloudCommunityRevokeBetweenPreAttemptAndDispatchSendsNothing(t *testing.T) {
	f := newFakeCloudServer(t)
	cfgPath, dbPath, _ := cloudCommunityFixture(t, f)
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	ctx := context.Background()
	rt := &countingTransport{base: http.DefaultTransport, path: "/v1/community/contribution"}
	gw := cloudCommunityGatewayWithTransport(t, st, f, rt, 0)
	grant, err := gw.ResolveStandingGrant(ctx, cloudcontract.PurposeCohortBenchmarking)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	atPre := make(chan struct{})
	resume := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- gw.StandingSendCommunity(ctx, cloudcontract.PurposeCohortBenchmarking, func(s cloudgateway.CommunitySession) error {
			_, uerr := s.UploadCommunity(ctx, cloudCommunityUploadFor(st, grant, func() error {
				close(atPre) // PreAttempt passed …
				<-resume     // … and the sender is descheduled here, before the socket
				return nil
			}))
			return uerr
		})
	}()
	<-atPre

	out, err := runCloudCmd(t, "consent", "revoke", "--config", cfgPath,
		"--purpose", string(cloudcontract.PurposeCohortBenchmarking))
	if err != nil {
		t.Fatalf("revoke: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Nothing further will be sent") {
		t.Fatalf("revoke did not make its promise:\n%s", out)
	}
	close(resume)

	select {
	case serr := <-result:
		if !errors.Is(serr, store.ErrCloudDispatchRefused) {
			t.Fatalf("the resumed sender did not refuse dispatch under the revoked receipt: %v", serr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the sender never returned")
	}
	if rt.count != 0 || f.communityAttempts != 0 {
		t.Fatalf("bytes left the machine after revoke returned: transport=%d server=%d", rt.count, f.communityAttempts)
	}
	if n, _ := st.CountActiveCloudDispatchLeases(ctx, []string{grant.ReceiptID}); n != 0 {
		t.Fatalf("%d lease(s) still active under the revoked receipt", n)
	}
}

// TestCloudCommunityRevokeWaitsForAnInFlightDispatch is the other half of N2:
// when the sender already HOLDS the lease (it is at the socket), revoke must
// NOT return until that attempt has finished — so its promise is never made
// while a send under the old receipt is still in flight.
func TestCloudCommunityRevokeWaitsForAnInFlightDispatch(t *testing.T) {
	f := newFakeCloudServer(t)
	cfgPath, dbPath, _ := cloudCommunityFixture(t, f)
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	ctx := context.Background()
	rt := &countingTransport{
		base: http.DefaultTransport, path: "/v1/community/contribution",
		holdAt: make(chan struct{}), resumeAt: make(chan struct{}),
	}
	atSocket := rt.holdAt
	gw := cloudCommunityGatewayWithTransport(t, st, f, rt, 0)
	grant, err := gw.ResolveStandingGrant(ctx, cloudcontract.PurposeCohortBenchmarking)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	result := make(chan error, 1)
	go func() {
		result <- gw.StandingSendCommunity(ctx, cloudcontract.PurposeCohortBenchmarking, func(s cloudgateway.CommunitySession) error {
			_, uerr := s.UploadCommunity(ctx, cloudCommunityUploadFor(st, grant, func() error { return nil }))
			return uerr
		})
	}()
	<-atSocket // the lease is held; the request is about to be written

	revoked := make(chan string, 1)
	go func() {
		out, err := runCloudCmd(t, "consent", "revoke", "--config", cfgPath,
			"--purpose", string(cloudcontract.PurposeCohortBenchmarking))
		if err != nil {
			t.Errorf("revoke: %v\n%s", err, out)
		}
		revoked <- out
	}()
	select {
	case out := <-revoked:
		t.Fatalf("revoke returned while a send under the receipt was still in flight:\n%s", out)
	case <-time.After(400 * time.Millisecond):
	}
	close(rt.resumeAt) // the in-flight attempt completes and releases its lease
	select {
	case out := <-revoked:
		if !strings.Contains(out, "Waited for 1 in-flight send(s)") {
			t.Fatalf("revoke did not report the in-flight send it waited for:\n%s", out)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("revoke never returned after the lease was released")
	}
	if serr := <-result; serr != nil {
		t.Fatalf("the in-flight send (which began before revoke) failed: %v", serr)
	}
	if rt.count != 1 || f.communityUploads != 1 {
		t.Fatalf("in-flight send: transport=%d accepted=%d, want 1 and 1", rt.count, f.communityUploads)
	}
}

// TestCloudSyncCommunityRefusesAReceiptReplacedBetweenResolveAndAttempt is
// the N8 exact-receipt test through the production rail: a NEWER standing
// receipt for the purpose appears after cloudSyncCommunity resolved the grant
// it built its bytes under and before the next attempt. The re-check must
// refuse — the terms on the wire would belong to a receipt that is no longer
// the one authorizing the send — and nothing further may be sent.
func TestCloudSyncCommunityRefusesAReceiptReplacedBetweenResolveAndAttempt(t *testing.T) {
	f := newFakeCloudServer(t)
	f.srv.Config.SetKeepAlivesEnabled(false) // see TestCloudDrainStructuralRechecksAuthorizationBeforeEveryAttempt
	_, dbPath, _ := cloudCommunityFixture(t, f)
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	ctx := context.Background()
	gw := cloudCommunityGatewayWithTransport(t, st, f, http.DefaultTransport, 1)

	f.communityHook = func(attempt int) {
		if attempt > 1 {
			t.Errorf("attempt %d: a contribution was sent after the receipt was replaced", attempt)
			return
		}
		// A second, NEWER live standing receipt for the purpose (the shape a
		// re-run `consent grant` mints), through a separate store handle —
		// inserted directly so the OLD receipt stays live and only the
		// exact-receipt check (not the gateway's any-live-grant re-check) can
		// catch the swap.
		st2, cleanup2 := openCloudTestStore(t, dbPath)
		defer cleanup2()
		review := time.Now().UTC().AddDate(1, 0, 0)
		if _, err := st2.InsertCloudConsentReceipt(context.Background(), store.CloudConsentReceipt{
			AccountPseudonym: "acct-test", Purpose: string(cloudcontract.PurposeCohortBenchmarking),
			EnvelopeSchemaVersion: cloudcontract.CommunityContributionSchemaVersion,
			Endpoint:              f.srv.URL + "/v1/community/contribution",
			UploadDigest:          cloudcontract.CommunityDataDictionaryDigest(),
			DataDictionaryDigest:  cloudcontract.CommunityDataDictionaryDigest(),
			CreatedAt:             time.Now().UTC(), GrantMode: store.CloudGrantStanding,
			DeclaredTimezone: "UTC", SourceWindowRule: cloudCommunitySourceWindowRule,
			ReviewAt: &review, ConsentGeneration: 2,
		}); err != nil {
			t.Errorf("insert newer receipt: %v", err)
		}
		panic(http.ErrAbortHandler) // a retryable transport fault → the retry must be refused
	}

	var buf bytes.Buffer
	cloudSyncCommunity(ctx, st, gw, time.Now(), &buf)
	if f.communityAttempts != 1 {
		t.Fatalf("the community route saw %d attempt(s), want exactly 1\n%s", f.communityAttempts, buf.String())
	}
	if f.communityUploads != 0 {
		t.Fatalf("a contribution was accepted after the receipt was replaced\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "the standing grant changed since this sync started") {
		t.Fatalf("sync did not name the exact-receipt refusal:\n%s", buf.String())
	}
}
