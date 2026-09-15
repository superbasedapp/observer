package api_test

import (
	"net/http"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

// portalinsights_test.go covers the two W2 BFF reads: auth, empty states, and
// that what the portal serves is exactly what the account's own devices
// uploaded — never another tenant's, and never a fabricated zero.

type insightsBody struct {
	Window struct {
		From    string `json:"from"`
		To      string `json:"to"`
		Days    int    `json:"days"`
		Devices int    `json:"devices"`
	} `json:"window"`
	Days []struct {
		Period       string `json:"period"`
		SessionCount int    `json:"session_count"`
		DeviceCount  int    `json:"device_count"`
	} `json:"days"`
	Summary struct {
		ActiveDays               int     `json:"active_days"`
		SessionCount             int     `json:"session_count"`
		ActionCount              int     `json:"action_count"`
		TokensIn                 int64   `json:"tokens_in"`
		CostUSD                  float64 `json:"cost_usd"`
		VerificationCoverageBand string  `json:"verification_coverage_band"`
		MaxDeviceCount           int     `json:"max_device_count"`
		FirstDay                 string  `json:"first_day"`
		LastDay                  string  `json:"last_day"`
		ToolMix                  []struct {
			Key   string `json:"key"`
			Count int    `json:"count"`
		} `json:"tool_mix"`
	} `json:"summary"`
	Coverage struct {
		Devices   int    `json:"devices"`
		Snapshots int    `json:"snapshots"`
		FirstDay  string `json:"first_day"`
		LastDay   string `json:"last_day"`
		Days      int    `json:"days"`
	} `json:"coverage"`
	Enrichment struct {
		JobsTotal    int    `json:"jobs_total"`
		ResultsTotal int    `json:"results_total"`
		Disclosure   string `json:"disclosure"`
	} `json:"enrichment"`
	StructuralDisclosure string `json:"structural_disclosure"`
}

type grantsBody struct {
	Grants []struct {
		Purpose              string   `json:"purpose"`
		FieldClasses         []string `json:"field_classes"`
		SchemaVersion        string   `json:"schema_version"`
		DataDictionaryDigest string   `json:"data_dictionary_digest"`
		DictionaryCurrent    bool     `json:"dictionary_current"`
		ConsentGeneration    int64    `json:"consent_generation"`
		DeclaredTimezone     string   `json:"declared_timezone"`
		SourceWindowRule     string   `json:"source_window_rule"`
		State                string   `json:"state"`
	} `json:"grants"`
	CurrentSchemaVersion  string `json:"current_schema_version"`
	CurrentDataDictionary string `json:"current_data_dictionary"`
	RetentionState        string `json:"retention_state"`
	RetentionDetail       string `json:"retention_detail"`
	StoredSnapshots       int    `json:"stored_snapshots"`
	StoredAccountDays     int    `json:"stored_account_days"`
	Devices               int    `json:"contributing_device_count"`
}

// TestPortalInsightsRequiresASession is the auth wall: no cookie, no data.
func TestPortalInsightsRequiresASession(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/portal/api/insights", "/portal/api/grants"} {
		resp, err := h.srv.Client().Get(h.srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("GET %s without a session = %d, want 401 (body=%s)", path, resp.StatusCode, readAll(resp))
		}
	}
}

// TestPortalInsightsEmptyState pins the honesty rule: an account with no synced
// window gets ZERO day rows and an explicit disclosure, never a run of
// fabricated zero-valued days.
func TestPortalInsightsEmptyState(t *testing.T) {
	h := newHarness(t)
	pc := h.portalLogin(t, "insights-empty")

	resp := pc.get("/portal/api/insights")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("insights status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var b insightsBody
	decode(t, resp, &b)
	if len(b.Days) != 0 {
		t.Fatalf("a fresh account got %d fabricated day rows: %+v", len(b.Days), b.Days)
	}
	if b.Summary.ActiveDays != 0 || b.Summary.SessionCount != 0 {
		t.Fatalf("fresh summary is not empty: %+v", b.Summary)
	}
	if b.Summary.VerificationCoverageBand != string(cloudcontract.CoverageBandNone) {
		t.Fatalf("empty summary band = %q, want none", b.Summary.VerificationCoverageBand)
	}
	if b.Coverage.Devices != 0 || b.Coverage.Snapshots != 0 || b.Coverage.Days != 0 {
		t.Fatalf("fresh coverage is not empty: %+v", b.Coverage)
	}
	if b.StructuralDisclosure == "" || b.Enrichment.Disclosure == "" {
		t.Fatal("both disclosure strings must be served on every response")
	}
	if b.Window.Days != 30 {
		t.Fatalf("default window = %d days, want 30", b.Window.Days)
	}

	// Grants: empty too, but the CURRENT schema facts are always stated so the
	// page can say what a grant would bind before one exists.
	resp = pc.get("/portal/api/grants")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("grants status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var g grantsBody
	decode(t, resp, &g)
	if len(g.Grants) != 0 {
		t.Fatalf("a fresh account has registered grants: %+v", g.Grants)
	}
	if g.CurrentSchemaVersion != cloudcontract.StructuralSnapshotSchemaVersion ||
		g.CurrentDataDictionary != cloudcontract.StructuralDataDictionaryDigest() {
		t.Fatalf("grants response does not state the current schema facts: %+v", g)
	}
	if g.RetentionState == "" || g.RetentionDetail == "" {
		t.Fatal("the retention state must always be stated")
	}
}

// TestPortalInsightsServesTheUploadedCorpus wires the two halves together: a
// device uploads, the portal session for the SAME account sees it, and the
// grant page restates the registration.
func TestPortalInsightsServesTheUploadedCorpus(t *testing.T) {
	h := newHarness(t)
	device := h.login(t, "insights-real")
	pc := h.portalLogin(t, "insights-real")
	if pc.accountID != device.accountID {
		t.Fatalf("fixture broke: the portal and device sessions are different accounts")
	}

	// Two days, one of them re-revised, so both the day list and the summary
	// have something non-trivial to be right about.
	today := timeNowUTCDay(0)
	yesterday := timeNowUTCDay(-1)
	ackOf(t, device.upload(seal(t, baseSnapshot(yesterday, 1, 2, 20))), http.StatusAccepted)
	ackOf(t, device.upload(seal(t, baseSnapshot(today, 1, 3, 30))), http.StatusAccepted)
	ackOf(t, device.upload(seal(t, baseSnapshot(today, 2, 5, 50))), http.StatusAccepted)

	resp := pc.get("/portal/api/insights")
	var b insightsBody
	decode(t, resp, &b)
	if len(b.Days) != 2 {
		t.Fatalf("portal served %d days, want 2: %+v", len(b.Days), b.Days)
	}
	if b.Summary.ActiveDays != 2 || b.Summary.SessionCount != 7 || b.Summary.ActionCount != 70 {
		t.Fatalf("summary did not fold the revised day correctly: %+v", b.Summary)
	}
	if b.Summary.MaxDeviceCount != 1 || b.Coverage.Devices != 1 {
		t.Fatalf("device counts wrong: summary=%+v coverage=%+v", b.Summary, b.Coverage)
	}
	if len(b.Summary.ToolMix) != 1 || b.Summary.ToolMix[0].Count != 7 {
		t.Fatalf("tool mix did not merge across days: %+v", b.Summary.ToolMix)
	}
	if b.Summary.FirstDay != yesterday || b.Summary.LastDay != today {
		t.Fatalf("summary window = %s..%s, want %s..%s", b.Summary.FirstDay, b.Summary.LastDay, yesterday, today)
	}
	// The superseded r1 is not counted: coverage counts CURRENT snapshots only.
	if b.Coverage.Snapshots != 2 {
		t.Fatalf("coverage counted superseded snapshots: %+v", b.Coverage)
	}

	resp = pc.get("/portal/api/grants")
	var g grantsBody
	decode(t, resp, &g)
	if len(g.Grants) != 1 {
		t.Fatalf("grants served %d rows, want 1: %+v", len(g.Grants), g.Grants)
	}
	gr := g.Grants[0]
	if gr.Purpose != string(cloudcontract.PurposeStructuralInsights) || gr.State != "active" {
		t.Fatalf("unexpected grant view: %+v", gr)
	}
	if len(gr.FieldClasses) != 1 || gr.FieldClasses[0] != string(cloudcontract.FieldClassStructuralMetrics) {
		t.Fatalf("field classes must be exactly structural_metrics: %+v", gr.FieldClasses)
	}
	if !gr.DictionaryCurrent || gr.SchemaVersion != cloudcontract.StructuralSnapshotSchemaVersion {
		t.Fatalf("grant does not report current schema state: %+v", gr)
	}
	if gr.ConsentGeneration != 1 || gr.DeclaredTimezone != "UTC" || gr.SourceWindowRule != testSourceWindowRule {
		t.Fatalf("grant view lost the R1 binding: %+v", gr)
	}
	if g.StoredSnapshots != 2 || g.StoredAccountDays != 2 || g.Devices != 1 {
		t.Fatalf("grant page retention counts wrong: %+v", g)
	}
}

// TestPortalInsightsIsTenantScoped: one account's upload is invisible to
// another's portal session.
func TestPortalInsightsIsTenantScoped(t *testing.T) {
	h := newHarness(t)
	device := h.login(t, "insights-owner")
	ackOf(t, device.upload(seal(t, baseSnapshot(timeNowUTCDay(0), 1, 4, 40))), http.StatusAccepted)

	stranger := h.portalLogin(t, "insights-stranger")
	if stranger.accountID == device.accountID {
		t.Fatalf("fixture broke: the stranger shares the owner's account")
	}
	var b insightsBody
	decode(t, stranger.get("/portal/api/insights"), &b)
	if len(b.Days) != 0 || b.Summary.SessionCount != 0 || b.Coverage.Snapshots != 0 {
		t.Fatalf("another tenant's corpus leaked into the portal: %+v", b)
	}
	var g grantsBody
	decode(t, stranger.get("/portal/api/grants"), &g)
	if len(g.Grants) != 0 || g.StoredSnapshots != 0 {
		t.Fatalf("another tenant's grant leaked into the portal: %+v", g)
	}
}

// TestPortalInsightsBoundsTheWindow: the days parameter is validated, not
// trusted.
func TestPortalInsightsBoundsTheWindow(t *testing.T) {
	h := newHarness(t)
	pc := h.portalLogin(t, "insights-bounds")
	for _, bad := range []string{"0", "-1", "91", "abc", "3.5"} {
		resp := pc.get("/portal/api/insights?days=" + bad)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("days=%s = %d, want 400 (body=%s)", bad, resp.StatusCode, readAll(resp))
		}
	}
	resp := pc.get("/portal/api/insights?days=7")
	var b insightsBody
	decode(t, resp, &b)
	if b.Window.Days != 7 {
		t.Fatalf("days=7 served a %d-day window", b.Window.Days)
	}
}

// TestPortalUsageCarriesPlanJobsAndResets is D20: the Usage page's payload
// keeps every /v1/usage field AND gains the plan/pool facts, the job states,
// and the two window reset boundaries.
func TestPortalUsageCarriesPlanJobsAndResets(t *testing.T) {
	h := newHarness(t)
	pc := h.portalLogin(t, "usage-d20")

	resp := pc.get("/portal/api/usage")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("usage status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var u struct {
		Feature         string         `json:"feature"`
		DailyCap        int            `json:"daily_cap"`
		MonthlyCap      int            `json:"monthly_cap"`
		Plan            string         `json:"plan"`
		PlanLabel       string         `json:"plan_label"`
		PlanVersion     int            `json:"plan_version"`
		BudgetPool      string         `json:"budget_pool"`
		Warnings        []any          `json:"warnings"`
		JobsByState     map[string]int `json:"jobs_by_state"`
		JobsTotal       int            `json:"jobs_total"`
		DailyResetsAt   string         `json:"daily_resets_at"`
		MonthlyResetsAt string         `json:"monthly_resets_at"`
		ConcurrencyNote string         `json:"concurrency_note"`
	}
	decode(t, resp, &u)

	// The pre-existing fields keep their names and meanings (additive change).
	if u.Feature == "" || u.DailyCap != 20 || u.MonthlyCap != 100 {
		t.Fatalf("the existing allowance fields changed shape: %+v", u)
	}
	if u.Plan != "free" || u.PlanLabel == "" || u.PlanVersion < 1 || u.BudgetPool != "free" {
		t.Fatalf("W4 plan/pool fields are not surfaced: %+v", u)
	}
	if u.Warnings == nil {
		t.Fatal("warnings must serialize as [] rather than null")
	}
	if u.JobsByState == nil || u.JobsTotal != 0 {
		t.Fatalf("job states not surfaced: %+v", u)
	}
	if u.DailyResetsAt == "" || u.MonthlyResetsAt == "" || u.ConcurrencyNote == "" {
		t.Fatalf("reset estimates not surfaced: %+v", u)
	}
}

// TestPortalInsightsDeviceCountMatchesTheWindow is the F13 regression. Every
// Overview card is labelled with one coverage line naming the window and a
// device count, and that count came from StructuralCoverageFor — an ALL-HISTORY
// figure. A machine that synced once and has been offline for months was
// therefore credited to a 7-day window it contributed nothing to.
//
// The two numbers now travel separately, each named for what it is:
// window.devices is measured over the SAME [from, to] the cards summarize, and
// coverage.devices stays the whole-corpus figure.
func TestPortalInsightsDeviceCountMatchesTheWindow(t *testing.T) {
	h := newHarness(t)
	recent := h.login(t, "insights-window")
	stale := h.login(t, "insights-window")
	pc := h.portalLogin(t, "insights-window")
	if recent.accountID != stale.accountID || pc.accountID != recent.accountID {
		t.Fatalf("fixture broke: the three sessions are not one account")
	}
	if recent.thumbprint == stale.thumbprint {
		t.Fatalf("fixture broke: both logins minted the same device")
	}

	// One device inside a narrow window; the other only well outside it. Both
	// are current snapshots, so both count toward all-history coverage.
	ackOf(t, recent.upload(seal(t, baseSnapshot(timeNowUTCDay(-1), 1, 2, 20))), http.StatusAccepted)
	ackOf(t, stale.upload(seal(t, baseSnapshot(timeNowUTCDay(-40), 1, 9, 90))), http.StatusAccepted)

	resp := pc.get("/portal/api/insights?days=7")
	var b insightsBody
	decode(t, resp, &b)

	if b.Window.Days != 7 {
		t.Fatalf("window = %d days, want 7", b.Window.Days)
	}
	if b.Window.Devices != 1 {
		t.Fatalf("window.devices = %d, want 1 — the count must cover the SAME [%s, %s] the cards summarize, "+
			"not all history", b.Window.Devices, b.Window.From, b.Window.To)
	}
	if b.Coverage.Devices != 2 {
		t.Fatalf("coverage.devices = %d, want 2 (the all-history figure is unchanged)", b.Coverage.Devices)
	}
	if len(b.Days) != 1 || b.Summary.ActiveDays != 1 {
		t.Fatalf("the narrow window served %d days / %d active, want 1/1: %+v", len(b.Days), b.Summary.ActiveDays, b.Days)
	}

	// Widen the window past the older day and BOTH devices are in it, so the
	// two figures agree — the window count is a real measurement, not a
	// constant.
	resp = pc.get("/portal/api/insights?days=60")
	var wide insightsBody
	decode(t, resp, &wide)
	if wide.Window.Devices != 2 {
		t.Fatalf("over 60 days window.devices = %d, want 2", wide.Window.Devices)
	}
	if wide.Summary.ActiveDays != 2 {
		t.Fatalf("over 60 days active_days = %d, want 2", wide.Summary.ActiveDays)
	}
}
