package dashboard

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudlane"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Project figures fold the cloud twin (cloud-agents lane CA-C1, decision
// CA-D21): the Overview Spend total, the Spend tab buckets and the "Where it
// ran" lane cover the same folded rows, so the B5 case (a tile reading the
// local project only while the lane added the cloud twin) shows one total
// with a split.

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestProjectDetailFoldsCloudTwin(t *testing.T) {
	f := seedCloudLaneFixture(t)
	var d dashapi.ProjectDetail
	laneGetJSON(t, f.s, "/api/project/"+itoa64(f.localID), &d)

	// One total: the local session's $1.25 plus the twin's cloud $0.75.
	if !near(d.Spend.TotalUSD, 2.0) {
		t.Fatalf("total_usd = %v, want 2.00 (local 1.25 + cloud twin 0.75)", d.Spend.TotalUSD)
	}
	loc := d.Spend.Locations
	if loc == nil {
		t.Fatal("a project with a folded cloud twin must carry the location split")
	}
	if len(loc.Folded) != 1 || loc.Folded[0].ID != f.cloudID || !loc.Folded[0].Synthetic {
		t.Fatalf("folded = %+v, want the synthetic twin", loc.Folded)
	}
	var sum float64
	byLoc := map[string]cloudlane.Bucket{}
	for _, b := range loc.Buckets {
		byLoc[b.Location] = b
		if b.CostUSD != nil {
			sum += *b.CostUSD
		}
	}
	if !near(sum, d.Spend.TotalUSD) {
		t.Fatalf("split adds to %v, total is %v", sum, d.Spend.TotalUSD)
	}
	if c := byLoc["vendor_cloud"]; c.CostUSD == nil || !near(*c.CostUSD, 0.75) || c.CostCoverage != cloudlane.CoveragePartial {
		t.Fatalf("cloud bucket = %+v, want $0.75 partial (cloud2 reported no turns)", c)
	}
	if c := byLoc["vendor_cloud"]; len(c.Ledger) != 1 || c.Ledger[0].Unit != "credit" || c.Ledger[0].Value != 3 {
		t.Fatalf("cloud ledger = %+v, want 3 credit in its own unit", c.Ledger)
	}
	if u := byLoc["unknown"]; u.CostUSD != nil {
		t.Fatalf("unknown bucket must not carry a fabricated cost: %+v", u)
	}

	// Per-session rows carry where each ran; the twin's sessions are there.
	ran := map[string]string{}
	for _, s := range d.Spend.BySession {
		ran[s.ID] = s.ExecutionLocation
	}
	if ran["cloud1"] != models.ExecutionVendorCloud || ran["loc1"] != models.ExecutionLocal {
		t.Fatalf("by_session locations = %v", ran)
	}
	if v, ok := ran["sA"]; !ok || v != "" {
		t.Fatalf("an unstamped session keeps an empty location, got %q (present %v)", v, ok)
	}

	// The dollar ROI tiles say the twin is not in them.
	for _, tile := range d.ROI {
		if strings.HasPrefix(tile.Unit, "usd") && !strings.Contains(tile.Caveat, "folded cloud project") {
			t.Errorf("tile %s caveat %q does not name the folded twin", tile.Key, tile.Caveat)
		}
	}

	// The lane's buckets add up to the same total.
	var lane apiCloudLaneResponse
	laneGetJSON(t, f.s, "/api/project/"+itoa64(f.localID)+"/cloud", &lane)
	var laneSum float64
	for _, b := range lane.Buckets {
		if b.CostUSD != nil {
			laneSum += *b.CostUSD
		}
	}
	if !near(laneSum, d.Spend.TotalUSD) {
		t.Fatalf("lane adds to %v, detail total %v", laneSum, d.Spend.TotalUSD)
	}
}

func TestProjectCostRowsFoldCloudTwin(t *testing.T) {
	f := seedCloudLaneFixture(t)
	for _, by := range []string{"session", "tool", "model", "day"} {
		var resp struct {
			Rows []dashapi.APIProjectCostBucketRow `json:"rows"`
		}
		laneGetJSON(t, f.s, "/api/project/"+itoa64(f.localID)+"/cost?by="+by, &resp)
		var sum float64
		for _, r := range resp.Rows {
			sum += r.CostUSD
		}
		if !near(sum, 2.0) {
			t.Errorf("by=%s rows add to %v, want the folded 2.00", by, sum)
		}
		if by != "session" {
			continue
		}
		ran := map[string]string{}
		for _, r := range resp.Rows {
			ran[r.Key] = r.ExecutionLocation
		}
		if ran["cloud1"] != models.ExecutionVendorCloud || ran["loc1"] != models.ExecutionLocal || ran["sA"] != "" {
			t.Errorf("by=session Ran column = %v", ran)
		}
	}
}

// TestProjectFoldPrecedence: the same cloud session reported by two rails is
// one session with one token total (plan acceptance test 2). cloud1 has a
// per-turn proxy row; a connector's provider run total for the same session
// is set aside, counted as superseded, never added.
func TestProjectFoldPrecedence(t *testing.T) {
	f := seedCloudLaneFixture(t)
	ctx := context.Background()
	st := store.New(f.s.opts.DB)
	if _, err := st.Ingest(ctx, nil, []models.TokenEvent{{
		SourceFile: "cloud-agents/codex-cloud", SourceEventID: "codex-cloud:t1:tokens:provider_run_total",
		SessionID: "cloud1", ProjectRoot: f.cloudRoot, Timestamp: time.Now().UTC().Add(-90 * time.Minute),
		Tool: models.ToolClaudeCode, Model: "claude-opus-4", InputTokens: 9000, OutputTokens: 900,
		EstimatedCostUSD: 5, Source: models.TokenSourceSessionSummary, Reliability: models.ReliabilityAccurate,
	}}, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	var d dashapi.ProjectDetail
	laneGetJSON(t, f.s, "/api/project/"+itoa64(f.localID), &d)
	if !near(d.Spend.TotalUSD, 2.0) {
		t.Fatalf("total_usd = %v, want 2.00: the provider run total must not add to the transcript", d.Spend.TotalUSD)
	}
	if d.Spend.Locations == nil || d.Spend.Locations.SupersededTurns != 1 {
		t.Fatalf("locations = %+v, want 1 superseded turn", d.Spend.Locations)
	}
	var lane apiCloudLaneResponse
	laneGetJSON(t, f.s, "/api/project/"+itoa64(f.cloudID)+"/cloud", &lane)
	if lane.SupersededTurns != 1 {
		t.Fatalf("lane superseded_turns = %d, want 1", lane.SupersededTurns)
	}

	// cloud2 has no transcript: its provider run total is the best tier
	// present and counts.
	if _, err := st.Ingest(ctx, nil, []models.TokenEvent{{
		SourceFile: "cloud-agents/codex-cloud", SourceEventID: "codex-cloud:t2:tokens:provider_run_total",
		SessionID: "cloud2", ProjectRoot: f.cloudRoot, Timestamp: time.Now().UTC().Add(-80 * time.Minute),
		Tool: models.ToolClaudeCode, Model: "claude-opus-4", InputTokens: 500, OutputTokens: 50,
		EstimatedCostUSD: 0.5, Source: models.TokenSourceSessionSummary, Reliability: models.ReliabilityAccurate,
	}}, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	laneGetJSON(t, f.s, "/api/project/"+itoa64(f.localID), &d)
	if !near(d.Spend.TotalUSD, 2.5) {
		t.Fatalf("total_usd = %v, want 2.50 (cloud2's run total is its only tier)", d.Spend.TotalUSD)
	}
}

// TestProjectDetailNoSplitForLocalOnly: a project that never ran off this
// machine and folds no twin carries no split, so its payload is unchanged.
func TestProjectDetailNoSplitForLocalOnly(t *testing.T) {
	s, root := newTestServer(t)
	pid, err := store.New(s.opts.DB).UpsertProject(context.Background(), root, "")
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/project/"+itoa64(pid), nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), `"locations"`) || strings.Contains(rr.Body.String(), "execution_location") {
		t.Fatalf("a local-only project must not carry the split: %s", rr.Body.String())
	}
}
