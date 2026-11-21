package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudlane"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// cloudLaneFixture is one local project with a git remote, its synthetic
// "cloud:" twin, and sessions in each:
//
//	sA     the newTestServer seed session (local project, unstamped)
//	loc1   local project, stamped local, one priced api turn
//	cloud1 synthetic project, vendor_cloud with a vendor ref, one priced turn,
//	       plus a provider ledger figure in ACUs
//	cloud2 synthetic project, vendor_cloud, an action but no token rows
type cloudLaneFixture struct {
	s                *Server
	localID, cloudID int64
	localRoot        string
	cloudRoot        string
}

func seedCloudLaneFixture(t *testing.T) cloudLaneFixture {
	t.Helper()
	s, root := newTestServer(t)
	ctx := context.Background()
	st := store.New(s.opts.DB)
	base := time.Now().UTC().Add(-2 * time.Hour)

	localID, err := st.UpsertProject(ctx, root, "https://github.com/acme/app.git")
	if err != nil {
		t.Fatal(err)
	}
	// The synthetic project carries the same normalized remote, so the two
	// pair (CloudProjectTwins) and the lane folds the synthetic one in.
	cloudRoot := models.SyntheticCloudProjectRoot("github.com/acme/app")
	cloudID, err := st.UpsertProject(ctx, cloudRoot, "github.com/acme/app")
	if err != nil {
		t.Fatal(err)
	}

	ev := func(sess, eventID string, ts time.Time, projectRoot string) models.ToolEvent {
		return models.ToolEvent{
			SessionID: sess, ProjectRoot: projectRoot, Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "x.go", Success: true,
			SourceFile: "/tmp/" + sess + ".jsonl", SourceEventID: eventID, Timestamp: ts,
		}
	}
	if _, err := st.Ingest(ctx, []models.ToolEvent{
		ev("loc1", "l-e1", base, root),
		ev("cloud1", "c1-e1", base.Add(time.Minute), cloudRoot),
		ev("cloud2", "c2-e1", base.Add(2*time.Minute), cloudRoot),
	}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, ex := range []models.SessionExecution{
		{SessionID: "loc1", ExecutionLocation: models.ExecutionLocal},
		{SessionID: "cloud1", ExecutionLocation: models.ExecutionVendorCloud, VendorSessionRef: "cse_01ABC"},
		{SessionID: "cloud2", ExecutionLocation: models.ExecutionVendorCloud},
	} {
		if _, err := st.SetSessionExecution(ctx, ex); err != nil {
			t.Fatal(err)
		}
	}
	for _, turn := range []struct {
		sess string
		pid  int64
		in   int
		cost float64
	}{{"loc1", localID, 1000, 1.25}, {"cloud1", cloudID, 400, 0.75}} {
		if _, err := s.opts.DB.ExecContext(ctx, `
			INSERT INTO api_turns (session_id, project_id, timestamp, provider, model, input_tokens, output_tokens, cost_usd)
			VALUES (?, ?, ?, 'anthropic', 'claude-opus-4', ?, 100, ?)`,
			turn.sess, turn.pid, base.Add(5*time.Minute).Format(time.RFC3339Nano), turn.in, turn.cost); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := st.InsertCloudUsage(ctx, store.CloudUsageEntry{
		Connector: "codex-cloud", SourceRecordID: "run-1",
		MeasurementSource: models.UsageSourceProviderRunTotal, ValueType: models.UsageValueDelta,
		Unit: "credit", Value: 3, MonetaryStatus: models.UsageMonetaryNone,
		ScopeSession: "cloud1", ReportedAt: base.Add(10 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertCloudConnectorAccount(ctx, store.CloudConnectorAccount{
		Connector: "codex-cloud", Provider: "openai", AccountID: "acct-1",
		DisplayEmail: "dev@example.com", CoverageState: "partial_history",
	}); err != nil {
		t.Fatal(err)
	}
	return cloudLaneFixture{s: s, localID: localID, cloudID: cloudID, localRoot: root, cloudRoot: cloudRoot}
}

func laneGetJSON(t *testing.T, s *Server, path string, out any) {
	t.Helper()
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET %s: status %d body=%s", path, rr.Code, rr.Body.String())
	}
	if err := json.Unmarshal(rr.Body.Bytes(), out); err != nil {
		t.Fatalf("GET %s: decode: %v", path, err)
	}
}

func TestAPISessionsExecutionFilterAndFields(t *testing.T) {
	f := seedCloudLaneFixture(t)
	type row struct {
		ID                string `json:"id"`
		ExecutionLocation string `json:"execution_location"`
		VendorSessionRef  string `json:"vendor_session_ref"`
	}
	cases := []struct {
		filter string
		want   []string
	}{
		{"", []string{"cloud1", "cloud2", "loc1", "sA"}},
		{"vendor_cloud", []string{"cloud1", "cloud2"}},
		{"VENDOR_CLOUD", []string{"cloud1", "cloud2"}}, // case-insensitive input
		{"local", []string{"loc1"}},
		{"customer_worker", nil},
		{"unknown", []string{"sA"}},                           // the NULL column
		{"cloud", []string{"cloud1", "cloud2", "loc1", "sA"}}, // not a value: fails open
	}
	for _, tc := range cases {
		t.Run("filter="+tc.filter, func(t *testing.T) {
			var resp struct {
				Rows  []row `json:"rows"`
				Total int   `json:"total"`
			}
			laneGetJSON(t, f.s, "/api/sessions?limit=50&execution_location="+tc.filter, &resp)
			var got []string
			for _, r := range resp.Rows {
				got = append(got, r.ID)
			}
			sort.Strings(got)
			if len(got) != len(tc.want) || resp.Total != len(tc.want) {
				t.Fatalf("rows = %v (total %d), want %v", got, resp.Total, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("rows = %v, want %v", got, tc.want)
				}
			}
		})
	}

	var raw struct {
		Rows []map[string]any `json:"rows"`
	}
	laneGetJSON(t, f.s, "/api/sessions?limit=50", &raw)
	for _, r := range raw.Rows {
		switch r["id"] {
		case "sA":
			if _, ok := r["execution_location"]; ok {
				t.Errorf("an unstamped row must omit execution_location, got %v", r["execution_location"])
			}
			if _, ok := r["vendor_session_ref"]; ok {
				t.Errorf("an unstamped row must omit vendor_session_ref")
			}
		case "cloud1":
			if r["execution_location"] != "vendor_cloud" || r["vendor_session_ref"] != "cse_01ABC" {
				t.Errorf("cloud1 row = %v", r)
			}
		}
	}
}

func TestAPISessionDetailCarriesExecution(t *testing.T) {
	f := seedCloudLaneFixture(t)
	var d map[string]any
	laneGetJSON(t, f.s, "/api/session/cloud1", &d)
	if d["execution_location"] != "vendor_cloud" || d["vendor_session_ref"] != "cse_01ABC" {
		t.Fatalf("detail = execution_location %v vendor_session_ref %v", d["execution_location"], d["vendor_session_ref"])
	}
	var u map[string]any
	laneGetJSON(t, f.s, "/api/session/sA", &u)
	if _, ok := u["execution_location"]; ok {
		t.Fatalf("an unstamped session must omit execution_location")
	}
}

func TestAPIProjectCloudLane(t *testing.T) {
	f := seedCloudLaneFixture(t)
	var resp apiCloudLaneResponse
	laneGetJSON(t, f.s, "/api/project/"+itoa64(f.localID)+"/cloud", &resp)

	if len(resp.Projects) != 2 || resp.Projects[0].ID != f.localID || resp.Projects[1].ID != f.cloudID || !resp.Projects[1].Synthetic {
		t.Fatalf("projects = %+v, want the local project then its synthetic twin", resp.Projects)
	}
	if resp.FoldedInto != nil {
		t.Fatalf("a local project is not folded into anything: %+v", resp.FoldedInto)
	}
	byLoc := map[string]cloudlane.Bucket{}
	for _, b := range resp.Buckets {
		byLoc[b.Location] = b
	}
	if len(byLoc) != 3 {
		t.Fatalf("buckets = %+v, want local, vendor_cloud, unknown", resp.Buckets)
	}
	local := byLoc["local"]
	if local.Sessions != 1 || local.Tokens == nil || local.TokenCoverage != cloudlane.CoverageFull || local.CostUSD == nil || *local.CostUSD != 1.25 {
		t.Fatalf("local bucket = %+v", local)
	}
	cloud := byLoc["vendor_cloud"]
	if cloud.Sessions != 2 || cloud.SessionsWithTokens != 1 || cloud.TokenCoverage != cloudlane.CoveragePartial {
		t.Fatalf("cloud bucket = %+v, want 2 sessions, 1 with tokens, partial", cloud)
	}
	if cloud.CostUSD == nil || *cloud.CostUSD != 0.75 || cloud.SessionsWithTurns != 1 || cloud.CostCoverage != cloudlane.CoveragePartial {
		t.Fatalf("cloud cost = %v (%d sessions with turns, %s), want 0.75 from 1 session, partial", cloud.CostUSD, cloud.SessionsWithTurns, cloud.CostCoverage)
	}
	if len(cloud.Provenance) != 1 || cloud.Provenance[0].Source != "proxy" {
		t.Fatalf("cloud provenance = %+v", cloud.Provenance)
	}
	if len(cloud.Ledger) != 1 || cloud.Ledger[0].Unit != "credit" || cloud.Ledger[0].Value != 3 || cloud.Ledger[0].Coverage != cloudlane.CoveragePartial {
		t.Fatalf("cloud ledger = %+v", cloud.Ledger)
	}
	unknown := byLoc["unknown"]
	if unknown.Sessions != 1 || unknown.Tokens != nil || unknown.CostUSD != nil || unknown.TokenCoverage != cloudlane.CoverageUnknown {
		t.Fatalf("unknown bucket must carry no fabricated zero: %+v", unknown)
	}
	if resp.OffMachineSessions != 2 || resp.UnknownSessions != 1 {
		t.Fatalf("off-machine %d unknown %d", resp.OffMachineSessions, resp.UnknownSessions)
	}
	if len(resp.Accounts) != 1 || resp.Accounts[0].CoverageState != "partial_history" {
		t.Fatalf("accounts = %+v", resp.Accounts)
	}

	// The account's e-mail and id never reach the lane payload.
	rr := httptest.NewRecorder()
	f.s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/project/"+itoa64(f.localID)+"/cloud", nil))
	for _, leak := range []string{"dev@example.com", "acct-1"} {
		if strings.Contains(rr.Body.String(), leak) {
			t.Fatalf("lane payload leaks %q: %s", leak, rr.Body.String())
		}
	}

	// The synthetic project's own lane points at its local twin.
	var twin apiCloudLaneResponse
	laneGetJSON(t, f.s, "/api/project/"+itoa64(f.cloudID)+"/cloud", &twin)
	if twin.FoldedInto == nil || twin.FoldedInto.ID != f.localID {
		t.Fatalf("synthetic lane folded_into = %+v, want the local project", twin.FoldedInto)
	}

	rr = httptest.NewRecorder()
	f.s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/project/999999/cloud", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown project: status %d, want 404", rr.Code)
	}
}

func TestAPIProjectsGroupsSyntheticTwin(t *testing.T) {
	f := seedCloudLaneFixture(t)
	var resp struct {
		Rows []map[string]any `json:"rows"`
	}
	laneGetJSON(t, f.s, "/api/projects", &resp)
	byID := map[int64]map[string]any{}
	for _, r := range resp.Rows {
		byID[int64(r["id"].(float64))] = r
	}
	local, cloud := byID[f.localID], byID[f.cloudID]
	if local == nil || cloud == nil {
		t.Fatalf("rows = %v", resp.Rows)
	}
	if cloud["synthetic_cloud"] != true || cloud["cloud_twin_of"] != float64(f.localID) {
		t.Fatalf("synthetic row = %v", cloud)
	}
	twins, _ := local["cloud_twins"].([]any)
	if len(twins) != 1 || twins[0] != float64(f.cloudID) {
		t.Fatalf("local row cloud_twins = %v", local["cloud_twins"])
	}
	mix, _ := local["execution_mix"].(map[string]any)
	if mix["local"] != float64(1) || mix["unknown"] != float64(1) {
		t.Fatalf("local execution_mix = %v", local["execution_mix"])
	}
	cmix, _ := cloud["execution_mix"].(map[string]any)
	if cmix["vendor_cloud"] != float64(2) {
		t.Fatalf("cloud execution_mix = %v", cloud["execution_mix"])
	}
}
