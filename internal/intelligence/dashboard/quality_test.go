package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/codequality"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func getQuality(t *testing.T, s *Server, projectID int64) (int, qualityResponse, string) {
	t.Helper()
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/project/"+itoa64(projectID)+"/quality", nil))
	var resp qualityResponse
	if rr.Code == http.StatusOK {
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v: %s", err, rr.Body.String())
		}
	}
	return rr.Code, resp, rr.Body.String()
}

// TestAPIProjectQuality pins the Quality tab: a project with no report and
// no codeintel index reads two honest "not measured" states with every
// list [] and no numbers; a synthetic lcov report at the default location
// then measures; a stored daily point shows in the history and the trend.
func TestAPIProjectQuality(t *testing.T) {
	s, root := newTestServer(t)
	s.opts.Projects.QualityMetrics = true
	ctx := context.Background()
	st := store.New(s.opts.DB)
	projectID, err := st.ProjectIDForRoot(ctx, root)
	if err != nil || projectID == 0 {
		t.Fatalf("ProjectIDForRoot: %d %v", projectID, err)
	}

	code, resp, body := getQuality(t, s, projectID)
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	if resp.Coverage.State != codequality.StateNoReport || resp.Coverage.Percent != nil {
		t.Fatalf("coverage = %+v", resp.Coverage)
	}
	// A build without codeintel (sbo_omit_codeintel, the minimal edition)
	// answers not_in_build for both index-backed blocks; the store's omit
	// side reports it (codequality_dup_omit.go).
	if (resp.Duplication.State != codequality.StateCodeIntelOff && resp.Duplication.State != codequality.StateNotInBuild) ||
		resp.Duplication.LineShare != nil {
		t.Fatalf("duplication = %+v", resp.Duplication)
	}
	if (resp.Complexity.State != codequality.StateCodeIntelOff && resp.Complexity.State != codequality.StateNotInBuild) ||
		resp.Complexity.OverShare != nil || resp.Complexity.Functions != 0 {
		t.Fatalf("complexity = %+v", resp.Complexity)
	}
	for _, k := range []string{`"reports":[]`, `"problems":[]`, `"least_covered":[]`, `"top_groups":[]`, `"history":[]`, `"top":[]`, `"per_language":[]`, `"uncounted_langs":[]`} {
		if !strings.Contains(body, k) {
			t.Errorf("body missing %s: %s", k, body)
		}
	}
	if strings.Contains(body, "null") {
		t.Errorf("body carries a null: %s", body)
	}

	if err := os.MkdirAll(filepath.Join(root, "coverage"), 0o755); err != nil {
		t.Fatal(err)
	}
	lcov := "TN:\nSF:src/a.ts\nDA:1,1\nDA:2,0\nDA:3,1\nDA:4,1\nend_of_record\n"
	if err := os.WriteFile(filepath.Join(root, "coverage", "lcov.info"), []byte(lcov), 0o644); err != nil {
		t.Fatal(err)
	}
	today := codequality.Day(time.Now())
	if err := st.UpsertProjectQualityDay(ctx, projectID, codequality.DayPoint{
		Day: today, MeasuredAt: time.Now().UTC(), CoverageState: codequality.StateMeasured,
		CoverageLines: 4, CoverageCovered: 3, DupState: codequality.StateCodeIntelOff,
	}); err != nil {
		t.Fatal(err)
	}
	_, resp, body = getQuality(t, s, projectID)
	if resp.Coverage.State != codequality.StateMeasured || resp.Coverage.Lines != 4 || resp.Coverage.Covered != 3 ||
		len(resp.Coverage.Reports) != 1 || resp.Coverage.Reports[0].RelPath != "coverage/lcov.info" {
		t.Fatalf("coverage = %+v", resp.Coverage)
	}
	if len(resp.History) != 1 || resp.History[0].Day != today || resp.History[0].CoveragePercent == nil || resp.Trend.Coverage.Days != 1 {
		t.Fatalf("history = %+v trend = %+v (%s)", resp.History, resp.Trend, body)
	}

	// Off: no numbers, no report read.
	s.opts.Projects.QualityMetrics = false
	_, resp, _ = getQuality(t, s, projectID)
	if resp.Enabled || resp.Coverage.State != codequality.StateOff || resp.Duplication.State != codequality.StateOff ||
		resp.Complexity.State != codequality.StateOff || len(resp.Coverage.Reports) != 0 {
		t.Fatalf("off = %+v", resp)
	}
}

func TestAPIProjectQualityUnknownProject(t *testing.T) {
	s, _ := newTestServer(t)
	if code, _, _ := getQuality(t, s, 999999); code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", code)
	}
}
