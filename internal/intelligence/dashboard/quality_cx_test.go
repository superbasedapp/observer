//go:build !sbo_omit_codeintel

package dashboard

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/codeintel"
	"github.com/marmutapp/superbased-observer/internal/codequality"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestAPIProjectQualityComplexity pins the complexity block: an index
// saved with counting on reads measured (stale, since code intelligence
// is off in the test config), the most complex function is listed with a
// project-relative path, and a stored daily point carries the over-share
// into the history and the trend.
func TestAPIProjectQualityComplexity(t *testing.T) {
	s, root := newTestServer(t)
	s.opts.Projects.QualityMetrics = true
	ctx := context.Background()
	st := store.New(s.opts.DB)
	projectID, err := st.ProjectIDForRoot(ctx, root)
	if err != nil || projectID == 0 {
		t.Fatalf("ProjectIDForRoot: %d %v", projectID, err)
	}
	if err := st.CodeIntelSaveFile(ctx, codeintel.FileResult{
		Project: root, Path: filepath.Join(root, "a.go"), Lang: "go", Parser: "goast", ContentHash: "h",
		Nodes: []codeintel.Node{
			{Kind: "function", Name: "Small", StartLine: 1, EndLine: 5, StartByte: 0, EndByte: 50, Complexity: 2},
			{Kind: "function", Name: "Big", StartLine: 6, EndLine: 90, StartByte: 51, EndByte: 900, Complexity: 17},
		},
		ExtractVersion: codeintel.ExtractVersion,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertProjectQualityDay(ctx, projectID, codequality.DayPoint{
		Day: codequality.Day(time.Now()), MeasuredAt: time.Now().UTC(),
		ComplexityState: codequality.StateMeasured, ComplexityFunctions: 2, ComplexityOver: 1, ComplexitySum: 19, ComplexityP90: 17, ComplexityMax: 17,
	}); err != nil {
		t.Fatal(err)
	}

	code, resp, body := getQuality(t, s, projectID)
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	c := resp.Complexity
	if c.State != codequality.StateMeasured || !c.Stale || c.Functions != 2 || c.Over != 1 || c.Max != 17 ||
		c.OverShare == nil || *c.OverShare != 50 || c.Method.Threshold != codequality.ComplexityThreshold {
		t.Fatalf("complexity = %+v (%s)", c, body)
	}
	if len(c.Top) != 2 || c.Top[0].Name != "Big" || c.Top[0].File != "a.go" {
		t.Fatalf("top = %+v", c.Top)
	}
	if len(resp.History) != 1 || resp.History[0].ComplexityOverShare == nil || *resp.History[0].ComplexityOverShare != 50 || resp.Trend.Complexity.Days != 1 {
		t.Fatalf("history = %+v trend = %+v", resp.History, resp.Trend)
	}
}
