package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/taskflow"
	"github.com/marmutapp/superbased-observer/internal/taskreport"
)

// A recorded zero is a measurement; no row is missing evidence. The session
// and task APIs must preserve that distinction without discarding lifecycles.
func TestAPISessionUsageAvailability(t *testing.T) {
	for _, tc := range []struct {
		name          string
		query         string
		available     bool
		taskAvailable bool
	}{
		{"missing", "DELETE FROM token_usage WHERE session_id = 'usage-test'", false, false},
		{"recorded_zero", "UPDATE token_usage SET input_tokens = 0, output_tokens = 0, cache_read_tokens = 0 WHERE session_id = 'usage-test'", true, true},
		{"recorded_positive", "SELECT 1", true, true},
		{"sidechain_only", "UPDATE token_usage SET is_sidechain = 1 WHERE session_id = 'usage-test'", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database, cleanup := openForecastTestDB(t)
			defer cleanup()
			seedTaskReportSession(t, database, "usage-test", "claude-opus-4-8")
			if _, err := database.ExecContext(context.Background(), tc.query); err != nil {
				t.Fatal(err)
			}
			s, err := New(Options{DB: database, CostEngine: newForecastTestEngine(t)})
			if err != nil {
				t.Fatal(err)
			}
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/session/usage-test", nil))
			if rr.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
			var detail struct {
				Available *bool  `json:"token_usage_available"`
				Note      string `json:"tokens_note"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &detail); err != nil {
				t.Fatal(err)
			}
			if detail.Available == nil || *detail.Available != tc.available {
				t.Fatalf("availability=%v want=%v", detail.Available, tc.available)
			}
			if (detail.Note == "") != tc.available {
				t.Fatalf("missing-usage note=%q, available=%v", detail.Note, tc.available)
			}
			report, err := taskreport.LoadSessionTaskReport(context.Background(), store.New(database), newForecastTestEngine(t), "usage-test", taskflow.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if report.TokenUsageAvailable != tc.taskAvailable || !report.HasTasks || len(report.Items) != 2 {
				t.Fatalf("incorrect availability or lost tasks: %+v", report)
			}
			if tc.available && !tc.taskAvailable && (report.Sidechain == nil || report.Sidechain.Tokens.InputTokens == 0) {
				t.Fatal("sidechain usage must remain available separately")
			}
		})
	}
}

func TestAPISessionCursorPartialUsage(t *testing.T) {
	database, cleanup := openForecastTestDB(t)
	defer cleanup()
	seedTaskReportSession(t, database, "usage-test", "composer-2.5")
	ctx := context.Background()
	if _, err := database.ExecContext(ctx, "UPDATE sessions SET tool='cursor' WHERE id='usage-test'"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, "UPDATE token_usage SET tool='cursor', source_event_id='cursor-cli-outcome:retry-' || id, reliability='unreliable' WHERE session_id='usage-test'"); err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{DB: database, CostEngine: newForecastTestEngine(t)})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/session/usage-test", nil))
	var detail struct {
		Available bool   `json:"token_usage_available"`
		Note      string `json:"tokens_note"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if !detail.Available || !strings.Contains(detail.Note, "lower bound") {
		t.Fatalf("partial totals not labeled: %+v", detail)
	}
	report, err := taskreport.LoadSessionTaskReport(ctx, store.New(database), newForecastTestEngine(t), "usage-test", taskflow.Options{})
	if err != nil || !report.TokenUsageAvailable || report.TokensNote != detail.Note {
		t.Fatalf("task API lost partial label: %+v %v", report, err)
	}
}
