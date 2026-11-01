//go:build !sbo_omit_remote

package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestAPIProjectCommitScan pins POST /api/project/{id}/commit-scan (the
// Projects page's "Rescan now", 2026-10-15): unavailable without the seam,
// confirm-token gated, and answering with the fresh capture health, the
// specific failure kind and git's message after a failed scan.
func TestAPIProjectCommitScan(t *testing.T) {
	s, _, projectID, _, _ := seedProjectsFixture(t)
	h := s.Handler()
	path := "/api/project/" + itoa64(projectID) + "/commit-scan"
	ck, token := getConfirm(t, h)

	// No seam wired: an honest 503, never a fake success.
	if rec := postConfirm(t, h, path, "{}", ck, token); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no seam: status %d body=%s", rec.Code, rec.Body.String())
	}

	st := store.New(s.db())
	var calls int
	s.opts.CommitRescan = func(ctx context.Context, id int64) error {
		calls++
		if id != projectID {
			t.Errorf("CommitRescan id = %d, want %d", id, projectID)
		}
		return st.SetCommitScanState(ctx, store.ScanState{
			ProjectID: id, LastScanAt: time.Now(), ConsecutiveFailures: 1,
			LastError:     "gitview.runGit [rev-parse --show-prefix]: exit status 128 (fatal: detected dubious ownership in repository)",
			LastErrorKind: "dubious_ownership",
		})
	}
	rec := postConfirm(t, h, path, "{}", ck, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("rescan: status %d body=%s", rec.Code, rec.Body.String())
	}
	var resp commitRescanResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Done || calls != 1 || resp.Capture.Commits != "error" || resp.Capture.CommitsKind != "dubious_ownership" ||
		resp.Capture.CommitScan == nil || resp.Capture.CommitScan.Detail == "" || !resp.Capture.CommitScan.CanRescan {
		t.Fatalf("rescan response = %+v (scan %+v)", resp, resp.Capture.CommitScan)
	}

	// A scan error is reported, not swallowed.
	s.opts.CommitRescan = func(context.Context, int64) error { return errors.New("project folder not found: /gone") }
	rec = postConfirm(t, h, path, "{}", ck, token)
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.Error == "" {
		t.Fatalf("error case: %s (%v)", rec.Body.String(), err)
	}

	// The detail payload advertises the action once the seam exists.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/project/"+itoa64(projectID), nil))
	var detail struct {
		Capture struct {
			CommitScan struct {
				CanRescan bool `json:"can_rescan"`
			} `json:"commit_scan"`
		} `json:"capture"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &detail); err != nil || !detail.Capture.CommitScan.CanRescan {
		t.Fatalf("detail capture = %s (%v)", rr.Body.String(), err)
	}
}
