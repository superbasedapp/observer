package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
)

// update_route_test.go pins the loopback apply route's ANSWER SHAPE, which is
// the review's M1: the handler must not stay open for the apply.
//
// Why that is not a nicety. This server is stopped with a 5s Shutdown budget
// that waits for ACTIVE connections, and the apply is what triggers the stop
// (it releases the listeners mid-handshake). A handler holding the connection
// therefore made a slow child boot expire the budget, which start.go's
// errgroup turned into an exit of the SUPERVISING PARENT - with the child
// alive, `applying` never settled and nobody left to roll back.

func newUpdateRouteServer(t *testing.T, apply func(context.Context, UpdateApplyRequest) (UpdateApplyResult, error)) *Server {
	t.Helper()
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	s, err := New(Options{DB: database, DBPath: path, UpdateApplyFunc: apply})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAnAcceptedApplyAnswers202WithItsLedgerEventID(t *testing.T) {
	s := newUpdateRouteServer(t, func(_ context.Context, req UpdateApplyRequest) (UpdateApplyResult, error) {
		if req.DryRun {
			t.Fatal("this case is not a dry run")
		}
		return UpdateApplyResult{
			State: "applying", Accepted: true, EventID: 42,
			Detail: "accepted; the daemon is running this apply on its own budget.",
		}, nil
	})
	rec := httptest.NewRecorder()
	s.handleUpdateApply(rec, httptest.NewRequest(http.MethodPost, "/api/update/apply", strings.NewReader(`{}`)))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 - the apply outlives this request by design (%s)", rec.Code, rec.Body.String())
	}
	var got UpdateApplyResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if !got.Accepted || got.EventID != 42 {
		t.Fatalf("body = %+v, want accepted with the ledger event id the caller follows", got)
	}
}

// A dry run performs nothing and its whole value is the plan it prints back,
// so it stays synchronous and stays a 200.
func TestADryRunStaysSynchronousAnd200(t *testing.T) {
	s := newUpdateRouteServer(t, func(_ context.Context, req UpdateApplyRequest) (UpdateApplyResult, error) {
		if !req.DryRun {
			t.Fatal("the dry-run flag did not reach the seam")
		}
		return UpdateApplyResult{State: "available", Steps: []string{"download", "verify", "swap"}}, nil
	})
	rec := httptest.NewRecorder()
	s.handleUpdateApply(rec, httptest.NewRequest(http.MethodPost, "/api/update/apply", strings.NewReader(`{"dry_run":true}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a dry run", rec.Code)
	}
	var got UpdateApplyResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Steps) != 3 || got.Accepted {
		t.Fatalf("body = %+v, want the plan and no 202 acceptance", got)
	}
}

// A refusal (a second concurrent apply) is still an immediate, readable
// answer rather than a 202 that will do nothing.
func TestARefusedApplyIsNotAccepted(t *testing.T) {
	s := newUpdateRouteServer(t, func(context.Context, UpdateApplyRequest) (UpdateApplyResult, error) {
		return UpdateApplyResult{}, errAlreadyApplying{}
	})
	rec := httptest.NewRecorder()
	s.handleUpdateApply(rec, httptest.NewRequest(http.MethodPost, "/api/update/apply", strings.NewReader(`{}`)))
	if rec.Code == http.StatusAccepted {
		t.Fatal("a refused apply was answered 202")
	}
	if !strings.Contains(rec.Body.String(), "already in progress") {
		t.Fatalf("body = %s, want the refusal reason", rec.Body.String())
	}
}

type errAlreadyApplying struct{}

func (errAlreadyApplying) Error() string {
	return "observer update: an apply is already in progress on this node"
}
