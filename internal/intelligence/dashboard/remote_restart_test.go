package dashboard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
)

// newRestartServer builds a loopback dashboard with an injected RestartFunc.
func newRestartServer(t *testing.T, restart func() error) http.Handler {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	database, err := openTestDB(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	s, err := New(Options{DB: database, ConfigPath: filepath.Join(dir, "config.toml"), RestartFunc: restart})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s.Handler()
}

func postRestart(t *testing.T, h http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/restart", nil)
	req.Host = "127.0.0.1:8080" // loopback, no Origin → passes browserGuard
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestHandleAdminRestart pins the dashboard-driven restart handler: 501 when
// the process can't self-restart (nil hook), a preflight refusal surfaced
// (config wouldn't come back → daemon keeps running), and the happy path
// scheduling exactly one restart. GET is rejected.
func TestHandleAdminRestart(t *testing.T) {
	t.Run("501 when RestartFunc is nil (mode can't self-restart)", func(t *testing.T) {
		rec := postRestart(t, newRestartServer(t, nil))
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("nil RestartFunc = %d, want 501: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("preflight refusal surfaces the reason, no 200", func(t *testing.T) {
		called := false
		rec := postRestart(t, newRestartServer(t, func() error {
			called = true
			return errors.New("restart refused — config would not load")
		}))
		if rec.Code == http.StatusOK {
			t.Fatalf("a refusal must not 200: %s", rec.Body.String())
		}
		if !called {
			t.Fatal("RestartFunc should have been invoked")
		}
		if !strings.Contains(rec.Body.String(), "config would not load") {
			t.Errorf("refusal reason not surfaced: %s", rec.Body.String())
		}
	})

	t.Run("ok schedules exactly one restart", func(t *testing.T) {
		called := 0
		rec := postRestart(t, newRestartServer(t, func() error {
			called++
			return nil
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("restart = %d, want 200: %s", rec.Code, rec.Body.String())
		}
		if called != 1 {
			t.Fatalf("RestartFunc called %d times, want 1", called)
		}
		if !strings.Contains(rec.Body.String(), "restart_scheduled") {
			t.Errorf("missing restart_scheduled: %s", rec.Body.String())
		}
	})

	t.Run("GET is the live-traffic status report, never a restart", func(t *testing.T) {
		// dashboard-config-management plan §3.3 item 3: GET reports whether a
		// restart is available and how many proxied requests landed in the
		// last minute, so the confirm dialog can say so. It must not restart.
		var called bool
		h := newRestartServer(t, func() error { called = true; return nil })
		req := httptest.NewRequest(http.MethodGet, "/api/admin/restart", nil)
		req.Host = "127.0.0.1:8080"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET = %d, want 200: %s", rec.Code, rec.Body.String())
		}
		if called {
			t.Error("GET must never invoke RestartFunc")
		}
		if !strings.Contains(rec.Body.String(), `"available":true`) {
			t.Errorf("GET must report availability: %s", rec.Body.String())
		}
	})
	t.Run("DELETE not allowed", func(t *testing.T) {
		h := newRestartServer(t, func() error { return nil })
		req := httptest.NewRequest(http.MethodDelete, "/api/admin/restart", nil)
		req.Host = "127.0.0.1:8080"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("DELETE = %d, want 405", rec.Code)
		}
	})
}
