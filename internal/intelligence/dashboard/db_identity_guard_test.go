package dashboard

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// TestDBIdentityGuard pins the daemon's half of L-125: a request naming this
// database is served and told so, one naming another is refused 409 before
// the route runs, and one naming none (a browser, an older CLI) is served
// exactly as before.
func TestDBIdentityGuard(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "observer.db")
	own := dashapi.DBIdentity(dbPath)
	other := dashapi.DBIdentity(filepath.Join(t.TempDir(), "other.db"))
	cases := []struct {
		name       string
		serverDB   string
		header     string
		wantStatus int
		wantRan    bool
		wantID     string
	}{
		{"no header: served, no identity", dbPath, "", http.StatusOK, true, ""},
		{"same database: served, identity named", dbPath, own, http.StatusOK, true, own},
		{"other database: refused 409, identity named", dbPath, other, http.StatusConflict, false, own},
		{"server without a database path: unchanged", "", other, http.StatusOK, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{opts: Options{DBPath: tc.serverDB}}
			ran := false
			h := s.dbIdentityGuard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				ran = true
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest(http.MethodPost, "/api/enrolment/push-now", nil)
			if tc.header != "" {
				req.Header.Set(dashapi.DBIdentityRequestHeader, tc.header)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != tc.wantStatus || ran != tc.wantRan {
				t.Fatalf("status %d ran %v, want %d ran %v", rr.Code, ran, tc.wantStatus, tc.wantRan)
			}
			if got := rr.Header().Get(dashapi.DBIdentityHeader); got != tc.wantID {
				t.Fatalf("identity header %q, want %q", got, tc.wantID)
			}
		})
	}
}
