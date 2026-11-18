package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/frontdoor"
)

func newConnectServer(t *testing.T, opts Options) *Server {
	t.Helper()
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "d.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	opts.DB = database
	srv, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

// TestConnectStatusRoute: the route serves the seam's status, handing it the
// sign-in state the Cloud account seam probed (unknown without one), and
// answers 501 when nothing is wired.
func TestConnectStatusRoute(t *testing.T) {
	get := func(srv *Server) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/connect/status", nil))
		return rec
	}
	if rec := get(newConnectServer(t, Options{})); rec.Code != http.StatusNotImplemented {
		t.Fatalf("unwired: %d %s", rec.Code, rec.Body.String())
	}
	var seen []frontdoor.Identity
	seam := func(_ context.Context, id frontdoor.Identity) frontdoor.Status {
		seen = append(seen, id)
		return frontdoor.Sentence(frontdoor.Facts{Identity: id})
	}
	for _, tc := range []struct {
		name  string
		cloud *dashapi.CloudAccountSeams
		want  frontdoor.Identity
		text  string
	}{
		{"no cloud seam", nil, frontdoor.IdentityUnknown, "Local only"},
		{"signed in", dashapi.NewCloudAccountSeams(func() (dashapi.CloudSignInState, error) {
			return dashapi.CloudSignInState{APITokenPresent: true}, nil
		}, nil, nil), frontdoor.IdentitySignedIn, "Local only · signed in to superbased"},
		{"signed out", dashapi.NewCloudAccountSeams(func() (dashapi.CloudSignInState, error) {
			return dashapi.CloudSignInState{}, nil
		}, nil, nil), frontdoor.IdentitySignedOut, "Local only"},
	} {
		seen = nil
		rec := get(newConnectServer(t, Options{ConnectStatus: seam, CloudAccount: tc.cloud}))
		var st frontdoor.Status
		if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", tc.name, rec.Code, rec.Body.String())
		}
		if len(seen) != 1 || seen[0] != tc.want || st.Sentence != tc.text {
			t.Errorf("%s: identity %v sentence %q, want %v %q", tc.name, seen, st.Sentence, tc.want, tc.text)
		}
	}
}
