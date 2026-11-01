package dashboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/db"
)

// TestTerminalProjectPolicy pins GET /api/terminal/project-policy (lane
// sec-p2b): with no seam or no directory it answers shown=false (what every
// node without a project delivery sees), and otherwise it passes the
// directory to the seam and returns its line verbatim.
func TestTerminalProjectPolicy(t *testing.T) {
	get := func(t *testing.T, seam func(string) dashapi.ProjectPolicyLine, query string) string {
		t.Helper()
		database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "d.db")})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = database.Close() })
		s, err := New(Options{DB: database, ProjectPolicy: seam})
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/terminal/project-policy"+query, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d, body %s", rec.Code, rec.Body.String())
		}
		return strings.TrimSpace(rec.Body.String())
	}
	var asked string
	seam := func(dir string) dashapi.ProjectPolicyLine {
		asked = dir
		return dashapi.ProjectPolicyLine{Shown: true, State: dashapi.ProjectPolicyNotMatched}
	}
	if got := get(t, nil, "?dir=/w/x"); got != `{"shown":false}` {
		t.Fatalf("no seam = %s", got)
	}
	if got := get(t, seam, ""); got != `{"shown":false}` || asked != "" {
		t.Fatalf("no dir = %s (asked %q)", got, asked)
	}
	if got := get(t, seam, "?dir=/w/x"); got != `{"shown":true,"state":"not_matched"}` || asked != "/w/x" {
		t.Fatalf("with seam = %s (asked %q)", got, asked)
	}
}
