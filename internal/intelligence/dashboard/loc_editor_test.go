package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
)

// TestLocEditorAuth is the (required × token present × token matches)
// matrix for the per-install editor credential.
//
// The two rows that matter most are the ones a "just check the header"
// implementation gets wrong: a WRONG token is refused even while the token
// is optional (otherwise the credential is decorative), and a daemon that
// holds no token at all still serves when required is set (otherwise a
// failed token-file write would refuse every save forever with no way for
// the extension to comply).
func TestLocEditorAuth(t *testing.T) {
	t.Parallel()
	const secret = "b8f1c0de"
	tests := []struct {
		name       string
		configured string
		presented  string
		required   bool
		want       bool
	}{
		{"no token configured, none sent, not required", "", "", false, true},
		{"no token configured, none sent, required (fail open)", "", "", true, true},
		{"no token configured, one sent anyway", "", "whatever", false, true},
		{"no token configured, one sent anyway, required", "", "whatever", true, true},
		{"configured, matching, not required", secret, secret, false, true},
		{"configured, matching, required", secret, secret, true, true},
		{"configured, absent, not required (old extension)", secret, "", false, true},
		{"configured, absent, required", secret, "", true, false},
		{"configured, WRONG, not required", secret, "b8f1c0df", false, false},
		{"configured, WRONG, required", secret, "b8f1c0df", true, false},
		{"configured, prefix of the real token", secret, "b8f1", false, false},
		{"configured, real token plus a tail", secret, secret + "0", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := locEditorAuth(tc.configured, tc.presented, tc.required); got != tc.want {
				t.Errorf("locEditorAuth(%q, %q, %v) = %v, want %v",
					tc.configured, tc.presented, tc.required, got, tc.want)
			}
		})
	}
}

// TestLocEditorChangeTokenOverHTTP walks the same decision through the real
// handler, so the status code and the body an operator debugging a refused
// save actually sees are pinned, not just the predicate.
func TestLocEditorChangeTokenOverHTTP(t *testing.T) {
	t.Parallel()
	const secret = "0123456789abcdef"
	tests := []struct {
		name      string
		required  bool
		header    string
		wantCode  int
		wantInBod string
	}{
		{"matching token", false, secret, http.StatusOK, ""},
		{"no token while optional", false, "", http.StatusOK, ""},
		{"wrong token while optional", false, "nope", http.StatusUnauthorized, "X-Observer-Token"},
		{"no token while required", true, "", http.StatusUnauthorized, "editor_token_required"},
		{"matching token while required", true, secret, http.StatusOK, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "d.db")})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = database.Close() })
			s, err := New(Options{
				DB:                     database,
				LocEditorToken:         secret,
				LocEditorTokenRequired: tc.required,
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			// A body with no counts: the point of the test is the auth
			// decision, and a 200 with note="no lines changed" proves the
			// request got PAST the token check.
			body, _ := json.Marshal(EditorChangeRequest{
				Path:          "src/a.go",
				WorkspaceRoot: t.TempDir(),
			})
			req := httptest.NewRequest(http.MethodPost, "/api/loc/editor-change", bytes.NewReader(body))
			if tc.header != "" {
				req.Header.Set(locEditorTokenHeader, tc.header)
			}
			rr := httptest.NewRecorder()
			s.handleLOCEditorChange(rr, req)

			if rr.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d (body %q)", rr.Code, tc.wantCode, rr.Body.String())
			}
			if tc.wantInBod != "" && !strings.Contains(rr.Body.String(), tc.wantInBod) {
				t.Errorf("401 body %q does not name %q — an operator cannot tell what to fix",
					rr.Body.String(), tc.wantInBod)
			}
			if tc.wantCode == http.StatusUnauthorized && strings.Contains(rr.Body.String(), secret) {
				t.Error("the refusal body echoed the configured token")
			}
		})
	}
}
