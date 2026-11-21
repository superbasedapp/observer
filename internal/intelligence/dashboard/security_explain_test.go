//go:build !sbo_omit_security

package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// TestHandleSecurityExplainFix: POST /api/security/findings/{id}/explain
// asks the suggest-a-fix variant only for a body of {"fix":true}, the plain
// explanation for any other JSON body or none, refuses a body that is not
// JSON rather than guess, demands the confirm token first, and answers a
// fix request compiled out when no fix seam is wired.
func TestHandleSecurityExplainFix(t *testing.T) {
	var plain, fix int
	seam := func(count *int, text string) dashapi.SecurityExplain {
		return func(_ context.Context, id string) (dashapi.SecurityExplanation, error) {
			if id != "f1" {
				return dashapi.SecurityExplanation{}, dashapi.ErrExplainUnknownFinding
			}
			*count++
			return dashapi.SecurityExplanation{Available: true, Text: text, Advisory: true}, nil
		}
	}
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	post := func(s *Server, id, body, tok string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/security/findings/"+id+"/explain", strings.NewReader(body))
		r.SetPathValue("id", id)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(remoteConfirmHeader, tok)
		r.AddCookie(&http.Cookie{Name: remoteConfirmCookie, Value: token})
		w := httptest.NewRecorder()
		s.handleSecurityExplain(w, r)
		return w
	}
	s := &Server{opts: Options{SecurityExplain: seam(&plain, "why"), SecurityExplainFix: seam(&fix, "how")}}
	cases := []struct {
		name            string
		id, body, tok   string
		code            int
		wantPlain, wFix int
		text            string
	}{
		{"no confirm token", "f1", `{"fix":true}`, "wrong", http.StatusForbidden, 0, 0, ""},
		{"not JSON", "f1", `fix`, token, http.StatusBadRequest, 0, 0, ""},
		{"empty body", "f1", ``, token, http.StatusOK, 1, 0, "why"},
		{"plain body", "f1", `{}`, token, http.StatusOK, 2, 0, "why"},
		{"fix false", "f1", `{"fix":false}`, token, http.StatusOK, 3, 0, "why"},
		{"fix true", "f1", `{"fix":true}`, token, http.StatusOK, 3, 1, "how"},
		{"unknown finding", "nope", `{"fix":true}`, token, http.StatusNotFound, 3, 1, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := post(s, tc.id, tc.body, tc.tok)
			if w.Code != tc.code || plain != tc.wantPlain || fix != tc.wFix {
				t.Fatalf("%d %s (plain %d, fix %d)", w.Code, w.Body, plain, fix)
			}
			if tc.text != "" {
				var ex dashapi.SecurityExplanation
				if err := json.Unmarshal(w.Body.Bytes(), &ex); err != nil || ex.Text != tc.text {
					t.Fatalf("body %s %v", w.Body, err)
				}
			}
		})
	}
	noFix := &Server{opts: Options{SecurityExplain: seam(&plain, "why")}}
	if w := post(noFix, "f1", `{"fix":true}`, token); w.Code != http.StatusNotFound || fix != 1 {
		t.Fatalf("no fix seam: %d", w.Code)
	}
	if w := post(noFix, "f1", `{}`, token); w.Code != http.StatusOK {
		t.Fatalf("plain without a fix seam: %d", w.Code)
	}
}
