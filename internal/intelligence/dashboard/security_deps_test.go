//go:build !sbo_omit_security && !sbo_omit_security_deps

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

// TestHandleSecurityDeps is milestone 3b: the Package checks card reads the
// install gate's state and records the disclosure accept only on an
// explicit POST carrying the confirm token; with no seam (no component)
// the route answers 404.
func TestHandleSecurityDeps(t *testing.T) {
	accepted := false
	s := &Server{opts: dashapi.Options{PackageChecks: &dashapi.PackageChecks{
		Status: func(context.Context) (dashapi.PackageChecksStatus, error) {
			return dashapi.PackageChecksStatus{Active: true, Online: true, Accepted: accepted, Text: "superbased.app", NotSetUp: !accepted}, nil
		},
		Accept: func(context.Context) error { accepted = true; return nil },
	}}}
	w := httptest.NewRecorder()
	s.handleSecurityDeps(w, httptest.NewRequest(http.MethodGet, "/api/security/deps", nil))
	if w.Code != http.StatusOK || accepted {
		t.Fatalf("GET %d %s", w.Code, w.Body)
	}
	var resp struct {
		Status       dashapi.PackageChecksStatus `json:"status"`
		ConfirmToken string                      `json:"confirm_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.ConfirmToken == "" || !resp.Status.NotSetUp {
		t.Fatalf("GET body %s %v", w.Body, err)
	}
	post := func(token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/security/deps", strings.NewReader(`{"accept":true}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(remoteConfirmHeader, token)
		r.AddCookie(&http.Cookie{Name: remoteConfirmCookie, Value: resp.ConfirmToken})
		w := httptest.NewRecorder()
		s.handleSecurityDeps(w, r)
		return w
	}
	if w := post("wrong"); w.Code != http.StatusForbidden || accepted {
		t.Fatalf("a POST without the token must not record: %d", w.Code)
	}
	if w := post(resp.ConfirmToken); w.Code != http.StatusOK || !accepted {
		t.Fatalf("POST %d %s", w.Code, w.Body)
	}
	none := &Server{}
	w = httptest.NewRecorder()
	none.handleSecurityDeps(w, httptest.NewRequest(http.MethodGet, "/api/security/deps", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("no seam: %d", w.Code)
	}
}
