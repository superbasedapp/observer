package dashboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// TestSecurityIaCInstallRoute (lane GATES-SEC): no seam is 404; a POST
// needs the confirm token and passes the engine and the pin shown to the
// seam; a refused install is 409.
func TestSecurityIaCInstallRoute(t *testing.T) {
	none := &Server{}
	w := httptest.NewRecorder()
	none.handleSecurityIaCInstall(w, httptest.NewRequest(http.MethodGet, "/api/security/iac/install", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("no seam: %d", w.Code)
	}
	var seen []string
	iac := &dashapi.IaC{
		Rows: func(context.Context) []dashapi.IaCScannerRow {
			return []dashapi.IaCScannerRow{{Component: "security.scan.trivy", Driver: "trivy", Kind: "process", Note: "Not selected"}}
		},
		Install: func(_ context.Context, engine, sha string) error {
			seen = append(seen, engine+":"+sha)
			if sha != "good" {
				return context.Canceled
			}
			return nil
		},
	}
	s := &Server{opts: Options{IaC: iac}}
	post := func(body string, confirm bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/security/iac/install", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if confirm {
			r.Header.Set(remoteConfirmHeader, strings.Repeat("ab", 32))
			r.AddCookie(&http.Cookie{Name: remoteConfirmCookie, Value: strings.Repeat("ab", 32)})
		}
		w := httptest.NewRecorder()
		s.handleSecurityIaCInstall(w, r)
		return w
	}
	if w := post(`{"engine":"trivy","sha256":"good"}`, false); w.Code == http.StatusOK || len(seen) != 0 {
		t.Fatalf("no confirm token: %d, seen %v", w.Code, seen)
	}
	if w := post(`{"engine":"trivy"}`, true); w.Code != http.StatusBadRequest {
		t.Fatalf("no pin: %d", w.Code)
	}
	if w := post(`{"engine":"trivy","sha256":"stale"}`, true); w.Code != http.StatusConflict {
		t.Fatalf("a refused install: %d", w.Code)
	}
	if w := post(`{"engine":"trivy","sha256":"good"}`, true); w.Code != http.StatusOK {
		t.Fatalf("the pin shown: %d %s", w.Code, w.Body)
	}
	if strings.Join(seen, ",") != "trivy:stale,trivy:good" {
		t.Fatalf("seen %v", seen)
	}
}
