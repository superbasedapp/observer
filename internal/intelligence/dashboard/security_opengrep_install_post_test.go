//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep

package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// opengrepSnapSvc is a components service holding one snapshot.
type opengrepSnapSvc struct {
	ComponentsService
	snap componentstate.Snapshot
}

func (f opengrepSnapSvc) State(context.Context) (componentstate.Snapshot, error) { return f.snap, nil }

// TestSecurityOpengrepInstallCarriesThePinShown: lane SEC-G2 audit finding
// 3. The POST passes the sha256 the dialog showed to the seam, and a pin
// change answers 409 with the current pin.
func TestSecurityOpengrepInstallCarriesThePinShown(t *testing.T) {
	const current = "aaaa000000000000000000000000000000000000000000000000000000000000"
	var seen []string
	og := &dashapi.Opengrep{
		Status: func(context.Context) (dashapi.OpengrepStatus, error) {
			return dashapi.OpengrepStatus{Selected: true, SHA256: current}, nil
		},
		Install: func(_ context.Context, sha string) error {
			seen = append(seen, sha)
			if sha != current {
				return &dashapi.OpengrepPinChanged{SHA256: current}
			}
			return nil
		},
	}
	rule := func(snap componentstate.Snapshot, id string) bool {
		return snap.Configured && (id == "security.scan.opengrep" || id == "security.code")
	}
	s := &Server{opts: Options{SecuritySelected: rule, Opengrep: og}}
	s.comps.svc = opengrepSnapSvc{snap: componentstate.Snapshot{Configured: true}}
	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/security/code/install", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(remoteConfirmHeader, strings.Repeat("ab", 32))
		r.AddCookie(&http.Cookie{Name: remoteConfirmCookie, Value: strings.Repeat("ab", 32)})
		w := httptest.NewRecorder()
		s.handleSecurityOpengrep(w, r)
		return w
	}
	for _, body := range []string{`{"install":true}`, `{"install":true,"sha256":"bbbb"}`} {
		w := post(body)
		if w.Code != http.StatusConflict {
			t.Fatalf("%s: status %d, want 409: %s", body, w.Code, w.Body)
		}
		var resp map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp["error"] != "pin_changed" || resp["sha256"] != current || resp["message"] == "" {
			t.Fatalf("%s: body %s (%v)", body, w.Body, err)
		}
	}
	if w := post(`{"install":true,"sha256":"` + current + `"}`); w.Code != http.StatusOK {
		t.Fatalf("the pin shown: status %d: %s", w.Code, w.Body)
	}
	if len(seen) != 3 || seen[0] != "" || seen[1] != "bbbb" || seen[2] != current {
		t.Fatalf("the seam saw %q", seen)
	}
}
