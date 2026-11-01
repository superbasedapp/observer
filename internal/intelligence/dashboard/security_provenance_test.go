//go:build !sbo_omit_security

package dashboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// TestSecurityProvenanceRoute: no seam is compiled out; GET returns the
// state, the records, a project's consent and the confirm token; every
// write needs the token; consent goes to the seam with the project's
// root; an unknown project and an unknown action are refused.
func TestSecurityProvenanceRoute(t *testing.T) {
	s, root := newTestServer(t)
	w := httptest.NewRecorder()
	s.handleSecurityProvenance(w, httptest.NewRequest(http.MethodGet, "/api/security/provenance", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("no seam: %d", w.Code)
	}
	var consentRoot string
	var notesGot, rotated bool
	s.opts.Provenance = &dashapi.Provenance{
		Status:  func(context.Context) (any, error) { return map[string]bool{"selected": true}, nil },
		Records: func(context.Context, string, int) (any, error) { return []string{}, nil },
		Consent: func(_ context.Context, r string, notes, _ bool) (any, error) {
			consentRoot, notesGot = r, notes
			return nil, nil
		},
		ConsentFor: func(context.Context, string) (bool, bool, error) { return notesGot, false, nil },
		RotateKey:  func(context.Context) (any, error) { rotated = true; return nil, nil },
	}
	hash := secposture.ProjectRootHash(root)
	w = httptest.NewRecorder()
	s.handleSecurityProvenance(w, httptest.NewRequest(http.MethodGet, "/api/security/provenance?project="+hash, nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"confirm_token"`) || !strings.Contains(w.Body.String(), `"consent"`) {
		t.Fatalf("GET: %d %s", w.Code, w.Body)
	}
	body := `{"action":"consent","project":"` + hash + `","notes":true}`
	if w := securityPost(s.handleSecurityProvenance, "/api/security/provenance", body, false); w.Code != http.StatusForbidden || consentRoot != "" {
		t.Fatalf("no token: %d", w.Code)
	}
	if w := securityPost(s.handleSecurityProvenance, "/api/security/provenance", body, true); w.Code != http.StatusOK || consentRoot != root || !notesGot {
		t.Fatalf("consent: %d %s root %q", w.Code, w.Body, consentRoot)
	}
	if w := securityPost(s.handleSecurityProvenance, "/api/security/provenance", `{"action":"consent","project":"nope","notes":true}`, true); w.Code != http.StatusNotFound {
		t.Fatalf("unknown project: %d", w.Code)
	}
	if w := securityPost(s.handleSecurityProvenance, "/api/security/provenance", `{"action":"rotate_key"}`, true); w.Code != http.StatusOK || !rotated {
		t.Fatalf("rotate: %d", w.Code)
	}
	if w := securityPost(s.handleSecurityProvenance, "/api/security/provenance", `{"action":"delete_all"}`, true); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown action: %d", w.Code)
	}
}

// TestSecurityProvenanceTrailerPreview is audit finding F7 (PR11): GET
// carries the exact hook block, and a consent turning the trailer on is
// refused unless it names that block's digest.
func TestSecurityProvenanceTrailerPreview(t *testing.T) {
	s, root := newTestServer(t)
	var trailerGot bool
	installed := false
	s.opts.Provenance = &dashapi.Provenance{
		Status:  func(context.Context) (any, error) { return map[string]bool{"selected": true}, nil },
		Records: func(context.Context, string, int) (any, error) { return []string{}, nil },
		Consent: func(_ context.Context, _ string, _, trailer bool) (any, error) {
			trailerGot, installed = trailer, trailer
			return nil, nil
		},
		ConsentFor: func(context.Context, string) (bool, bool, error) { return false, trailerGot, nil },
		RotateKey:  func(context.Context) (any, error) { return nil, nil },
		TrailerPreview: func(context.Context, string) (dashapi.ProvenanceHookPreview, error) {
			return dashapi.ProvenanceHookPreview{HookPath: "/r/.git/hooks/prepare-commit-msg", Block: "# >>> block\n", Digest: "d1", Installed: installed}, nil
		},
	}
	hash := secposture.ProjectRootHash(root)
	w := httptest.NewRecorder()
	s.handleSecurityProvenance(w, httptest.NewRequest(http.MethodGet, "/api/security/provenance?project="+hash, nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"trailer_preview"`) || !strings.Contains(w.Body.String(), "prepare-commit-msg") {
		t.Fatalf("GET: %d %s", w.Code, w.Body)
	}
	if w := securityPost(s.handleSecurityProvenance, "/api/security/provenance", `{"action":"consent","project":"`+hash+`","trailer":true}`, true); w.Code != http.StatusConflict || trailerGot {
		t.Fatalf("no digest: %d", w.Code)
	}
	if w := securityPost(s.handleSecurityProvenance, "/api/security/provenance", `{"action":"consent","project":"`+hash+`","trailer":true,"trailer_block_digest":"other"}`, true); w.Code != http.StatusConflict || trailerGot {
		t.Fatalf("wrong digest: %d", w.Code)
	}
	if w := securityPost(s.handleSecurityProvenance, "/api/security/provenance", `{"action":"consent","project":"`+hash+`","trailer":true,"trailer_block_digest":"d1"}`, true); w.Code != http.StatusOK || !trailerGot {
		t.Fatalf("shown digest: %d %s", w.Code, w.Body)
	}
	// Already on: re-sending needs no digest.
	if w := securityPost(s.handleSecurityProvenance, "/api/security/provenance", `{"action":"consent","project":"`+hash+`","notes":true,"trailer":true}`, true); w.Code != http.StatusOK {
		t.Fatalf("already on: %d", w.Code)
	}
}
