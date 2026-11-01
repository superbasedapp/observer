//go:build !sbo_omit_security && !sbo_omit_security_trust

package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestSecurityTrustNotSelected (plans decision log P-031 finding 2, P-044):
// the trust GET and POST answer 404 unless the daemon's rule selects
// security.trust, and the dialog renders no chip on that 404. The component
// is offered, so an install with no [components] block (every compiled
// module active under componentstate.Legacy) gets the chip; a block that
// leaves security.trust out (removes it, or picks a distro where it is off)
// answers 404.
func TestSecurityTrustNotSelected(t *testing.T) {
	root := trustTestRepo(t, map[string]string{".mcp.json": `{"mcpServers":{"x":{"command":"node","args":["s.js"]}}}`})
	cases := []struct {
		name string
		svc  ComponentsService
		rule func(componentstate.Snapshot, string) bool
		want int
	}{
		{"no component service", nil, trustSelectedRule, http.StatusNotFound},
		{"no rule wired", trustSnapSvc{snap: componentstate.Legacy()}, nil, http.StatusNotFound},
		{"no [components] block", trustSnapSvc{snap: componentstate.Legacy()}, trustSelectedRule, http.StatusOK},
		{"a block that removes it", trustSnapSvc{snap: componentstate.Resolve(config.ComponentsConfig{Remove: []string{"security.trust"}}, nil)}, trustSelectedRule, http.StatusNotFound},
		{"a block whose distro leaves it off", trustSnapSvc{snap: componentstate.Resolve(config.ComponentsConfig{Distro: "managed"}, nil)}, trustSelectedRule, http.StatusNotFound},
		{"a block that adds it", trustSnapSvc{snap: componentstate.Resolve(config.ComponentsConfig{Distro: "managed", Add: []string{"security.trust"}}, nil)}, trustSelectedRule, http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &Server{opts: Options{SecuritySelected: c.rule}}
			s.comps.svc = c.svc
			w := httptest.NewRecorder()
			s.handleSecurityTrust(w, httptest.NewRequest(http.MethodGet, "/api/security/trust?dir="+url.QueryEscape(root), nil))
			if w.Code != c.want {
				t.Fatalf("GET status %d, want %d: %s", w.Code, c.want, w.Body)
			}
			if c.want == http.StatusNotFound {
				if !strings.Contains(w.Body.String(), "not_selected") {
					t.Fatalf("GET 404 body %s, want not_selected", w.Body)
				}
				pw := httptest.NewRecorder()
				s.handleSecurityTrust(pw, httptest.NewRequest(http.MethodPost, "/api/security/trust", strings.NewReader(`{"dir":"`+root+`","all":true}`)))
				if pw.Code != http.StatusNotFound {
					t.Fatalf("POST status %d, want 404: %s", pw.Code, pw.Body)
				}
			}
		})
	}
}

// TestSecurityTrustAcceptAllowed (plans decision log P-031 finding 1): the
// GET says whether the dashboard accept would go through. On a managed node
// whose governance hides or pins the Code security page, accept_allowed is
// false, no confirm token is minted and the note says who can accept (the
// developer's own terminal, or an admin), while the chip itself still reads
// through the Terminals page; the POST meets exactly the refusal the GET
// predicted. With the page shown, the accept is allowed.
func TestSecurityTrustAcceptAllowed(t *testing.T) {
	root := trustTestRepo(t, map[string]string{".mcp.json": `{"mcpServers":{"x":{"command":"node","args":["s.js"]}}}`})
	cases := []struct {
		name       string
		gov        func(t *testing.T) GovernanceProvider
		allowed    bool
		postStatus int
		postCode   string
	}{
		{"ungoverned", func(*testing.T) GovernanceProvider { return nil }, true, 0, ""},
		{"code security shown", func(t *testing.T) GovernanceProvider {
			return governedProvider(t, []string{"cache"}, nil, nil, nil)
		}, true, 0, ""},
		{"code security hidden", func(t *testing.T) GovernanceProvider {
			return governedProvider(t, []string{"cache", "code-security"}, nil, nil, nil)
		}, false, http.StatusNotFound, "governance_hidden"},
		{"managed node default visibility", func(t *testing.T) GovernanceProvider {
			return governedProviderAs(t, true, nil, nil)
		}, false, http.StatusNotFound, "governance_hidden"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newRemoteTestServer(t, Options{Governance: c.gov(t), SecuritySelected: trustSelectedRule})
			s.comps.svc = trustSnapSvc{snap: componentstate.Legacy()}
			h := s.guardedHandler("127.0.0.1:8081")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, loopbackRequest(http.MethodGet, "/api/security/trust?dir="+url.QueryEscape(root)))
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %d %s: the chip must still read", rec.Code, rec.Body)
			}
			var resp securityTrustResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			if resp.AcceptAllowed != c.allowed {
				t.Fatalf("accept_allowed = %v, want %v: %s", resp.AcceptAllowed, c.allowed, rec.Body)
			}
			if !c.allowed {
				if resp.ConfirmToken != "" {
					t.Fatal("a confirm token minted for an accept that would be refused")
				}
				if !strings.Contains(resp.AcceptNote, "observer security trust accept --all --dir "+root) ||
					!strings.Contains(resp.AcceptNote, "organization admin") {
					t.Fatalf("accept_note %q must name the terminal accept and the admin", resp.AcceptNote)
				}
			} else if resp.ConfirmToken == "" || resp.AcceptNote != "" {
				t.Fatalf("allowed accept: token %q note %q", resp.ConfirmToken, resp.AcceptNote)
			}
			post := httptest.NewRecorder()
			req := loopbackRequest(http.MethodPost, "/api/security/trust")
			h.ServeHTTP(post, req)
			var refusal governanceRefusal
			_ = json.Unmarshal(post.Body.Bytes(), &refusal)
			if c.postStatus != 0 {
				if post.Code != c.postStatus || refusal.Error != c.postCode {
					t.Fatalf("POST %d %s, want %d %s", post.Code, post.Body, c.postStatus, c.postCode)
				}
			} else if strings.HasPrefix(refusal.Error, "governance_") {
				t.Fatalf("POST refused by governance although accept_allowed: %s", post.Body)
			}
		})
	}
}
