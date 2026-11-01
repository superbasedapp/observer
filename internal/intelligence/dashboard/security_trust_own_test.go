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
)

// TestSecurityTrustChipLeavesObserverOwnOut (SEC-TRUST4 merge audit
// finding 1): the New Terminal chip runs the check with the launch row's
// Observer-entry test (Options.RepoTrustOwn), so at the home directory
// Observer's own entries are neither shown nor offered for accept, as the
// launch leaves them out; a foreign entry still shows. A root the test
// gives nothing for (any repository but the home directory) shows both.
func TestSecurityTrustChipLeavesObserverOwnOut(t *testing.T) {
	root := trustTestRepo(t, map[string]string{".mcp.json": `{"mcpServers":{"observer":{"command":"/opt/obs/observer","args":["serve"]},"x":{"command":"node","args":["s.js"]}}}`})
	ownAt := func(home string) func(string) func(code, file, key, content string) bool {
		return func(r string) func(code, file, key, content string) bool {
			if r != home {
				return nil
			}
			return func(_, _, _, content string) bool { return strings.HasPrefix(content, "/opt/obs/observer ") }
		}
	}
	get := func(own func(string) func(code, file, key, content string) bool) []string {
		t.Helper()
		s := &Server{opts: Options{SecuritySelected: trustSelectedRule, RepoTrustOwn: own}}
		s.comps.svc = trustSnapSvc{snap: componentstate.Legacy()}
		w := httptest.NewRecorder()
		s.handleSecurityTrust(w, httptest.NewRequest(http.MethodGet, "/api/security/trust?dir="+url.QueryEscape(root), nil))
		if w.Code != http.StatusOK {
			t.Fatalf("GET status %d: %s", w.Code, w.Body)
		}
		var resp struct {
			Reasons []struct {
				Key string `json:"key"`
			} `json:"reasons"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		var keys []string
		for _, r := range resp.Reasons {
			keys = append(keys, r.Key)
		}
		return keys
	}
	if keys := get(ownAt(root)); len(keys) != 1 || strings.Contains(keys[0], "observer") {
		t.Fatalf("at the home directory: reasons %q, want the foreign server only", keys)
	}
	if keys := get(ownAt("/somewhere/else")); len(keys) != 2 {
		t.Fatalf("elsewhere: reasons %q, want both servers", keys)
	}
	if keys := get(nil); len(keys) != 2 {
		t.Fatalf("no test wired: reasons %q, want both servers", keys)
	}
}
