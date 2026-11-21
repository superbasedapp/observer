//go:build !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// sandbox_content_import_route_test.go pins the microVM panel's "Import
// image set" route (dashboard CLI parity item B-G7): 404 while no content
// driver is selected, the confirm token, an absolute folder, and the CLI's
// own import with no debug key.

// importRouteConfig writes a config whose [components] block selects the
// microVM driver when vm is true, and returns its path.
func importRouteConfig(t *testing.T, vm bool) string {
	t.Helper()
	dir := t.TempDir()
	body := "[observer]\ndb_path = \"" + filepath.ToSlash(filepath.Join(dir, "observer.db")) + "\"\n"
	if vm {
		body += "\n[components]\ndistro = \"developer\"\nadd = [\"terminals.sandbox.vm\"]\n"
	}
	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func importRoutePost(t *testing.T, cfgPath, body string, confirm bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/terminal/sandbox/content/import", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if confirm {
		tok := strings.Repeat("cd", 32)
		req.AddCookie(&http.Cookie{Name: hostedConfirmCookie, Value: tok})
		req.Header.Set(hostedConfirmHeader, tok)
	}
	w := httptest.NewRecorder()
	sandboxContentImportHandler(w, req, cfgPath)
	return w
}

func TestSandboxContentImportRoute(t *testing.T) {
	var gotDir string
	runErr := error(nil)
	old := sandboxImportRouteRun
	sandboxImportRouteRun = func(_ contentchan.Store, _ []ed25519.PublicKey, dir string) ([]sandboxImportStaged, error) {
		gotDir = dir
		if runErr != nil {
			return nil, runErr
		}
		return []sandboxImportStaged{{kind: content.SandboxRootfs, version: 3}}, nil
	}
	t.Cleanup(func() { sandboxImportRouteRun = old })
	set := t.TempDir()
	esc := func(p string) string { return strings.ReplaceAll(p, `\`, `\\`) }

	cases := []struct {
		name       string
		vm         bool
		body       string
		confirm    bool
		runErr     error
		wantStatus int
		wantText   string
	}{
		{"no content driver selected", false, `{"dir":"` + esc(set) + `"}`, true, nil, http.StatusNotFound, ""},
		{"no confirm token", true, `{"dir":"` + esc(set) + `"}`, false, nil, http.StatusForbidden, ""},
		{"a relative folder", true, `{"dir":"rel/set"}`, true, nil, http.StatusBadRequest, "absolute path"},
		{"a folder that is not there", true, `{"dir":"` + esc(filepath.Join(set, "missing")) + `"}`, true, nil, http.StatusBadRequest, "not a folder"},
		{"a refused set", true, `{"dir":"` + esc(set) + `"}`, true, errors.New("sandbox content import: sandbox.rootfs: signature refused"), http.StatusConflict, "signature refused"},
		{"an installed set", true, `{"dir":"` + esc(set) + `"}`, true, nil, http.StatusOK, `"kind":"sandbox.rootfs"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotDir, runErr = "", tc.runErr
			w := importRoutePost(t, importRouteConfig(t, tc.vm), tc.body, tc.confirm)
			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.wantStatus, w.Body.String())
			}
			if tc.wantText != "" && !strings.Contains(w.Body.String(), tc.wantText) {
				t.Fatalf("answer does not say %q: %s", tc.wantText, w.Body.String())
			}
			ran := tc.wantStatus == http.StatusOK || tc.wantStatus == http.StatusConflict
			if ran != (gotDir == set) {
				t.Fatalf("import ran with %q (want ran=%v)", gotDir, ran)
			}
		})
	}
}
