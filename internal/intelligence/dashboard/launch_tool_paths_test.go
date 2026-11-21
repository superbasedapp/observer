package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// Dashboard CLI parity follow-up (plan section 9): the "Launch binary paths"
// card writes [launch.tools.<tool>].path through the save pipeline: a dry run
// first, the confirm token on the real save, null removes, other lines kept.

const launchToolPathsCorpus = `# my node
[observer]
log_level = "info"

[launch.tools.gemini]
path = "/opt/gemini/bin/gemini"
`

func getLaunchToolPaths(t *testing.T, s *Server) (launchToolPathsView, *http.Cookie) {
	t.Helper()
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/launch/tool-paths", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/launch/tool-paths: %d %s", rr.Code, rr.Body.String())
	}
	var v launchToolPathsView
	if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	var cookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == remoteConfirmCookie {
			cookie = c
		}
	}
	return v, cookie
}

func putLaunchToolPaths(t *testing.T, s *Server, query, body string, confirm bool) *httptest.ResponseRecorder {
	t.Helper()
	v, cookie := getLaunchToolPaths(t, s)
	req := httptest.NewRequest(http.MethodPut, "/api/launch/tool-paths"+query, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if confirm {
		req.Header.Set(remoteConfirmHeader, v.ConfirmToken)
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	return rr
}

// launchPathBody is a PUT body for tool and path (path "" => null).
func launchPathBody(tool, path string) string {
	m := map[string]any{"tool": tool, "path": nil}
	if path != "" {
		m["path"] = path
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// fakeBinary makes a regular file to stand in for a tool binary.
func fakeBinary(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte("stub"), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func launchPathsOnDisk(t *testing.T, path string) map[string]string {
	t.Helper()
	cfg, err := loadConfigForDashboard(path)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for k, v := range cfg.Launch.Tools {
		out[k] = v.Path
	}
	return out
}

func TestLaunchToolPaths_GetShape(t *testing.T) {
	s, _ := newSecretTestServer(t, launchToolPathsCorpus)
	v, cookie := getLaunchToolPaths(t, s)
	if len(v.Paths) != 1 || v.Paths[0].Tool != "gemini" || v.Paths[0].Path != "/opt/gemini/bin/gemini" || v.Paths[0].Exists {
		t.Fatalf("paths = %+v", v.Paths)
	}
	if v.ConfirmToken == "" || cookie == nil || v.ConfigEtag == "" {
		t.Fatalf("GET must mint a confirm token and report the etag: %+v", v)
	}
}

func TestLaunchToolPaths_GetEmptyIsEmptyListAndSorted(t *testing.T) {
	s, _ := newSecretTestServer(t, "[observer]\nlog_level = \"info\"\n")
	v, _ := getLaunchToolPaths(t, s)
	if v.Paths == nil || len(v.Paths) != 0 {
		t.Fatalf("no overrides must be an empty list, got %#v", v.Paths)
	}
	rows := launchToolPathRows(configWithTools(map[string]string{"zed": "/z", "codex": "/c", "aider": "/a"}))
	if rows[0].Tool != "aider" || rows[1].Tool != "codex" || rows[2].Tool != "zed" {
		t.Fatalf("rows not sorted by tool: %+v", rows)
	}
}

func TestLaunchToolPaths_DryRunWritesNothingAndShowsTheDiff(t *testing.T) {
	s, path := newSecretTestServer(t, launchToolPathsCorpus)
	bin := fakeBinary(t, "codex-bin")
	before, _ := os.ReadFile(path)
	rr := putLaunchToolPaths(t, s, "?dry_run=1", launchPathBody("codex", bin), false)
	if rr.Code != http.StatusOK {
		t.Fatalf("dry run: %d %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	diff, _ := resp["diff"].(string)
	if resp["dry_run"] != true || resp["needs_confirm"] != true || resp["exists"] != true || !strings.Contains(diff, "[launch.tools.codex]") {
		t.Fatalf("dry run answer: %v", resp)
	}
	if strings.Contains(diff, "\n-[observer]") || strings.Contains(diff, "-log_level") {
		t.Fatalf("diff should only add the new table:\n%s", diff)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("a dry run wrote config.toml")
	}
}

func TestLaunchToolPaths_DryRunAllowsAMissingFileButReportsIt(t *testing.T) {
	s, _ := newSecretTestServer(t, launchToolPathsCorpus)
	missing := filepath.Join(t.TempDir(), "nope")
	rr := putLaunchToolPaths(t, s, "?dry_run=1", launchPathBody("codex", missing), false)
	if rr.Code != http.StatusOK {
		t.Fatalf("dry run: %d %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["exists"] != false {
		t.Fatalf("exists = %v, want false", resp["exists"])
	}
}

func TestLaunchToolPaths_SaveNeedsTheConfirmToken(t *testing.T) {
	s, path := newSecretTestServer(t, launchToolPathsCorpus)
	bin := fakeBinary(t, "codex-bin")
	if rr := putLaunchToolPaths(t, s, "", launchPathBody("codex", bin), false); rr.Code == http.StatusOK {
		t.Fatalf("a save without the confirm token was accepted: %s", rr.Body.String())
	}
	if got := launchPathsOnDisk(t, path); len(got) != 1 {
		t.Fatalf("refused save wrote %v", got)
	}
}

func TestLaunchToolPaths_SetChangeRemoveKeepsOtherLines(t *testing.T) {
	s, path := newSecretTestServer(t, launchToolPathsCorpus)
	first := fakeBinary(t, "codex-1")
	second := fakeBinary(t, "codex-2")
	steps := []struct {
		name string
		body string
		want map[string]string
	}{
		{"set", launchPathBody("codex", first), map[string]string{"gemini": "/opt/gemini/bin/gemini", "codex": first}},
		{"change", launchPathBody("codex", second), map[string]string{"gemini": "/opt/gemini/bin/gemini", "codex": second}},
		{"remove", launchPathBody("codex", ""), map[string]string{"gemini": "/opt/gemini/bin/gemini"}},
		{"remove last", launchPathBody("gemini", ""), map[string]string{}},
	}
	for _, c := range steps {
		rr := putLaunchToolPaths(t, s, "", c.body, true)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", c.name, rr.Code, rr.Body.String())
		}
		got := launchPathsOnDisk(t, path)
		if len(got) != len(c.want) {
			t.Fatalf("%s: tools = %v, want %v", c.name, got, c.want)
		}
		for k, v := range c.want {
			if got[k] != v {
				t.Fatalf("%s: tools = %v, want %v", c.name, got, c.want)
			}
		}
		b, _ := os.ReadFile(path)
		if !strings.Contains(string(b), "# my node") || !strings.Contains(string(b), `log_level = "info"`) {
			t.Fatalf("%s: the save lost another line:\n%s", c.name, b)
		}
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), "launch.tools") {
		t.Fatalf("removing the last override should drop the table:\n%s", b)
	}
}

func TestLaunchToolPaths_Refusals(t *testing.T) {
	bin := fakeBinary(t, "ok-bin")
	cases := []struct {
		name, body, want string
	}{
		{"unknown tool", launchPathBody("not-a-real-tool", bin), "not a tool Observer knows"},
		{"relative path", launchPathBody("codex", "bin/codex"), "must be absolute"},
		{"control character", launchPathBody("codex", bin+"\x07"), "control character"},
		{"missing file", launchPathBody("codex", filepath.Join(t.TempDir(), "gone")), "Nothing is there"},
		{"directory not file", launchPathBody("codex", t.TempDir()), "Nothing is there"},
		{"too long", launchPathBody("codex", filepath.Join(t.TempDir(), strings.Repeat("a", 4100))), "longer than"},
		{"blank path", `{"tool":"codex","path":"  "}`, "full path"},
		{"unknown field", `{"tool":"codex","path":null,"extra":1}`, "unknown field"},
		{"missing path field", `{"tool":"codex"}`, "path is required"},
		{"missing tool field", `{"path":null}`, "tool is required"},
		{"remove blank tool", `{"tool":" ","path":null}`, "Choose a tool"},
	}
	s, path := newSecretTestServer(t, launchToolPathsCorpus)
	for _, c := range cases {
		rr := putLaunchToolPaths(t, s, "", c.body, true)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d %s, want 400", c.name, rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), c.want) {
			t.Fatalf("%s: message %q lacks %q", c.name, rr.Body.String(), c.want)
		}
	}
	if got := launchPathsOnDisk(t, path); len(got) != 1 || got["gemini"] == "" {
		t.Fatalf("a refused body changed the file: %v", got)
	}
}

func TestLaunchToolPaths_StaleEtagIsRefused(t *testing.T) {
	s, path := newSecretTestServer(t, launchToolPathsCorpus)
	bin := fakeBinary(t, "codex-bin")
	if err := os.WriteFile(path, []byte(launchToolPathsCorpus+"\n# edited elsewhere\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rr := putLaunchToolPaths(t, s, "?base_etag=stale", launchPathBody("codex", bin), true)
	if rr.Code != http.StatusConflict {
		t.Fatalf("%d %s, want 409", rr.Code, rr.Body.String())
	}
}

// configWithTools is a config holding the given launch overrides.
func configWithTools(m map[string]string) config.Config {
	var cfg config.Config
	cfg.Launch.Tools = map[string]config.LaunchToolConfig{}
	for k, v := range m {
		cfg.Launch.Tools[k] = config.LaunchToolConfig{Path: v}
	}
	return cfg
}
