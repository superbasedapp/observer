package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestFirstLaunchPlanRules walks firstLaunchRules: one case per row, plus
// the all-needed and nothing-needed ends.
func TestFirstLaunchPlanRules(t *testing.T) {
	ready := firstLaunchState{
		allowedTools: []string{"claude-code"},
		freshOn:      true,
		allowedRoots: []string{"/home/u/code"},
		tool:         "claude-code",
		folder:       "/home/u/code/app",
	}
	cases := []struct {
		name string
		edit func(s *firstLaunchState)
		want []firstLaunchChange
	}{
		{"nothing needed", func(*firstLaunchState) {}, []firstLaunchChange{}},
		{"row allow_tool: tool not on the list", func(s *firstLaunchState) { s.allowedTools = []string{"codex"} }, []firstLaunchChange{changeAllowTool}},
		{"row allow_fresh: fresh launch off", func(s *firstLaunchState) { s.freshOn = false }, []firstLaunchChange{changeAllowFresh}},
		{"row allow_folder: folder outside every root", func(s *firstLaunchState) { s.folder = "/srv/other" }, []firstLaunchChange{changeAllowFolder}},
		{"row allow_folder: default directory needs no root", func(s *firstLaunchState) { s.folder = ""; s.allowedRoots = nil }, []firstLaunchChange{}},
		{"row allow_folder: a sibling with a shared prefix is not covered", func(s *firstLaunchState) { s.folder = "/home/u/code2" }, []firstLaunchChange{changeAllowFolder}},
		{"row create_folder: playground missing", func(s *firstLaunchState) {
			s.folder = "/home/u/observer-playground"
			s.folderMissing = true
		}, []firstLaunchChange{changeAllowFolder, changeCreateFolder}},
		{"fresh machine: everything", func(s *firstLaunchState) {
			s.allowedTools = nil
			s.freshOn = false
			s.allowedRoots = nil
			s.folder = "/home/u/observer-playground"
			s.folderMissing = true
		}, []firstLaunchChange{changeAllowTool, changeAllowFresh, changeAllowFolder, changeCreateFolder}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := ready
			tc.edit(&s)
			if got := firstLaunchPlan(s); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("plan = %v, want %v", got, tc.want)
			}
		})
	}
}

// firstLaunchHomeAt points the playground at a temporary home for one test.
func firstLaunchHomeAt(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	prev := firstLaunchHome
	firstLaunchHome = func() (string, error) { return home, nil }
	t.Cleanup(func() { firstLaunchHome = prev })
	return home
}

// postFirstLaunch performs a confirmed POST /api/terminal/first-launch with
// the query and body, minting the token through the route's own GET.
func postFirstLaunch(t *testing.T, h http.Handler, query, body string) (int, map[string]any, string) {
	t.Helper()
	greq := httptest.NewRequest(http.MethodGet, "/api/terminal/first-launch", nil)
	greq.Host = "127.0.0.1:8080"
	grec := httptest.NewRecorder()
	h.ServeHTTP(grec, greq)
	if grec.Code != http.StatusOK {
		t.Fatalf("GET first-launch = %d", grec.Code)
	}
	var g struct {
		ConfirmToken string `json:"confirm_token"`
	}
	_ = json.Unmarshal(grec.Body.Bytes(), &g)
	var ck *http.Cookie
	for _, c := range grec.Result().Cookies() {
		if c.Name == remoteConfirmCookie {
			ck = c
		}
	}
	if ck == nil || g.ConfirmToken == "" {
		t.Fatal("no confirm cookie/token")
	}
	req := httptest.NewRequest(http.MethodPost, "/api/terminal/first-launch"+query, strings.NewReader(body))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(remoteConfirmHeader, g.ConfirmToken)
	req.AddCookie(ck)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, rec.Body.String()
}

func jsonPath(p string) string { return strings.ReplaceAll(p, `\`, `\\`) }

// TestFirstLaunchGetNamesPlayground pins the GET: the playground path under
// home, not yet existing, and a confirm token.
func TestFirstLaunchGetNamesPlayground(t *testing.T) {
	home := firstLaunchHomeAt(t)
	_, h := newManageServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/terminal/first-launch", nil)
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out struct {
		ConfirmToken     string `json:"confirm_token"`
		PlaygroundPath   string `json:"playground_path"`
		PlaygroundExists bool   `json:"playground_exists"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("GET = %d %v", rec.Code, err)
	}
	if out.PlaygroundPath != filepath.Join(home, firstLaunchPlaygroundName) || out.PlaygroundExists || out.ConfirmToken == "" {
		t.Fatalf("GET = %+v", out)
	}
}

// TestFirstLaunchPreviewCreatesNothing pins the dry run: the diff names the
// three keys, the plan lists all four changes, and neither the folder nor
// the config is written.
func TestFirstLaunchPreviewCreatesNothing(t *testing.T) {
	home := firstLaunchHomeAt(t)
	s, h := newManageServer(t)
	tool := launchableTools()[0]
	pg := filepath.Join(home, firstLaunchPlaygroundName)
	before, _ := os.ReadFile(s.opts.ConfigPath)
	body := `{"tool":"` + tool + `","folder":"` + jsonPath(pg) + `","changes":["allow_tool","allow_fresh","allow_folder","create_folder"]}`
	code, out, raw := postFirstLaunch(t, h, "?dry_run=1", body)
	if code != http.StatusOK || out["dry_run"] != true || out["would_write"] != true {
		t.Fatalf("dry run = %d %s", code, raw)
	}
	diff, _ := out["diff"].(string)
	for _, want := range []string{"allow_fresh_agent", "allowed_tools", "allowed_project_roots", firstLaunchPlaygroundName} {
		if !strings.Contains(diff, want) {
			t.Errorf("diff misses %q:\n%s", want, diff)
		}
	}
	if _, err := os.Stat(pg); !os.IsNotExist(err) {
		t.Fatalf("the dry run created the playground folder: %v", err)
	}
	after, _ := os.ReadFile(s.opts.ConfigPath)
	if string(before) != string(after) {
		t.Fatal("the dry run wrote the config")
	}
}

// TestFirstLaunchApplyWritesExactlyThePlan pins the save: the folder exists,
// the three keys hold exactly the additions, and nothing else changed.
func TestFirstLaunchApplyWritesExactlyThePlan(t *testing.T) {
	home := firstLaunchHomeAt(t)
	s, h := newManageServer(t)
	tool := launchableTools()[0]
	pg := filepath.Join(home, firstLaunchPlaygroundName)
	body := `{"tool":"` + tool + `","folder":"` + jsonPath(pg) + `","changes":["create_folder","allow_folder","allow_fresh","allow_tool"]}`
	code, out, raw := postFirstLaunch(t, h, "", body)
	if code != http.StatusOK || out["saved"] != true || out["folder_created"] != true {
		t.Fatalf("save = %d %s", code, raw)
	}
	if st, err := os.Stat(pg); err != nil || !st.IsDir() {
		t.Fatalf("playground folder not created: %v", err)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: s.opts.ConfigPath})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	l := cfg.Terminal.Launch
	realPG, _ := filepath.EvalSymlinks(pg)
	if !l.AllowFreshAgent || !reflect.DeepEqual(l.AllowedTools, []string{tool}) || !reflect.DeepEqual(l.AllowedProjectRoots, []string{realPG}) {
		t.Fatalf("launch policy = %+v", l)
	}
	if l.AllowShell || !l.AllowInstall {
		t.Fatalf("the consent touched another key: allow_shell=%v allow_install=%v", l.AllowShell, l.AllowInstall)
	}
	// A second consent for the same launch has nothing left to change.
	code, out, raw = postFirstLaunch(t, h, "?dry_run=1", `{"tool":"`+tool+`","folder":"`+jsonPath(pg)+`","changes":[]}`)
	if code != http.StatusOK || out["would_write"] != false {
		t.Fatalf("repeat dry run = %d %s", code, raw)
	}
}

// TestFirstLaunchRefusals pins what the route refuses, and that a refused
// save leaves no folder behind.
func TestFirstLaunchRefusals(t *testing.T) {
	home := firstLaunchHomeAt(t)
	_, h := newManageServer(t)
	tool := launchableTools()[0]
	pg := filepath.Join(home, firstLaunchPlaygroundName)
	cases := []struct {
		name string
		body string
		code int
	}{
		{"the plan the person saw differs", `{"tool":"` + tool + `","folder":"` + jsonPath(pg) + `","changes":["allow_tool"]}`, http.StatusConflict},
		{"an unknown field", `{"tool":"` + tool + `","folder":"","changes":["allow_tool","allow_fresh"],"allow_shell":true}`, http.StatusBadRequest},
		{"a tool that is not launchable", `{"tool":"not-a-tool","folder":"","changes":["allow_tool","allow_fresh"]}`, http.StatusBadRequest},
		{"no tool", `{"tool":"","folder":"","changes":["allow_fresh"]}`, http.StatusBadRequest},
		{"a missing folder that is not the playground", `{"tool":"` + tool + `","folder":"` + jsonPath(filepath.Join(home, "elsewhere")) + `","changes":["allow_tool","allow_fresh","allow_folder","create_folder"]}`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, raw := postFirstLaunch(t, h, "", tc.body)
			if code != tc.code {
				t.Fatalf("code = %d, want %d: %s", code, tc.code, raw)
			}
			for _, p := range []string{pg, filepath.Join(home, "elsewhere")} {
				if _, err := os.Stat(p); !os.IsNotExist(err) {
					t.Fatalf("a refused consent left %s behind", p)
				}
			}
		})
	}
}

// TestFirstLaunchNeedsConfirm pins the double-submit token on the POST.
func TestFirstLaunchNeedsConfirm(t *testing.T) {
	firstLaunchHomeAt(t)
	_, h := newManageServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/terminal/first-launch", strings.NewReader(`{"tool":"x","folder":"","changes":[]}`))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST without a token = %d", rec.Code)
	}
}

// TestFirstLaunchFreshConfigWritesOnlyItsKeys pins the fresh machine: with no
// config.toml yet, the save creates one holding only the consent's keys (not
// every default, D-551), and it loads back to the consented policy.
func TestFirstLaunchFreshConfigWritesOnlyItsKeys(t *testing.T) {
	home := firstLaunchHomeAt(t)
	s, h := newManageServer(t)
	if err := os.Remove(s.opts.ConfigPath); err != nil {
		t.Fatalf("remove config: %v", err)
	}
	tool := launchableTools()[0]
	pg := filepath.Join(home, firstLaunchPlaygroundName)
	body := `{"tool":"` + tool + `","folder":"` + jsonPath(pg) + `","changes":["allow_tool","allow_fresh","allow_folder","create_folder"]}`
	code, out, raw := postFirstLaunch(t, h, "?dry_run=1", body)
	if code != http.StatusOK || out["write_mode"] != "surgical" {
		t.Fatalf("dry run = %d %s", code, raw)
	}
	if stats, _ := out["diff_stats"].(map[string]any); stats == nil || stats["added"].(float64) > 12 {
		t.Fatalf("the preview is not just the consent's keys: %v", out["diff_stats"])
	}
	code, _, raw = postFirstLaunch(t, h, "", body)
	if code != http.StatusOK {
		t.Fatalf("save = %d %s", code, raw)
	}
	b, err := os.ReadFile(s.opts.ConfigPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	text := string(b)
	if strings.Contains(text, "[org_client]") || strings.Contains(text, "[observer]") {
		t.Fatalf("the new config pins defaults:\n%s", text)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: s.opts.ConfigPath})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !cfg.Terminal.Launch.AllowFreshAgent || len(cfg.Terminal.Launch.AllowedTools) != 1 || len(cfg.Terminal.Launch.AllowedProjectRoots) != 1 {
		t.Fatalf("launch policy = %+v\n%s", cfg.Terminal.Launch, text)
	}
}
