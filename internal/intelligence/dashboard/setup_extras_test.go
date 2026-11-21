package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/db"
)

// fakeStatusline records calls and never touches a file.
type fakeStatusline struct {
	calls []string
	err   error
}

func (f *fakeStatusline) Status(context.Context) (dashapi.StatuslineStatus, error) {
	return dashapi.StatuslineStatus{Supported: true, State: dashapi.StatuslineAbsent, Command: "observer statusline"}, nil
}

func (f *fakeStatusline) Apply(_ context.Context, a dashapi.SetupAction, dry, force bool) (dashapi.SetupOutcome, error) {
	f.calls = append(f.calls, fmt.Sprintf("%s dry=%v force=%v", a, dry, force))
	if f.err != nil {
		return dashapi.SetupOutcome{}, f.err
	}
	return dashapi.SetupOutcome{Action: a, DryRun: dry, Changed: true, Lines: []string{"line"}}, nil
}

type fakeLoginStart struct{ calls []string }

func (f *fakeLoginStart) Status(context.Context) (dashapi.LoginStartStatus, error) {
	return dashapi.LoginStartStatus{Supported: true, Manager: "systemd-user"}, nil
}

func (f *fakeLoginStart) Apply(_ context.Context, a dashapi.SetupAction, dry bool) (dashapi.SetupOutcome, error) {
	f.calls = append(f.calls, fmt.Sprintf("%s dry=%v", a, dry))
	return dashapi.SetupOutcome{Action: a, DryRun: dry, Lines: []string{}}, nil
}

type fakeBrowser struct{ ids []string }

func (f *fakeBrowser) Status(context.Context) (dashapi.BrowserCaptureStatus, error) {
	return dashapi.BrowserCaptureStatus{Supported: true, HostFiles: []string{}, Candidates: []dashapi.BrowserExtensionCandidate{}}, nil
}

func (f *fakeBrowser) Apply(_ context.Context, id string, dry bool) (dashapi.SetupOutcome, error) {
	f.ids = append(f.ids, id)
	if id == "bad" {
		return dashapi.SetupOutcome{}, fmt.Errorf("%w: extension id", dashapi.ErrSetupInput)
	}
	return dashapi.SetupOutcome{Action: dashapi.SetupInstall, DryRun: dry, Lines: []string{}}, nil
}

func setupExtrasServer(t *testing.T, extras *dashapi.SetupExtras) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(dir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	cfgPath := filepath.Join(dir, "config.toml")
	s, err := New(Options{DB: database, ConfigPath: cfgPath, SetupExtras: extras})
	if err != nil {
		t.Fatal(err)
	}
	return s, cfgPath
}

// setupExtrasToken GETs path and returns the confirm token and cookie.
func setupExtrasToken(t *testing.T, s *Server, path string) (string, *http.Cookie) {
	t.Helper()
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, rr.Code, rr.Body.String())
	}
	var body struct {
		Token string `json:"confirm_token"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == remoteConfirmCookie {
			return body.Token, c
		}
	}
	t.Fatalf("GET %s: no confirm cookie", path)
	return "", nil
}

func setupExtrasPost(s *Server, path, body, tok string, ck *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if tok != "" {
		req.Header.Set(remoteConfirmHeader, tok)
	}
	if ck != nil {
		req.AddCookie(ck)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	return rr
}

func TestSetupStatuslineRoute(t *testing.T) {
	fake := &fakeStatusline{}
	s, _ := setupExtrasServer(t, &dashapi.SetupExtras{Statusline: fake})
	tok, ck := setupExtrasToken(t, s, "/api/setup/statusline")

	if rr := setupExtrasPost(s, "/api/setup/statusline", `{"action":"install"}`, "", nil); rr.Code != http.StatusForbidden {
		t.Fatalf("no confirm token: %d", rr.Code)
	}
	if len(fake.calls) != 0 {
		t.Fatal("a refused request reached the seam")
	}
	for _, tc := range []struct {
		name, body string
		code       int
		call       string
	}{
		{"preview install", `{"action":"install","dry_run":true}`, http.StatusOK, "install dry=true force=false"},
		{"apply install forced", `{"action":"install","force":true}`, http.StatusOK, "install dry=false force=true"},
		{"remove", `{"action":"remove"}`, http.StatusOK, "remove dry=false force=false"},
		{"unknown action", `{"action":"explode"}`, http.StatusBadRequest, ""},
		{"missing action", `{}`, http.StatusBadRequest, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(fake.calls)
			rr := setupExtrasPost(s, "/api/setup/statusline", tc.body, tok, ck)
			if rr.Code != tc.code {
				t.Fatalf("code %d, want %d: %s", rr.Code, tc.code, rr.Body.String())
			}
			if tc.call == "" {
				if len(fake.calls) != before {
					t.Fatalf("a bad request reached the seam: %v", fake.calls)
				}
				return
			}
			if got := fake.calls[len(fake.calls)-1]; got != tc.call {
				t.Fatalf("seam saw %q, want %q", got, tc.call)
			}
		})
	}
	fake.err = errors.New("settings.json already has a non-observer statusLine")
	if rr := setupExtrasPost(s, "/api/setup/statusline", `{"action":"install"}`, tok, ck); rr.Code != http.StatusConflict {
		t.Fatalf("refusal should be 409, got %d", rr.Code)
	}
}

func TestSetupLoginStartRoute(t *testing.T) {
	fake := &fakeLoginStart{}
	s, _ := setupExtrasServer(t, &dashapi.SetupExtras{LoginStart: fake})
	tok, ck := setupExtrasToken(t, s, "/api/setup/login-start")
	if rr := setupExtrasPost(s, "/api/setup/login-start", `{"action":"install","dry_run":true}`, "", nil); rr.Code != http.StatusForbidden {
		t.Fatalf("no confirm token: %d", rr.Code)
	}
	if rr := setupExtrasPost(s, "/api/setup/login-start", `{"action":"install","dry_run":true}`, tok, ck); rr.Code != http.StatusOK {
		t.Fatalf("preview: %d %s", rr.Code, rr.Body.String())
	}
	if rr := setupExtrasPost(s, "/api/setup/login-start", `{"action":"remove"}`, tok, ck); rr.Code != http.StatusOK {
		t.Fatalf("remove: %d %s", rr.Code, rr.Body.String())
	}
	if strings.Join(fake.calls, ",") != "install dry=true,remove dry=false" {
		t.Fatalf("seam saw %v", fake.calls)
	}
}

func TestSetupBrowserRoute(t *testing.T) {
	fake := &fakeBrowser{}
	s, _ := setupExtrasServer(t, &dashapi.SetupExtras{Browser: fake})
	tok, ck := setupExtrasToken(t, s, "/api/setup/browser")
	if rr := setupExtrasPost(s, "/api/setup/browser", `{"action":"remove"}`, tok, ck); rr.Code != http.StatusBadRequest {
		t.Fatalf("remove is not offered here: %d", rr.Code)
	}
	if rr := setupExtrasPost(s, "/api/setup/browser", `{"extension_id":"bad","dry_run":true}`, tok, ck); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad id should be 400: %d", rr.Code)
	}
	if rr := setupExtrasPost(s, "/api/setup/browser", `{"extension_id":"abcdefghijklmnopabcdefghijklmnop","dry_run":true}`, tok, ck); rr.Code != http.StatusOK {
		t.Fatalf("preview: %d %s", rr.Code, rr.Body.String())
	}
}

func TestSetupExtrasNotWired(t *testing.T) {
	s, _ := setupExtrasServer(t, nil)
	for _, p := range []string{"/api/setup/statusline", "/api/setup/login-start", "/api/setup/browser"} {
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, p, nil))
		if rr.Code != http.StatusNotImplemented {
			t.Errorf("%s: %d, want 501", p, rr.Code)
		}
	}
}

func TestApplyBrowserSites(t *testing.T) {
	for _, tc := range []struct {
		name    string
		start   map[string]bool
		want    map[string]bool
		wantErr string
		wantMap map[string]bool
	}{
		{"turn one off", nil, map[string]bool{"chatgpt-web": false}, "", map[string]bool{"chatgpt-web": false}},
		{
			"turn it back on keeps others",
			map[string]bool{"chatgpt-web": false, "claude-web": false},
			map[string]bool{"chatgpt-web": true},
			"",
			map[string]bool{"chatgpt-web": true, "claude-web": false},
		},
		{"unknown site", nil, map[string]bool{"bing-web": false}, "unknown site", nil},
		{"empty", nil, map[string]bool{}, "no sites", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.Browser.Sites = tc.start
			_, err := applyBrowserSites(&cfg, tc.want)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.Browser.Sites) != len(tc.wantMap) {
				t.Fatalf("sites = %v, want %v", cfg.Browser.Sites, tc.wantMap)
			}
			for k, v := range tc.wantMap {
				if cfg.Browser.Sites[k] != v {
					t.Fatalf("sites = %v, want %v", cfg.Browser.Sites, tc.wantMap)
				}
			}
		})
	}
}

func TestBrowserSiteViews(t *testing.T) {
	views := browserSiteViews(config.BrowserConfig{Sites: map[string]bool{"gemini-web": false}})
	if len(views) != len(browserSiteTable) {
		t.Fatalf("views = %d rows", len(views))
	}
	for _, v := range views {
		switch v.Site {
		case "gemini-web":
			if v.Enabled || !v.Explicit {
				t.Errorf("gemini-web = %+v, want disabled and explicit", v)
			}
		default:
			if !v.Enabled || v.Explicit {
				t.Errorf("%s = %+v, want enabled by default", v.Site, v)
			}
		}
	}
}

func TestBrowserSitesRoute(t *testing.T) {
	s, cfgPath := setupExtrasServer(t, nil)
	tok, ck := setupExtrasToken(t, s, "/api/browser/sites")

	if rr := setupExtrasPost(s, "/api/browser/sites", `{"sites":{"chatgpt-web":false}}`, "", nil); rr.Code != http.StatusForbidden {
		t.Fatalf("no confirm token: %d", rr.Code)
	}
	if rr := setupExtrasPost(s, "/api/browser/sites", `{"sites":{"nope-web":false}}`, tok, ck); rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown site: %d %s", rr.Code, rr.Body.String())
	}
	// A preview writes nothing.
	if rr := setupExtrasPost(s, "/api/browser/sites?dry_run=1", `{"sites":{"chatgpt-web":false}}`, tok, ck); rr.Code != http.StatusOK {
		t.Fatalf("dry run: %d %s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(cfgPath); err == nil {
		t.Fatal("a dry run wrote config.toml")
	}
	rr := setupExtrasPost(s, "/api/browser/sites", `{"sites":{"chatgpt-web":false}}`, tok, ck)
	if rr.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		RestartRequired bool `json:"restart_required"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.RestartRequired {
		t.Error("a per-site toggle is read per captured turn and needs no restart")
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil || !strings.Contains(string(raw), "chatgpt-web") {
		t.Fatalf("config.toml = %q, err %v", raw, err)
	}
	loaded, err := loadConfigForDashboard(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := loaded.Browser.Sites["chatgpt-web"]; !ok || v {
		t.Fatalf("loaded sites = %v, want chatgpt-web=false", loaded.Browser.Sites)
	}
}
