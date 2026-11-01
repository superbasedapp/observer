package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/codextrust"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// withFakeHome redirects $HOME so the snapshot reads our test fixture
// rather than the real ~/.codex/config.toml. UserHomeDir respects HOME
// on POSIX and USERPROFILE on Windows; we set both to be safe under
// `go test ./...` from any platform.
func withFakeHome(t *testing.T, contents string) string {
	t.Helper()
	home := t.TempDir()
	if contents != "" {
		dir := filepath.Join(home, ".codex")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir codex dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(contents), 0o600); err != nil {
			t.Fatalf("write config.toml: %v", err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CODEX_HOME", "") // disable auth.json detection — irrelevant here
	return home
}

func newSetupServer(t *testing.T, port int) *Server {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	srv, err := New(Options{DB: database, DBPath: dbPath, ProxyPort: port})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func decodeJSON(t *testing.T, rr *httptest.ResponseRecorder, into any) {
	t.Helper()
	if err := json.NewDecoder(rr.Body).Decode(into); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rr.Body.String())
	}
}

// TestSetupCodex_GET_NoConfig pins the cold-start case — no
// ~/.codex/config.toml. Status="no_config", would_register=true.
func TestSetupCodex_GET_NoConfig(t *testing.T) {
	withFakeHome(t, "")
	srv := newSetupServer(t, 8820)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/setup/codex", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("GET: %d body=%s", rr.Code, rr.Body.String())
	}
	var got codexSetupSnapshot
	decodeJSON(t, rr, &got)
	if got.Status != "no_config" {
		t.Errorf("status: got %q want no_config", got.Status)
	}
	if !got.WouldRegister {
		t.Errorf("would_register: got false want true")
	}
	if got.DesiredBaseURL != "http://127.0.0.1:8820/v1" {
		t.Errorf("desired_base_url: got %q", got.DesiredBaseURL)
	}
	if got.ConfigExists {
		t.Errorf("config_exists: got true want false")
	}
}

// TestSetupCodex_GET_RoutedToObserver pins the green-path case where
// config.toml already routes through us. would_register stays true
// because the registrar is idempotent.
func TestSetupCodex_GET_RoutedToObserver(t *testing.T) {
	cfg := `model_provider = "openai-observer"

[model_providers.openai-observer]
name = "OpenAI (via Observer)"
base_url = "http://127.0.0.1:8820/v1"
wire_api = "responses"
requires_openai_auth = true
`
	withFakeHome(t, cfg)
	srv := newSetupServer(t, 8820)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/setup/codex", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("GET: %d body=%s", rr.Code, rr.Body.String())
	}
	var got codexSetupSnapshot
	decodeJSON(t, rr, &got)
	if got.Status != "routed_to_observer" {
		t.Errorf("status: got %q want routed_to_observer", got.Status)
	}
	if got.CurrentBaseURL != "http://127.0.0.1:8820/v1" {
		t.Errorf("current_base_url: %q", got.CurrentBaseURL)
	}
	if got.CurrentModelProvider != "openai-observer" {
		t.Errorf("current_model_provider: %q", got.CurrentModelProvider)
	}
}

// TestSetupCodex_GET_ReservedBlock — codex 0.128.0+ rejects any
// [model_providers.openai] block. Status surfaces the conflict and
// would_register=false until force=true.
func TestSetupCodex_GET_ReservedBlock(t *testing.T) {
	cfg := `[model_providers.openai]
base_url = "http://127.0.0.1:8820/v1"
`
	withFakeHome(t, cfg)
	srv := newSetupServer(t, 8820)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/setup/codex", nil)
	srv.Handler().ServeHTTP(rr, req)
	var got codexSetupSnapshot
	decodeJSON(t, rr, &got)
	if got.Status != "reserved_block_present" {
		t.Errorf("status: got %q want reserved_block_present", got.Status)
	}
	if !got.HasReservedBlock {
		t.Errorf("has_reserved_openai_block: got false want true")
	}
	if got.WouldRegister {
		t.Errorf("would_register: got true want false")
	}
	if !strings.Contains(got.WouldRegisterError, "force=true") {
		t.Errorf("would_register_error should mention force=true: %q", got.WouldRegisterError)
	}
}

// TestSetupCodex_GET_NonLoopback — observer provider exists but
// base_url points off-host (a transparent proxy in the user's network,
// say). Refuses without force, status surfaces the value.
func TestSetupCodex_GET_NonLoopback(t *testing.T) {
	cfg := `[model_providers.openai-observer]
base_url = "http://corp-proxy.internal:9000/v1"
`
	withFakeHome(t, cfg)
	srv := newSetupServer(t, 8820)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/setup/codex", nil)
	srv.Handler().ServeHTTP(rr, req)
	var got codexSetupSnapshot
	decodeJSON(t, rr, &got)
	if got.Status != "non_loopback" {
		t.Errorf("status: got %q want non_loopback", got.Status)
	}
	if got.WouldRegister {
		t.Errorf("would_register: got true want false")
	}
}

// TestSetupCodex_POST_FreshFile writes a green-path config.toml end-to-
// end. After POST the file on disk should round-trip back through GET
// to status="routed_to_observer".
func TestSetupCodex_POST_FreshFile(t *testing.T) {
	home := withFakeHome(t, "")
	srv := newSetupServer(t, 8820)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/setup/codex",
		strings.NewReader(`{}`))
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("POST: %d body=%s", rr.Code, rr.Body.String())
	}
	var got codexSetupPostResponse
	decodeJSON(t, rr, &got)
	if !got.Added {
		t.Errorf("added: got false want true")
	}
	if got.Snapshot.Status != "routed_to_observer" {
		t.Errorf("snapshot.status post-write: got %q want routed_to_observer", got.Snapshot.Status)
	}

	// Verify file landed where we expect.
	cfgPath := filepath.Join(home, ".codex", "config.toml")
	body, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read written config: %v", err)
	}
	if !strings.Contains(string(body), `model_provider = "openai-observer"`) {
		t.Errorf("written config missing model_provider switch:\n%s", body)
	}
}

// TestSetupCodex_POST_ReservedBlockWithoutForce — the legacy reserved
// block conflict comes back as 409 with the typed error so the
// frontend can offer a "force overwrite" button.
func TestSetupCodex_POST_ReservedBlockWithoutForce(t *testing.T) {
	cfg := `[model_providers.openai]
base_url = "http://127.0.0.1:8820/v1"
`
	withFakeHome(t, cfg)
	srv := newSetupServer(t, 8820)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/setup/codex",
		strings.NewReader(`{"force":false}`))
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("POST without force: got %d want 409 body=%s", rr.Code, rr.Body.String())
	}
	var got codexSetupPostResponse
	decodeJSON(t, rr, &got)
	if got.Error == "" {
		t.Errorf("error field empty; want reserved-block message")
	}
	if got.Snapshot.Status != "reserved_block_present" {
		t.Errorf("snapshot.status: got %q want reserved_block_present", got.Snapshot.Status)
	}
}

// TestSetupCodex_POST_ReservedBlockWithForce — force=true migrates the
// install in one click. The reserved block is removed and the custom
// provider is wired up.
func TestSetupCodex_POST_ReservedBlockWithForce(t *testing.T) {
	cfg := `[model_providers.openai]
base_url = "http://127.0.0.1:8820/v1"
`
	withFakeHome(t, cfg)
	srv := newSetupServer(t, 8820)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/setup/codex",
		strings.NewReader(`{"force":true}`))
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("POST with force: %d body=%s", rr.Code, rr.Body.String())
	}
	var got codexSetupPostResponse
	decodeJSON(t, rr, &got)
	if !got.Added {
		t.Errorf("added: got false want true")
	}
	if got.Snapshot.HasReservedBlock {
		t.Errorf("reserved block still present after force overwrite")
	}
	if got.Snapshot.Status != "routed_to_observer" {
		t.Errorf("snapshot.status: got %q want routed_to_observer", got.Snapshot.Status)
	}
}

// TestSetupCodex_POST_DryRun — dry_run=true returns the registration
// result without touching disk.
func TestSetupCodex_POST_DryRun(t *testing.T) {
	home := withFakeHome(t, "")
	srv := newSetupServer(t, 8820)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/setup/codex",
		strings.NewReader(`{"dry_run":true}`))
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("POST dry_run: %d body=%s", rr.Code, rr.Body.String())
	}
	var got codexSetupPostResponse
	decodeJSON(t, rr, &got)
	if !got.DryRun {
		t.Errorf("dry_run: got false want true")
	}
	if !got.Added {
		t.Errorf("added: got false (dry-run still claims it would add)")
	}
	// File should not exist.
	if _, err := os.Stat(filepath.Join(home, ".codex", "config.toml")); !os.IsNotExist(err) {
		t.Errorf("dry-run wrote a file: stat err=%v", err)
	}
}

// TestSetupCodex_GET_NotConfiguredEmpty — config.toml exists but is
// empty (or has unrelated keys); status="not_configured".
func TestSetupCodex_GET_NotConfiguredEmpty(t *testing.T) {
	cfg := `# unrelated codex settings
mcp_servers = {}
`
	withFakeHome(t, cfg)
	srv := newSetupServer(t, 8820)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/setup/codex", nil)
	srv.Handler().ServeHTTP(rr, req)
	var got codexSetupSnapshot
	decodeJSON(t, rr, &got)
	if got.Status != "not_configured" {
		t.Errorf("status: got %q want not_configured", got.Status)
	}
	if !got.ConfigExists {
		t.Errorf("config_exists should be true")
	}
	if !got.WouldRegister {
		t.Errorf("would_register: got false want true")
	}
}

// TestSetupCodex_MethodNotAllowed — DELETE etc. return 405 with Allow.
func TestSetupCodex_MethodNotAllowed(t *testing.T) {
	withFakeHome(t, "")
	srv := newSetupServer(t, 8820)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/setup/codex", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE: got %d want 405", rr.Code)
	}
	if got := rr.Header().Get("Allow"); !strings.Contains(got, "GET") || !strings.Contains(got, "POST") {
		t.Errorf("Allow header: %q", got)
	}
}

// withFakeClaudeHome stages a $HOME with optional ~/.claude/.credentials.json.
// `creds` empty means the file is absent (api_key_ready path).
func withFakeClaudeHome(t *testing.T, creds string) string {
	t.Helper()
	home := t.TempDir()
	if creds != "" {
		dir := filepath.Join(home, ".claude")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir .claude: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".credentials.json"), []byte(creds), 0o600); err != nil {
			t.Fatalf("write credentials.json: %v", err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("ANTHROPIC_CONFIG_DIR", "")
	return home
}

// TestSetupClaude_GET_OAuthReady — credentials.json with a real-shaped
// claudeAiOauth.accessToken classifies as oauth_ready.
func TestSetupClaude_GET_OAuthReady(t *testing.T) {
	creds := `{
  "claudeAiOauth": {
    "accessToken": "sk-ant-oat01-test-abc",
    "subscriptionType": "max"
  }
}`
	withFakeClaudeHome(t, creds)
	srv := newSetupServer(t, 8820)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/setup/claude", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("GET: %d body=%s", rr.Code, rr.Body.String())
	}
	var got claudeSetupSnapshot
	decodeJSON(t, rr, &got)
	if got.Status != "oauth_ready" && got.Status != "claude_not_installed" {
		// claude binary may or may not be on PATH in the test env; if
		// it isn't, status takes precedence over oauth_ready (the
		// launcher won't work without the binary). Both are valid here.
		t.Errorf("status: got %q want oauth_ready or claude_not_installed", got.Status)
	}
	if !got.HasOAuthCredentials {
		t.Errorf("has_oauth_credentials: got false want true")
	}
	if got.ProxyPort != 8820 {
		t.Errorf("proxy_port: got %d want 8820", got.ProxyPort)
	}
	if got.ProxyURL != "http://127.0.0.1:8820" {
		t.Errorf("proxy_url: got %q", got.ProxyURL)
	}
	if !strings.Contains(got.LauncherCommand, "observer claude") {
		t.Errorf("launcher_command: got %q", got.LauncherCommand)
	}
	if !strings.Contains(got.LauncherCommand, "http://127.0.0.1:8820") {
		t.Errorf("launcher_command missing proxy URL: got %q", got.LauncherCommand)
	}
}

// TestSetupClaude_POST_RoutesDurably — the L1 one-click (usability arc
// P1.5): POST /api/setup/claude writes env.ANTHROPIC_BASE_URL into
// ~/.claude/settings.json via proxyroute.RegisterClaudeCode. Pins:
// dry_run touches nothing, the real write lands + snapshot reports
// routed, a second POST is idempotent, a deliberate third-party URL
// 409s, and force=true overrides it.
func TestSetupClaude_POST_RoutesDurably(t *testing.T) {
	home := withFakeClaudeHome(t, "")
	srv := newSetupServer(t, 8820)
	settingsPath := filepath.Join(home, ".claude", "settings.json")

	post := func(t *testing.T, body string) (int, claudeSetupPostResponse) {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/setup/claude", strings.NewReader(body))
		srv.Handler().ServeHTTP(rr, req)
		var resp claudeSetupPostResponse
		decodeJSON(t, rr, &resp)
		return rr.Code, resp
	}

	// Dry run first: reports added but writes nothing.
	code, resp := post(t, `{"dry_run":true}`)
	if code != 200 || !resp.Added || !resp.DryRun {
		t.Fatalf("dry_run: code=%d resp=%+v", code, resp)
	}
	if _, err := os.Stat(settingsPath); !os.IsNotExist(err) {
		t.Fatalf("dry_run must not create settings.json")
	}

	// Real write.
	code, resp = post(t, `{}`)
	if code != 200 || !resp.Added {
		t.Fatalf("write: code=%d resp=%+v", code, resp)
	}
	raw, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("settings.json not written: %v", err)
	}
	if !strings.Contains(string(raw), `"ANTHROPIC_BASE_URL": "http://127.0.0.1:8820"`) {
		t.Errorf("settings.json missing route: %s", raw)
	}
	if !resp.Snapshot.RoutedToObserver {
		t.Errorf("post-write snapshot should report routed_to_observer; got %+v", resp.Snapshot)
	}

	// Idempotent.
	code, resp = post(t, `{}`)
	if code != 200 || !resp.AlreadySet {
		t.Fatalf("idempotent re-POST: code=%d resp=%+v", code, resp)
	}

	// Third-party URL the user set deliberately → 409, then force wins.
	thirdParty := `{
  "env": { "ANTHROPIC_BASE_URL": "https://corp-gateway.example.com:8443" },
  "hooks": { "Stop": [] }
}`
	if err := os.WriteFile(settingsPath, []byte(thirdParty), 0o600); err != nil {
		t.Fatal(err)
	}
	code, resp = post(t, `{}`)
	if code != http.StatusConflict || resp.Error == "" {
		t.Fatalf("third-party conflict: code=%d resp=%+v", code, resp)
	}
	code, resp = post(t, `{"force":true}`)
	if code != 200 || !resp.Added {
		t.Fatalf("force override: code=%d resp=%+v", code, resp)
	}
	raw, _ = os.ReadFile(settingsPath)
	if !strings.Contains(string(raw), `"ANTHROPIC_BASE_URL": "http://127.0.0.1:8820"`) {
		t.Errorf("force did not switch the route: %s", raw)
	}
	if !strings.Contains(string(raw), `"hooks"`) {
		t.Errorf("unrelated settings keys must survive the route write: %s", raw)
	}
}

// TestSetupClaude_GET_APIKeyReady — no credentials file → api_key_ready
// (assuming claude binary on PATH; otherwise claude_not_installed).
func TestSetupClaude_GET_APIKeyReady(t *testing.T) {
	withFakeClaudeHome(t, "")
	srv := newSetupServer(t, 8820)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/setup/claude", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("GET: %d", rr.Code)
	}
	var got claudeSetupSnapshot
	decodeJSON(t, rr, &got)
	if got.HasOAuthCredentials {
		t.Errorf("has_oauth_credentials: got true (no credentials file should mean false)")
	}
	if got.Status != "api_key_ready" && got.Status != "claude_not_installed" {
		t.Errorf("status: got %q want api_key_ready or claude_not_installed", got.Status)
	}
}

// TestSetupClaude_GET_MalformedCredentialsTreatedAsAPIKey — corrupt
// JSON shouldn't 500; snapshot just falls back to api_key_ready.
func TestSetupClaude_GET_MalformedCredentialsTreatedAsAPIKey(t *testing.T) {
	withFakeClaudeHome(t, `{ this is not valid JSON`)
	srv := newSetupServer(t, 8820)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/setup/claude", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("GET: %d", rr.Code)
	}
	var got claudeSetupSnapshot
	decodeJSON(t, rr, &got)
	if got.HasOAuthCredentials {
		t.Errorf("malformed credentials should not register as OAuth")
	}
}

// TestSetupClaude_GET_EmptyAccessToken — file exists with shape but
// empty accessToken doesn't promote to oauth_ready.
func TestSetupClaude_GET_EmptyAccessToken(t *testing.T) {
	withFakeClaudeHome(t, `{"claudeAiOauth":{"accessToken":""}}`)
	srv := newSetupServer(t, 8820)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/setup/claude", nil)
	srv.Handler().ServeHTTP(rr, req)
	var got claudeSetupSnapshot
	decodeJSON(t, rr, &got)
	if got.HasOAuthCredentials {
		t.Errorf("empty accessToken must not classify as OAuth-ready")
	}
}

// TestSetupClaude_MethodNotAllowed — methods beyond GET/POST return
// 405 with Allow. (POST became legitimate in the usability arc P1.5 —
// it writes the durable route; see TestSetupClaude_POST_RoutesDurably.)
func TestSetupClaude_MethodNotAllowed(t *testing.T) {
	withFakeClaudeHome(t, "")
	srv := newSetupServer(t, 8820)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/setup/claude", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE: got %d want 405", rr.Code)
	}
	allow := rr.Header().Get("Allow")
	if !strings.Contains(allow, "GET") || !strings.Contains(allow, "POST") {
		t.Errorf("Allow header: %q want GET, POST", allow)
	}
}

// TestSetupClaude_HonorsConfigDirEnv — CLAUDE_CONFIG_DIR override
// trumps $HOME/.claude/. Pinning this so users with a non-default
// install layout aren't silently misclassified as API-key.
func TestSetupClaude_HonorsConfigDirEnv(t *testing.T) {
	overrideHome := t.TempDir()
	overrideDir := filepath.Join(overrideHome, "custom-claude")
	if err := os.MkdirAll(overrideDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(overrideDir, ".credentials.json"),
		[]byte(`{"claudeAiOauth":{"accessToken":"sk-ant-oat01-from-override"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir()) // empty fake home — no .claude/ here
	t.Setenv("USERPROFILE", t.TempDir())
	t.Setenv("CLAUDE_CONFIG_DIR", overrideDir)
	t.Setenv("ANTHROPIC_CONFIG_DIR", "")

	srv := newSetupServer(t, 8820)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/setup/claude", nil)
	srv.Handler().ServeHTTP(rr, req)
	var got claudeSetupSnapshot
	decodeJSON(t, rr, &got)
	if !got.HasOAuthCredentials {
		t.Errorf("CLAUDE_CONFIG_DIR override not honored: got has_oauth=false")
	}
	if !strings.HasPrefix(got.CredentialsPath, overrideDir) {
		t.Errorf("credentials_path: got %q, want prefix %q", got.CredentialsPath, overrideDir)
	}
}

// withFakeCodexHooks seeds ~/.codex/hooks.json with observer-owned
// entries for each requested event. Returns the home dir and the
// hooks file path so tests can write a matching config.toml.
// tomlKeyPath escapes a filesystem path for embedding inside a TOML
// basic-string key. On Windows the path carries backslashes, which a TOML
// basic string reads as escape sequences (\U…, \h…) and rejects, failing
// the whole config.toml parse; doubling them keeps the PARSED key
// byte-identical to the original native path, so checkCodexHookTrust's
// HasPrefix(key, out.HooksFile+":") match still holds (out.HooksFile is a
// native filepath.Join path, so we must NOT normalize to forward slashes).
// A no-op on POSIX paths (no backslashes).
func tomlKeyPath(p string) string { return strings.ReplaceAll(p, `\`, `\\`) }

func withFakeCodexHooks(t *testing.T, events ...string) (home, hooksPath string) {
	t.Helper()
	home = t.TempDir()
	dir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	hooks := map[string]any{}
	for _, e := range events {
		hooks[e] = []any{
			map[string]any{
				"matcher": "*",
				"hooks": []any{
					map[string]any{"type": "command", "command": "/usr/local/bin/observer hook codex " + e},
				},
			},
		}
	}
	body, _ := json.Marshal(map[string]any{"hooks": hooks})
	hooksPath = filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(hooksPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CODEX_HOME", "")
	return home, hooksPath
}

func TestSetupCodexHooks_NoCodex(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	srv := newSetupServer(t, 8820)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/setup/codex-hooks", nil)
	srv.Handler().ServeHTTP(rr, req)
	var got codexHookTrustSnapshot
	decodeJSON(t, rr, &got)
	if got.Status != "no_codex" {
		t.Errorf("status=%q want no_codex", got.Status)
	}
}

func TestSetupCodexHooks_NoObserverHooks(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	srv := newSetupServer(t, 8820)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/setup/codex-hooks", nil)
	srv.Handler().ServeHTTP(rr, req)
	var got codexHookTrustSnapshot
	decodeJSON(t, rr, &got)
	if got.Status != "no_hooks" {
		t.Errorf("status=%q want no_hooks", got.Status)
	}
}

func TestSetupCodexHooks_NeedsTrust(t *testing.T) {
	withFakeCodexHooks(t, "SessionStart", "PreToolUse", "Stop")
	srv := newSetupServer(t, 8820)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/setup/codex-hooks", nil)
	srv.Handler().ServeHTTP(rr, req)
	var got codexHookTrustSnapshot
	decodeJSON(t, rr, &got)
	if got.Status != "config_missing" {
		t.Errorf("status=%q want config_missing (no config.toml yet)", got.Status)
	}
	if len(got.UntrustedEvents) != 3 {
		t.Errorf("UntrustedEvents=%d want 3", len(got.UntrustedEvents))
	}
	if !strings.Contains(got.Instruction, "/hooks") {
		t.Errorf("instruction missing /hooks reference: %q", got.Instruction)
	}
}

func TestSetupCodexHooks_FeatureDisabled(t *testing.T) {
	home, _ := withFakeCodexHooks(t, "SessionStart")
	// config.toml exists but missing the hooks=true flag.
	cfg := `personality = "p"
`
	if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := newSetupServer(t, 8820)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/setup/codex-hooks", nil)
	srv.Handler().ServeHTTP(rr, req)
	var got codexHookTrustSnapshot
	decodeJSON(t, rr, &got)
	if got.Status != "feature_disabled" {
		t.Errorf("status=%q want feature_disabled", got.Status)
	}
	if got.FeatureFlagEnabled {
		t.Errorf("FeatureFlagEnabled=true unexpected")
	}
}

// codexRegistryEvents is every Codex event Observer registers.
func codexRegistryEvents(t *testing.T) []string {
	t.Helper()
	c, ok := integration.For(models.ToolCodex)
	if !ok {
		t.Fatal("no codex registry row")
	}
	return c.Hook.RegisteredEvents()
}

// codexStateTOML renders one [hooks.state] entry per event.
func codexStateTOML(hooksPath string, hashes map[string]string) string {
	keys := make([]string, 0, len(hashes))
	for k := range hashes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, e := range keys {
		fmt.Fprintf(&b, "[hooks.state.\"%s:%s:0:0\"]\ntrusted_hash = %q\n\n", hooksPath, codextrust.CamelToSnake(e), hashes[e])
	}
	return b.String()
}

func TestSetupCodexHooks_AllTrusted(t *testing.T) {
	events := codexRegistryEvents(t)
	home, hooksPathRaw := withFakeCodexHooks(t, events...)
	hashes := map[string]string{}
	for _, e := range events {
		hashes[e] = "sha256:recorded-" + e
	}
	cfg := "[features]\nhooks = true\n\n" + codexStateTOML(tomlKeyPath(hooksPathRaw), hashes)
	if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	got := getCodexHooks(t)
	if got.Status != "all_trusted" {
		t.Errorf("status=%q want all_trusted (got: %+v)", got.Status, got)
	}
	if len(got.UntrustedEvents) != 0 || len(got.MissingEvents) != 0 {
		t.Errorf("Untrusted=%v Missing=%v want both empty", got.UntrustedEvents, got.MissingEvents)
	}
	if len(got.TrustedEvents) != len(events) || len(got.Entries) != len(events) {
		t.Errorf("TrustedEvents=%v Entries=%d want %d", got.TrustedEvents, len(got.Entries), len(events))
	}
	if got.HashVerified {
		t.Error("fake recorded hashes must not count as verified")
	}
}

func getCodexHooks(t *testing.T) codexHookTrustSnapshot {
	t.Helper()
	srv := newSetupServer(t, 8820)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/setup/codex-hooks", nil))
	var got codexHookTrustSnapshot
	decodeJSON(t, rr, &got)
	return got
}

// TestSetupCodexHooks_ModifiedAndMissing: a recomputed trust hash proves
// one entry changed after it was trusted; an event the registry expects
// but hooks.json lacks is listed as missing (T-039).
func TestSetupCodexHooks_ModifiedAndMissing(t *testing.T) {
	events := codexRegistryEvents(t)
	present := events[:len(events)-1]
	home, hooksPathRaw := withFakeCodexHooks(t, present...)
	star := "*"
	hashes := map[string]string{}
	for _, e := range present {
		cmd := "/usr/local/bin/observer hook codex " + e
		m := &star
		if e == "UserPromptSubmit" || e == "Stop" {
			m = nil
		}
		// SessionEnd (registered since hook-parity Lane C) defaults to
		// Codex's short 1 s hook timeout, every other event to 600 s.
		timeout := int64(600)
		if e == "SessionEnd" {
			timeout = 1
		}
		hashes[e] = codextrust.Hash(codextrust.CamelToSnake(e), m, cmd, timeout, false, nil)
	}
	hashes[present[0]] = "sha256:stale"
	cfg := "[features]\nhooks = true\n\n" + codexStateTOML(tomlKeyPath(hooksPathRaw), hashes)
	if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	got := getCodexHooks(t)
	if got.Status != "needs_trust" || !got.HashVerified {
		t.Fatalf("status=%q verified=%v, want needs_trust + verified", got.Status, got.HashVerified)
	}
	if fmt.Sprint(got.ModifiedEvents) != fmt.Sprint([]string{present[0]}) {
		t.Errorf("ModifiedEvents=%v want [%s]", got.ModifiedEvents, present[0])
	}
	if fmt.Sprint(got.MissingEvents) != fmt.Sprint([]string{events[len(events)-1]}) {
		t.Errorf("MissingEvents=%v want [%s]", got.MissingEvents, events[len(events)-1])
	}
	if !strings.Contains(got.Instruction, "re-trust") || !strings.Contains(got.Instruction, "/hooks") {
		t.Errorf("instruction must say how to re-trust: %q", got.Instruction)
	}
}

func TestSetupCodexHooks_PartialTrust(t *testing.T) {
	home, hooksPathRaw := withFakeCodexHooks(t, "SessionStart", "PreToolUse", "Stop")
	hooksPath := tomlKeyPath(hooksPathRaw)
	cfg := `[features]
hooks = true

[hooks.state."` + hooksPath + `:session_start:0:0"]
trusted_hash = "sha256:abc"
`
	if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := newSetupServer(t, 8820)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/setup/codex-hooks", nil)
	srv.Handler().ServeHTTP(rr, req)
	var got codexHookTrustSnapshot
	decodeJSON(t, rr, &got)
	if got.Status != "needs_trust" {
		t.Errorf("status=%q want needs_trust", got.Status)
	}
	if len(got.TrustedEvents) != 1 || got.TrustedEvents[0] != "SessionStart" {
		t.Errorf("TrustedEvents=%v want [SessionStart]", got.TrustedEvents)
	}
	if len(got.UntrustedEvents) != 2 {
		t.Errorf("UntrustedEvents=%v want 2 entries", got.UntrustedEvents)
	}
	if !strings.Contains(got.Instruction, "PreToolUse") || !strings.Contains(got.Instruction, "Stop") {
		t.Errorf("instruction missing untrusted event names: %q", got.Instruction)
	}
}

func TestSetupCodexHooks_RejectsNonGET(t *testing.T) {
	srv := newSetupServer(t, 8820)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/setup/codex-hooks", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status=%d want 405", rr.Code)
	}
}

// TestSetupClaude_ExtensionOnlyIsNotAbsent (WINNODE2 16b): with no `claude`
// on PATH but the Claude Code VS Code extension's install signal holding,
// the snapshot says extension_ready (the header pill then reports the
// route instead of "No Claude Code"); without the signal it stays
// claude_not_installed.
func TestSetupClaude_ExtensionOnlyIsNotAbsent(t *testing.T) {
	withFakeClaudeHome(t, "")
	t.Setenv("PATH", t.TempDir())
	for _, tc := range []struct {
		tools []string
		want  string
	}{
		{[]string{"claude-code"}, "extension_ready"},
		{[]string{"codex"}, "claude_not_installed"},
		{nil, "claude_not_installed"},
	} {
		srv := newSetupServer(t, 8820)
		tools := tc.tools
		srv.opts.InstallSignalTools = func() []string { return tools }
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/setup/claude", nil))
		var got claudeSetupSnapshot
		decodeJSON(t, rr, &got)
		if got.Status != tc.want || got.EditorExtensionInstalled != (tc.want == "extension_ready") {
			t.Errorf("signals %v: status %q extension=%v, want %q", tc.tools, got.Status, got.EditorExtensionInstalled, tc.want)
		}
	}
}
