package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/configschema"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// keysCorpus is a hand-written config.toml with comments in every position
// the surgical editor must preserve.
const keysCorpus = `# Operator header comment — must survive.
[observer]
# log_level explains itself
log_level = "warn" # inline: keep me

[observer.watch]
poll_interval_seconds = 5

[terminal]
enabled = true

[terminal.launch]
allow_shell = false
allowed_tools = ["claude"]

[profiles]
default = "default"
`

// configGet performs GET /api/config and returns the etag, the confirm token
// and the cookie the PUT must echo.
func configGet(t *testing.T, s *Server) (etag, token string, cookie *http.Cookie) {
	t.Helper()
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/config: %d %s", rr.Code, rr.Body.String())
	}
	var got struct {
		Etag  string `json:"config_etag"`
		Token string `json:"confirm_token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == remoteConfirmCookie {
			cookie = c
		}
	}
	if got.Etag == "" || got.Token == "" || cookie == nil {
		t.Fatalf("GET /api/config must mint etag + confirm token + cookie: %+v cookie=%v", got, cookie)
	}
	return got.Etag, got.Token, cookie
}

// putKeys sends PUT /api/config/keys. confirm=true echoes the token.
func putKeys(t *testing.T, s *Server, body string, confirm bool) *httptest.ResponseRecorder {
	t.Helper()
	_, token, cookie := configGet(t, s)
	req := httptest.NewRequest(http.MethodPut, "/api/config/keys", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if confirm {
		req.Header.Set(remoteConfirmHeader, token)
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	return rr
}

func keysBody(etag string, patches ...string) string {
	return `{"base_etag":"` + etag + `","patches":[` + strings.Join(patches, ",") + `]}`
}

func decodeMap(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode %q: %v", rr.Body.String(), err)
	}
	return m
}

func strs(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, it := range arr {
		out = append(out, it.(string))
	}
	return out
}

func TestConfigKeys_SurgicalWriteKeepsCommentsAndClassifies(t *testing.T) {
	s, path := newSecretTestServer(t, keysCorpus)
	etag, _, _ := configGet(t, s)
	rr := putKeys(t, s, keysBody(
		etag,
		`{"key":"observer.log_level","value":"debug","was":"warn"}`,
		`{"key":"terminal.max_concurrent","value":12}`,
		`{"key":"profiles.default","value":"claude-code"}`,
	), false)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	m := decodeMap(t, rr)
	if m["write_mode"] != "surgical" || m["comments_preserved"] != true {
		t.Fatalf("expected a surgical, comment-preserving write: %v", m)
	}
	if m["restart_required"] != true {
		t.Fatalf("observer.log_level binds at start — restart_required must be true: %v", m)
	}
	if got := strs(m["restart_required_keys"]); strings.Join(got, ",") != "observer.log_level,terminal.max_concurrent" {
		t.Errorf("restart_required_keys = %v (terminal limits have no live setter on a bare test server, so they degrade to restart)", got)
	}
	if got := strs(m["applied_live_keys"]); strings.Join(got, ",") != "profiles.default" {
		t.Errorf("applied_live_keys = %v", got)
	}
	body, _ := os.ReadFile(path)
	text := string(body)
	for _, want := range []string{"# Operator header comment — must survive.", "# log_level explains itself", `log_level = "debug" # inline: keep me`, "max_concurrent = 12", `default = "claude-code"`, `allowed_tools = ["claude"]`} {
		if !strings.Contains(text, want) {
			t.Errorf("file missing %q:\n%s", want, text)
		}
	}
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Errorf(".bak must exist after a write: %v", err)
	}
	newEtag, _, _ := configGet(t, s)
	if newEtag == etag || m["config_etag"] != newEtag {
		t.Errorf("etag must advance and be echoed: before=%s after=%s resp=%v", etag, newEtag, m["config_etag"])
	}
	// The audit row names keys and counts, never values.
	st := store.New(s.opts.DB)
	rows, err := st.RecentRemoteAudit(context.Background(), 5)
	if err != nil || len(rows) == 0 {
		t.Fatalf("audit rows: %v %v", rows, err)
	}
	if !strings.Contains(rows[0].Detail, "config_keys") || !strings.Contains(rows[0].Detail, "observer.log_level") || strings.Contains(rows[0].Detail, "debug") {
		t.Errorf("audit detail must carry key names, not values: %q", rows[0].Detail)
	}
}

func TestConfigKeys_TierGates(t *testing.T) {
	s, path := newSecretTestServer(t, keysCorpus)
	orig, _ := os.ReadFile(path)
	untouched := func(t *testing.T) {
		t.Helper()
		now, _ := os.ReadFile(path)
		if string(now) != string(orig) {
			t.Fatalf("file must be untouched after a refusal")
		}
	}
	etag, _, _ := configGet(t, s)

	t.Run("secret is 403 and names the file", func(t *testing.T) {
		rr := putKeys(t, s, keysBody(etag, `{"key":"selfobs.secret","value":"x"}`, `{"key":"observer.log_level","value":"info"}`), true)
		if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "selfobs.secret") || !strings.Contains(rr.Body.String(), "config.toml") {
			t.Fatalf("got %d %s", rr.Code, rr.Body.String())
		}
		untouched(t)
	})
	t.Run("owner-elsewhere is 409 naming the owner", func(t *testing.T) {
		rr := putKeys(t, s, keysBody(etag, `{"key":"org_client.enabled","value":true}`), true)
		if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "observer org") {
			t.Fatalf("got %d %s", rr.Code, rr.Body.String())
		}
		untouched(t)
	})
	t.Run("deprecated alias is 409", func(t *testing.T) {
		rr := putKeys(t, s, keysBody(etag, `{"key":"compression.code_graph.enabled","value":true}`), true)
		if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "deprecated") {
			t.Fatalf("got %d %s", rr.Code, rr.Body.String())
		}
		untouched(t)
	})
	t.Run("compound table is 409", func(t *testing.T) {
		rr := putKeys(t, s, keysBody(etag, `{"key":"intelligence.pricing.models","value":{}}`), true)
		if rr.Code != http.StatusConflict {
			t.Fatalf("got %d %s", rr.Code, rr.Body.String())
		}
		untouched(t)
	})
	t.Run("unknown key is 400", func(t *testing.T) {
		rr := putKeys(t, s, keysBody(etag, `{"key":"observer.nope","value":1}`), true)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "observer.nope") {
			t.Fatalf("got %d %s", rr.Code, rr.Body.String())
		}
		untouched(t)
	})
	t.Run("sensitive without confirm token is 403", func(t *testing.T) {
		rr := putKeys(t, s, keysBody(etag, `{"key":"terminal.launch.allow_shell","value":true}`), false)
		if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "confirm token") {
			t.Fatalf("got %d %s", rr.Code, rr.Body.String())
		}
		untouched(t)
	})
	t.Run("sensitive with confirm token writes", func(t *testing.T) {
		rr := putKeys(t, s, keysBody(etag, `{"key":"terminal.launch.allow_shell","value":true}`), true)
		if rr.Code != http.StatusOK {
			t.Fatalf("got %d %s", rr.Code, rr.Body.String())
		}
		now, _ := os.ReadFile(path)
		if !strings.Contains(string(now), "allow_shell = true") {
			t.Fatalf("value not written: %s", now)
		}
	})
}

func TestConfigKeys_EtagConflictNamesDivergedKeys(t *testing.T) {
	s, path := newSecretTestServer(t, keysCorpus)
	etag, _, _ := configGet(t, s)
	// Someone edits the file by hand after the page loaded.
	if err := os.WriteFile(path, []byte(strings.Replace(keysCorpus, `log_level = "warn"`, `log_level = "error"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	rr := putKeys(t, s, keysBody(
		etag,
		`{"key":"observer.log_level","value":"debug","was":"warn"}`,
		`{"key":"observer.watch.poll_interval_seconds","value":9,"was":5}`,
	), false)
	if rr.Code != http.StatusConflict {
		t.Fatalf("got %d %s", rr.Code, rr.Body.String())
	}
	m := decodeMap(t, rr)
	if m["error"] != "config_changed" {
		t.Fatalf("error = %v", m["error"])
	}
	if got := strs(m["diverged_keys"]); strings.Join(got, ",") != "observer.log_level" {
		t.Errorf("diverged_keys = %v; only log_level moved under the client", got)
	}
	if m["config_etag"] == etag || m["config_etag"] == "" {
		t.Errorf("409 must carry the current etag")
	}
	now, _ := os.ReadFile(path)
	if strings.Contains(string(now), "debug") {
		t.Fatal("a conflicting write must not land")
	}
	if rr := putKeys(t, s, `{"patches":[{"key":"observer.log_level","value":"debug"}]}`, false); rr.Code != http.StatusBadRequest {
		t.Fatalf("missing base_etag must be 400, got %d", rr.Code)
	}
}

func TestConfigKeys_PerKeyValidation(t *testing.T) {
	s, path := newSecretTestServer(t, keysCorpus)
	orig, _ := os.ReadFile(path)
	etag, _, _ := configGet(t, s)
	rr := putKeys(t, s, keysBody(
		etag,
		`{"key":"observer.log_level","value":"loud"}`,
		`{"key":"terminal.max_concurrent","value":"twelve"}`,
		`{"key":"observer.watch.poll_interval_seconds","value":7}`,
	), false)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("got %d %s", rr.Code, rr.Body.String())
	}
	m := decodeMap(t, rr)
	errs, _ := m["key_errors"].([]any)
	if len(errs) != 2 {
		t.Fatalf("expected 2 key_errors, got %v", m)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "not in {debug, info, warn, error}") || !strings.Contains(body, "wants an integer") {
		t.Errorf("errors must be per-key and specific: %s", body)
	}
	if now, _ := os.ReadFile(path); string(now) != string(orig) {
		t.Fatal("file must be untouched when any key is invalid")
	}

	// config.Validate (the daemon-start check) is the second gate.
	rr = putKeys(t, s, keysBody(etag, `{"key":"observer.watch.poll_interval_seconds","value":-1}`), false)
	if rr.Code != http.StatusBadRequest || decodeMap(t, rr)["error"] != "invalid_config" {
		t.Fatalf("got %d %s", rr.Code, rr.Body.String())
	}
	if now, _ := os.ReadFile(path); string(now) != string(orig) {
		t.Fatal("file must be untouched when config.Validate refuses")
	}
}

func TestConfigKeys_ReadBackFailureRestoresBackup(t *testing.T) {
	s, path := newSecretTestServer(t, keysCorpus)
	orig, _ := os.ReadFile(path)
	prev := readBackConfig
	t.Cleanup(func() { readBackConfig = prev })
	readBackConfig = func(string) (config.Config, error) {
		return config.Config{}, errors.New("simulated round-trip failure")
	}
	etag, _, _ := configGet(t, s)
	rr := putKeys(t, s, keysBody(etag, `{"key":"observer.log_level","value":"debug"}`), false)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("got %d %s", rr.Code, rr.Body.String())
	}
	m := decodeMap(t, rr)
	if m["error"] != "read_back_failed" || !strings.Contains(m["message"].(string), "restored") {
		t.Fatalf("response must name the failure and the restore: %v", m)
	}
	now, _ := os.ReadFile(path)
	if string(now) != string(orig) {
		t.Fatalf("file must be restored from .bak:\n%s", now)
	}
}

func TestConfigKeys_ListPatchReserializesAndSaysSo(t *testing.T) {
	s, path := newSecretTestServer(t, keysCorpus)
	etag, _, _ := configGet(t, s)
	rr := putKeys(t, s, keysBody(etag, `{"key":"terminal.launch.allowed_tools","value":["claude","codex"]}`), true)
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d %s", rr.Code, rr.Body.String())
	}
	m := decodeMap(t, rr)
	if m["write_mode"] != "reserialize" || m["comments_preserved"] != false || m["write_mode_reason"] == "" {
		t.Fatalf("a list write must re-serialize and say why: %v", m)
	}
	loaded, err := config.Load(config.LoadOptions{GlobalPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(loaded.Terminal.Launch.AllowedTools, ",") != "claude,codex" {
		t.Fatalf("value not persisted: %v", loaded.Terminal.Launch.AllowedTools)
	}
	if bak, _ := os.ReadFile(path + ".bak"); string(bak) != keysCorpus {
		t.Fatal(".bak must hold the prior, commented file")
	}
}

func TestConfigKeys_NextSpawnAndNoopClasses(t *testing.T) {
	s, _ := newSecretTestServer(t, keysCorpus)
	etag, _, _ := configGet(t, s)
	rr := putKeys(t, s, keysBody(etag, `{"key":"intelligence.mcp.get_file.enabled","value":false}`, `{"key":"terminal.attach.route_proxy","value":false}`), false)
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d %s", rr.Code, rr.Body.String())
	}
	m := decodeMap(t, rr)
	if m["restart_required"] != false {
		t.Fatalf("next_spawn keys must not demand a restart: %v", m)
	}
	if got := strs(m["next_spawn_keys"]); len(got) == 0 {
		t.Errorf("next_spawn_keys = %v", got)
	}
	// Writing the same values again is a no-op: nothing changes, nothing
	// is written, no restart.
	etag2, _, _ := configGet(t, s)
	rr = putKeys(t, s, keysBody(etag2, `{"key":"terminal.attach.route_proxy","value":false}`), false)
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d %s", rr.Code, rr.Body.String())
	}
	m = decodeMap(t, rr)
	if m["write_mode"] != "noop" || len(strs(m["changed_keys"])) != 0 {
		t.Fatalf("expected a no-op: %v", m)
	}
}

func TestGovernance_ConfigKeysBatchIsRefusedBySection(t *testing.T) {
	tdir := t.TempDir()
	cfgPath := tdir + "/config.toml"
	if err := os.WriteFile(cfgPath, []byte(keysCorpus), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newRemoteTestServer(t, Options{
		ConfigPath: cfgPath,
		Governance: governedProvider(t, nil, nil, []string{"proxy"}, []string{"observer"}),
	})
	etag, _, _ := configGet(t, s)
	orig, _ := os.ReadFile(cfgPath)

	cases := []struct {
		name string
		body string
		code int
		err  string
	}{
		{"read-only section refuses the whole batch", keysBody(etag, `{"key":"terminal.max_concurrent","value":3}`, `{"key":"observer.log_level","value":"info"}`), http.StatusConflict, "governance_read_only"},
		{"hidden section is 404", keysBody(etag, `{"key":"proxy.port","value":8821}`), http.StatusNotFound, "governance_hidden"},
		{"unmappable key fails closed", keysBody(etag, `{"key":"observer.does_not_exist","value":1}`), http.StatusConflict, "governance_unmappable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/api/config/keys", strings.NewReader(c.body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr, req)
			if rr.Code != c.code || !strings.Contains(rr.Body.String(), c.err) {
				t.Fatalf("got %d %s; want %d %s", rr.Code, rr.Body.String(), c.code, c.err)
			}
			if now, _ := os.ReadFile(cfgPath); string(now) != string(orig) {
				t.Fatal("a governance refusal must not write")
			}
		})
	}
	// An ungoverned key still writes on the same governed node (and the
	// body survived the guard's read).
	req := httptest.NewRequest(http.MethodPut, "/api/config/keys", strings.NewReader(keysBody(etag, `{"key":"terminal.max_concurrent","value":3}`)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("ungoverned key: %d %s", rr.Code, rr.Body.String())
	}
}

// TestConfigSection_RestartHonesty pins P0-8 on the legacy section route:
// restart_required is derived from the changed keys' schema classes, not
// from the section name.
func TestConfigSection_RestartHonesty(t *testing.T) {
	s, _ := newSecretTestServer(t, keysCorpus)
	put := func(section, body string) map[string]any {
		t.Helper()
		req := httptest.NewRequest(http.MethodPut, "/api/config/section/"+section, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("PUT %s: %d %s", section, rr.Code, rr.Body.String())
		}
		return decodeMap(t, rr)
	}
	// The terminal attach route_proxy flag is read per launch: no restart.
	m := put("terminal", `{"RouteProxy":false}`)
	if m["restart_required"] != false || strings.Join(strs(m["next_spawn_keys"]), ",") != "terminal.attach.route_proxy" {
		t.Errorf("route_proxy-only save: %v", m)
	}
	// observer.log_level binds at start.
	m = put("observer", `{"DBPath":"/tmp/x.db","LogLevel":"info"}`)
	if m["restart_required"] != true || !strings.Contains(strings.Join(strs(m["restart_required_keys"]), ","), "observer.log_level") {
		t.Errorf("log_level save: %v", m)
	}
	// Saving the same values again changes nothing: no restart.
	m = put("observer", `{"DBPath":"/tmp/x.db","LogLevel":"info"}`)
	if m["restart_required"] != false || len(strs(m["changed_keys"])) != 0 {
		t.Errorf("no-op save must not demand a restart: %v", m)
	}
}

// TestSecretFieldsMatchSchemaT2 is the P0-9 consistency pin: the dashboard's
// hand-written redaction table and configschema's secret tier must name
// exactly the same keys, in both directions.
func TestSecretFieldsMatchSchemaT2(t *testing.T) {
	table := map[string]bool{}
	for _, f := range secretFields {
		table[f.Key] = true
	}
	schemaT2 := map[string]bool{}
	for _, l := range configschema.Leaves() {
		if l.Tier == configschema.TierSecret {
			schemaT2[l.Path] = true
		}
	}
	for k := range table {
		if !schemaT2[k] {
			t.Errorf("secretFields redacts %s but configschema does not mark it secret", k)
		}
	}
	for k := range schemaT2 {
		if !table[k] {
			t.Errorf("configschema marks %s secret but secretFields has no redaction row — GET /api/config would leak it", k)
		}
	}
}

func TestAdminRestartStatusReportsLiveTraffic(t *testing.T) {
	s, _ := newSecretTestServer(t, keysCorpus)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/admin/restart", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d %s", rr.Code, rr.Body.String())
	}
	m := decodeMap(t, rr)
	if m["available"] != false || m["proxy_recent_requests"] != float64(0) || m["window_s"] != float64(60) {
		t.Fatalf("unexpected status: %v", m)
	}
}

func TestConfigSchemaRouteServesEmbeddedSchema(t *testing.T) {
	s, _ := newSecretTestServer(t, keysCorpus)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/config/schema", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d", rr.Code)
	}
	var d configschema.Descriptor
	if err := json.Unmarshal(rr.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if d.SchemaVersion != configschema.SchemaVersion || len(d.Leaves) != len(configschema.Leaves()) {
		t.Fatalf("embedded schema is stale: version %d leaves %d (runtime %d) — run make config-schema-build", d.SchemaVersion, len(d.Leaves), len(configschema.Leaves()))
	}
	var docs int
	for _, l := range d.Leaves {
		if l.Doc != "" {
			docs++
		}
	}
	if docs < len(d.Leaves)/2 {
		t.Errorf("only %d/%d leaves carry a doc comment — the go/ast harvest is broken", docs, len(d.Leaves))
	}
}
