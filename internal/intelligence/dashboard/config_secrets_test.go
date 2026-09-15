package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
)

// The four T2 credential values used across this file. Each is a distinctive
// literal so a leak is unambiguous and the failing assertion can name the key
// that leaked — the mutation-proof property: delete any row from
// secretFields and exactly one of these turns up in the response body.
const (
	tSelfObsSecret = "SELFOBS-SECRET-b3d1f0a7c9"
	tSelfObsToken  = "SELFOBS-TOKEN-4e77aa10bd"
	tETWToken      = "ETW-TOKEN-91c40de2f5"
	tKeyPoolA1     = "sk-ant-POOLKEY-ONE-77b2ce"
	tKeyPoolA2     = "sk-ant-POOLKEY-TWO-13da90"
	tKeyPoolO1     = "sk-oai-POOLKEY-THREE-5fe8b1"
	tBrowserToken  = "BROWSER-LISTENER-TOKEN-a8c3e19d40"
)

// secretCorpus is the config.toml body carrying every T2 credential, plus
// non-secret siblings whose survival proves redaction is surgical.
const secretCorpus = `
[observer]
log_level = "warn"

[observer.process.etw]
enabled = true
listen_addr = "127.0.0.1:8823"
token = "` + tETWToken + `"
token_path = "/tmp/etw-token"

[selfobs]
enabled = true
endpoint = "https://gateway.example.invalid:4318"
key_id = "kid-visible-not-a-secret"
secret = "` + tSelfObsSecret + `"
token = "` + tSelfObsToken + `"

[routing]
enabled = false
mode = "off"

[routing.key_pool]
anthropic = ["` + tKeyPoolA1 + `", "` + tKeyPoolA2 + `"]
openai = ["` + tKeyPoolO1 + `"]

[browser.listener]
enabled = false
token = "` + tBrowserToken + `"
`

// allT2Values pairs each credential with the dotted key that owns it, so a
// leak assertion can name the redaction row that is missing.
var allT2Values = []struct{ key, value string }{
	{"selfobs.secret", tSelfObsSecret},
	{"selfobs.token", tSelfObsToken},
	{"observer.process.etw.token", tETWToken},
	{"routing.key_pool", tKeyPoolA1},
	{"routing.key_pool", tKeyPoolA2},
	{"routing.key_pool", tKeyPoolO1},
	{"browser.listener.token", tBrowserToken},
}

func newSecretTestServer(t *testing.T, body string) (*Server, string) {
	t.Helper()
	tdir := t.TempDir()
	cfgPath := filepath.Join(tdir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	return server, cfgPath
}

// TestHandleConfig_RedactsEveryT2Credential is the P0-1 leak gate: no byte of
// any credential may appear anywhere in the GET /api/config response.
func TestHandleConfig_RedactsEveryT2Credential(t *testing.T) {
	server, _ := newSecretTestServer(t, secretCorpus)

	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	raw := rr.Body.Bytes()

	for _, tc := range allT2Values {
		if bytes.Contains(raw, []byte(tc.value)) {
			t.Errorf("SECRET LEAK: %s value %q appears in GET /api/config — the %s redaction row is missing or broken",
				tc.key, tc.value, tc.key)
		}
	}

	var got struct {
		Config           config.Config   `json:"config"`
		RedactedSecrets  map[string]bool `json:"redacted_secrets"`
		RedactedSentinel string          `json:"redacted_sentinel"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}

	if got.RedactedSentinel != secretSentinel {
		t.Errorf("redacted_sentinel: got %q want %q", got.RedactedSentinel, secretSentinel)
	}
	// Every T2 key reports has_value=true for this corpus, so the UI can
	// render "credential configured" without the value.
	for _, key := range []string{"selfobs.secret", "selfobs.token", "observer.process.etw.token", "routing.key_pool"} {
		if !got.RedactedSecrets[key] {
			t.Errorf("redacted_secrets[%q]: want true (a value IS configured)", key)
		}
	}

	// Sentinels in place of the values.
	if got.Config.SelfObs.Secret != secretSentinel {
		t.Errorf("selfobs.secret: got %q want sentinel", got.Config.SelfObs.Secret)
	}
	if got.Config.SelfObs.Token != secretSentinel {
		t.Errorf("selfobs.token: got %q want sentinel", got.Config.SelfObs.Token)
	}
	if got.Config.Observer.Process.ETW.Token != secretSentinel {
		t.Errorf("observer.process.etw.token: got %q want sentinel", got.Config.Observer.Process.ETW.Token)
	}
	// key_pool keeps its structure so the UI can say how many keys exist.
	if n := len(got.Config.Routing.KeyPool["anthropic"]); n != 2 {
		t.Errorf("routing.key_pool[anthropic]: got %d entries want 2 (structure must survive redaction)", n)
	}
	for provider, ring := range got.Config.Routing.KeyPool {
		for i, key := range ring {
			if key != secretSentinel {
				t.Errorf("routing.key_pool[%s][%d]: got %q want sentinel", provider, i, key)
			}
		}
	}

	// Redaction must be surgical: non-secret siblings survive.
	if got.Config.SelfObs.KeyID != "kid-visible-not-a-secret" {
		t.Errorf("selfobs.key_id must NOT be redacted (it names a credential, it is not one): %q", got.Config.SelfObs.KeyID)
	}
	if got.Config.Observer.Process.ETW.ListenAddr != "127.0.0.1:8823" {
		t.Errorf("etw.listen_addr must survive: %q", got.Config.Observer.Process.ETW.ListenAddr)
	}
	if got.Config.SelfObs.Endpoint != "https://gateway.example.invalid:4318" {
		t.Errorf("selfobs.endpoint must survive: %q", got.Config.SelfObs.Endpoint)
	}
}

// TestHandleConfig_ReportsAbsentCredentialsHonestly pins the other half of
// has_value: an unset credential is reported false, not "configured".
func TestHandleConfig_ReportsAbsentCredentialsHonestly(t *testing.T) {
	server, _ := newSecretTestServer(t, "[observer]\nlog_level = \"warn\"\n")

	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Config          config.Config   `json:"config"`
		RedactedSecrets map[string]bool `json:"redacted_secrets"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for key, has := range got.RedactedSecrets {
		if has {
			t.Errorf("redacted_secrets[%q]: want false on a config with no credentials", key)
		}
	}
	if len(got.RedactedSecrets) != len(secretFields) {
		t.Errorf("redacted_secrets: got %d keys want %d (one per T2 row)", len(got.RedactedSecrets), len(secretFields))
	}
	// An unset credential stays empty rather than becoming a sentinel, so
	// the UI cannot mistake "not configured" for "configured, hidden".
	if got.Config.SelfObs.Secret != "" {
		t.Errorf("unset selfobs.secret: got %q want empty", got.Config.SelfObs.Secret)
	}
}

// TestRedactSecrets_DoesNotMutateSource proves the read path works on a copy:
// the caller's loaded config still holds the real key material afterwards.
func TestRedactSecrets_DoesNotMutateSource(t *testing.T) {
	src := config.Config{}
	src.SelfObs.Secret = tSelfObsSecret
	src.Routing.KeyPool = map[string][]string{"anthropic": {tKeyPoolA1}}

	out, present := redactSecrets(src)

	if src.SelfObs.Secret != tSelfObsSecret {
		t.Errorf("source selfobs.secret was mutated: %q", src.SelfObs.Secret)
	}
	if src.Routing.KeyPool["anthropic"][0] != tKeyPoolA1 {
		t.Errorf("source key_pool was mutated in place: %q", src.Routing.KeyPool["anthropic"][0])
	}
	if out.SelfObs.Secret != secretSentinel || out.Routing.KeyPool["anthropic"][0] != secretSentinel {
		t.Errorf("copy not redacted: %+v", out.Routing.KeyPool)
	}
	if !present["selfobs.secret"] || !present["routing.key_pool"] {
		t.Errorf("has_value map wrong: %v", present)
	}
}

// TestConfigSectionRoundTrip_PreservesCredentials is the end-to-end clobber
// gate. It performs the exact sequence the dashboard performs (Routing.tsx
// enableAdvise): GET /api/config, take the redacted Routing block, flip a
// field, PUT the whole block back. The real API keys must survive on disk.
//
// Two independent layers make this pass, and it is worth knowing which is
// which. Layer 1: no shipped section decoder has a field for a T2 value, so
// the sentinel is dropped at decode. Layer 2: reconcileSecrets restores the
// on-disk value whenever a sentinel does arrive. TODAY layer 1 alone would
// satisfy this test — the sentinel-preserving behaviour of layer 2 is pinned
// directly by TestReconcileSecrets, which is where its mutation coverage
// lives. This test guards the composition, so that a future decoder (or the
// plan's P1 generic /api/config/keys writer) that DOES accept the field
// cannot silently start clobbering.
func TestConfigSectionRoundTrip_PreservesCredentials(t *testing.T) {
	server, cfgPath := newSecretTestServer(t, secretCorpus)

	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Config map[string]json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	var routingSection map[string]any
	if err := json.Unmarshal(got.Config["Routing"], &routingSection); err != nil {
		t.Fatal(err)
	}
	// Sanity: the block the UI is about to send back really does carry
	// sentinels, so this test exercises the clobber path rather than a
	// vacuously safe body.
	pool, _ := routingSection["KeyPool"].(map[string]any)
	ring, _ := pool["anthropic"].([]any)
	if len(ring) != 2 || ring[0] != secretSentinel {
		t.Fatalf("precondition: GET must return a sentinel key_pool, got %v", pool)
	}

	routingSection["Enabled"] = true
	routingSection["Mode"] = "advise"
	body, err := json.Marshal(routingSection)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPut, "/api/config/section/routing", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	pr := httptest.NewRecorder()
	server.Handler().ServeHTTP(pr, req)
	if pr.Code != http.StatusOK {
		t.Fatalf("PUT status: %d body=%s", pr.Code, pr.Body.String())
	}

	// The edit landed...
	saved, err := loadConfigForDashboard(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !saved.Routing.Enabled || saved.Routing.Mode != "advise" {
		t.Errorf("edit did not land: enabled=%v mode=%q", saved.Routing.Enabled, saved.Routing.Mode)
	}
	// ...and the credentials it round-tripped as sentinels are intact.
	wantPool := map[string][]string{
		"anthropic": {tKeyPoolA1, tKeyPoolA2},
		"openai":    {tKeyPoolO1},
	}
	if !keyPoolEqual(saved.Routing.KeyPool, wantPool) {
		t.Errorf("CLOBBERED: routing.key_pool on disk is %v, want %v", saved.Routing.KeyPool, wantPool)
	}
	// Belt and braces: the sentinel must never reach the file.
	onDisk, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(onDisk, []byte(secretSentinel)) {
		t.Errorf("sentinel %q was written to %s:\n%s", secretSentinel, cfgPath, onDisk)
	}
	// The other three credentials are untouched by a routing save.
	if saved.SelfObs.Secret != tSelfObsSecret || saved.SelfObs.Token != tSelfObsToken {
		t.Errorf("selfobs credentials disturbed: %q / %q", saved.SelfObs.Secret, saved.SelfObs.Token)
	}
	if saved.Observer.Process.ETW.Token != tETWToken {
		t.Errorf("etw token disturbed: %q", saved.Observer.Process.ETW.Token)
	}
}

// TestConfigSectionProcess_IgnoresEchoedETWToken covers the second
// round-tripping section: the process form sends the whole ETW block back.
func TestConfigSectionProcess_IgnoresEchoedETWToken(t *testing.T) {
	server, cfgPath := newSecretTestServer(t, secretCorpus)

	body := `{"Enabled":true,"ETW":{"Enabled":true,"Token":"` + secretSentinel + `","ListenAddr":"127.0.0.1:8899"}}`
	req := httptest.NewRequest(http.MethodPut, "/api/config/section/process", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT status: %d body=%s", rr.Code, rr.Body.String())
	}
	saved, err := loadConfigForDashboard(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Observer.Process.ETW.ListenAddr != "127.0.0.1:8899" {
		t.Errorf("edit did not land: %q", saved.Observer.Process.ETW.ListenAddr)
	}
	if saved.Observer.Process.ETW.Token != tETWToken {
		t.Errorf("CLOBBERED: etw token on disk is %q, want the original", saved.Observer.Process.ETW.Token)
	}
}

// TestReconcileSecrets covers the write guard's three outcomes per row.
func TestReconcileSecrets(t *testing.T) {
	withSecrets := func(secret, token, etw string, pool map[string][]string) config.Config {
		var c config.Config
		c.SelfObs.Secret = secret
		c.SelfObs.Token = token
		c.Observer.Process.ETW.Token = etw
		c.Routing.KeyPool = pool
		return c
	}
	realPool := map[string][]string{"anthropic": {tKeyPoolA1, tKeyPoolA2}}

	tests := []struct {
		name       string
		next       config.Config
		wantErrKey string // "" = must succeed
		wantAfter  config.Config
	}{
		{
			name:      "unchanged passes through",
			next:      withSecrets(tSelfObsSecret, tSelfObsToken, tETWToken, cloneKeyPool(realPool)),
			wantAfter: withSecrets(tSelfObsSecret, tSelfObsToken, tETWToken, realPool),
		},
		{
			name:      "echoed sentinels are restored, never written",
			next:      withSecrets(secretSentinel, secretSentinel, secretSentinel, map[string][]string{"anthropic": {secretSentinel, secretSentinel}}),
			wantAfter: withSecrets(tSelfObsSecret, tSelfObsToken, tETWToken, realPool),
		},
		{
			name:      "partially echoed key ring is restored wholesale",
			next:      withSecrets(tSelfObsSecret, tSelfObsToken, tETWToken, map[string][]string{"anthropic": {secretSentinel, tKeyPoolA2}}),
			wantAfter: withSecrets(tSelfObsSecret, tSelfObsToken, tETWToken, realPool),
		},
		{
			name:       "writing selfobs.secret is refused",
			next:       withSecrets("attacker-supplied", tSelfObsToken, tETWToken, cloneKeyPool(realPool)),
			wantErrKey: "selfobs.secret",
		},
		{
			name:       "writing selfobs.token is refused",
			next:       withSecrets(tSelfObsSecret, "attacker-supplied", tETWToken, cloneKeyPool(realPool)),
			wantErrKey: "selfobs.token",
		},
		{
			name:       "writing the etw token is refused",
			next:       withSecrets(tSelfObsSecret, tSelfObsToken, "attacker-supplied", cloneKeyPool(realPool)),
			wantErrKey: "observer.process.etw.token",
		},
		{
			name:       "replacing a pooled key is refused",
			next:       withSecrets(tSelfObsSecret, tSelfObsToken, tETWToken, map[string][]string{"anthropic": {"attacker-supplied", tKeyPoolA2}}),
			wantErrKey: "routing.key_pool",
		},
		{
			name:       "adding a provider ring is refused",
			next:       withSecrets(tSelfObsSecret, tSelfObsToken, tETWToken, map[string][]string{"anthropic": {tKeyPoolA1, tKeyPoolA2}, "openai": {"new"}}),
			wantErrKey: "routing.key_pool",
		},
		{
			name:       "clearing a credential is refused too",
			next:       withSecrets("", tSelfObsToken, tETWToken, cloneKeyPool(realPool)),
			wantErrKey: "selfobs.secret",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prev := withSecrets(tSelfObsSecret, tSelfObsToken, tETWToken, cloneKeyPool(realPool))
			next := tc.next
			err := reconcileSecrets(&next, &prev, "/home/u/.observer/config.toml")

			if tc.wantErrKey == "" {
				if err != nil {
					t.Fatalf("unexpected refusal: %v", err)
				}
				if next.SelfObs.Secret != tc.wantAfter.SelfObs.Secret ||
					next.SelfObs.Token != tc.wantAfter.SelfObs.Token ||
					next.Observer.Process.ETW.Token != tc.wantAfter.Observer.Process.ETW.Token {
					t.Errorf("scalars not preserved: %+v", next.SelfObs)
				}
				if !keyPoolEqual(next.Routing.KeyPool, tc.wantAfter.Routing.KeyPool) {
					t.Errorf("key_pool not preserved: got %v want %v", next.Routing.KeyPool, tc.wantAfter.Routing.KeyPool)
				}
				return
			}

			var secErr *errSecretWrite
			if !errors.As(err, &secErr) {
				t.Fatalf("want an errSecretWrite for %s, got %v", tc.wantErrKey, err)
			}
			if secErr.Key != tc.wantErrKey {
				t.Errorf("refused key: got %q want %q", secErr.Key, tc.wantErrKey)
			}
			if msg := secErr.Error(); !strings.Contains(msg, "/home/u/.observer/config.toml") ||
				!strings.Contains(msg, "is a credential and is only settable by editing") {
				t.Errorf("error must name the file and the reason: %q", msg)
			}
		})
	}
}

// TestHandleConfigSection_RefusesCredentialWrite proves the handler maps a
// refusal from the guard to 403 (not the 400 every other section error
// takes). No shipped section decoder can carry a T2 value today — that is
// the point — so the table is swapped for a row that always refuses, which
// exercises the wiring rather than the row.
func TestHandleConfigSection_RefusesCredentialWrite(t *testing.T) {
	server, _ := newSecretTestServer(t, secretCorpus)

	orig := secretFields
	t.Cleanup(func() { secretFields = orig })
	secretFields = []secretField{{
		Key:       "selfobs.token",
		Values:    func(*config.Config) []string { return nil },
		Redact:    func(*config.Config) {},
		Reconcile: func(_, _ *config.Config) bool { return false },
	}}

	req := httptest.NewRequest(http.MethodPut, "/api/config/section/observer",
		strings.NewReader(`{"DBPath":"/tmp/x.db","LogLevel":"info"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403; body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "selfobs.token") || !strings.Contains(body, "config.toml") {
		t.Errorf("403 must name the key and the file: %q", body)
	}
}

// TestHandleConfigBackup_RedactsCredentials pins the sibling read path: the
// .bak preview is the same four credentials in a different serialization.
func TestHandleConfigBackup_RedactsCredentials(t *testing.T) {
	server, cfgPath := newSecretTestServer(t, "[observer]\nlog_level = \"warn\"\n")
	// The backup is whatever a prior save left behind; write it directly.
	if err := os.WriteFile(cfgPath+".bak", []byte(secretCorpus), 0o600); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/config/backup", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	raw := rr.Body.Bytes()
	for _, tc := range allT2Values {
		if bytes.Contains(raw, []byte(tc.value)) {
			t.Errorf("SECRET LEAK: %s value %q appears in GET /api/config/backup", tc.key, tc.value)
		}
	}
	var got struct {
		Exists  bool   `json:"exists"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Exists {
		t.Fatal("backup should exist")
	}
	// Redaction is surgical: the preview still shows the operator what the
	// restore would bring back.
	if !strings.Contains(got.Content, `listen_addr = "127.0.0.1:8823"`) {
		t.Errorf("non-secret lines must survive the preview:\n%s", got.Content)
	}
	if strings.Count(got.Content, secretSentinel) != 7 {
		t.Errorf("want 7 sentinels (4 scalars + 3 pooled keys), got %d:\n%s",
			strings.Count(got.Content, secretSentinel), got.Content)
	}
}

func TestRedactSecretsInTOMLText(t *testing.T) {
	base := func(secret string, pool []string) *config.Config {
		var c config.Config
		c.SelfObs.Secret = secret
		if pool != nil {
			c.Routing.KeyPool = map[string][]string{"anthropic": pool}
		}
		return &c
	}

	t.Run("multi-line array is fully redacted", func(t *testing.T) {
		text := "[routing.key_pool]\nanthropic = [\n  \"" + tKeyPoolA1 + "\",\n  \"" + tKeyPoolA2 + "\",\n]\n"
		out, ok := redactSecretsInTOMLText(text, base("", []string{tKeyPoolA1, tKeyPoolA2}))
		if !ok {
			t.Fatal("want ok")
		}
		if strings.Contains(out, tKeyPoolA1) || strings.Contains(out, tKeyPoolA2) {
			t.Errorf("value survived a multi-line array:\n%s", out)
		}
	})

	t.Run("inline table is fully redacted", func(t *testing.T) {
		text := "[routing]\nkey_pool = { anthropic = [\"" + tKeyPoolA1 + "\"] }\n"
		out, ok := redactSecretsInTOMLText(text, base("", []string{tKeyPoolA1}))
		if !ok || strings.Contains(out, tKeyPoolA1) {
			t.Errorf("ok=%v out=%s", ok, out)
		}
	})

	t.Run("no credentials passes text through unchanged", func(t *testing.T) {
		text := "[observer]\nlog_level = \"warn\" # keep my comment\n"
		out, ok := redactSecretsInTOMLText(text, base("", nil))
		if !ok || out != text {
			t.Errorf("ok=%v out=%q", ok, out)
		}
	})

	t.Run("a too-short credential fails closed", func(t *testing.T) {
		// Substituting a 3-byte value would garble unrelated bytes, so the
		// redactor withholds the content instead of half-masking it.
		out, ok := redactSecretsInTOMLText("[selfobs]\nsecret = \"abc\"\n", base("abc", nil))
		if ok {
			t.Errorf("want fail-closed for a short credential, got %q", out)
		}
	})

	t.Run("an escaped credential fails closed", func(t *testing.T) {
		// The file spells the value with an escape, so the parsed value and
		// the literal bytes differ and substitution cannot reach it.
		var c config.Config
		c.SelfObs.Secret = `secret"with"quotes`
		text := "[selfobs]\nsecret = \"secret\\\"with\\\"quotes\"\n"
		if _, ok := redactSecretsInTOMLText(text, &c); ok {
			t.Error("want fail-closed when the literal bytes differ from the parsed value")
		}
	})
}
