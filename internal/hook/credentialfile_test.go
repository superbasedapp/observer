package hook

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"

	"github.com/marmutapp/superbased-observer/internal/hookdigest"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// credFixtureSecret is a fixture credential: it must never appear in an
// error, a result, a log line or hook_checksums.json, and must survive every
// write unchanged.
const credFixtureSecret = "sk-test-not-real"

// credCase is one flagged writer with a credential-bearing fixture.
type credCase struct {
	tool   string
	rel    string // file path under the fixture home
	format string // json | yaml | toml
	body   string // a valid file holding credFixtureSecret
	broken string // an unparseable file holding credFixtureSecret
	owned  string // the top-level key the writer owns
	// alsoOwned is a second top-level key the writer may add: Codex's
	// [hooks.state] trust records for Observer's own entries (live check
	// 2026-10-20). "" when there is none.
	alsoOwned string
}

func credCases() []credCase {
	return []credCase{
		{
			tool: "claude-code", rel: ".claude/settings.json", format: "json", owned: "hooks",
			body:   "{\n    \"model\": \"opus\",\n    \"env\": {\"ANTHROPIC_API_KEY\": \"" + credFixtureSecret + "\",   \"N\": 9007199254740993},\n    \"permissions\": {\"allow\": [\"Bash(ls)\"]}\n}\n",
			broken: "{\"env\": {\"ANTHROPIC_API_KEY\": \"" + credFixtureSecret + "\"}, \"x\": " + credFixtureSecret + "}",
		},
		{
			tool: "qwen-code", rel: ".qwen/settings.json", format: "json", owned: "hooks",
			body:   "{\"security\": {\"auth\": {\"apiKey\": \"" + credFixtureSecret + "\"}}, \"env\": {\"OPENAI_API_KEY\": \"" + credFixtureSecret + "\"}}",
			broken: "{\"security\": {\"auth\": {\"apiKey\": \"" + credFixtureSecret + "\"}},, }",
		},
		{
			tool: "junie", rel: ".junie/config.json", format: "json", owned: "hooks",
			body:   "{\n  \"byok\": {\"openai\": \"" + credFixtureSecret + "\"},\n  \"model\": \"x\"\n}\n",
			broken: "{\"byok\": {\"openai\": " + credFixtureSecret + "}}",
		},
		{
			tool: "zcode", rel: ".zcode/cli/config.json", format: "json", owned: "hooks",
			body:   "{\"providers\": {\"zai\": {\"options\": {\"apiKey\": \"" + credFixtureSecret + "\"}}}, \"mcp\": {\"servers\": {}}}",
			broken: "{\"providers\": {\"zai\": {\"options\": {\"apiKey\": '" + credFixtureSecret + "'}}}}",
		},
		{
			tool: "crush", rel: ".config/crush/crush.json", format: "json", owned: "hooks",
			body:   "{\"providers\": {\"openai\": {\"api_key\": \"" + credFixtureSecret + "\", \"base_url\": \"https://example.invalid/v1\"}}}",
			broken: "{\"providers\": {\"openai\": {\"api_key\": \"" + credFixtureSecret + "\"}}",
		},
		{
			tool: "poolside", rel: ".config/poolside/settings.yaml", format: "yaml", owned: "hooks",
			body:   "# keep this comment\npool:\n  api_url: https://example.invalid\nweb_search:\n  provider: brave\n  api_key: " + credFixtureSecret + " # inline note\n",
			broken: "web_search:\n  api_key: " + credFixtureSecret + "\n  - [unclosed\n",
		},
		{
			tool: "codex", rel: ".codex/config.toml", format: "toml", owned: "features", alsoOwned: "hooks",
			body:   "# my codex config\nmodel = \"o3\"\n\n[features.multi_agent_v2.message_board_remote]\nbearer_token = \"" + credFixtureSecret + "\"\n",
			broken: "bearer_token = \"" + credFixtureSecret + "\"\nbroken = \n",
		},
		{
			tool: "kimi-code", rel: ".kimi-code/config.toml", format: "toml", owned: "hooks",
			body: "# kimi config\ndefault_model = \"openai/gpt-4o\"\n\n[providers.openai]\ntype = \"openai\"\napi_key = \"" + credFixtureSecret + "\" # inline note\n\n" +
				"[[hooks]]\nevent = \"Notification\"\ncommand = \"notify-send done\"\n",
			broken: "[providers.openai]\napi_key = \"" + credFixtureSecret + "\"\nbroken = \n",
		},
		// The 2026-10-21 wave.
		{
			tool: "autohand", rel: ".autohand/config.json", format: "json", owned: "hooks",
			body:   "{\n  \"provider\": \"openrouter\",\n  \"openrouter\": {\"apiKey\": \"" + credFixtureSecret + "\"},\n  \"api\": {\"companySecret\": \"" + credFixtureSecret + "\"}\n}\n",
			broken: "{\"openrouter\": {\"apiKey\": " + credFixtureSecret + "}}",
		},
		{
			tool: "codebuddy", rel: ".codebuddy/settings.json", format: "json", owned: "hooks",
			body:   "{\"env\": {\"CODEBUDDY_API_KEY\": \"" + credFixtureSecret + "\"}, \"model\": \"x\"}",
			broken: "{\"env\": {\"CODEBUDDY_API_KEY\": \"" + credFixtureSecret + "\"},, }",
		},
	}
}

// captureLogs routes the standard logger and slog's default into a buffer
// for the test's lifetime.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	prevSlog := slog.Default()
	log.SetOutput(&buf)
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
		slog.SetDefault(prevSlog)
	})
	return &buf
}

func credRegistry(t *testing.T, home string) *Registry {
	t.Helper()
	reg, err := NewRegistry(Options{
		BinaryPath:    "/opt/observer/bin/observer",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return reg
}

// decodeFixture decodes a fixture file into a generic top-level map.
func decodeFixture(t *testing.T, format string, b []byte) map[string]any {
	t.Helper()
	out := map[string]any{}
	var err error
	switch format {
	case "json":
		err = json.Unmarshal(b, &out)
	case "yaml":
		err = yaml.Unmarshal(b, &out)
	case "toml":
		_, err = toml.Decode(string(b), &out)
	}
	if err != nil {
		t.Fatalf("decode %s: %v", format, err)
	}
	return out
}

// assertNoSecret fails when s carries the fixture credential.
func assertNoSecret(t *testing.T, what, s string) {
	t.Helper()
	if strings.Contains(s, credFixtureSecret) {
		t.Errorf("%s carries the fixture credential: %q", what, s)
	}
}

func TestCredentialFileRowsAreTheAuditedSet(t *testing.T) {
	want := []string{"autohand", "claude-code", "codebuddy", "codex", "crush", "hermes", "junie", "kimi-code", "poolside", "qwen-code", "zcode"}
	got := integration.CredentialFileHookTools()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("credential-file rows = %v, want %v", got, want)
	}
	for _, tool := range got {
		c, _ := integration.For(tool)
		if strings.TrimSpace(c.Hook.CredentialFileReason) == "" {
			t.Errorf("%s: HooksShareCredentialFile without a CredentialFileReason", tool)
		}
	}
	if !integration.HooksShareCredentialFile("claude-code-windows") {
		t.Error("a -windows bridge target must answer for its base row")
	}
	if integration.HooksShareCredentialFile("grok") {
		t.Error("grok owns a dedicated hooks file and must not be flagged")
	}
}

func TestCredentialFileWritersKeepCredentials(t *testing.T) {
	for _, tc := range credCases() {
		t.Run(tc.tool, func(t *testing.T) {
			logs := captureLogs(t)
			home := t.TempDir()
			path := filepath.Join(home, filepath.FromSlash(tc.rel))
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(tc.body), 0o640); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o640); err != nil {
				t.Fatal(err)
			}
			before := []byte(tc.body)
			reg := credRegistry(t, home)

			res := reg.Register(tc.tool)
			if res.Error != nil {
				t.Fatalf("Register: %v", res.Error)
			}
			if len(res.HooksAdded) == 0 {
				t.Fatalf("Register added nothing: %+v", res)
			}
			assertNoSecret(t, "the registration result", fmt.Sprintf("%+v", res))

			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if n := strings.Count(string(after), credFixtureSecret); n != strings.Count(tc.body, credFixtureSecret) {
				t.Errorf("credential count %d after the write, want %d", n, strings.Count(tc.body, credFixtureSecret))
			}
			if fi, err := os.Stat(path); err != nil || posixModes && fi.Mode().Perm() != 0o640 {
				t.Errorf("mode after the write = %v (%v), want 0640", fi.Mode().Perm(), err)
			}
			assertOnlyOwnedKeyChanged(t, tc, before, after)
			if tc.format != "json" {
				// Line-edited / node-edited formats keep the comments.
				for _, l := range strings.Split(tc.body, "\n") {
					if strings.HasPrefix(strings.TrimSpace(l), "#") && !strings.Contains(string(after), strings.TrimSpace(l)) {
						t.Errorf("comment %q was lost", l)
					}
				}
			}
			if _, err := os.Stat(path + ".bak"); err == nil {
				t.Error("a credential-file write must not leave a backup")
			}
			assertChecksumsSafe(t, home, path, before, after)

			ures := reg.Unregister(tc.tool)
			if ures.Error != nil {
				t.Fatalf("Unregister: %v", ures.Error)
			}
			assertNoSecret(t, "the unregistration result", fmt.Sprintf("%+v", ures))
			final, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(final), credFixtureSecret) {
				t.Error("the credential did not survive the unregister")
			}
			if fi, err := os.Stat(path); err != nil || posixModes && fi.Mode().Perm() != 0o640 {
				t.Errorf("mode after the unregister = %v (%v), want 0640", fi.Mode().Perm(), err)
			}
			assertNoSecret(t, "the log output", logs.String())
		})
	}
}

// assertOnlyOwnedKeyChanged checks every top-level key but the owned one
// decodes the same before and after, and for JSON that its source bytes
// are untouched.
func assertOnlyOwnedKeyChanged(t *testing.T, tc credCase, before, after []byte) {
	t.Helper()
	b := decodeFixture(t, tc.format, before)
	a := decodeFixture(t, tc.format, after)
	for k, v := range b {
		if k == tc.owned || (tc.alsoOwned != "" && k == tc.alsoOwned) {
			continue
		}
		if tc.format == "toml" && k == "features" {
			continue
		}
		if !reflect.DeepEqual(a[k], v) {
			t.Errorf("key %q changed: %v -> %v", k, v, a[k])
		}
	}
	for k := range a {
		if _, ok := b[k]; !ok && k != tc.owned && (tc.alsoOwned == "" || k != tc.alsoOwned) {
			t.Errorf("unexpected new top-level key %q", k)
		}
	}
	switch tc.format {
	case "json":
		bm, am := map[string]json.RawMessage{}, map[string]json.RawMessage{}
		_ = json.Unmarshal(before, &bm)
		_ = json.Unmarshal(after, &am)
		for k, raw := range bm {
			if k != tc.owned && !bytes.Equal(raw, am[k]) {
				t.Errorf("key %q source bytes changed: %s -> %s", k, raw, am[k])
			}
			if k != tc.owned && !bytes.Contains(after, raw) {
				t.Errorf("key %q source bytes missing from the file", k)
			}
		}
	case "toml":
		for _, l := range strings.Split(strings.TrimRight(string(before), "\n"), "\n") {
			if !strings.Contains(string(after), l) {
				t.Errorf("TOML line %q was rewritten", l)
			}
		}
		if tc.owned != "features" {
			break
		}
		if f, _ := a["features"].(map[string]any); f == nil || f["hooks"] != true {
			t.Errorf("features.hooks not set: %v", a["features"])
		}
		bf, _ := b["features"].(map[string]any)
		af, _ := a["features"].(map[string]any)
		for k, v := range bf {
			if !reflect.DeepEqual(af[k], v) {
				t.Errorf("features.%s changed", k)
			}
		}
	}
}

// assertChecksumsSafe checks hook_checksums.json holds neither the
// credential nor a whole-file hash of the credential-bearing file, and that
// any entry for it is a hooks-subtree digest.
func assertChecksumsSafe(t *testing.T, home, path string, before, after []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(home, ".observer", "hook_checksums.json"))
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecret(t, "hook_checksums.json", string(raw))
	for _, body := range [][]byte{before, after} {
		sum := sha256.Sum256(body)
		if bytes.Contains(raw, []byte(hex.EncodeToString(sum[:]))) {
			t.Error("hook_checksums.json records a whole-file hash of the credential-bearing file")
		}
	}
	entries := map[string]map[string]any{}
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatal(err)
	}
	if e, ok := entries[path]; ok {
		if _, has := e["sha256"]; has {
			t.Error("the entry still carries a whole-file sha256")
		}
		if e[hookdigest.KeyScope] != hookdigest.Scope {
			t.Errorf("entry scope = %v, want %q", e[hookdigest.KeyScope], hookdigest.Scope)
		}
		want, err := hookdigest.HooksSubtree(path, after)
		if err != nil || e[hookdigest.KeyDigest] != want {
			t.Errorf("hooks digest = %v, want %s (%v)", e[hookdigest.KeyDigest], want, err)
		}
	}
}

func TestCredentialFileUnparseableIsRefusedWithoutDetail(t *testing.T) {
	for _, tc := range credCases() {
		t.Run(tc.tool, func(t *testing.T) {
			logs := captureLogs(t)
			home := t.TempDir()
			path := filepath.Join(home, filepath.FromSlash(tc.rel))
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(tc.broken), 0o600); err != nil {
				t.Fatal(err)
			}
			reg := credRegistry(t, home)
			for _, dry := range []bool{true, false} {
				reg.opts.DryRun = dry
				res := reg.Register(tc.tool)
				if res.Error == nil {
					// Codex's dry run never opens config.toml (the hooks
					// live in hooks.json); every real write must refuse.
					if !dry {
						t.Fatalf("Register accepted an unparseable file")
					}
					assertNoSecret(t, "the result", fmt.Sprintf("%+v", res))
					continue
				}
				assertNoSecret(t, "the error", res.Error.Error())
				assertNoSecret(t, "the result", fmt.Sprintf("%+v", res))
				if !errors.Is(res.Error, ErrCredentialDetailWithheld) {
					t.Errorf("dry=%v: error %q does not withhold the detail", dry, res.Error)
				}
				if err := reg.RecordAutoRegisterResult(res.ConfigPath, res.Error); err != nil {
					t.Fatal(err)
				}
				ures := reg.Unregister(tc.tool)
				if ures.Error != nil {
					assertNoSecret(t, "the unregister error", ures.Error.Error())
				}
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.broken {
				t.Error("an unparseable credential file was modified")
			}
			if raw, err := os.ReadFile(filepath.Join(home, ".observer", "hook_checksums.json")); err == nil {
				assertNoSecret(t, "hook_checksums.json", string(raw))
			}
			assertNoSecret(t, "the log output", logs.String())
		})
	}
}

func TestHermesPluginsEnabledKeepsCredentials(t *testing.T) {
	logs := captureLogs(t)
	home := t.TempDir()
	cfg := filepath.Join(home, HermesConfigFile)
	body := "# hermes config\nmodel:\n  provider: openrouter\n  api_key: " + credFixtureSecret + "\nplugins:\n  enabled:\n    - web-tavily\n"
	if err := os.WriteFile(cfg, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfg, 0o640); err != nil {
		t.Fatal(err)
	}
	opts := HermesOptions{HermesHome: home}
	if _, err := RegisterHermesPluginEnabled(opts); err != nil {
		t.Fatalf("RegisterHermesPluginEnabled: %v", err)
	}
	after, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(after), credFixtureSecret) || !strings.Contains(string(after), "# hermes config") {
		t.Errorf("the credential or the comment was lost:\n%s", after)
	}
	if !strings.Contains(string(after), HermesPluginDirName) {
		t.Error("plugin not enabled")
	}
	if fi, _ := os.Stat(cfg); posixModes && fi.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v, want 0640", fi.Mode().Perm())
	}
	// No backup copy: the MCP write edits only its own node too (T-384), so
	// nothing needs the pre-invocation copy, and a copy of the file is a copy
	// of its credentials.
	if _, err := os.Stat(cfg + ".bak"); !os.IsNotExist(err) {
		t.Errorf("a credential-file writer left a backup copy: stat err = %v", err)
	}
	if _, err := UnregisterHermesPluginEnabled(opts); err != nil {
		t.Fatalf("UnregisterHermesPluginEnabled: %v", err)
	}
	final, _ := os.ReadFile(cfg)
	if !strings.Contains(string(final), credFixtureSecret) || strings.Contains(string(final), HermesPluginDirName) {
		t.Errorf("unregister result wrong:\n%s", final)
	}
	broken := "model:\n  api_key: " + credFixtureSecret + "\n  - [unclosed\n"
	if err := os.WriteFile(cfg, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = RegisterHermesPluginEnabled(opts)
	if err == nil || strings.Contains(err.Error(), credFixtureSecret) || !errors.Is(err, ErrCredentialDetailWithheld) {
		t.Errorf("unparseable hermes config: err = %v", err)
	}
	assertNoSecret(t, "the log output", logs.String())
}

func TestSpliceTopLevelJSON(t *testing.T) {
	orig := []byte("{\n  \"b\": 1.0,\n  \"a\": {\"x\":   2},\n  \"hooks\": {}\n}\n")
	cases := []struct {
		name string
		next map[string]json.RawMessage
		want string
	}{
		{
			"replace the last member",
			map[string]json.RawMessage{"b": json.RawMessage("1.0"), "a": json.RawMessage("{\"x\":   2}"), "hooks": json.RawMessage(`{"E":[1]}`)},
			"{\n  \"b\": 1.0,\n  \"a\": {\"x\":   2},\n  \"hooks\": {\n    \"E\": [\n      1\n    ]\n  }\n}\n",
		},
		{
			"remove the last member",
			map[string]json.RawMessage{"b": json.RawMessage("1.0"), "a": json.RawMessage("{\"x\":   2}")},
			"{\n  \"b\": 1.0,\n  \"a\": {\"x\":   2}\n}\n",
		},
		{
			"remove the first member",
			map[string]json.RawMessage{"a": json.RawMessage("{\"x\":   2}"), "hooks": json.RawMessage(`{}`)},
			"{\n  \"a\": {\"x\":   2},\n  \"hooks\": {}\n}\n",
		},
		{
			"add a member",
			map[string]json.RawMessage{"b": json.RawMessage("1.0"), "a": json.RawMessage("{\"x\":   2}"), "hooks": json.RawMessage(`{}`), "z": json.RawMessage(`true`)},
			"{\n  \"b\": 1.0,\n  \"a\": {\"x\":   2},\n  \"hooks\": {},\n  \"z\": true\n}\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := spliceTopLevelJSON(orig, tc.next)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf("got\n%s\nwant\n%s", got, tc.want)
			}
		})
	}
	got, err := spliceTopLevelJSON([]byte("{}"), map[string]json.RawMessage{"hooks": json.RawMessage(`{}`)})
	if err != nil || string(got) != "{\n  \"hooks\": {}\n}" {
		t.Errorf("into {}: %q %v", got, err)
	}
	if _, err := spliceTopLevelJSON([]byte("[1]"), map[string]json.RawMessage{}); err == nil {
		t.Error("a non-object must be refused")
	}
}

func TestSetTOMLFeaturesHooks(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
		refuse         bool
	}{
		{"existing table, no key", "a = 1\n[features]\nweb_search = true\n", "a = 1\n[features]\nhooks = true\nweb_search = true\n", false},
		{"existing false key", "[features]\n  hooks = false\n[other]\nx = 1\n", "[features]\n  hooks = true\n[other]\nx = 1\n", false},
		{"no features", "model = \"o3\"\n", "model = \"o3\"\n\n[features]\nhooks = true\n", false},
		{"empty file", "", "[features]\nhooks = true\n", false},
		{"dotted keys", "features.web_search = true\n", "", true},
		{"inline table", "features = { web_search = true }\n", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := map[string]any{}
			if _, err := toml.Decode(tc.in, &before); err != nil {
				t.Fatal(err)
			}
			got, err := setTOMLFeaturesHooks([]byte(tc.in), before)
			if tc.refuse {
				if err == nil {
					t.Fatalf("accepted:\n%s", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf("got\n%q\nwant\n%q", got, tc.want)
			}
		})
	}
}

// TestCredentialSafeErrorKeepsSafeMessages: conflicts, refusals and
// filesystem errors keep their text; anything else is withheld.
func TestCredentialSafeErrorKeepsSafeMessages(t *testing.T) {
	conflict := hookConflictError("hook.registerJunie", "PreToolUse")
	if got := credentialSafeError("junie", "/x", conflict); !errors.Is(got, conflict) || got.Error() != conflict.Error() {
		t.Errorf("conflict rewritten: %v", got)
	}
	_, statErr := os.Stat(filepath.Join(t.TempDir(), "missing"))
	wrapped := fmt.Errorf("hook.registerJunie: read: %w", statErr)
	if got := credentialSafeError("junie", "/x", wrapped); !errors.Is(got, wrapped) || got.Error() != wrapped.Error() {
		t.Errorf("path error rewritten: %v", got)
	}
	parse := fmt.Errorf("parse /x: invalid character 's' near %s", credFixtureSecret)
	got := credentialSafeError("junie", "/x", parse)
	if strings.Contains(got.Error(), credFixtureSecret) || !errors.Is(got, ErrCredentialDetailWithheld) {
		t.Errorf("parse error not withheld: %v", got)
	}
}
