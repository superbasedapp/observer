package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/hook/commandcodemod"
)

// toolGateRegistry is a Registry over a fresh throwaway home (TEST-ISO-1:
// HomeDir pinned, never auto-detected) with each of dirs pre-created.
func toolGateRegistry(t *testing.T, force bool, dirs ...string) *Registry {
	t.Helper()
	home := t.TempDir()
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(home, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	r, err := NewRegistry(Options{
		BinaryPath:    "/opt/observer/bin/observer",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
		Force:         force,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// jsonHooksForeign is a user-authored entry in t's entry shape.
func jsonHooksForeign(t jsonHooksTarget) map[string]any {
	h := map[string]any{"type": "command", t.commandKey: "./mine.sh"}
	if t.grouped {
		return map[string]any{"matcher": "x", "hooks": []any{h}}
	}
	return h
}

// jsonHooksSeed builds a hooks file holding a user top-level key and the
// given event lists under t.eventsPath.
func jsonHooksSeed(t *testing.T, tg jsonHooksTarget, events map[string]any) []byte {
	t.Helper()
	var node any = events
	for i := len(tg.eventsPath) - 1; i >= 0; i-- {
		node = map[string]any{tg.eventsPath[i]: node}
	}
	top := node.(map[string]any)
	top["userKey"] = map[string]any{"keep": 1.5}
	b, err := json.Marshal(top)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestJSONHooksVendorWriters runs the shared JSON hooks-file writer through
// every Lane A6 row: fresh install, idempotent re-register, foreign key and
// foreign event preserved, a foreign hook on Observer's event is a --force
// conflict (and --force keeps it beside Observer's), and unregister removes
// only Observer's entries (a dedicated file is deleted once empty).
func TestJSONHooksVendorWriters(t *testing.T) {
	for _, tc := range []struct {
		tool   string
		dir    string
		target func(*Registry) jsonHooksTarget
		check  func(t *testing.T, raw []byte, home string)
	}{
		{"grok", ".grok", (*Registry).grokHooksTarget, func(t *testing.T, raw []byte, _ string) {
			mustContain(t, raw, `"timeout": 10`, `hook grok PreToolUse"`)
		}},
		{"copilot-cli", ".copilot", (*Registry).copilotCLIHooksTarget, func(t *testing.T, raw []byte, _ string) {
			mustContain(t, raw, `"version": 1`, `"bash": "/opt/observer/bin/observer hook copilot-cli preToolUse"`, `"timeoutSec": 30`)
		}},
		{"goose", filepath.Join(".config", "goose"), (*Registry).gooseHooksTarget, func(t *testing.T, raw []byte, home string) {
			mustContain(t, raw, `"matcher": ".*"`, `hook goose PreToolUse`)
			if b, err := os.ReadFile(filepath.Join(home, ".agents", "plugins", "superbased-observer", "plugin.json")); err != nil || string(b) != string(goosePluginManifest) {
				t.Errorf("plugin.json = %q, %v", b, err)
			}
		}},
		{"junie", ".junie", (*Registry).junieHooksTarget, func(t *testing.T, raw []byte, _ string) {
			mustContain(t, raw, `"timeout": 10`, `hook junie PreToolUse`)
		}},
		{"crush", filepath.Join(".config", "crush"), (*Registry).crushHooksTarget, func(t *testing.T, raw []byte, _ string) {
			mustContain(t, raw, `"name": "superbased-observer"`, `hook crush PreToolUse`)
		}},
		{"open-interpreter", ".openinterpreter", (*Registry).openInterpreterHooksTarget, func(t *testing.T, raw []byte, home string) {
			mustContain(t, raw, `"matcher": "*"`, `hook open-interpreter PreToolUse`)
			if _, err := os.Stat(filepath.Join(home, ".openinterpreter", "config.toml")); err == nil {
				t.Error("the writer created config.toml (it may hold plaintext keys; never touched)")
			}
		}},
		{"zcode", ".zcode", (*Registry).zcodeHooksTarget, func(t *testing.T, raw []byte, _ string) {
			mustContain(t, raw, `"enabled": true`, `"timeoutMs": 30000`, `hook zcode UserPromptSubmit`, `hook zcode PreToolUse`)
		}},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			t.Run("fresh, idempotent, round trip", func(t *testing.T) {
				r := toolGateRegistry(t, false, tc.dir)
				tg := tc.target(r)
				path := filepath.Join(tg.dir, tg.file)
				res := r.Register(tc.tool)
				if res.Error != nil || strings.Join(res.HooksAdded, ",") != strings.Join(tg.events, ",") || res.ConfigPath != path {
					t.Fatalf("Register = %+v, want %v at %s", res, tg.events, path)
				}
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				tc.check(t, raw, r.opts.HomeDir)
				if again := r.Register(tc.tool); again.Error != nil || len(again.HooksAdded) != 0 || len(again.AlreadySet) != len(tg.events) {
					t.Fatalf("re-register = %+v, want all AlreadySet", again)
				}
				if after, _ := os.ReadFile(path); string(after) != string(raw) {
					t.Errorf("an idempotent re-register rewrote the file")
				}
				un := r.Unregister(tc.tool)
				if un.Error != nil || len(un.HooksRemoved) != len(tg.events) {
					t.Fatalf("Unregister = %+v", un)
				}
				after, err := os.ReadFile(path)
				switch {
				case tg.dedicated:
					if err == nil {
						t.Errorf("dedicated file kept after unregister: %s", after)
					}
					if len(tg.extraFiles) > 0 {
						if _, err := os.Stat(tg.dir); err == nil {
							t.Errorf("plugin dir %s kept after unregister", tg.dir)
						}
					}
				case err != nil:
					t.Fatalf("shared file removed: %v", err)
				case strings.Contains(string(after), "observer hook"):
					t.Errorf("observer entry kept: %s", after)
				}
			})
			t.Run("foreign content preserved", func(t *testing.T) {
				r := toolGateRegistry(t, false, tc.dir)
				tg := tc.target(r)
				path := filepath.Join(tg.dir, tg.file)
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				seed := jsonHooksSeed(t, tg, map[string]any{"OtherEvent": []any{jsonHooksForeign(tg)}})
				if err := os.WriteFile(path, seed, 0o600); err != nil {
					t.Fatal(err)
				}
				if res := r.Register(tc.tool); res.Error != nil || len(res.HooksAdded) != len(tg.events) {
					t.Fatalf("Register = %+v", res)
				}
				raw, _ := os.ReadFile(path)
				mustContain(t, raw, `"userKey"`, `1.5`, `"OtherEvent"`, `"./mine.sh"`)
				if un := r.Unregister(tc.tool); un.Error != nil || len(un.HooksRemoved) != len(tg.events) {
					t.Fatalf("Unregister = %+v", un)
				}
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("a file holding the user's hook was removed: %v", err)
				}
				mustContain(t, raw, `"userKey"`, `"OtherEvent"`, `"./mine.sh"`)
				if strings.Contains(string(raw), "observer hook") {
					t.Errorf("observer entry kept: %s", raw)
				}
			})
			t.Run("foreign hook on the gate event", func(t *testing.T) {
				for _, force := range []bool{false, true} {
					r := toolGateRegistry(t, force, tc.dir)
					tg := tc.target(r)
					path := filepath.Join(tg.dir, tg.file)
					if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
						t.Fatal(err)
					}
					gate := tg.events[len(tg.events)-1]
					seed := jsonHooksSeed(t, tg, map[string]any{gate: []any{jsonHooksForeign(tg)}})
					if err := os.WriteFile(path, seed, 0o600); err != nil {
						t.Fatal(err)
					}
					res := r.Register(tc.tool)
					raw, _ := os.ReadFile(path)
					if !force {
						if res.Error == nil || !strings.Contains(res.Error.Error(), "--force") || string(raw) != string(seed) {
							t.Fatalf("no force: Register = %+v, file %s; want a --force conflict and an untouched file", res, raw)
						}
						continue
					}
					if res.Error != nil {
						t.Fatalf("force: Register = %+v", res)
					}
					mustContain(t, raw, `"./mine.sh"`, "hook "+tc.tool+" "+gate)
				}
			})
		})
	}
}

func mustContain(t *testing.T, raw []byte, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if !strings.Contains(string(raw), s) {
			t.Errorf("missing %q in:\n%s", s, raw)
		}
	}
}

// TestCommandCodeShellGateFollowsRegistry: Command Code has two gate paths,
// the shell hooks file (settings.json PreToolUse, Lane A) and the Mods
// plugin's beforeToolCall (Lane D, the gate of record). They are never both
// written: the registry's shell row is dialect-only, so the shell entry is
// not written and one Observer wrote earlier is removed, with or without a
// gating mod (Integration 5).
func TestCommandCodeShellGateFollowsRegistry(t *testing.T) {
	if commandcodemod.ShellGateRegistered() {
		t.Fatal("the registry registers the command-code shell gate; this test pins the Lane D mod as the gate of record")
	}
	r := toolGateRegistry(t, false, ".commandcode")
	home := filepath.Join(r.opts.HomeDir, ".commandcode")
	tg := commandCodeShellTarget(home, "", "")
	settings := filepath.Join(home, "settings.json")

	// A shell entry an earlier release wrote.
	if res := r.registerJSONHooks(tg); res.Error != nil {
		t.Fatal(res.Error)
	}
	raw, _ := os.ReadFile(settings)
	mustContain(t, raw, `"/opt/observer/bin/observer hook command-code PreToolUse"`)

	res := r.withCommandCodeShellGate(RegistrationResult{Tool: "command-code"}, tg)
	if res.Error != nil || len(res.HooksAdded) != 0 {
		t.Fatalf("shell gate without a gating mod = %+v, want none written", res)
	}
	raw, _ = os.ReadFile(settings)
	if strings.Contains(string(raw), "observer hook") {
		t.Errorf("stale shell entry kept: %s", raw)
	}

	mod := filepath.Join(home, "mods", "observer-guard.ts")
	if err := os.MkdirAll(filepath.Dir(mod), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mod, []byte("export default { hooks: { beforeToolCall() {} } }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !commandCodeModGatesTools(home) {
		t.Fatal("a mod subscribing to beforeToolCall must be the gate of record")
	}
	res = r.withCommandCodeShellGate(RegistrationResult{Tool: "command-code"}, tg)
	if res.Error != nil || len(res.HooksAdded) != 0 {
		t.Fatalf("with a gating mod = %+v, want no shell entry", res)
	}
}

// TestCommandCodeRegisterHonoursSkipEvent: `observer start` passes the
// owes-a-live-test filter as Options.SkipEvent. The mod is ONE file every
// subscribed event shares, so the filter must reach the rendered event map:
// a skipped beforeToolCall is not subscribed, and the dialect-only shell
// gate is not written in its place (Integration 5 live smoke finding).
func TestCommandCodeRegisterHonoursSkipEvent(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".commandcode"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Options{
		BinaryPath:    "/opt/observer/bin/observer",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
		SkipEvent:     func(tool, event string) bool { return tool == "command-code" && event == "beforeToolCall" },
	})
	if err != nil {
		t.Fatal(err)
	}
	res := r.Register("command-code")
	if res.Error != nil || strings.Join(res.HooksAdded, ",") != "transformInput" {
		t.Fatalf("Register(command-code) with beforeToolCall skipped = %+v, want only transformInput", res)
	}
	raw, err := os.ReadFile(filepath.Join(home, ".commandcode", "mods", commandcodemod.ModFileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"beforeToolCall":"`) {
		t.Errorf("skipped beforeToolCall still subscribed in the mod profile")
	}
	mustContain(t, raw, `"transformInput":"`)
	if _, err := os.Stat(filepath.Join(home, ".commandcode", "settings.json")); err == nil {
		t.Errorf("the dialect-only shell gate was written in place of the skipped mod gate")
	}

	// Without the filter (observer init) the mod is the tool gate of record.
	r2, err := NewRegistry(Options{
		BinaryPath:    "/opt/observer/bin/observer",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := r2.Register("command-code"); res.Error != nil {
		t.Fatal(res.Error)
	}
	raw, _ = os.ReadFile(filepath.Join(home, ".commandcode", "mods", commandcodemod.ModFileName))
	mustContain(t, raw, `"beforeToolCall":"`)
}

// TestMistralVibeWriter: ~/.vibe/hooks.toml [[hooks]] round trip.
func TestMistralVibeWriter(t *testing.T) {
	path := func(r *Registry) string { return filepath.Join(r.opts.HomeDir, ".vibe", "hooks.toml") }
	decode := func(t *testing.T, p string) []map[string]any {
		t.Helper()
		var top struct {
			Hooks []map[string]any `toml:"hooks"`
			Keep  string           `toml:"keep"`
		}
		if _, err := toml.DecodeFile(p, &top); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return top.Hooks
	}

	r := toolGateRegistry(t, false, ".vibe")
	res := r.Register("mistral-code")
	if res.Error != nil || strings.Join(res.HooksAdded, ",") != "pre_tool" {
		t.Fatalf("Register = %+v", res)
	}
	hooks := decode(t, path(r))
	if len(hooks) != 1 || hooks[0]["name"] != "superbased-observer" || hooks[0]["type"] != "pre_tool" ||
		hooks[0]["match"] != "*" || hooks[0]["timeout"] != int64(30) || hooks[0]["strict"] != nil ||
		hooks[0]["command"] != "/opt/observer/bin/observer hook mistral-code pre_tool" {
		t.Fatalf("hooks.toml = %v", hooks)
	}
	if again := r.Register("mistral-code"); again.Error != nil || len(again.AlreadySet) != 1 {
		t.Fatalf("re-register = %+v", again)
	}
	if un := r.Unregister("mistral-code"); un.Error != nil || len(un.HooksRemoved) != 1 {
		t.Fatalf("Unregister = %+v", un)
	}
	if _, err := os.Stat(path(r)); err == nil {
		t.Error("an emptied hooks.toml was kept")
	}

	// A user's post_tool hook and top-level key survive; a user pre_tool
	// hook is a --force conflict.
	r = toolGateRegistry(t, false, ".vibe")
	seed := "keep = \"yes\"\n\n[[hooks]]\nname = \"mine\"\ntype = \"post_tool\"\ncommand = \"./mine.sh\"\n"
	if err := os.WriteFile(path(r), []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := r.Register("mistral-code"); res.Error != nil {
		t.Fatalf("Register beside a post_tool hook = %+v", res)
	}
	if hooks := decode(t, path(r)); len(hooks) != 2 || hooks[0]["name"] != "mine" {
		t.Fatalf("user hook not kept first: %v", hooks)
	}
	if un := r.Unregister("mistral-code"); un.Error != nil || len(un.HooksRemoved) != 1 {
		t.Fatalf("Unregister = %+v", un)
	}
	raw, _ := os.ReadFile(path(r))
	mustContain(t, raw, `keep = "yes"`, `./mine.sh`)

	conflict := "[[hooks]]\nname = \"mine\"\ntype = \"pre_tool\"\ncommand = \"./mine.sh\"\n"
	if err := os.WriteFile(path(r), []byte(conflict), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := r.Register("mistral-code"); res.Error == nil || !strings.Contains(res.Error.Error(), "--force") {
		t.Fatalf("Register over a user pre_tool hook = %+v, want a --force conflict", res)
	}
	if raw, _ := os.ReadFile(path(r)); string(raw) != conflict {
		t.Errorf("file changed on conflict: %s", raw)
	}
}

// TestClineGuardWriter (guard-fix lane B, FU-154): the Cline CLI guard is
// the plugin in the plugins directory (beforeModel + beforeTool) plus the
// PreToolUse gate file, an executable that execs Observer's cline-cli gate
// (the Cline CLI runs hook files and no plugin). It is idempotent, removed
// by unregister, honours CLINE_DIR, and never touches a PreToolUse of the
// developer's own.
func TestClineGuardWriter(t *testing.T) {
	if clineHooksUnsupportedOS(runtime.GOOS) {
		t.Skip("the Cline guard is macOS / Linux only")
	}
	r := toolGateRegistry(t, false, ".cline")
	plugin := filepath.Join(r.opts.HomeDir, ".cline", "plugins", "superbased-observer-guard.js")
	keep := filepath.Join(r.opts.HomeDir, ".cline", "hooks", "PreToolUse")
	res := r.Register("cline-cli")
	if res.Error != nil || strings.Join(res.HooksAdded, ",") != "beforeModel,beforeTool,PreToolUse" || res.ConfigPath != plugin {
		t.Fatalf("Register = %+v", res)
	}
	raw, err := os.ReadFile(plugin)
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, raw, `"shape":"cline"`, `"beforeModel":"prompt_gate"`, `"beforeTool":"tool_gate"`, `"ask":true`, `"bin":"/opt/observer/bin/observer"`)
	wantGate := "#!/usr/bin/env bash\n" + clineHookMarker + "\nexec /opt/observer/bin/observer hook cline-cli PreToolUse\n"
	if got, _ := os.ReadFile(keep); string(got) != wantGate {
		t.Fatalf("gate file = %q, want %q", got, wantGate)
	}
	if fi, err := os.Stat(keep); err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("gate file mode = %v (%v), want 0755", fi.Mode(), err)
	}
	if !clineHookIsObservers([]byte(wantGate)) {
		t.Error("the gate file does not read as Observer's")
	}
	if again := r.Register("cline-cli"); again.Error != nil || len(again.HooksAdded) != 0 || len(again.AlreadySet) != 3 {
		t.Fatalf("re-register = %+v", again)
	}
	un := r.Unregister("cline-cli")
	if un.Error != nil || strings.Join(un.HooksRemoved, ",") != "beforeModel,beforeTool,PreToolUse" {
		t.Fatalf("Unregister = %+v", un)
	}
	for _, p := range []string{plugin, keep} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s kept after unregister", p)
		}
	}

	// A developer's own PreToolUse already keeps hooks.jsonl on: Observer
	// writes the plugin only, and unregister keeps the user's file.
	user := keep + ".sh"
	if err := os.WriteFile(user, []byte("#!/bin/sh\necho mine\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if res := r.Register("cline-cli"); res.Error != nil || strings.Join(res.HooksAdded, ",") != "beforeModel,beforeTool" {
		t.Fatalf("Register beside a user PreToolUse.sh = %+v", res)
	}
	if _, err := os.Stat(keep); err == nil {
		t.Error("keep-alive written beside the user's own PreToolUse")
	}
	if err := os.WriteFile(keep, []byte("#!/bin/sh\necho mine too\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if un := r.Unregister("cline-cli"); un.Error != nil || len(un.HooksKept) != 1 {
		t.Fatalf("Unregister over a user script = %+v, want it kept", un)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("user script deleted: %v", err)
	}
}

// TestClineGuardWriterHonoursClineDir: $CLINE_DIR moves the plugins
// directory (the vendor's own override).
func TestClineGuardWriterHonoursClineDir(t *testing.T) {
	if clineHooksUnsupportedOS(runtime.GOOS) {
		t.Skip("the Cline guard is macOS / Linux only")
	}
	home := t.TempDir()
	alt := filepath.Join(t.TempDir(), "cline-data")
	r := pluginShimRegistry(t, home, false, func(k string) string {
		if k == "CLINE_DIR" {
			return alt
		}
		return ""
	})
	res := r.Register("cline-cli")
	if want := filepath.Join(alt, "plugins", "superbased-observer-guard.js"); res.Error != nil || res.ConfigPath != want {
		t.Fatalf("Register = %+v, want the plugin at %s", res, want)
	}
}

// TestClineKeepAliveHonoursClineDir: the PreToolUse keep-alive goes under
// the same $CLINE_DIR the SDK and CLI scan ($CLINE_DIR/hooks), not under
// ~/.cline/hooks, and an unregister removes it there (S-6; red on the old
// writer, which joined HomeDir only).
func TestClineKeepAliveHonoursClineDir(t *testing.T) {
	if clineHooksUnsupportedOS(runtime.GOOS) {
		t.Skip("the Cline guard is macOS / Linux only")
	}
	home := t.TempDir()
	alt := filepath.Join(t.TempDir(), "cline-home")
	r := pluginShimRegistry(t, home, false, func(k string) string {
		if k == "CLINE_DIR" {
			return " " + alt + " " // the vendor trims the value
		}
		return ""
	})
	if res := r.Register("cline-cli"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	keep := filepath.Join(alt, "hooks", "PreToolUse")
	if got, err := os.ReadFile(keep); err != nil || !clineHookIsObservers(got) {
		t.Fatalf("keep-alive not at %s: %v", keep, err)
	}
	if _, err := os.Stat(filepath.Join(home, ".cline", "hooks")); err == nil {
		t.Error("a hooks dir was written under ~/.cline although CLINE_DIR moved it")
	}
	if res := r.Unregister("cline-cli"); res.Error != nil {
		t.Fatalf("Unregister: %v", res.Error)
	}
	if _, err := os.Stat(keep); err == nil {
		t.Error("unregister left the keep-alive under $CLINE_DIR")
	}
}

// TestClineGuardWriterReplacesLegacyGate: a PreToolUse script an earlier
// version wrote (a gate for `observer hook cline` or a stale one, or the
// no-verdict keep-alive) is Observer's own: registering replaces it with
// the current gate file (FU-154); with a user PreToolUse beside it,
// Observer's script is removed instead.
func TestClineGuardWriterReplacesLegacyGate(t *testing.T) {
	if clineHooksUnsupportedOS(runtime.GOOS) {
		t.Skip("the Cline guard is macOS / Linux only")
	}
	keepAlive := "#!/usr/bin/env bash\n" + clineKeepAliveMarker + "\ncat >/dev/null\nexit 0\n"
	for name, legacy := range map[string]string{
		"cline":      "#!/usr/bin/env bash\n" + clineHookMarker + "\nexec /opt/observer/bin/observer hook cline PreToolUse\n",
		"moved":      "#!/usr/bin/env bash\n" + clineHookMarker + "\nexec /usr/lib/observer-old/observer hook cline-cli PreToolUse\n",
		"keep-alive": keepAlive,
	} {
		t.Run(name, func(t *testing.T) {
			r := toolGateRegistry(t, false, ".cline")
			path := filepath.Join(r.opts.HomeDir, ".cline", "hooks", "PreToolUse")
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(legacy), 0o755); err != nil {
				t.Fatal(err)
			}
			if res := r.Register("cline-cli"); res.Error != nil {
				t.Fatalf("Register over the legacy gate = %+v", res)
			}
			if raw, _ := os.ReadFile(path); string(raw) != string(r.clineGateScript()) {
				t.Fatalf("PreToolUse = %q, want the gate file", raw)
			}
			if err := os.WriteFile(path, []byte(legacy), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path+".py", []byte("print('mine')\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			if res := r.Register("cline-cli"); res.Error != nil {
				t.Fatalf("Register over the legacy gate beside a user hook = %+v", res)
			}
			if _, err := os.Stat(path); err == nil {
				t.Error("legacy gate kept beside the user's own PreToolUse")
			}
			if err := os.WriteFile(path, []byte(legacy), 0o755); err != nil {
				t.Fatal(err)
			}
			if un := r.Unregister("cline-cli"); un.Error != nil || !strings.Contains(strings.Join(un.HooksRemoved, ","), "PreToolUse") {
				t.Fatalf("Unregister of the legacy gate = %+v, want it removed", un)
			}
		})
	}
	r := toolGateRegistry(t, false, ".cline")
	if res := r.Register("cline"); res.Error == nil {
		t.Errorf("Register(cline) = %+v, want unsupported: the extension row registers no hook", res)
	}
}

// TestClineHooksUnsupportedOnWindows pins the platform row: the Cline SDK's
// Windows hooks run detached, so no gate is written there.
func TestClineHooksUnsupportedOnWindows(t *testing.T) {
	if !clineHooksUnsupportedOS("windows") || clineHooksUnsupportedOS("linux") || clineHooksUnsupportedOS("darwin") {
		t.Fatal("cline hook files: windows unsupported, linux / darwin supported")
	}
}

// TestInstalledDetectsToolGateVendors pins each Lane A6 install signal.
func TestInstalledDetectsToolGateVendors(t *testing.T) {
	for _, row := range installedToolGateDirs {
		t.Run(row.tool, func(t *testing.T) {
			if len(row.dirs) == 0 {
				// Detected only through its artifact-resolved home
				// (homeArtifacts), so a relocation variable moves the
				// signal; the tool's own test covers that path
				// (TestCortexInstallFollowsTheArtifact).
				if _, ok := homeArtifacts[row.tool]; !ok {
					t.Fatalf("%s has no install directory and no homeArtifacts row, so it can never be detected", row.tool)
				}
				return
			}
			r := toolGateRegistry(t, false, filepath.Join(row.dirs[0]...))
			for _, tool := range r.Installed() {
				if tool == row.tool {
					return
				}
			}
			t.Errorf("Installed() = %v does not include %s", r.Installed(), row.tool)
		})
	}
	if r := toolGateRegistry(t, false, ".agents"); func() bool {
		for _, tool := range r.Installed() {
			if tool == "goose" {
				return true
			}
		}
		return false
	}() {
		t.Error("~/.agents alone (shared by every Open Plugins host) must not read as a goose install")
	}
}

// TestClineGateFileSkipIsReported (audit-report-arc-w11 row 6): a developer's
// own PreToolUse hook file keeps Observer from writing its gate file, and
// that is reported as a not-applicable skip of the gate and a Warning on the
// cline-cli result naming the file, so the plugin's events do not read as
// covering a Cline CLI that loads no plugins. The file is kept byte for byte.
func TestClineGateFileSkipIsReported(t *testing.T) {
	if clineHooksUnsupportedOS(runtime.GOOS) {
		t.Skip("the Cline guard is macOS / Linux only")
	}
	r := toolGateRegistry(t, false, ".cline")
	user := filepath.Join(r.opts.HomeDir, ".cline", "hooks", "PreToolUse.sh")
	if err := os.MkdirAll(filepath.Dir(user), 0o755); err != nil {
		t.Fatal(err)
	}
	const mine = "#!/bin/sh\necho mine\n"
	if err := os.WriteFile(user, []byte(mine), 0o755); err != nil {
		t.Fatal(err)
	}
	gate := r.registerClineGateFile()
	if !gate.Skipped || gate.SkipKind != SkipNotApplicable || !strings.Contains(gate.SkipReason, user) || len(gate.HooksAdded)+len(gate.AlreadySet) != 0 {
		t.Fatalf("gate = %+v, want a not-applicable skip naming %s", gate, user)
	}
	res := r.Register("cline-cli")
	if res.Error != nil || res.Skipped {
		t.Fatalf("Register = %+v", res)
	}
	warned := false
	for _, w := range res.Warnings {
		if strings.Contains(w, user) && strings.Contains(w, "NOT gated") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("no Warning names %s: %v", user, res.Warnings)
	}
	if got, _ := os.ReadFile(user); string(got) != mine {
		t.Errorf("the developer's file changed: %q", got)
	}
	// Without the developer's file there is no such warning.
	if err := os.Remove(user); err != nil {
		t.Fatal(err)
	}
	if res := r.Register("cline-cli"); len(res.Warnings) != 0 {
		t.Errorf("Warnings without a developer file: %v", res.Warnings)
	}
}
