package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
)

// Kiro CLI writer tests (gfiD, 2026-10-15): the dedicated agent, the
// chat.defaultAgent default, the merge into the user's own agents, the V3
// standalone file, idempotence and a clean uninstall.

const kiroTestBin = "/opt/observer/bin/observer"

func kiroRegistry(t *testing.T, home string, env map[string]string) *Registry {
	t.Helper()
	reg, err := NewRegistry(Options{
		BinaryPath:    kiroTestBin,
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
		Getenv:        func(k string) string { return env[k] },
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return reg
}

func kiroWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func kiroReadJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	m := map[string]any{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse %s: %v\n%s", path, err, raw)
	}
	return m
}

// kiroHookCommands lists the commands under hooks[event] of an agent JSON.
func kiroHookCommands(t *testing.T, agent map[string]any, event string) []string {
	t.Helper()
	hooks, _ := agent["hooks"].(map[string]any)
	list, _ := hooks[event].([]any)
	var out []string
	for _, e := range list {
		m, _ := e.(map[string]any)
		cmd, _ := m["command"].(string)
		out = append(out, cmd)
	}
	return out
}

func kiroCmd(event string) string { return kiroTestBin + " hook kiro-cli " + event }

func TestKiroCLIRegisterTable(t *testing.T) {
	for _, tc := range []struct {
		name string
		// seed is written before Register: relative path -> body.
		seed map[string]string
		// wantDefault is chat.defaultAgent after Register.
		wantDefault string
		// userAgent / wantUserPre: a user agent file and the preToolUse
		// commands it must hold after Register (nil: not checked).
		userAgent   string
		wantUserPre []string
		// wantWarning: a substring of ProbeWarning ("" = none).
		wantWarning string
	}{
		{
			name:        "fresh install: own agent becomes the default",
			wantDefault: kiroAgentName,
		},
		{
			name:        "a configured default agent is kept",
			seed:        map[string]string{".kiro/settings/cli.json": `{"chat.defaultAgent":"mine","chat.defaultModel":"m"}`},
			wantDefault: "mine",
		},
		{
			name:        "a nested default agent counts as set",
			seed:        map[string]string{".kiro/settings/cli.json": `{"chat":{"defaultAgent":"mine"}}`},
			wantDefault: "",
		},
		{
			name: "user agent hooks are merged beside, never replaced",
			seed: map[string]string{
				".kiro/agents/mine.json": `{"name":"mine","tools":["read"],"allowedTools":["read"],"hooks":{"preToolUse":[{"command":"lint.sh","matcher":"write"}],"agentSpawn":[{"command":"git status"}]}}`,
			},
			wantDefault: kiroAgentName,
			userAgent:   ".kiro/agents/mine.json",
			wantUserPre: []string{"lint.sh", kiroCmd("preToolUse")},
		},
		{
			name: "a user agent with a V3 hooks array is left untouched",
			seed: map[string]string{
				".kiro/agents/v3.json": `{"name":"v3","hooks":[{"trigger":"PreToolUse","command":"x"}]}`,
			},
			wantDefault: kiroAgentName,
			wantWarning: "v3.json",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			for rel, body := range tc.seed {
				kiroWrite(t, filepath.Join(home, rel), body)
			}
			seeded := map[string][]byte{}
			for rel := range tc.seed {
				seeded[rel], _ = os.ReadFile(filepath.Join(home, rel))
			}
			reg := kiroRegistry(t, home, nil)
			res := reg.Register("kiro-cli")
			if res.Error != nil {
				t.Fatalf("Register: %v", res.Error)
			}
			if tc.wantWarning == "" && res.ProbeWarning != "" || !strings.Contains(res.ProbeWarning, tc.wantWarning) {
				t.Errorf("ProbeWarning = %q, want %q", res.ProbeWarning, tc.wantWarning)
			}
			added := append([]string(nil), res.HooksAdded...)
			sort.Strings(added)
			if !reflect.DeepEqual(added, []string{"preToolUse", "userPromptSubmit"}) {
				t.Errorf("HooksAdded = %v", res.HooksAdded)
			}

			// Observer's own agent.
			own := kiroReadJSON(t, filepath.Join(home, ".kiro", "agents", kiroAgentName+".json"))
			if own["name"] != kiroAgentName || !reflect.DeepEqual(own["tools"], []any{"*"}) {
				t.Errorf("own agent = %v", own)
			}
			if _, ok := own["allowedTools"]; ok {
				t.Error("own agent must never set allowedTools (it would pre-approve every tool)")
			}
			hooks, _ := own["hooks"].(map[string]any)
			pre, _ := hooks["preToolUse"].([]any)
			if len(pre) != 1 || !reflect.DeepEqual(pre[0], map[string]any{"command": kiroCmd("preToolUse"), "matcher": "*", "timeout_ms": float64(kiroHookTimeoutMS)}) {
				t.Errorf("own preToolUse = %v", pre)
			}
			if got := kiroHookCommands(t, own, "userPromptSubmit"); !reflect.DeepEqual(got, []string{kiroCmd("userPromptSubmit")}) {
				t.Errorf("own userPromptSubmit = %v", got)
			}

			// chat.defaultAgent.
			settings := filepath.Join(home, ".kiro", "settings", "cli.json")
			if _, err := os.Stat(settings); err == nil || tc.wantDefault == kiroAgentName {
				s := kiroReadJSON(t, settings)
				got, _ := s[kiroDefaultAgentKey].(string)
				if got != tc.wantDefault {
					t.Errorf("chat.defaultAgent = %q, want %q (%v)", got, tc.wantDefault, s)
				}
			}

			// The user's own agent.
			if tc.userAgent != "" {
				ua := kiroReadJSON(t, filepath.Join(home, tc.userAgent))
				if got := kiroHookCommands(t, ua, "preToolUse"); !reflect.DeepEqual(got, tc.wantUserPre) {
					t.Errorf("user preToolUse = %v, want %v", got, tc.wantUserPre)
				}
				if got := kiroHookCommands(t, ua, "agentSpawn"); !reflect.DeepEqual(got, []string{"git status"}) {
					t.Errorf("user agentSpawn = %v (a hook Observer does not own was changed)", got)
				}
				if !reflect.DeepEqual(ua["allowedTools"], []any{"read"}) {
					t.Errorf("user allowedTools changed: %v", ua["allowedTools"])
				}
			}
			if tc.wantWarning != "" {
				for rel, want := range seeded {
					if got, _ := os.ReadFile(filepath.Join(home, rel)); string(got) != string(want) {
						t.Errorf("%s changed:\n%s", rel, got)
					}
				}
			}

			// The V3 standalone file.
			v3 := kiroReadJSON(t, filepath.Join(home, ".kiro", "hooks", kiroAgentName+".json"))
			if v3["version"] != "v1" {
				t.Errorf("v3 version = %v", v3["version"])
			}
			list, _ := v3["hooks"].([]any)
			var triggers []string
			for _, h := range list {
				m, _ := h.(map[string]any)
				action, _ := m["action"].(map[string]any)
				trig, _ := m["trigger"].(string)
				triggers = append(triggers, trig)
				if action["command"] != kiroCmd(trig) || action["type"] != "command" {
					t.Errorf("v3 %s action = %v", trig, action)
				}
			}
			if !reflect.DeepEqual(triggers, []string{"PreToolUse", "UserPromptSubmit"}) {
				t.Errorf("v3 triggers = %v", triggers)
			}

			// Idempotent: a second run changes no byte.
			before := kiroSnapshot(t, home)
			again := kiroRegistry(t, home, nil).Register("kiro-cli")
			if again.Error != nil || len(again.HooksAdded) != 0 {
				t.Fatalf("second Register: added %v err %v", again.HooksAdded, again.Error)
			}
			if after := kiroSnapshot(t, home); !reflect.DeepEqual(before, after) {
				t.Errorf("second Register changed files")
			}

			// Uninstall removes every Observer write and nothing else.
			un := kiroRegistry(t, home, nil).Unregister("kiro-cli")
			if un.Error != nil {
				t.Fatalf("Unregister: %v", un.Error)
			}
			for _, p := range []string{
				filepath.Join(home, ".kiro", "agents", kiroAgentName+".json"),
				filepath.Join(home, ".kiro", "hooks", kiroAgentName+".json"),
			} {
				if _, err := os.Stat(p); !os.IsNotExist(err) {
					t.Errorf("%s survived uninstall (err %v)", p, err)
				}
			}
			if _, err := os.Stat(settings); err == nil {
				s := kiroReadJSON(t, settings)
				if got, _ := s[kiroDefaultAgentKey].(string); got == kiroAgentName {
					t.Error("chat.defaultAgent still names Observer's removed agent")
				}
				if tc.wantDefault == "mine" && s[kiroDefaultAgentKey] != "mine" {
					t.Errorf("uninstall cleared the user's own default: %v", s)
				}
			}
			if tc.userAgent != "" {
				ua := kiroReadJSON(t, filepath.Join(home, tc.userAgent))
				if got := kiroHookCommands(t, ua, "preToolUse"); !reflect.DeepEqual(got, []string{"lint.sh"}) {
					t.Errorf("user preToolUse after uninstall = %v", got)
				}
			}
		})
	}
}

// kiroSnapshot reads every file under home/.kiro.
func kiroSnapshot(t *testing.T, home string) map[string]string {
	t.Helper()
	out := map[string]string{}
	_ = filepath.Walk(filepath.Join(home, ".kiro"), func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || strings.HasSuffix(p, settingsLockSuffix) {
			return nil
		}
		b, _ := os.ReadFile(p)
		out[p] = string(b)
		return nil
	})
	return out
}

// TestKiroCLIHonoursKiroHome: KIRO_HOME relocates every write.
func TestKiroCLIHonoursKiroHome(t *testing.T) {
	home, alt := t.TempDir(), t.TempDir()
	res := kiroRegistry(t, home, map[string]string{"KIRO_HOME": alt}).Register("kiro-cli")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	for _, rel := range []string{"agents/" + kiroAgentName + ".json", "hooks/" + kiroAgentName + ".json", "settings/cli.json"} {
		if _, err := os.Stat(filepath.Join(alt, rel)); err != nil {
			t.Errorf("%s not under KIRO_HOME: %v", rel, err)
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".kiro")); !os.IsNotExist(err) {
		t.Errorf("~/.kiro written although KIRO_HOME is set (err %v)", err)
	}
}

// TestKiroCLIDryRunWritesNothing: a dry run reports and writes no file.
func TestKiroCLIDryRunWritesNothing(t *testing.T) {
	home := t.TempDir()
	reg, err := NewRegistry(Options{
		BinaryPath: kiroTestBin, HomeDir: home, DryRun: true,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	res := reg.Register("kiro-cli")
	if res.Error != nil || len(res.HooksAdded) == 0 {
		t.Fatalf("dry run: added %v err %v", res.HooksAdded, res.Error)
	}
	if snap := kiroSnapshot(t, home); len(snap) != 0 {
		t.Errorf("dry run wrote %v", snap)
	}
}

// TestKiroCLISkipEventRespected: `observer start`'s skip filter drops an
// event from every Kiro file.
func TestKiroCLISkipEventRespected(t *testing.T) {
	home := t.TempDir()
	reg, err := NewRegistry(Options{
		BinaryPath: kiroTestBin, HomeDir: home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
		SkipEvent:     func(tool, event string) bool { return tool == "kiro-cli" && event == "userPromptSubmit" },
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := reg.Register("kiro-cli"); res.Error != nil {
		t.Fatal(res.Error)
	}
	own := kiroReadJSON(t, filepath.Join(home, ".kiro", "agents", kiroAgentName+".json"))
	if got := kiroHookCommands(t, own, "userPromptSubmit"); len(got) != 0 {
		t.Errorf("skipped event written to the agent: %v", got)
	}
	v3, _ := os.ReadFile(filepath.Join(home, ".kiro", "hooks", kiroAgentName+".json"))
	if strings.Contains(string(v3), "UserPromptSubmit") {
		t.Errorf("skipped event written to the V3 file:\n%s", v3)
	}
}

// TestFU208KiroUserAgentRefusalReason: a user agent file Observer refuses to
// write into because an entry in Observer's shape runs another binary
// (FU-192) is reported with that refusal's own text, not as "not a 2.x agent
// JSON"; a file that really is not one keeps that text. Both stay byte for
// byte.
func TestFU208KiroUserAgentRefusalReason(t *testing.T) {
	home := t.TempDir()
	foreign := `{"name":"mine","hooks":{"preToolUse":[{"command":"/opt/lc/lc-hook.sh hook kiro-cli preToolUse"}]}}`
	v3 := `{"name":"v3","hooks":[{"trigger":"PreToolUse","command":"x"}]}`
	kiroWrite(t, filepath.Join(home, ".kiro", "agents", "mine.json"), foreign)
	kiroWrite(t, filepath.Join(home, ".kiro", "agents", "v3.json"), v3)
	res := kiroRegistry(t, home, nil).Register("kiro-cli")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	w := res.ProbeWarning
	if !strings.Contains(w, "kiro-cli: left untouched mine.json: hook.registerKiroCLI: event preToolUse already has a non-observer hook ("+foreignBinaryReason+"); pass --force to overwrite") {
		t.Errorf("the foreign-binary refusal is not reported with its reason: %q", w)
	}
	if !strings.Contains(w, "not a 2.x agent JSON with a hooks object): v3.json") {
		t.Errorf("the V3 file lost its own reason: %q", w)
	}
	if strings.Contains(w, "agent JSON with a hooks object): mine.json") || strings.Contains(w, "hooks object): v3.json, mine.json") {
		t.Errorf("the foreign-binary file is reported as not a 2.x agent JSON: %q", w)
	}
	for name, want := range map[string]string{"mine.json": foreign, "v3.json": v3} {
		if got, _ := os.ReadFile(filepath.Join(home, ".kiro", "agents", name)); string(got) != want {
			t.Errorf("%s changed:\n%s", name, got)
		}
	}
}

// TestFU213KiroUserAgentKeptEntryIsReported: uninstall keeps an entry in
// Observer's shape that runs another binary in one of the user's own agent
// files (FU-203) and reports it with that file named, with and without
// --force; Observer's own agent and its default pointer go.
func TestFU213KiroUserAgentKeptEntryIsReported(t *testing.T) {
	for _, force := range []bool{false, true} {
		home := t.TempDir()
		reg := kiroRegistry(t, home, nil)
		if res := reg.Register("kiro-cli"); res.Error != nil {
			t.Fatalf("Register: %v", res.Error)
		}
		mine := filepath.Join(home, ".kiro", "agents", "mine.json")
		foreign := `{"name":"mine","hooks":{"preToolUse":[{"command":"/opt/lc/lc-hook.sh hook kiro-cli preToolUse"}]}}`
		kiroWrite(t, mine, foreign)
		reg.opts.Force = force
		res := reg.Unregister("kiro-cli")
		if res.Error != nil {
			t.Fatalf("force=%v: Unregister: %v", force, res.Error)
		}
		if got, _ := os.ReadFile(mine); string(got) != foreign {
			t.Errorf("force=%v: the user's agent changed:\n%s", force, got)
		}
		if !slices.Contains(res.HooksKeptForeign, "preToolUse") {
			t.Errorf("force=%v: HooksKeptForeign = %v, want preToolUse", force, res.HooksKeptForeign)
		}
		var named bool
		for _, k := range res.HooksKeptForeignIn {
			if k.Path == mine && slices.Contains(k.Events, "preToolUse") {
				named = true
			}
		}
		if !named {
			t.Errorf("force=%v: HooksKeptForeignIn = %+v, want %s named", force, res.HooksKeptForeignIn, mine)
		}
		if _, err := os.Stat(filepath.Join(home, ".kiro", "agents", kiroAgentName+".json")); !os.IsNotExist(err) {
			t.Errorf("force=%v: Observer's own agent was kept: %v", force, err)
		}
		top, _, err := readKiroSettings(reg.kiroSettingsPath())
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if def := kiroDefaultAgent(top); def == kiroAgentName {
			t.Errorf("force=%v: the default agent still points at Observer's removed agent", force)
		}
	}
}
