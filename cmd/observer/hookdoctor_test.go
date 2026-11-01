package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// bindingCheckFor finds the binding check for (event, cap).
func bindingCheckFor(cs []diag.Check, tool, event string, cp integration.HookCap) (diag.Check, bool) {
	name := "hook.binding:" + tool + ":" + event + ":" + string(cp)
	for _, c := range cs {
		if c.Name == name {
			return c, true
		}
	}
	return diag.Check{}, false
}

// TestHookBindingChecks_Registered: after registration every Observer
// binding of the mechanism reads registered=yes, one check per binding,
// and vendor-only events are summarised, not checked.
func TestHookBindingChecks_Registered(t *testing.T) {
	binary := probeHookTestBinary(t)
	home := probeHookSetupHome(t)
	cfgPath, _ := toolGateTestConfig(t, "observe")
	probeHookRegister(t, home, binary, cfgPath, "claude-code")
	cs := hookBindingChecks(context.Background(), hookDoctorOptions{Binary: binary, ConfigPath: cfgPath}, "claude-code", probeGateAll)
	c, _ := integration.For("claude-code")
	mine := 0
	for _, b := range c.Hook.Bindings {
		if !b.Registered && !b.Wired {
			continue
		}
		mine++
		ck, ok := bindingCheckFor(cs, "claude-code", b.NativeEvent, b.Cap)
		if !ok {
			t.Errorf("no check for %s/%s", b.NativeEvent, b.Cap)
			continue
		}
		if ck.Status != diag.StatusOK || !strings.Contains(ck.Message, "registered=yes") || !strings.Contains(ck.Message, "trusted=n/a") {
			t.Errorf("%s: %v %s", ck.Name, ck.Status, ck.Message)
		}
		if b.Cap.IsGate() && b.Wired && !strings.Contains(ck.Message, "probe=not run") {
			t.Errorf("%s: gate binding without a probe hint: %s", ck.Name, ck.Message)
		}
	}
	if len(cs) != mine+1 || !strings.HasPrefix(cs[0].Name, "hook.bindings:") || !strings.Contains(cs[0].Message, "vendor-only") {
		t.Errorf("checks = %d (want %d + summary); summary %+v", len(cs), mine, cs[0])
	}
}

// TestHookBindingChecks_DefaultConfigSpellings: a hook `observer init`
// registered with no --config reads the default global config, so a doctor
// run with that default path spelled out (the dashboard always passes one)
// counts it as registered, and the reverse holds too; a different config
// path does not (found live: the dashboard Doctor reported 0 of 25).
func TestHookBindingChecks_DefaultConfigSpellings(t *testing.T) {
	binary := probeHookTestBinary(t)
	home := probeHookSetupHome(t)
	def := filepath.Join(home, ".observer", "config.toml")
	cases := []struct {
		name               string
		registered, doctor string
		want               string
	}{
		{"registered bare, doctor default path", "", def, "registered=yes"},
		{"registered default path, doctor bare", def, "", "registered=yes"},
		{"registered bare, doctor other path", "", filepath.Join(home, "other.toml"), "registered=no"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.RemoveAll(filepath.Join(home, ".claude")); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
				t.Fatal(err)
			}
			probeHookRegister(t, home, binary, tc.registered, "claude-code")
			cs := hookBindingChecks(context.Background(), hookDoctorOptions{Binary: binary, ConfigPath: tc.doctor}, "claude-code", probeGateAll)
			ck, ok := bindingCheckFor(cs, "claude-code", "PreToolUse", integration.HookCapToolGate)
			if !ok || !strings.Contains(ck.Message, tc.want) {
				t.Errorf("PreToolUse check = %+v, want %s", ck, tc.want)
			}
		})
	}
}

// TestHookBindingChecks_NotInstalledAndHookless: a tool with no config home
// reports one "not installed" summary; a hook-less adapter its honest zero.
func TestHookBindingChecks_NotInstalledAndHookless(t *testing.T) {
	binary := probeHookTestBinary(t)
	probeHookSetupHome(t)
	o := hookDoctorOptions{Binary: binary}
	cs := hookBindingChecks(context.Background(), o, "cursor", probeGateAll)
	if len(cs) != 1 || !strings.Contains(cs[0].Message, "not installed") {
		t.Errorf("cursor on a fresh home = %+v", cs)
	}
	for _, c := range integration.Capabilities() {
		if c.Hook.Mechanism != integration.HookNone {
			continue
		}
		cs := hookBindingChecks(context.Background(), o, c.Tool, probeGateAll)
		if len(cs) != 1 || cs[0].Status != diag.StatusOK || !strings.Contains(cs[0].Message, "no hook mechanism") {
			t.Errorf("%s = %+v", c.Tool, cs)
		}
		break
	}
}

// TestHookBindingChecks_CodexTrust: a registered Codex hook the user has not
// approved reads trusted=no (WARN, with the /hooks remedy); one approved in
// config.toml [hooks.state] reads trusted=yes.
func TestHookBindingChecks_CodexTrust(t *testing.T) {
	binary := probeHookTestBinary(t)
	home := probeHookSetupHome(t)
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfgPath, _ := toolGateTestConfig(t, "observe")
	probeHookRegister(t, home, binary, cfgPath, "codex")
	o := hookDoctorOptions{Binary: binary, ConfigPath: cfgPath}
	// Registration records Codex's trust for Observer's own entries (live
	// check 2026-10-20), so the freshly registered hook reads as trusted.
	cs := hookBindingChecks(context.Background(), o, "codex", probeGateAll)
	ck, ok := bindingCheckFor(cs, "codex", "UserPromptSubmit", integration.HookCapPromptGate)
	if !ok || ck.Status != diag.StatusOK || !strings.Contains(ck.Message, "trusted=yes") {
		t.Fatalf("registered codex prompt hook = %+v, want trusted by the registration", ck)
	}
	// Without the trust record (an older Observer's registration, or the
	// user removed it) the hook reads as untrusted, with the remedy.
	if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte("[features]\nhooks = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cs = hookBindingChecks(context.Background(), o, "codex", probeGateAll)
	ck, _ = bindingCheckFor(cs, "codex", "UserPromptSubmit", integration.HookCapPromptGate)
	if ck.Status != diag.StatusWarn || !strings.Contains(ck.Message, "trusted=no") {
		t.Fatalf("untrusted codex prompt hook = %+v", ck)
	}
	if !strings.Contains(strings.Join(ck.Details, " "), "/hooks") {
		t.Errorf("no trust remedy: %v", ck.Details)
	}
	hooksPath := filepath.Join(home, ".codex", "hooks.json")
	toml := "[hooks.state.\"" + filepath.ToSlash(hooksPath) + ":user_prompt_submit:0:0\"]\ntrusted_hash = \"abc\"\n"
	if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	cs = hookBindingChecks(context.Background(), o, "codex", probeGateAll)
	ck, _ = bindingCheckFor(cs, "codex", "UserPromptSubmit", integration.HookCapPromptGate)
	if ck.Status != diag.StatusOK || !strings.Contains(ck.Message, "trusted=yes") {
		t.Errorf("trusted codex prompt hook = %+v", ck)
	}
}

// TestRunHookDoctorRejectsUnknownGate pins the --gate vocabulary.
func TestRunHookDoctorRejectsUnknownGate(t *testing.T) {
	var buf bytes.Buffer
	if err := runHookDoctor(context.Background(), &buf, hookDoctorOptions{Probe: true, Gate: "everything"}); err == nil ||
		!strings.Contains(err.Error(), "--gate") {
		t.Errorf("err = %v", err)
	}
}
