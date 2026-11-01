package integration

import (
	"errors"
	"strings"
	"testing"

	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestNativeSandboxRowsAreGrounded: every row names a registry tool, a
// mechanism, a grounding and a switch; a default-on sandbox has a per-run
// switch or a note saying why not; every need is in the closed vocabulary.
func TestNativeSandboxRowsAreGrounded(t *testing.T) {
	needs := map[NativeSandboxNeed]bool{NeedFreshProc: true, NeedDevNetTUN: true, NeedNestedUserns: true, NeedContainerEngine: true, NeedAppContainer: true, NeedSeatbelt: true}
	for _, tool := range NativeSandboxTools() {
		n, _ := NativeSandboxFor(tool)
		if _, ok := For(tool); !ok {
			t.Errorf("%s: not a registry tool", tool)
		}
		if n.Mechanism == "" || n.Grounding == "" || n.Note == "" || n.Disable.Kind == NativeSwitchNone || n.Disable.Value == "" {
			t.Errorf("%s: incomplete row %+v", tool, n)
		}
		for _, x := range n.Needs {
			if !needs[x] {
				t.Errorf("%s: need %q not in the vocabulary", tool, x)
			}
		}
	}
	if _, ok := NativeSandboxFor("goose"); ok {
		t.Fatal("goose has no native sandbox")
	}
	grounded := NativeSwitch{SourceURL: "https://example.com/doc", VerifiedOn: "2026-10-23"}
	env, glob := grounded, grounded
	env.Kind, env.Value = NativeSwitchEnv, "AGENT_SANDBOX=off"
	glob.Kind, glob.Value = NativeSwitchGlobalSetting, "sandbox.enabled: false"
	if !env.PerRun() || glob.PerRun() {
		t.Fatal("PerRun")
	}
	// A switch without its documentation is never per run (lane SBX-P3D).
	if (NativeSwitch{Kind: NativeSwitchEnv, Value: "AGENT_SANDBOX=off"}).PerRun() {
		t.Fatal("an ungrounded switch counted as per run")
	}
}

// TestNativeSwitchRowsNameTheirSource: every per-run switch and every probe
// in the side table names its documentation and date (lane SBX-P3D); a row
// without them is never applied.
func TestNativeSwitchRowsNameTheirSource(t *testing.T) {
	for _, tool := range NativeSandboxTools() {
		n, _ := NativeSandboxFor(tool)
		for _, sw := range []NativeSwitch{n.Disable, n.WeakMode} {
			if (sw.Kind == NativeSwitchFlag || sw.Kind == NativeSwitchEnv) && sw.SourceURL != "" && !sw.PerRun() {
				t.Errorf("%s: switch %q names a source but does not validate", tool, sw.Value)
			}
		}
		for _, m := range n.Managed {
			if !m.Grounded() {
				t.Errorf("%s: a managed-policy probe without its documentation", tool)
			}
		}
	}
	// The three rows grounded today.
	for tool, want := range map[string][]string{
		"codex":       {"--sandbox", "danger-full-access"},
		"copilot-cli": {"--no-sandbox"},
		"claude-code": {"--settings", `{"sandbox":{"enabled":false}}`},
	} {
		n, _ := NativeSandboxFor(tool)
		got, err := NativeSwitchArgs(n.Disable)
		if err != nil || strings.Join(got, "|") != strings.Join(want, "|") || !n.Disable.PerRun() {
			t.Errorf("%s: %v %v", tool, got, err)
		}
	}
}

// TestNativeSwitchArgsValidation: one case per validation rule, with
// hostile rows refused.
func TestNativeSwitchArgsValidation(t *testing.T) {
	cases := []struct {
		value string
		ok    bool
	}{
		{"--no-sandbox", true},
		{"--sandbox danger-full-access", true},
		{"--sandbox=danger-full-access", true},
		{"-s read-only", true},
		{"", false},
		{"danger-full-access", false},
		{"--a b c", false},
		{"--a --b", false},
		{"--x; rm -rf /", false},
		{"--x $(id)", false},
		{"--x `id`", false},
		{"--x a|b", false},
		{"--label <label>", false},
		{"--x \u0007", false},
		{"--x " + strings.Repeat("a", 300), false},
		{"--x=\x1b[31m", false},
	}
	for _, c := range cases {
		v := c.value
		_, err := NativeSwitchArgs(NativeSwitch{Kind: NativeSwitchFlag, Value: v})
		if (err == nil) != c.ok {
			t.Errorf("%q: err=%v, want ok=%v", v, err, c.ok)
		}
	}
	if _, err := NativeSwitchArgs(NativeSwitch{Kind: NativeSwitchEnv, Value: "A=b"}); err == nil {
		t.Error("an env switch has no argv form")
	}
}

// TestNativeSwitchArgsForState: the one rule the launch composition
// applies, one case per state.
func TestNativeSwitchArgsForState(t *testing.T) {
	cases := []struct {
		tool  string
		state vocab.NativeSandboxState
		want  string
		err   bool
	}{
		{"codex", vocab.NativeDisabledByObserver, "--sandbox|danger-full-access", false},
		{"codex", "", "", false},
		{"codex", vocab.NativeOrgForced, "", false},
		{"codex", vocab.NativeWeak, "", true},
		{"droid", vocab.NativeDisabledByObserver, "", true},
		{"goose", vocab.NativeDisabledByObserver, "", true},
	}
	for _, c := range cases {
		got, err := NativeSwitchArgsForState(c.tool, c.state)
		if (err != nil) != c.err || strings.Join(got, "|") != c.want {
			t.Errorf("%s %s: %v %v", c.tool, c.state, got, err)
		}
	}
	if !errors.Is(func() error { _, e := NativeSwitchArgsForState("droid", vocab.NativeDisabledByObserver); return e }(), ErrNoNativeSwitch) {
		t.Error("not ErrNoNativeSwitch")
	}
}

func TestAppendNativeArgs(t *testing.T) {
	cases := []struct{ args, sw, want []string }{
		{nil, nil, nil},
		{nil, []string{"--no-sandbox"}, []string{"--", "--no-sandbox"}},
		{[]string{"--model", "x"}, []string{"--no-sandbox"}, []string{"--model", "x", "--", "--no-sandbox"}},
		{[]string{"--", "--model", "x"}, []string{"--no-sandbox"}, []string{"--", "--model", "x", "--no-sandbox"}},
	}
	for _, c := range cases {
		if got := AppendNativeArgs(c.args, c.sw); strings.Join(got, " ") != strings.Join(c.want, " ") {
			t.Errorf("%v + %v = %v", c.args, c.sw, got)
		}
	}
}
