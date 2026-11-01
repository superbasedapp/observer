//go:build !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox_seatbelt && !sbo_omit_terminals_sandbox_apple_container && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxenv"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// sandboxCanaryParent is a launching environment holding the leaks of the
// WINFIX2 audit's finding 1 (another service's token, a cloud key, the
// launching agent session's own variables, a canary) next to what a box
// legitimately gets.
func sandboxCanaryParent(goos string) []string {
	env := []string{
		"PATH=/usr/bin", "HOME=/home/u", "TERM=xterm-256color",
		"SBO_CANARY_SECRET=sbo-dummy-not-a-secret", "GITHUB_TOKEN=gh-dummy",
		"AWS_SECRET_ACCESS_KEY=aws-dummy", "CLAUDECODE=1", "CLAUDE_CODE_ENTRYPOINT=cli",
		"ANTHROPIC_API_KEY=provider-dummy", "OPENAI_API_KEY=other-provider-dummy",
		envDaemonChild + "=1",
		sandboxenv.EnvAllow + "=ANTHROPIC_API_KEY",
	}
	if goos == "windows" {
		env = append(env, `SystemRoot=C:\Windows`, `USERPROFILE=C:\Users\u`)
	}
	return env
}

// leaked returns the parent's secret entries that crossed into env.
func leaked(env []string) []string {
	var out []string
	for _, kv := range env {
		for _, bad := range []string{"SBO_CANARY_SECRET=", "GITHUB_TOKEN=", "AWS_SECRET_ACCESS_KEY=", "CLAUDECODE=", "CLAUDE_CODE_ENTRYPOINT=", "OPENAI_API_KEY="} {
			if strings.HasPrefix(kv, bad) {
				out = append(out, sandboxEnvKey(kv))
			}
		}
	}
	return out
}

func hasEnv(env []string, kv string) bool { return slices.Contains(env, kv) }

func TestSandboxBoxEnvIsAnAllowList(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		env := sandboxBoxEnv(goos, sandboxCanaryParent(goos))
		if l := leaked(env); len(l) > 0 {
			t.Errorf("%s: %v crossed into the box", goos, l)
		}
		for _, want := range []string{"PATH=/usr/bin", "ANTHROPIC_API_KEY=provider-dummy", envDaemonChild + "=1"} {
			if !hasEnv(env, want) {
				t.Errorf("%s: %s is missing from %v", goos, want, env)
			}
		}
	}
}

// TestDriverEnvDropsTheCanary runs the canary through every OS-neutral
// driver env function (the Linux-only ones are in the _linux test): each
// must build the box's environment from the allow-list. Before the fix each
// passed the parent's environment minus a deny-list, so the canary crossed.
func TestDriverEnvDropsTheCanary(t *testing.T) {
	tok := strings.Repeat("t", 43)
	cases := map[string][]string{
		"mxc-process":     mxcBoxEnv(sandboxCanaryParent("windows"), `C:\t\box`, `C:\t\box\tmp`, vocab.TierInternet, 4242, tok, nil),
		"seatbelt":        seatbeltAgentEnv(sandboxCanaryParent("darwin"), macRunDirs{TempDir: "/tmp/r", SocketDir: "/tmp/r/s"}, 0, nil, nil),
		"apple-container": appleRunEnv(sandboxCanaryParent("darwin")),
		"bwrap host":      sandboxHostChildEnv(sandboxCanaryParent("linux"), sandbox.HostArgs{}),
	}
	for name, env := range cases {
		if l := leaked(env); len(l) > 0 {
			t.Errorf("%s: %v crossed into the box", name, l)
		}
		if !hasEnv(env, "ANTHROPIC_API_KEY=provider-dummy") {
			t.Errorf("%s: the provider variable the launch named did not cross", name)
		}
	}
}

func TestWithSandboxEnvAllowStripsInherited(t *testing.T) {
	env := []string{"PATH=/x", sandboxenv.EnvAllow + "=GITHUB_TOKEN", sandboxenv.EnvPassed + "=GITHUB_TOKEN"}
	got := withSandboxEnvAllow(env, []string{"ANTHROPIC_API_KEY", "OBSERVER_SANDBOX", "B"}, []string{"B"})
	want := []string{"PATH=/x", sandboxenv.EnvAllow + "=ANTHROPIC_API_KEY,B", sandboxenv.EnvPassed + "=B"}
	if !slices.Equal(got, want) {
		t.Fatalf("withSandboxEnvAllow = %v, want %v", got, want)
	}
	if got := withSandboxEnvAllow(env, nil, nil); !slices.Equal(got, []string{"PATH=/x"}) {
		t.Fatalf("an empty allow list left an inherited value: %v", got)
	}
}

func TestSandboxEnvAllowNamesFromTheRow(t *testing.T) {
	got := sandboxEnvAllowNames("claude-code", []string{"GITHUB_TOKEN"})
	for _, want := range []string{"ANTHROPIC_API_KEY", "CLAUDE_CONFIG_DIR", "GITHUB_TOKEN"} {
		if !slices.Contains(got, want) {
			t.Errorf("sandboxEnvAllowNames(claude-code) = %v, missing %s", got, want)
		}
	}
	if got := sandboxEnvAllowNames("no-such-tool", nil); len(got) != 0 {
		t.Errorf("an unknown tool named %v", got)
	}
}

func TestSandboxLaunchEnvNamesTheDaemonsOwnVariables(t *testing.T) {
	req := termsvc.LaunchRequest{
		SandboxEnvAllow: []string{"ANTHROPIC_API_KEY"}, SandboxEnvPassed: []string{"GITHUB_TOKEN"},
		ExtraEnv: []string{"ANTHROPIC_MODEL=opus"},
	}
	got := sandboxLaunchEnv([]string{"PATH=/x"}, req)
	if !hasEnv(got, sandboxenv.EnvAllow+"=ANTHROPIC_API_KEY,ANTHROPIC_MODEL") || !hasEnv(got, sandboxenv.EnvPassed+"=GITHUB_TOKEN") {
		t.Fatalf("sandboxLaunchEnv = %v", got)
	}
}

func TestSandboxEnvPosture(t *testing.T) {
	if s := sandboxEnvPostureNotice(nil); s != "" {
		t.Fatalf("a run with no pass_env printed %q", s)
	}
	if s := sandboxEnvPostureNotice([]string{"A", "B"}); !strings.Contains(s, "A, B") {
		t.Fatalf("notice = %q", s)
	}
	if s := sandboxEnvPostureLine([]string{"X"}, nil); !strings.Contains(s, "pass_env: none") {
		t.Fatalf("line = %q", s)
	}
	if s := sandboxCLIPassEnvLabel([]string{"A", "B"}); s != ", pass_env A,B" {
		t.Fatalf("label = %q", s)
	}
}
