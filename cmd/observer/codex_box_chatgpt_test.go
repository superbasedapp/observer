package main

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

// TestCodexBoxRoutesChatGPTAccountCalls pins D-MU5's launcher side: inside an
// Observer box, codex gets chatgpt_base_url pointed at the forwarded proxy's
// /backend-api/ (its account and workspace-routing calls), once; a user's own
// override wins; outside a box nothing is added.
func TestCodexBoxRoutesChatGPTAccountCalls(t *testing.T) {
	const proxy = "http://127.0.0.1:41234/"
	want := `chatgpt_base_url="http://127.0.0.1:41234/backend-api/"`

	got, added := withCodexBoxChatGPTBase([]string{"exec", "hi"}, proxy)
	if !added || !slices.Equal(got, []string{"-c", want, "exec", "hi"}) {
		t.Fatalf("box args = %v (added %v)", got, added)
	}
	for _, user := range [][]string{
		{"-c", `chatgpt_base_url="https://example.test/"`},
		{"-c=chatgpt_base_url=x"},
		{"--config", "chatgpt_base_url=x"},
	} {
		if out, added := withCodexBoxChatGPTBase(user, proxy); added || !slices.Equal(out, user) {
			t.Errorf("user override %v replaced: %v", user, out)
		}
	}

	prev := cliSandboxedEnv
	t.Cleanup(func() { cliSandboxedEnv = prev })
	for _, inBox := range []bool{true, false} {
		cliSandboxedEnv = func() bool { return inBox }
		var stderr bytes.Buffer
		args := codexLaunchArgs(codexLauncherOptions{stderr: &stderr}, []string{"exec"}, proxy)
		has := slices.Contains(args, want)
		if has != inBox {
			t.Errorf("inBox=%v: args = %v", inBox, args)
		}
		if inBox && !strings.Contains(stderr.String(), "chatgpt_base_url injected") {
			t.Errorf("no notice: %q", stderr.String())
		}
	}
}
