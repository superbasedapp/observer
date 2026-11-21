//go:build linux && !sbo_omit_capture_proxy && !sbo_omit_terminals_sandbox_credentials && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxcred"
)

// TestCredLocalBoxEnvDropsOtherCredentials (F-005, F-010 A7): with a lane
// open, the box gets the sentinel in the lane's key variable and no other
// variable the credential table classes (the tool row's
// ANTHROPIC_AUTH_TOKEN, another provider's key a user passed through
// pass_env); an unclassed variable the user passed stays; the record names
// the dropped variables and holds none of their values.
func TestCredLocalBoxEnvDropsOtherCredentials(t *testing.T) {
	obs, ks := credEnvForTest(t, true)
	if err := ks.Set(sandboxcred.KeyName("anthropic"), credTestKey); err != nil {
		t.Fatal(err)
	}
	live := true
	credLocalHelperLive(t, &live)
	rig := newCredLocalRig(t, obs, "run-n3-boxenv", "127.0.0.1:1")
	const (
		authTok = "tok-ant-oat01-SENTINEL-0000"
		oaiKey  = "sk-proj-SENTINEL-0001"
		ghTok   = "gh-SENTINEL-0002"
	)
	in := []string{"PATH=/usr/bin", "ANTHROPIC_API_KEY=" + credTestKey, "ANTHROPIC_AUTH_TOKEN=" + authTok, "OPENAI_API_KEY=" + oaiKey, "GITHUB_TOKEN=" + ghTok}
	env := credLocalBoxEnv(rig.h, in)
	joined := strings.Join(env, "\n")
	for _, v := range []string{credTestKey, authTok, oaiKey, "ANTHROPIC_AUTH_TOKEN=", "OPENAI_API_KEY="} {
		if strings.Contains(joined, v) {
			t.Fatalf("the box env still holds %q: %v", v, env)
		}
	}
	if !slices.Contains(env, "GITHUB_TOKEN="+ghTok) || !slices.Contains(env, "PATH=/usr/bin") {
		t.Fatalf("an unclassed variable was dropped: %v", env)
	}
	var sentinel string
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "ANTHROPIC_API_KEY="); ok {
			sentinel = v
		}
	}
	if !sandboxcred.IsSentinel(sentinel) {
		t.Fatalf("key variable %q, want the sentinel", sentinel)
	}
	rec, err := credReadRecord(obs, rig.run)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(rec.DroppedEnv, []string{"ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY"}) {
		t.Fatalf("record names %v", rec.DroppedEnv)
	}
	b, err := os.ReadFile(credRunPath(obs, rig.run))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{credTestKey, authTok, oaiKey, ghTok, sentinel} {
		if bytes.Contains(b, []byte(v)) {
			t.Fatal("the record holds a value")
		}
	}

	// No lane (the key variable is not in the launching env): the env is
	// exactly as before, the other credentials included.
	other := newCredLocalRig(t, obs, "run-n3-boxenv-nolane", "127.0.0.1:1")
	plain := []string{"ANTHROPIC_AUTH_TOKEN=" + authTok, "OPENAI_API_KEY=" + oaiKey}
	if got := credLocalBoxEnv(other.h, plain); !slices.Equal(got, plain) {
		t.Fatalf("an env with no lane changed: %v", got)
	}
}
