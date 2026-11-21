package sandboxcred

import (
	"slices"
	"testing"
)

// TestBoxEnvActionRows is one case per row of boxEnvRules, plus the keep.
func TestBoxEnvActionRows(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, provider, env string
		want                EnvAction
	}{
		{"the lane's key variable", "anthropic", "ANTHROPIC_API_KEY", EnvSentinel},
		{"the lane provider's other credential", "anthropic", "ANTHROPIC_AUTH_TOKEN", EnvDrop},
		{"another provider's key", "anthropic", "OPENAI_API_KEY", EnvDrop},
		{"a second key variable of the lane's provider", "google", "GOOGLE_API_KEY", EnvDrop},
		{"an unknown provider injects nothing", "nobody", "ANTHROPIC_API_KEY", EnvDrop},
		{"an unclassed variable", "anthropic", "PATH", EnvKeep},
		{"an unclassed token the user passed", "anthropic", "GITHUB_TOKEN", EnvKeep},
		{"a name that only looks like one", "anthropic", "ANTHROPIC_API_KEY_HINT", EnvKeep},
	} {
		if got := BoxEnvAction(tc.provider, tc.env); got != tc.want {
			t.Errorf("%s: BoxEnvAction(%q, %q) = %s, want %s", tc.name, tc.provider, tc.env, got, tc.want)
		}
	}
	if len(boxEnvRules) != 2 {
		t.Fatalf("boxEnvRules has %d rows; add a case per new row and update this count", len(boxEnvRules))
	}
}

// TestBoxEnv: the key variable holds only the sentinel, every other
// classed variable is gone (named once, never with its value), and the
// rest is untouched and in order.
func TestBoxEnv(t *testing.T) {
	t.Parallel()
	in := []string{
		"PATH=/usr/bin", "ANTHROPIC_API_KEY=sk-ant-SENTINEL-0000", "ANTHROPIC_AUTH_TOKEN=tok-SENTINEL-0001",
		"OPENAI_API_KEY=sk-SENTINEL-0002", "GITHUB_TOKEN=gh-SENTINEL-0003", "ANTHROPIC_AUTH_TOKEN=tok-SENTINEL-0004",
	}
	out, dropped := BoxEnv("anthropic", "obsbx-sentinel", in)
	want := []string{"PATH=/usr/bin", "ANTHROPIC_API_KEY=obsbx-sentinel", "GITHUB_TOKEN=gh-SENTINEL-0003"}
	if !slices.Equal(out, want) {
		t.Fatalf("env %v, want %v", out, want)
	}
	if !slices.Equal(dropped, []string{"ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY"}) {
		t.Fatalf("dropped %v", dropped)
	}
}

// TestBoxEnvSet: a lane binding several providers puts each provider's own
// sentinel in that provider's key variable only, and still drops every
// other classed variable.
func TestBoxEnvSet(t *testing.T) {
	t.Parallel()
	in := []string{
		"PATH=/usr/bin", "ANTHROPIC_API_KEY=sk-ant-REAL", "OPENAI_API_KEY=sk-REAL",
		"ANTHROPIC_AUTH_TOKEN=tok-REAL", "XAI_API_KEY=xai-REAL", "HOME=/h",
	}
	out, dropped := BoxEnvSet(map[string]string{"anthropic": "s-ant", "openai": "s-oai"}, in)
	want := []string{"PATH=/usr/bin", "ANTHROPIC_API_KEY=s-ant", "OPENAI_API_KEY=s-oai", "HOME=/h"}
	if !slices.Equal(out, want) {
		t.Fatalf("env %v, want %v", out, want)
	}
	if !slices.Equal(dropped, []string{"ANTHROPIC_AUTH_TOKEN", "XAI_API_KEY"}) {
		t.Fatalf("dropped %v", dropped)
	}
	// One provider through BoxEnvSet is BoxEnv.
	a, da := BoxEnv("anthropic", "s", in)
	b, db := BoxEnvSet(map[string]string{"anthropic": "s"}, in)
	if !slices.Equal(a, b) || !slices.Equal(da, db) {
		t.Fatalf("BoxEnv %v %v, BoxEnvSet %v %v", a, da, b, db)
	}
}

// TestCredEnvHoldsKeyEnv: every provider's key variable is in its own
// credential list, so the table classes it.
func TestCredEnvHoldsKeyEnv(t *testing.T) {
	t.Parallel()
	for _, p := range Providers() {
		if !slices.Contains(p.CredEnv, p.KeyEnv) || !IsCredentialEnv(p.KeyEnv) {
			t.Errorf("%s: KeyEnv %s not in CredEnv %v", p.ID, p.KeyEnv, p.CredEnv)
		}
	}
}
