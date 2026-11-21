package sandboxkey

import (
	"slices"
	"strings"
	"testing"
)

// TestToolProviderRules: one case per row of usableRules and
// injectableRules.
func TestToolProviderRules(t *testing.T) {
	t.Parallel()
	all := allIDs()
	cases := []struct {
		name       string
		in         ToolRoute
		usable     []string
		injectable []string
	}{
		{"vendor locked", ToolRoute{VendorLocked: true, Families: []string{"anthropic"}, Routed: true}, []string{"anthropic"}, []string{"anthropic"}},
		{"vendor locked keeps its vendor whatever the route says", ToolRoute{VendorLocked: true, Families: []string{"xai"}, Routed: true, RouteProviders: []string{}}, []string{"xai"}, []string{"xai"}},
		{"vendor locked to a provider the table does not know", ToolRoute{VendorLocked: true, Families: []string{"nosuch"}, Routed: true}, nil, nil},
		{"no proxy route: no injection", ToolRoute{}, all, nil},
		{"a route that names its providers", ToolRoute{Routed: true, RouteProviders: []string{"openrouter", "groq", "anthropic"}}, all, []string{"anthropic", "openrouter"}},
		{"a route lane to a host the table does not know", ToolRoute{Routed: true, RouteProviders: []string{}}, all, nil},
		{"a route the registry says nothing about", ToolRoute{Routed: true}, all, all},
	}
	for _, c := range cases {
		if got := UsableProviders(c.in); !slices.Equal(got, c.usable) {
			t.Errorf("%s: usable %v, want %v", c.name, got, c.usable)
		}
		if got := InjectableProviders(c.in); !slices.Equal(got, c.injectable) {
			t.Errorf("%s: injectable %v, want %v", c.name, got, c.injectable)
		}
	}
}

// TestBindProvidersRules: one case per row of bindRules.
func TestBindProvidersRules(t *testing.T) {
	t.Parallel()
	all := allIDs()
	cases := []struct {
		name string
		in   BindFacts
		want []string
	}{
		{"org route, one provider: its sentinel with no key stored", BindFacts{Candidates: []string{"anthropic"}, OrgRoute: true}, []string{"anthropic"}},
		{"org route, several providers: only the stored ones", BindFacts{Candidates: all, Stored: []string{"openai"}, OrgRoute: true}, []string{"openai"}},
		{"org route, several providers, none stored", BindFacts{Candidates: all, OrgRoute: true}, nil},
		{"stored keys, one provider", BindFacts{Candidates: []string{"anthropic"}, Stored: []string{"anthropic", "openai"}}, []string{"anthropic"}},
		{"stored keys, several providers", BindFacts{Candidates: all, Stored: []string{"openai", "anthropic"}}, []string{"anthropic", "openai"}},
		{"a stored key for a provider the tool cannot use", BindFacts{Candidates: []string{"anthropic"}, Stored: []string{"openai"}}, nil},
		{"no candidates", BindFacts{Stored: all}, nil},
	}
	for _, c := range cases {
		if got := BindProviders(c.in); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// TestBindLocal: a local lane binds a provider only where the launching env
// already carries its key variable and its key is stored, and stays closed
// rather than drop a credential the tool can use.
func TestBindLocal(t *testing.T) {
	t.Parallel()
	all := allIDs()
	cases := []struct {
		name string
		in   LocalBindFacts
		want []string
	}{
		{"one provider, as before", LocalBindFacts{Candidates: []string{"anthropic"}, Stored: []string{"anthropic"}, EnvNames: []string{"ANTHROPIC_API_KEY", "PATH"}}, []string{"anthropic"}},
		{"one provider, another provider's key in the env is dropped as before", LocalBindFacts{Candidates: []string{"anthropic"}, Stored: []string{"anthropic"}, EnvNames: []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY"}}, []string{"anthropic"}},
		{"one provider, its other credential is dropped as before", LocalBindFacts{Candidates: []string{"anthropic"}, Stored: []string{"anthropic"}, EnvNames: []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"}}, []string{"anthropic"}},
		{"no key variable in the env", LocalBindFacts{Candidates: []string{"anthropic"}, Stored: []string{"anthropic"}, EnvNames: []string{"ANTHROPIC_AUTH_TOKEN"}}, nil},
		{"no stored key", LocalBindFacts{Candidates: []string{"anthropic"}, EnvNames: []string{"ANTHROPIC_API_KEY"}}, nil},
		{"several providers, both stored", LocalBindFacts{Candidates: all, Stored: []string{"anthropic", "openai"}, EnvNames: []string{"OPENAI_API_KEY", "ANTHROPIC_API_KEY"}}, []string{"anthropic", "openai"}},
		{"several providers, one key the lane cannot replace: closed", LocalBindFacts{Candidates: all, Stored: []string{"openai"}, EnvNames: []string{"OPENAI_API_KEY", "ANTHROPIC_API_KEY"}}, nil},
		{"several providers, a key file variable the lane cannot replace: closed", LocalBindFacts{Candidates: all, Stored: []string{"openai"}, EnvNames: []string{"OPENAI_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS"}}, nil},
		{"several providers, only the stored one in the env", LocalBindFacts{Candidates: all, Stored: []string{"openai", "anthropic"}, EnvNames: []string{"OPENAI_API_KEY"}}, []string{"openai"}},
	}
	for _, c := range cases {
		if got := BindLocal(c.in); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// TestInBoxKeyEnv: the in-box forward list is derived from the one provider
// table, holds every provider's key variable (the gap: xAI's was missing),
// and never a key file path, a login token or a refresh token.
func TestInBoxKeyEnv(t *testing.T) {
	t.Parallel()
	got := InBoxKeyEnv()
	for _, p := range Providers() {
		if !slices.Contains(got, p.KeyEnv) {
			t.Errorf("%s: its key variable %s is not forwarded", p.ID, p.KeyEnv)
		}
		for _, n := range p.InBoxEnv {
			if !slices.Contains(p.CredEnv, n) {
				t.Errorf("%s: in-box variable %s is not in its credential table", p.ID, n)
			}
			if InBoxEnvProvider(n) != p.ID {
				t.Errorf("%s: InBoxEnvProvider(%s) = %q", p.ID, n, InBoxEnvProvider(n))
			}
		}
	}
	for _, n := range got {
		for _, bad := range []string{"CREDENTIALS", "REFRESH", "OAUTH", "AUTH_TOKEN", "BEARER"} {
			if strings.Contains(n, bad) {
				t.Errorf("in-box variable %s is not a plain API key", n)
			}
		}
	}
	for _, n := range []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENROUTER_API_KEY", "XAI_API_KEY"} {
		if !slices.Contains(got, n) {
			t.Errorf("%s is no longer forwarded", n)
		}
	}
}

func TestProviderLabels(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		ids  []string
		want string
	}{
		{nil, ""},
		{[]string{"openai"}, "OpenAI API key"},
		{[]string{"anthropic", "openai"}, "Anthropic API key and OpenAI API key"},
		{[]string{"anthropic", "openai", "xai"}, "Anthropic API key, OpenAI API key and xAI API key"},
	} {
		if got := ProviderLabels(c.ids, "and"); got != c.want {
			t.Errorf("%v: %q, want %q", c.ids, got, c.want)
		}
	}
}
