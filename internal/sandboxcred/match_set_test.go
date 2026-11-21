package sandboxcred

import (
	"crypto/rand"
	"testing"
)

// match_set_test.go pins a run that binds several providers (gap H2): the
// destination host picks the binding, and every match row then holds
// against that one binding, so provider P's key reaches only P's host and
// only for P's own sentinel of this run.

// setRun is a run bound to anthropic, openai and xai (openai and xai share
// the bearer auth form).
func setRun(t *testing.T) (RunFacts, map[string]string, string) {
	t.Helper()
	tok, _ := MintToken(rand.Reader)
	sent := map[string]string{}
	f := RunFacts{Found: true, Live: true, TokenHash: Hash(tok), KeyStored: true}
	for _, id := range []string{"anthropic", "openai", "xai"} {
		sent[id] = mustSentinel(t, id)
		f.Bindings = append(f.Bindings, Binding{Provider: id, SentinelHash: Hash(sent[id])})
	}
	return f, sent, tok
}

// carrying puts a credential in a provider's own auth form.
func carrying(provider, value string) Request {
	p, _ := ProviderFor(provider)
	switch p.Auth {
	case AuthBearer:
		return Request{Authorization: "Bearer " + value}
	case AuthGoogKey:
		return Request{GoogKey: value}
	}
	return Request{XAPIKey: value}
}

func TestDecideProviderSet(t *testing.T) {
	t.Parallel()
	f, sent, tok := setRun(t)
	stranger := mustSentinel(t, "openai")
	cases := []struct {
		name     string
		form     string // whose auth form carries the value
		value    string
		host     string
		edit     func(*RunFacts)
		want     Code
		provider string
	}{
		{"anthropic's sentinel on anthropic's host", "anthropic", sent["anthropic"], "api.anthropic.com", nil, CodeInjected, "anthropic"},
		{"openai's sentinel on openai's host", "openai", sent["openai"], "api.openai.com", nil, CodeInjected, "openai"},
		{"xai's sentinel on xai's host", "xai", sent["xai"], "api.x.ai", nil, CodeInjected, "xai"},
		{"anthropic's sentinel sent to openai's host", "anthropic", sent["anthropic"], "api.openai.com", nil, CodeWrongAuthForm, ""},
		{"openai's sentinel sent to anthropic's host", "openai", sent["openai"], "api.anthropic.com", nil, CodeWrongAuthForm, ""},
		{"openai's sentinel on xai's host (the same auth form)", "openai", sent["openai"], "api.x.ai", nil, CodeNotSentinel, ""},
		{"xai's sentinel on openai's host (the same auth form)", "xai", sent["xai"], "api.openai.com", nil, CodeNotSentinel, ""},
		{"xai's sentinel to a provider not in the set", "xai", sent["xai"], "openrouter.ai", nil, CodeWrongHost, ""},
		{"openai's sentinel to Gemini, not in the set", "openai", sent["openai"], "generativelanguage.googleapis.com", nil, CodeWrongHost, ""},
		{"a Gemini-form sentinel to Gemini, not in the set", "google", sent["openai"], "generativelanguage.googleapis.com", nil, CodeWrongAuthForm, ""},
		{"openai's sentinel to another host", "openai", sent["openai"], "evil.example.com", nil, CodeWrongHost, ""},
		{"another run's openai sentinel", "openai", stranger, "api.openai.com", nil, CodeNotSentinel, ""},
		{"a real key on the right host", "openai", "sk-real", "api.openai.com", nil, CodeNotSentinel, ""},
		{"the selected provider's key is not stored", "openai", sent["openai"], "api.openai.com", func(f *RunFacts) { f.KeyStored = false }, CodeNoKey, ""},
		{"a box-forged token", "openai", sent["openai"], "api.openai.com", func(f *RunFacts) { f.TokenHash = Hash("other") }, CodeNotRelayed, ""},
		{"a dead run", "openai", sent["openai"], "api.openai.com", func(f *RunFacts) { f.Live = false }, CodeRunNotLive, ""},
		{"a binding the table does not know is never a provider", "openai", "sk-real", "evil.example.com", func(f *RunFacts) {
			f.Bindings = append([]Binding(nil), f.Bindings...)
			f.Bindings[0].Provider = "nope"
		}, CodeUnknownProv, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			r := carrying(c.form, c.value)
			r.RunID, r.Token, r.Host = "run1", tok, c.host
			facts := f
			if c.edit != nil {
				c.edit(&facts)
			}
			d := Decide(r, facts)
			if d.Code != c.want || d.Inject != (c.want == CodeInjected) || d.Provider != c.provider {
				t.Fatalf("Decide = %+v, want %s provider %q", d, c.want, c.provider)
			}
			if d.Inject {
				p, _ := ProviderFor(d.Provider)
				if d.Auth != p.Auth {
					t.Fatalf("auth %s for %s", d.Auth, p.ID)
				}
			}
		})
	}
}

// TestDecideProviderSetNeverCrosses: over every bound sentinel, every auth
// form and every host, an injected request is always on its provider's own
// host and carries that provider's own sentinel of this run.
func TestDecideProviderSetNeverCrosses(t *testing.T) {
	t.Parallel()
	f, sent, tok := setRun(t)
	hosts := []string{"evil.example.com"}
	for _, p := range Providers() {
		hosts = append(hosts, p.Host)
	}
	injected := map[string]bool{}
	for owner, s := range sent {
		for _, form := range providerIDs() {
			for _, host := range hosts {
				r := carrying(form, s)
				r.RunID, r.Token, r.Host = "run1", tok, host
				d := Decide(r, f)
				if !d.Inject {
					continue
				}
				injected[owner+"@"+host] = true
				p, _ := ProviderFor(d.Provider)
				if d.Provider != owner || p.Host != host {
					t.Fatalf("%s's sentinel in %s's form to %s injected %s's key", owner, form, host, d.Provider)
				}
			}
		}
	}
	if len(injected) != len(sent) {
		t.Fatalf("injected %v, want one per bound provider on its own host", injected)
	}
}

// TestDecideOneBindingIsTheOldRecord: a record with one binding in Bindings
// is decided exactly as the one-provider record (Provider, SentinelHash),
// which every run had before; so an existing record is decided as before.
func TestDecideOneBindingIsTheOldRecord(t *testing.T) {
	t.Parallel()
	sent := mustSentinel(t, "anthropic")
	tok, _ := MintToken(rand.Reader)
	legacy := RunFacts{Found: true, Live: true, Provider: "anthropic", SentinelHash: Hash(sent), TokenHash: Hash(tok), KeyStored: true}
	set := legacy
	set.Provider, set.SentinelHash = "", ""
	set.Bindings = []Binding{{Provider: "anthropic", SentinelHash: Hash(sent)}}
	for _, r := range []Request{
		{RunID: "run1", Token: tok, Host: "api.anthropic.com", XAPIKey: sent},
		{RunID: "run1", Token: tok, Host: "evil.example.com", XAPIKey: sent},
		{RunID: "run1", Token: tok, Host: "api.openai.com", Authorization: "Bearer " + sent},
		{RunID: "run1", Token: tok, Host: "api.anthropic.com", XAPIKey: "sk-ant-real"},
		{RunID: "", Token: tok, Host: "api.anthropic.com", XAPIKey: sent},
		{RunID: "run1", Token: "x", Host: "api.anthropic.com", XAPIKey: sent},
	} {
		if a, b := Decide(r, legacy), Decide(r, set); a != b {
			t.Fatalf("%+v: legacy %+v, one binding %+v", r, a, b)
		}
	}
	if d := Decide(Request{RunID: "run1", Token: tok, Host: "api.anthropic.com", XAPIKey: sent}, legacy); !d.Inject || d.Provider != "anthropic" {
		t.Fatalf("the legacy record: %+v", d)
	}
}

// providerIDs is every provider id of the table, in table order.
func providerIDs() []string {
	var out []string
	for _, p := range Providers() {
		out = append(out, p.ID)
	}
	return out
}
