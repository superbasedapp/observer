package sandboxcred

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

func mustSentinel(t *testing.T, provider string) string {
	t.Helper()
	s, err := MintSentinel(rand.Reader, provider)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestDecideRows has one case per row of the match table and the pass.
func TestDecideRows(t *testing.T) {
	t.Parallel()
	sent := mustSentinel(t, "anthropic")
	other := mustSentinel(t, "anthropic")
	tok, _ := MintToken(rand.Reader)
	facts := RunFacts{Found: true, Live: true, Provider: "anthropic", SentinelHash: Hash(sent), TokenHash: Hash(tok), KeyStored: true}
	good := Request{RunID: "run1", Token: tok, Host: "api.anthropic.com", XAPIKey: sent}
	cases := []struct {
		name string
		edit func(*Request, *RunFacts)
		want Code
	}{
		{"injects", func(*Request, *RunFacts) {}, CodeInjected},
		{"no run header", func(r *Request, _ *RunFacts) { r.RunID = "" }, CodeNoRun},
		{"no injection record", func(_ *Request, f *RunFacts) { f.Found = false }, CodeRunNotLive},
		{"box-forged run header (no token)", func(r *Request, _ *RunFacts) { r.Token = "" }, CodeNotRelayed},
		{"box-forged token", func(r *Request, _ *RunFacts) { r.Token = "guess" }, CodeNotRelayed},
		{"dead run", func(_ *Request, f *RunFacts) { f.Live = false }, CodeRunNotLive},
		{"unknown provider", func(_ *Request, f *RunFacts) { f.Provider = "nope" }, CodeUnknownProv},
		{"wrong auth form", func(r *Request, _ *RunFacts) { r.XAPIKey, r.Authorization = "", "Bearer "+sent }, CodeWrongAuthForm},
		{"another run's sentinel", func(r *Request, _ *RunFacts) { r.XAPIKey = other }, CodeNotSentinel},
		{"a real key, not a sentinel", func(r *Request, _ *RunFacts) { r.XAPIKey = "sk-ant-real" }, CodeNotSentinel},
		{"another host", func(r *Request, _ *RunFacts) { r.Host = "evil.example.com" }, CodeWrongHost},
		{"look-alike host", func(r *Request, _ *RunFacts) { r.Host = "api.anthropic.com.evil.example" }, CodeWrongHost},
		{"no key stored", func(_ *Request, f *RunFacts) { f.KeyStored = false }, CodeNoKey},
	}
	if len(cases) < len(matchRules)+1 {
		t.Fatalf("%d cases for %d rows", len(cases), len(matchRules))
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, f := good, facts
			c.edit(&r, &f)
			d := Decide(r, f)
			if d.Code != c.want || d.Inject != (c.want == CodeInjected) {
				t.Fatalf("Decide = %+v, want %s", d, c.want)
			}
		})
	}
}

// TestDecideBearerAndGoogle covers the other two auth forms.
func TestDecideBearerAndGoogle(t *testing.T) {
	t.Parallel()
	tok, _ := MintToken(rand.Reader)
	for _, c := range []struct {
		provider string
		req      func(s string) Request
	}{
		{"openai", func(s string) Request { return Request{Host: "api.openai.com", Authorization: "Bearer " + s} }},
		{"google", func(s string) Request { return Request{Host: "generativelanguage.googleapis.com", GoogKey: s} }},
	} {
		s := mustSentinel(t, c.provider)
		r := c.req(s)
		r.RunID, r.Token = "run1", tok
		d := Decide(r, RunFacts{Found: true, Live: true, Provider: c.provider, SentinelHash: Hash(s), TokenHash: Hash(tok), KeyStored: true})
		p, _ := ProviderFor(c.provider)
		if !d.Inject || d.Auth != p.Auth {
			t.Fatalf("%s: %+v", c.provider, d)
		}
	}
}

func TestSentinelShape(t *testing.T) {
	t.Parallel()
	s := mustSentinel(t, "openai")
	if !IsSentinel(s) || !strings.Contains(s, "openai") || len(s) < 40 {
		t.Fatalf("sentinel %q", s)
	}
	if _, err := MintSentinel(rand.Reader, "nope"); err == nil {
		t.Fatal("a sentinel for an unknown provider")
	}
	if _, err := MintSentinel(bytes.NewReader(nil), "openai"); err == nil {
		t.Fatal("a sentinel from an empty random source")
	}
	if Hash(s) == s || len(Hash(s)) != 64 {
		t.Fatal("hash")
	}
}

func TestProviderTable(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, p := range Providers() {
		if p.ID == "" || p.Host == "" || p.KeyEnv == "" || !strings.HasPrefix(p.Docs, "https://") || seen[p.ID] {
			t.Fatalf("bad row %+v", p)
		}
		seen[p.ID] = true
		if p.Auth.Header() == "" || p.Auth.Value("k") == "" {
			t.Fatalf("auth form %q", p.Auth)
		}
	}
	if ProviderForTool(true, []string{"anthropic"}) != "anthropic" || ProviderForTool(false, []string{"anthropic"}) != "" || ProviderForTool(true, []string{"anthropic", "openai"}) != "" {
		t.Fatal("ProviderForTool")
	}
	if AuthBearer.Value("k") != "Bearer k" || AuthBearer.Header() != "Authorization" || AuthXAPIKey.Header() != "X-Api-Key" {
		t.Fatal("auth rendering")
	}
}
