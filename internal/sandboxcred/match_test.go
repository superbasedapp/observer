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
		{"unknown lane", func(_ *Request, f *RunFacts) { f.Lane = "elsewhere" }, CodeUnknownLane},
		{"local record, wrong custody", func(_ *Request, f *RunFacts) { f.Lane, f.Custody, f.HelperLive = LaneLocal, "home_relay", true }, CodeWrongCustody},
		{"local record, helper gone", func(_ *Request, f *RunFacts) { f.Lane, f.Custody = LaneLocal, CustodyLocal }, CodeHelperGone},
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

// TestDecideLocalRuns: a local run's request is judged by every hosted row
// plus the local ones, and injects only with all of them holding.
func TestDecideLocalRuns(t *testing.T) {
	t.Parallel()
	sent := mustSentinel(t, "anthropic")
	tok, _ := MintToken(rand.Reader)
	facts := RunFacts{Found: true, Live: true, Provider: "anthropic", SentinelHash: Hash(sent), TokenHash: Hash(tok), KeyStored: true, Lane: LaneLocal, Custody: CustodyLocal, HelperLive: true}
	good := Request{RunID: "run1", Token: tok, Host: "api.anthropic.com", XAPIKey: sent}
	if d := Decide(good, facts); !d.Inject || d.Auth != AuthXAPIKey {
		t.Fatalf("a local run with every row holding: %+v", d)
	}
	cases := []struct {
		name string
		edit func(*Request, *RunFacts)
		want Code
	}{
		{"another run named (box-forged header, no token)", func(r *Request, _ *RunFacts) { r.Token = "" }, CodeNotRelayed},
		{"another run's token", func(r *Request, _ *RunFacts) { r.Token, _ = MintToken(rand.Reader) }, CodeNotRelayed},
		{"expired record", func(_ *Request, f *RunFacts) { f.Live = false }, CodeRunNotLive},
		{"helper gone", func(_ *Request, f *RunFacts) { f.HelperLive = false }, CodeHelperGone},
		{"hosted custody on a local record", func(_ *Request, f *RunFacts) { f.Custody = "home_relay" }, CodeWrongCustody},
		{"the real key, not the sentinel", func(r *Request, _ *RunFacts) { r.XAPIKey = "sk-ant-real" }, CodeNotSentinel},
		{"another host", func(r *Request, _ *RunFacts) { r.Host = "evil.example.com" }, CodeWrongHost},
	}
	for _, c := range cases {
		r, f := good, facts
		c.edit(&r, &f)
		if d := Decide(r, f); d.Inject || d.Code != c.want {
			t.Fatalf("%s: %+v, want %s", c.name, d, c.want)
		}
	}
	// A hosted record is not judged by the local rows (Lane zero value).
	hosted := facts
	hosted.Lane, hosted.Custody, hosted.HelperLive = LaneHosted, "", false
	if d := Decide(good, hosted); !d.Inject {
		t.Fatalf("a hosted record read the local rows: %+v", d)
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
	hosts := map[string]bool{}
	for _, p := range Providers() {
		if hosts[p.Host] {
			t.Fatalf("two providers share the host %s: the destination would not decide the provider", p.Host)
		}
		hosts[p.Host] = true
		if got, ok := ProviderForHost(strings.ToUpper(p.Host) + "."); !ok || got.ID != p.ID {
			t.Fatalf("ProviderForHost(%s) = %v %v", p.Host, got.ID, ok)
		}
	}
	if _, ok := ProviderForHost("api.anthropic.com.evil.example"); ok {
		t.Fatal("a look-alike host names a provider")
	}
	if AuthBearer.Value("k") != "Bearer k" || AuthBearer.Header() != "Authorization" || AuthXAPIKey.Header() != "X-Api-Key" {
		t.Fatal("auth rendering")
	}
}
