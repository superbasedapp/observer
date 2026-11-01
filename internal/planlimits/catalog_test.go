package planlimits

import (
	"slices"
	"testing"
)

// codexBarProviders is the reference provider list: every UsageProvider case
// in CodexBar's Sources/CodexBarCore/Providers/Providers.swift at commit
// 74f64b62b5d38b9cea59107d15799d69563eb38a (2026-10-15), which registers 104
// provider ids (docs/providers.md there says the same). D-681 makes this the
// coverage target. When the reference grows, add the new id here and a row.
var codexBarProviders = []string{
	"codex", "openai", "azureopenai", "claude", "clinepass", "cursor", "opencode", "opencodego", "alibaba",
	"alibabatokenplan", "qwencloud", "factory", "fireworks", "gemini", "antigravity", "copilot", "devin", "zai",
	"minimax", "manus", "kimi", "kilo", "kiro", "vertexai", "augment", "jetbrains", "moonshot", "amp", "t3chat",
	"langdock", "ollama", "synthetic", "openrouter", "elevenlabs", "warp", "windsurf", "zed", "perplexity", "mimo",
	"doubao", "sakana", "abacus", "mistral", "deepseek", "deepinfra", "codebuff", "venice", "commandcode", "qoder",
	"stepfun", "bedrock", "grok", "groq", "llmproxy", "litellm", "bifrost", "aixy", "deepgram", "poe", "chutes",
	"neuralwatt", "helmcode", "clawrouter", "longcat", "sub2api", "wayfinder", "zenmux", "aiand", "zoommate", "xai",
	"xapi", "notion", "ibmbob", "nous", "muse", "coderabbit", "replicate", "huggingface", "raycast", "pi", "v0",
	"typesafe", "hyper", "gitkraken", "devpass", "atlascloud", "vercel", "llmman", "xkiro", "museai", "lithosai",
	"workbuddy", "tavily", "linkup", "tinyapi", "exa", "cosmic", "aerostack", "sailresearch", "sofya", "fal", "flora",
	"parallel", "claudeplatform",
}

// catalogComplete turns on the coverage gate once every build lane has
// landed: then each row must have a live source or an honest gap.
const catalogComplete = true

func TestReferenceListIsTheReference(t *testing.T) {
	if len(codexBarProviders) != 104 {
		t.Fatalf("reference list has %d ids, want 104", len(codexBarProviders))
	}
	seen := map[string]bool{}
	for _, id := range codexBarProviders {
		if seen[id] {
			t.Errorf("reference id %q listed twice", id)
		}
		seen[id] = true
	}
}

func TestEveryReferenceProviderHasARow(t *testing.T) {
	covered := map[string]bool{}
	for _, p := range Providers {
		for _, r := range p.Ref {
			covered[r] = true
		}
	}
	for _, id := range codexBarProviders {
		if !covered[id] {
			t.Errorf("CodexBar provider %q has no catalogue row", id)
		}
	}
	for r := range covered {
		if !slices.Contains(codexBarProviders, r) {
			t.Errorf("a row names reference id %q, which is not in the reference list", r)
		}
	}
}

func TestCatalogueRowsAreWellFormed(t *testing.T) {
	groups := map[string]bool{GroupPlans: true, GroupBalance: true, GroupUsage: true}
	gaps := map[string]bool{GapNone: true}
	for _, g := range AllGaps() {
		gaps[g] = true
	}
	shows := map[string]bool{}
	for _, s := range AllShows() {
		shows[s] = true
	}
	ids := map[string]bool{}
	for _, p := range Providers {
		if p.ID == "" || ids[p.ID] {
			t.Errorf("provider id %q empty or duplicated", p.ID)
		}
		ids[p.ID] = true
		if !groups[p.Group] {
			t.Errorf("%s: unknown group %q", p.ID, p.Group)
		}
		if !gaps[p.Gap] {
			t.Errorf("%s: unknown gap %q", p.ID, p.Gap)
		}
		for _, s := range p.Shows {
			if !shows[s] {
				t.Errorf("%s: unknown shows code %q", p.ID, s)
			}
		}
	}
	for _, s := range Sources {
		if s.Provider != "" && !ids[s.Provider] {
			t.Errorf("source %s names unknown provider %q", s.ID, s.Provider)
		}
		if AuthOf(s.Kind) == "" {
			t.Errorf("source %s kind %q has no auth method", s.ID, s.Kind)
		}
	}
}

// TestEveryProviderIsCoveredOrHasAGap: a row either has a live source or
// says why not; a row never claims both.
func TestEveryProviderIsCoveredOrHasAGap(t *testing.T) {
	for _, p := range Providers {
		if p.ID == ProviderOther {
			continue
		}
		live := CoverageOf(p.ID) != CoverageManual
		switch {
		case live && p.Gap != GapNone:
			t.Errorf("%s has a live source and a gap %q", p.ID, p.Gap)
		case !live && p.Gap == GapNone && catalogComplete:
			t.Errorf("%s has no live source and no gap", p.ID)
		}
	}
}

func TestCoverageAndAuthAreDerived(t *testing.T) {
	cases := []struct {
		provider string
		cov      Coverage
		auth     []AuthMethod
	}{
		{ProviderOpenRouter, CoverageOfficial, []AuthMethod{AuthPastedKey}},
		{ProviderClaude, CoverageOfficial, []AuthMethod{AuthNone, AuthVendorLocal}},
		{ProviderKimiCode, CoverageExperimental, []AuthMethod{AuthUndocumented}},
		{ProviderWindsurf, CoverageExperimental, []AuthMethod{AuthVendorLocal}},
		{ProviderOther, CoverageManual, nil},
	}
	for _, c := range cases {
		if got := CoverageOf(c.provider); got != c.cov {
			t.Errorf("%s coverage = %q, want %q", c.provider, got, c.cov)
		}
		if got := AuthMethodsOf(c.provider); !slices.Equal(got, c.auth) {
			t.Errorf("%s auth = %v, want %v", c.provider, got, c.auth)
		}
	}
	for _, k := range AllKinds() {
		if AuthOf(k) == "" {
			t.Errorf("kind %q has no auth method", k)
		}
	}
}

func TestSessionPasteIsNormalised(t *testing.T) {
	cases := []struct{ in, cookie, bearer string }{
		{"Cookie: a=b; c=d", "a=b; c=d", "Cookie: a=b; c=d"},
		{"  a=b\r\nX-Evil: 1 ", "a=bX-Evil: 1", "a=bX-Evil: 1"},
		{"Authorization: Bearer tok123", "Authorization: Bearer tok123", "tok123"},
		{"Bearer tok", "Bearer tok", "tok"},
		{"'a=b'", "a=b", "a=b"},
	}
	for _, c := range cases {
		if got := SessionCookie(c.in); got != c.cookie {
			t.Errorf("SessionCookie(%q) = %q, want %q", c.in, got, c.cookie)
		}
		if got := SessionBearer(c.in); got != c.bearer {
			t.Errorf("SessionBearer(%q) = %q, want %q", c.in, got, c.bearer)
		}
	}
}

func TestJReader(t *testing.T) {
	j, err := ParseJ([]byte(`{"a":{"b":[{"c":"12.5"},{"c":3}]},"t":1760000000,"tm":1760000000000,"n":null,"s":"2026-10-15T00:00:00Z"}`))
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := j.At("a.b.0.c").Num(); !ok || v != 12.5 {
		t.Errorf("string number: %v %v", v, ok)
	}
	if v, ok := j.At("a.b.1.c").Num(); !ok || v != 3 {
		t.Errorf("number: %v %v", v, ok)
	}
	if _, ok := j.At("n").Num(); ok {
		t.Error("null must be unknown, never zero")
	}
	if _, ok := j.At("a.b.9.c").Num(); ok {
		t.Error("out of range must be unknown")
	}
	if m, ok := j.At("a.b.0.c").Micros(0); !ok || m != 12_500_000 {
		t.Errorf("micros: %v %v", m, ok)
	}
	if tt := j.At("t").Time(); tt == nil || tt.Unix() != 1760000000 {
		t.Errorf("epoch seconds: %v", tt)
	}
	if tt := j.At("tm").Time(); tt == nil || tt.Unix() != 1760000000 {
		t.Errorf("epoch millis: %v", tt)
	}
	if tt := j.At("s").Time(); tt == nil || tt.Day() != 15 {
		t.Errorf("iso: %v", tt)
	}
	if _, err := ParseJ([]byte("<html>")); err == nil {
		t.Error("non-JSON must be a shape error")
	}
}
