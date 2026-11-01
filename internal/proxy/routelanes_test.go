package proxy

import (
	"net/http/httptest"
	"testing"
)

// routelanes_test.go: node-local route lanes (lane P1).

func TestSetRouteLanesValidatesAllOrNothing(t *testing.T) {
	p, err := New(Options{Sink: &fakeSink{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.SetRouteLanes(map[string]string{"route-openrouter-ai": "https://openrouter.ai"}); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]map[string]string{
		"no prefix":      {"openrouter": "https://openrouter.ai"},
		"bare prefix":    {"route-": "https://openrouter.ai"},
		"slash in id":    {"route-a/b": "https://openrouter.ai"},
		"plain http":     {"route-x": "http://llm.example.com"},
		"no host":        {"route-x": "https://"},
		"mixed good+bad": {"route-ok": "https://ok.example.com", "nope": "https://x.example.com"},
	} {
		if err := p.SetRouteLanes(bad); err == nil {
			t.Errorf("%s: accepted %v", name, bad)
		}
	}
	// A refused set leaves the previous one serving.
	if !p.ResolvableLanes()["route-openrouter-ai"] || p.ResolvableLanes()["route-ok"] {
		t.Fatalf("lanes after refused sets = %v", p.ResolvableLanes())
	}
	if err := p.SetRouteLanes(nil); err != nil || p.ResolvableLanes()["route-openrouter-ai"] {
		t.Fatalf("clear: %v, %v", err, p.ResolvableLanes())
	}
}

// TestRouteLaneResolvesFirstForItsPrefix: a route lane answers for its own
// id even when [proxy.upstreams] names the same id, and never for any other.
func TestRouteLaneResolvesFirstForItsPrefix(t *testing.T) {
	p, err := New(Options{Sink: &fakeSink{}, Upstreams: map[string]string{"route-openrouter-ai": "https://elsewhere.example.com", "openrouter": "https://openrouter.ai"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.SetRouteLanes(map[string]string{"route-openrouter-ai": "https://openrouter.ai"}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/up/route-openrouter-ai/api/v1/chat/completions", nil)
	res := p.resolveUpstreamPrefix(r)
	if res.up == nil || res.up.Host != "openrouter.ai" || !res.agent || r.URL.Path != "/api/v1/chat/completions" {
		t.Fatalf("route lane: %+v path %q", res, r.URL.Path)
	}
	r = httptest.NewRequest("POST", "/up/route-unknown/v1/chat/completions", nil)
	if res := p.resolveUpstreamPrefix(r); res.unresolved != "route-unknown" {
		t.Fatalf("unknown route lane: %+v, want refused", res)
	}
	r = httptest.NewRequest("POST", "/up/openrouter/api/v1/chat/completions", nil)
	if res := p.resolveUpstreamPrefix(r); res.up == nil || res.up.Host != "openrouter.ai" || res.agent {
		t.Fatalf("hosted lane: %+v", res)
	}
	if !p.ResolvableLanes()["route-openrouter-ai"] {
		t.Fatal("route lane missing from /-/lanes")
	}
}
