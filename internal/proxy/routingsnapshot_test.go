package proxy

import (
	"log/slog"
	"testing"
)

// newBareProxy builds a Proxy with the minimum required Options for a
// snapshot-only unit test (no listener, no forwarding).
func newBareProxy(t *testing.T) *Proxy {
	t.Helper()
	p, err := New(Options{
		AnthropicUpstream: "https://api.anthropic.com",
		OpenAIUpstream:    "https://api.openai.com",
		ChatGPTUpstream:   "https://chatgpt.com",
		GeminiUpstream:    "https://generativelanguage.googleapis.com",
		Sink:              &fakeSink{},
		Logger:            slog.New(slog.NewTextHandler(discardWriter{}, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// TestSetRoutingSnapshotAtomic pins Sol S7: SetRoutingSnapshot installs BOTH
// the /up lane table and the org-gateway route as ONE generation, and a
// caller reads a consistent pair — never new lanes with an old mode. It also
// pins the all-or-nothing contract on a bad org-route.
func TestSetRoutingSnapshotAtomic(t *testing.T) {
	p := newBareProxy(t)
	gen0 := p.RoutingGeneration()

	// Install lanes + gateway mode together.
	if err := p.SetRoutingSnapshot(
		map[string]string{"hermes": "https://openrouter.ai/api"}, "hermes",
		"gateway", "https://gw.acme.example:8840", []string{"https://gw2.acme.example:8840"},
	); err != nil {
		t.Fatalf("SetRoutingSnapshot: %v", err)
	}
	mode, primary, fallbacks, gen1 := p.OrgRoute()
	if gen1 == gen0 {
		t.Errorf("generation did not advance: %d", gen1)
	}
	if mode != "gateway" || primary != "https://gw.acme.example:8840" || len(fallbacks) != 1 {
		t.Errorf("org-route half wrong: mode=%q primary=%q fallbacks=%v", mode, primary, fallbacks)
	}
	lanes, autoDefault := p.LaneTable()
	if autoDefault != "hermes" || lanes["hermes"] == "" {
		t.Errorf("lane half wrong: lanes=%v autoDefault=%q", lanes, autoDefault)
	}
	if gen1 != p.RoutingGeneration() {
		t.Errorf("OrgRoute generation %d != RoutingGeneration %d — halves came from different loads", gen1, p.RoutingGeneration())
	}

	// A bad org-route is all-or-nothing: the previous snapshot keeps serving.
	if err := p.SetRoutingSnapshot(map[string]string{"x": "https://ok.example"}, "", "gateway", "://bad", nil); err == nil {
		t.Fatal("expected an error for a malformed gateway primary")
	}
	mode2, primary2, _, gen2 := p.OrgRoute()
	if gen2 != gen1 || mode2 != "gateway" || primary2 != "https://gw.acme.example:8840" {
		t.Errorf("rejected install must not mutate live snapshot: gen=%d mode=%q primary=%q", gen2, mode2, primary2)
	}

	// Explicit node mode clears the org-route in one generation.
	if err := p.SetRoutingSnapshot(map[string]string{"hermes": "https://openrouter.ai/api"}, "", "", "", nil); err != nil {
		t.Fatalf("SetRoutingSnapshot node: %v", err)
	}
	mode3, _, _, gen3 := p.OrgRoute()
	if mode3 != orgModeNode || gen3 == gen1 {
		t.Errorf("node-mode install: mode=%q gen=%d (want node, advanced)", mode3, gen3)
	}
}
