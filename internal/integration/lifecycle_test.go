package integration_test

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestLifecycleValidIsAClosedVocabulary pins the three-value vocabulary: the
// zero value is active, the two named statuses are valid, and anything else
// — a typo, a future status someone spelled by hand — is not. It is the
// guard behind TestLifecycleVocabularyClosed's registry sweep.
func TestLifecycleValidIsAClosedVocabulary(t *testing.T) {
	for _, tc := range []struct {
		name string
		l    integration.Lifecycle
		want bool
	}{
		{"zero value is active", integration.LifecycleActive, true},
		{"deprecated", integration.LifecycleDeprecated, true},
		{"dead", integration.LifecycleDead, true},
		{"typo", integration.Lifecycle("depricated"), false},
		{"future status", integration.Lifecycle("sunset"), false},
		{"uppercase is not the vocabulary", integration.Lifecycle("DEAD"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.l.Valid(); got != tc.want {
				t.Errorf("Lifecycle(%q).Valid() = %v, want %v", string(tc.l), got, tc.want)
			}
		})
	}
}

// TestLifecycleStringAndAdvertised pins the two renderings every consumer
// depends on: the zero value reads "active" (never an empty cell), and
// Advertised is true for active ALONE — deprecated and dead differ in
// wording and docs treatment, never in dispatch.
func TestLifecycleStringAndAdvertised(t *testing.T) {
	for _, tc := range []struct {
		l          integration.Lifecycle
		wantString string
		wantAdv    bool
	}{
		{integration.LifecycleActive, "active", true},
		{integration.LifecycleDeprecated, "deprecated", false},
		{integration.LifecycleDead, "dead", false},
	} {
		t.Run(tc.wantString, func(t *testing.T) {
			if got := tc.l.String(); got != tc.wantString {
				t.Errorf("String() = %q, want %q", got, tc.wantString)
			}
			if got := tc.l.Advertised(); got != tc.wantAdv {
				t.Errorf("Advertised() = %v, want %v", got, tc.wantAdv)
			}
		})
	}
}

// TestCapabilityAdvertisedReadsTheRowLifecycle pins that the row-level
// helper is exactly the field's predicate — one definition of the policy,
// not two.
func TestCapabilityAdvertisedReadsTheRowLifecycle(t *testing.T) {
	for _, l := range []integration.Lifecycle{
		integration.LifecycleActive,
		integration.LifecycleDeprecated,
		integration.LifecycleDead,
	} {
		c := integration.Capability{Tool: "synthetic", Lifecycle: l}
		if got, want := c.Advertised(), l.Advertised(); got != want {
			t.Errorf("Capability{Lifecycle:%q}.Advertised() = %v, want %v", string(l), got, want)
		}
	}
}

// launchableSyntheticRow builds a Capability that is launchable on EVERY
// terminal dimension the launch surfaces read — a grounded LaunchSpec, an
// attach spec, a binary row, a hook, an MCP target and a proxy route — so a
// test that flips ONLY the lifecycle isolates the lifecycle as the cause of
// a false predicate. It deliberately does not reuse a real registry row: the
// point is that shape alone can never win over lifecycle.
func launchableSyntheticRow(l integration.Lifecycle) integration.Capability {
	return integration.Capability{
		Tool:        "synthetic-tool",
		Lifecycle:   l,
		Proxy:       &integration.ProxyRoute{Kind: integration.RouteEnvSettings, EnvVar: "SYNTHETIC_BASE_URL", Launcher: "observer synthetic"},
		Routability: integration.RouteStatusRoutableNow,
		Hook:        integration.HookSpec{Mechanism: integration.HookClaudeSettings, AutoWired: true},
		MCP:         &integration.MCPTarget{Format: integration.MCPServersJSON, Implemented: true},
		TokenTier:   integration.TokenTier{Best: "proxy"},
		Handoff: integration.HandoffCapability{
			Transcript: integration.TranscriptFull,
			Launch:     &integration.LaunchSpec{Subcommand: "synthetic", Mode: integration.LaunchSeeded},
		},
		Attach: &integration.AttachSpec{Subcommand: "synthetic"},
		Binary: &integration.BinaryResolveSpec{
			Names: integration.BinaryNames{Unix: []string{"synthetic"}, Windows: []string{"synthetic.exe"}},
		},
	}
}

// TestTerminalLaunchableIsShapeAndLifecycle pins the composite predicate the
// terminal launch surfaces dispatch on: a grounded LaunchSpec is necessary
// but NOT sufficient — an unadvertised lifecycle vetoes a fully-shaped row,
// and an advertised lifecycle cannot conjure a launcher for a row that has
// none.
func TestTerminalLaunchableIsShapeAndLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name string
		cap  integration.Capability
		want bool
	}{
		{"full shape + active", launchableSyntheticRow(integration.LifecycleActive), true},
		{"full shape + deprecated", launchableSyntheticRow(integration.LifecycleDeprecated), false},
		{"full shape + dead", launchableSyntheticRow(integration.LifecycleDead), false},
		{"no launch spec + active", integration.Capability{Tool: "file-lane-only"}, false},
		{
			"no launch spec + dead",
			integration.Capability{Tool: "file-lane-only", Lifecycle: integration.LifecycleDead},
			false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := integration.TerminalLaunchable(tc.cap); got != tc.want {
				t.Errorf("TerminalLaunchable() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestLifecycleForResolvesBothKeySpaces pins LifecycleFor's contract: a
// registry tool answers from its row, a rowless product answers from the
// product table, and an unknown id answers ok=false — the honest floor,
// never a fabricated "active".
func TestLifecycleForResolvesBothKeySpaces(t *testing.T) {
	for _, tc := range []struct {
		name      string
		id        string
		wantOK    bool
		wantCycle integration.Lifecycle
		wantNote  string // substring; "" skips the check
	}{
		{"registry tool", "cline", true, integration.LifecycleActive, "roo-code"},
		{"rowless dead retag", "roo-code", true, integration.LifecycleDead, "archived read-only"},
		{"rowless deprecated alias", "windsurf", true, integration.LifecycleDeprecated, "Devin Desktop"},
		{"rowless dead sibling line", "open-interpreter-python", true, integration.LifecycleDead, "interpreter"},
		{"unknown id", "definitely-not-a-product", false, integration.LifecycleActive, ""},
		{"empty id", "", false, integration.LifecycleActive, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, note, ok := integration.LifecycleFor(tc.id)
			if ok != tc.wantOK {
				t.Fatalf("LifecycleFor(%q) ok = %v, want %v", tc.id, ok, tc.wantOK)
			}
			if l != tc.wantCycle {
				t.Errorf("LifecycleFor(%q) lifecycle = %q, want %q", tc.id, string(l), string(tc.wantCycle))
			}
			if !ok {
				if note != "" {
					t.Errorf("LifecycleFor(%q) note = %q, want empty for an unknown id", tc.id, note)
				}
				return
			}
			if tc.wantNote != "" && !strings.Contains(note, tc.wantNote) {
				t.Errorf("LifecycleFor(%q) note does not mention %q: %q", tc.id, tc.wantNote, note)
			}
		})
	}
}

// TestLifecycleForPrefersTheRegistryRow pins the tie-break documented on
// LifecycleFor: no id may be answered by BOTH key spaces, so the two can
// never disagree. Today the product table shares no id with the registry;
// this test is what keeps that true as rows are added.
func TestLifecycleForPrefersTheRegistryRow(t *testing.T) {
	tools := map[string]bool{}
	for _, tool := range integration.Tools() {
		tools[tool] = true
	}
	for _, p := range integration.ProductLifecycles() {
		if tools[p.ID] {
			t.Errorf("product lifecycle %q collides with a registry row — the row wins in LifecycleFor, "+
				"so the product entry would be unreachable; carry the lifecycle on the row instead", p.ID)
		}
	}
}

// TestProductLifecyclesSortedByID pins the accessor's documented ordering,
// which the adapters matrix and the doctor render straight through — an
// unsorted table would make `observer adapters` output non-deterministic
// (Go map iteration).
func TestProductLifecyclesSortedByID(t *testing.T) {
	products := integration.ProductLifecycles()
	if len(products) == 0 {
		t.Fatal("ProductLifecycles() is empty — the shipped table has roo-code / windsurf / open-interpreter-python")
	}
	for i := 1; i < len(products); i++ {
		if products[i-1].ID >= products[i].ID {
			t.Errorf("ProductLifecycles() not sorted by ID: %q before %q", products[i-1].ID, products[i].ID)
		}
	}
}
