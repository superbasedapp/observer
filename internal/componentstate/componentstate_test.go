package componentstate

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// fullCompiled is every node row: a plain `go build`.
func fullCompiled() []string {
	var out []string
	for _, c := range components.ForBinary(components.BinaryNode) {
		out = append(out, c.ID)
	}
	return out
}

func without(ids []string, drop ...string) []string {
	d := toSet(drop)
	var out []string
	for _, id := range ids {
		if !d[id] {
			out = append(out, id)
		}
	}
	return out
}

// TestLegacyEveryCompiledComponentActive is the byte-identical guarantee: an
// install with no [components] block keeps every compiled component active
// and reports nothing.
func TestLegacyEveryCompiledComponentActive(t *testing.T) {
	s := Resolve(config.ComponentsConfig{}, fullCompiled())
	if s.Configured {
		t.Fatal("zero block reported as configured")
	}
	if len(s.Issues) != 0 {
		t.Fatalf("legacy snapshot reports issues: %v", s.Issues)
	}
	for _, id := range fullCompiled() {
		if !s.Active(id) {
			d, _ := s.Decision(id)
			t.Errorf("legacy: %s not active (%s/%s %s)", id, d.State, d.Reason, d.Because)
		}
	}
	if got := len(s.Inactive()); got != 0 {
		t.Fatalf("legacy: %d inactive components, want 0: %v", got, s.Inactive())
	}
}

func TestResolveTable(t *testing.T) {
	full := fullCompiled()
	cases := []struct {
		name       string
		sec        config.ComponentsConfig
		compiled   []string
		active     []string
		inactive   []string
		issueParts []string
	}{
		{
			name:     "no_obs build keeps the rest active",
			compiled: without(full, "obs"),
			active:   []string{"core", "codeintel", "terminals", "adapter.claude-code"},
			inactive: []string{"obs"},
		},
		{
			name:     "minimal base leaves off cells inactive",
			sec:      config.ComponentsConfig{Distro: "minimal"},
			compiled: full,
			active:   []string{"core", "ui.dashboard", "guard", "integration.hooks"},
			inactive: []string{"codeintel", "terminals", "capture.proxy", "adapter.claude-code"},
		},
		{
			name:     "developer base plus add",
			sec:      config.ComponentsConfig{Distro: "developer", Add: []string{"codeintel"}},
			compiled: full,
			active:   []string{"codeintel", "terminals", "capture.proxy", "org.client"},
			inactive: []string{"processobs", "remote"},
		},
		{
			name:     "remove on the all base",
			sec:      config.ComponentsConfig{Remove: []string{"adapter.zed", "remote"}},
			compiled: full,
			active:   []string{"adapter.claude-code", "codeintel", "terminals"},
			inactive: []string{"adapter.zed", "remote"},
		},
		{
			name:       "core cannot be removed",
			sec:        config.ComponentsConfig{Remove: []string{"core"}},
			compiled:   full,
			active:     []string{"core"},
			issueParts: []string{"core and cannot be removed"},
		},
		{
			name:       "unknown ids are reported and ignored",
			sec:        config.ComponentsConfig{Add: []string{"nope"}, Remove: []string{"also-nope"}},
			compiled:   full,
			active:     []string{"codeintel"},
			issueParts: []string{`"nope" is not a component`, `"also-nope" is not a component`},
		},
		{
			name:       "server ids are refused",
			sec:        config.ComponentsConfig{Add: []string{"org.saml"}},
			compiled:   full,
			issueParts: []string{"org server component"},
		},
		{
			name:       "unknown distro falls back to everything",
			sec:        config.ComponentsConfig{Distro: "tiny"},
			compiled:   full,
			active:     []string{"codeintel", "adapter.zed"},
			issueParts: []string{`distro "tiny" is not a prebuilt distro`},
		},
		{
			name:       "removing a component another one requires keeps it, reported",
			sec:        config.ComponentsConfig{Remove: []string{"terminals"}},
			compiled:   full,
			active:     []string{"terminals", "benchmark"},
			issueParts: []string{`"terminals" stays active because benchmark requires it`},
		},
		{
			name:       "a removal a selection overrides is reported",
			sec:        config.ComponentsConfig{Remove: []string{"adapter.cline"}},
			compiled:   full,
			active:     []string{"adapter.cline", "adapter.kilo-code"},
			issueParts: []string{`"adapter.cline" stays active because`},
		},
		{
			name:       "an added component missing from the build is an error",
			sec:        config.ComponentsConfig{Distro: "minimal", Add: []string{"codeintel"}},
			compiled:   without(full, "codeintel"),
			inactive:   []string{"codeintel"},
			issueParts: []string{"codeintel: not in this build"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := Resolve(tc.sec, tc.compiled)
			for _, id := range tc.active {
				if !s.Active(id) {
					d, _ := s.Decision(id)
					t.Errorf("%s: want active, got %s/%s", id, d.State, d.Reason)
				}
			}
			for _, id := range tc.inactive {
				if s.Active(id) {
					t.Errorf("%s: want inactive, got active", id)
				}
			}
			joined := strings.Join(s.Issues, "\n")
			for _, part := range tc.issueParts {
				if !strings.Contains(joined, part) {
					t.Errorf("issues lack %q:\n%s", part, joined)
				}
			}
			if len(tc.issueParts) == 0 && tc.sec.Configured() && len(s.Issues) != 0 && tc.name != "an added component missing from the build is an error" {
				t.Errorf("unexpected issues: %v", s.Issues)
			}
		})
	}
}

func TestActiveFailsOpenForUnknownIDs(t *testing.T) {
	s := Resolve(config.ComponentsConfig{Distro: "minimal"}, fullCompiled())
	if !s.Active("not.a.component") {
		t.Fatal("an unknown id must fail open (true)")
	}
	if !s.AnyActive() {
		t.Fatal("AnyActive with no ids is core: true")
	}
}

func TestAdapterActiveStripsWindowsSuffix(t *testing.T) {
	s := Resolve(config.ComponentsConfig{Remove: []string{"adapter.claude-code"}}, fullCompiled())
	if s.AdapterActive("claude-code-windows") || s.AdapterActive("claude-code") {
		t.Fatal("claude-code removed but its targets report active")
	}
	if !s.AdapterActive("codex-windows") {
		t.Fatal("codex is active")
	}
}

// TestAdapterActiveResolvesXcodeTargets (FU-145): every Xcode agent-home
// hook target answers for its base tool's adapter, the base hook's own
// table deciding the base (the "-xcode" suffix is pinned to it here).
func TestAdapterActiveResolvesXcodeTargets(t *testing.T) {
	s := Resolve(config.ComponentsConfig{Remove: []string{"adapter.claude-code"}}, fullCompiled())
	found := 0
	for _, tool := range integration.Tools() {
		for _, target := range hook.XcodeTargetsFor(tool) {
			found++
			if base, ok := hook.XcodeTargetBase(target); !ok || base != tool || strings.TrimSuffix(target, "-xcode") != tool {
				t.Errorf("%s: base %q, %v; the -xcode suffix no longer names the base %s", target, base, ok, tool)
			}
			if got, want := s.AdapterActive(target), s.AdapterActive(tool); got != want {
				t.Errorf("AdapterActive(%s) = %v, its base %s = %v", target, got, tool, want)
			}
		}
	}
	if found == 0 {
		t.Fatal("no Xcode agent-home target found")
	}
	if s.AdapterActive("claude-code-xcode") {
		t.Error("claude-code removed but claude-code-xcode reports active")
	}
}

// TestAdapterActiveResolvesWSLTwins (FU-197): every Windows to WSL "-wsl"
// twin answers for its base tool's adapter (the suffix is pinned to the
// twin table here), so a removed adapter keeps its twin off.
func TestAdapterActiveResolvesWSLTwins(t *testing.T) {
	s := Resolve(config.ComponentsConfig{Remove: []string{"adapter.cursor"}}, fullCompiled())
	found := 0
	for _, tool := range integration.Tools() {
		for _, target := range hook.WSLTwinsFor(tool) {
			found++
			if base, ok := hook.WSLTwinBase(target); !ok || base != tool || strings.TrimSuffix(target, "-wsl") != tool {
				t.Errorf("%s: base %q, %v; the -wsl suffix no longer names the base %s", target, base, ok, tool)
			}
			if got, want := s.AdapterActive(target), s.AdapterActive(tool); got != want {
				t.Errorf("AdapterActive(%s) = %v, its base %s = %v", target, got, tool, want)
			}
		}
	}
	if found == 0 {
		t.Fatal("no WSL twin found")
	}
	if s.AdapterActive("cursor-wsl") {
		t.Error("cursor removed but cursor-wsl reports active")
	}
}

func TestSectionRoundTrip(t *testing.T) {
	in := config.ComponentsConfig{Distro: "developer", Add: []string{"codeintel", "codeintel"}, Remove: []string{"terminals"}}
	s := Resolve(in, fullCompiled())
	got := s.Section()
	if got.Distro != "developer" || len(got.Add) != 1 || got.Add[0] != "codeintel" || len(got.Remove) != 1 {
		t.Fatalf("section round trip: %+v", got)
	}
	if Resolve(config.ComponentsConfig{}, fullCompiled()).Section().Configured() {
		t.Fatal("legacy section renders as configured")
	}
}

func TestViewCountsAndRefusal(t *testing.T) {
	s := Resolve(config.ComponentsConfig{Remove: []string{"codeintel"}}, without(fullCompiled(), "obs"))
	v := s.View()
	if !v.Configured || v.Base != BaseAll {
		t.Fatalf("view header: %+v", v)
	}
	if v.CompiledCount != len(fullCompiled())-1 {
		t.Fatalf("compiled count %d", v.CompiledCount)
	}
	var codeintel, obs RowView
	for _, r := range v.Components {
		switch r.ID {
		case "codeintel":
			codeintel = r
		case "obs":
			obs = r
		}
	}
	if codeintel.State != components.StateAvailable || !codeintel.Compiled || codeintel.Selected {
		t.Fatalf("codeintel row: %+v", codeintel)
	}
	if obs.State != components.StateAbsent || obs.Compiled {
		t.Fatalf("obs row: %+v", obs)
	}
	if line := s.RefusalLine("codeintel"); !strings.Contains(line, "installed but inactive") || !strings.Contains(line, "observer components add codeintel") {
		t.Fatalf("refusal line: %s", line)
	}
	if line := s.RefusalLine("obs"); !strings.Contains(line, "not in this build") {
		t.Fatalf("absent refusal line: %s", line)
	}
	body := s.NotActive("codeintel")
	if body.Error != NotActiveError || body.State != components.StateAvailable {
		t.Fatalf("not-active body: %+v", body)
	}
	for _, line := range []string{s.RefusalLine("codeintel"), s.RefusalLine("obs"), RestartNote} {
		if strings.ContainsAny(line, "\u2013\u2014") {
			t.Fatalf("dash in copy: %s", line)
		}
	}
}

// TestManagedNodeIgnoresLocalNarrowing is ledger MODPKG-7 / ruling D-434
// (T-677): on an org-managed node the local block's distro and remove
// entries are ignored and reported, add entries still count, and an
// individual node is unchanged.
func TestManagedNodeIgnoresLocalNarrowing(t *testing.T) {
	full := fullCompiled()
	block := config.ComponentsConfig{Distro: "minimal", Remove: []string{"org.client", "guard"}, Add: []string{"codeintel"}}
	managed := Governed{OrgManaged: true, OrgName: "Acme", Source: "legacy_pinned"}

	t.Run("individual node: the block narrows", func(t *testing.T) {
		s := ResolveGoverned(block, full, Governed{})
		if s.Active("org.client") || s.Active("guard") {
			t.Fatalf("individual node kept removed components active")
		}
		if len(s.Ignored) != 0 || s.View().OrgManaged {
			t.Fatalf("individual node reported managed state: %v", s.Ignored)
		}
	})
	t.Run("managed node: distro and remove ignored, add kept", func(t *testing.T) {
		s := ResolveGoverned(block, full, managed)
		for _, id := range []string{"org.client", "guard", "integration.hooks", "codeintel"} {
			if !s.Active(id) {
				d, _ := s.Decision(id)
				t.Errorf("%s narrowed on a managed node: %+v", id, d)
			}
		}
		if s.Base != BaseAll {
			t.Errorf("base = %s, want all (the distro is ignored)", s.Base)
		}
		if len(s.Ignored) != 2 {
			t.Errorf("ignored = %v, want the distro and the remove list", s.Ignored)
		}
		var named bool
		for _, is := range s.Issues {
			if strings.Contains(is, "managed by Acme") {
				named = true
			}
			if strings.ContainsAny(is, string([]rune{0x2013, 0x2014})) {
				t.Errorf("dash in copy: %s", is)
			}
		}
		if !named {
			t.Errorf("issues do not name the org: %v", s.Issues)
		}
		v := s.View()
		if !v.OrgManaged || v.OrgName != "Acme" || v.GovernanceSource != "legacy_pinned" {
			t.Errorf("view = managed %v org %q source %q", v.OrgManaged, v.OrgName, v.GovernanceSource)
		}
	})
	t.Run("zero governance is Resolve", func(t *testing.T) {
		a, b := Resolve(block, full), ResolveGoverned(block, full, Governed{})
		if strings.Join(a.ActiveIDs(), ",") != strings.Join(b.ActiveIDs(), ",") || strings.Join(a.Issues, "|") != strings.Join(b.Issues, "|") {
			t.Fatal("ResolveGoverned with zero governance differs from Resolve")
		}
	})
}

// TestPackageIsPure pins CLAUDE.md module rule 1: no SQL, HTTP, fsnotify or
// os/exec in this package.
func TestPackageIsPure(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"database/sql", "net/http", "github.com/fsnotify/fsnotify", "os/exec"},
		Reason:    "internal/componentstate must stay pure",
	})
}
