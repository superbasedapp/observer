package componentstate

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/config"
)

// stampDistro makes the snapshots of one test resolve as a distro build
// (phase P3, lane MP-REL) without building one.
func stampDistro(t *testing.T, d components.Distro) {
	t.Helper()
	prev := buildDistro
	buildDistro = func() components.Distro { return d }
	t.Cleanup(func() { buildDistro = prev })
}

// TestDistroBuildStartsFromItsDistro pins the P3 default: a stamped binary
// with no [components] block resolves exactly like `distro = "<name>"`, and
// a component its distro lists `out` (absent from the offered compiled set,
// components.Compiled) can never be activated, even by an add.
func TestDistroBuildStartsFromItsDistro(t *testing.T) {
	cases := []struct {
		distro     components.Distro
		active     []string
		inactive   []string
		absentAdds []string
	}{
		{
			distro:     components.DistroMinimal,
			active:     []string{"core", "ui.dashboard", "guard"},
			inactive:   []string{"capture.proxy", "terminals", "adapter.claude-code", "egress.pricing-feed", "obs"},
			absentAdds: []string{"capture.proxy", "terminals"},
		},
		{
			distro:   components.DistroDeveloper,
			active:   []string{"core", "capture.proxy", "terminals", "egress.pricing-feed", "adapter.claude-code"},
			inactive: []string{"obs", "codeintel", "proxy.compression"},
			// D7: obs is compiled into developer (off), so an add
			// activates it; developer compiles out nothing a test can add.
			absentAdds: nil,
		},
		{
			distro:     components.DistroManaged,
			active:     []string{"core", "capture.proxy", "org.client", "org.update"},
			inactive:   []string{"terminals", "egress.pricing-feed", "cloud.intelligence", "demo"},
			absentAdds: []string{"egress.pricing-feed", "demo"},
		},
	}
	for _, tc := range cases {
		t.Run(string(tc.distro), func(t *testing.T) {
			stampDistro(t, tc.distro)
			compiled := components.InDistro(tc.distro)
			s := Resolve(config.ComponentsConfig{}, compiled)
			if s.Base != string(tc.distro) {
				t.Errorf("base = %q, want %q", s.Base, tc.distro)
			}
			if s.Configured || len(s.Issues) != 0 {
				t.Errorf("an unconfigured distro build reports configured=%v issues=%v", s.Configured, s.Issues)
			}
			for _, id := range tc.active {
				if !s.Active(id) {
					t.Errorf("%s is inactive; the %s distro activates it by default", id, tc.distro)
				}
			}
			for _, id := range tc.inactive {
				if s.Active(id) {
					t.Errorf("%s is active; the %s distro does not activate it by default", id, tc.distro)
				}
			}
			// Same set as configuring the distro by name.
			named := Resolve(config.ComponentsConfig{Distro: string(tc.distro)}, compiled)
			for _, d := range s.Result.Decisions {
				if named.Active(d.ID) != s.Active(d.ID) {
					t.Errorf("%s: unconfigured stamped build says active=%v, distro=%q says %v", d.ID, s.Active(d.ID), tc.distro, named.Active(d.ID))
				}
			}
			// An excluded component stays inactive even when added.
			added := Resolve(config.ComponentsConfig{Add: tc.absentAdds}, compiled)
			for _, id := range tc.absentAdds {
				if added.Active(id) {
					t.Errorf("%s activated by add in the %s distro, which excludes it", id, tc.distro)
				}
			}
		})
	}
}

// TestUnstampedBuildKeepsLegacyBase pins that today's release (no stamp)
// is unchanged: every compiled component is active with no block.
func TestUnstampedBuildKeepsLegacyBase(t *testing.T) {
	stampDistro(t, "")
	compiled := components.InDistro(components.DistroFull)
	s := Resolve(config.ComponentsConfig{}, compiled)
	if s.Base != BaseAll {
		t.Fatalf("base = %q, want %q", s.Base, BaseAll)
	}
	for _, id := range compiled {
		if !s.Active(id) {
			t.Errorf("%s inactive in an unstamped build with no [components] block", id)
		}
	}
}

// TestDeveloperDistroObsAddable pins D7: the developer distro compiles obs
// in but leaves it off, and a [components] add turns it on.
func TestDeveloperDistroObsAddable(t *testing.T) {
	stampDistro(t, components.DistroDeveloper)
	compiled := components.InDistro(components.DistroDeveloper)
	if s := Resolve(config.ComponentsConfig{}, compiled); s.Active("obs") {
		t.Fatal("obs is active by default in the developer distro; D7 says off")
	}
	if s := Resolve(config.ComponentsConfig{Add: []string{"obs"}}, compiled); !s.Active("obs") {
		t.Fatalf("obs added in the developer distro stays inactive (issues %v)", s.Issues)
	}
}
