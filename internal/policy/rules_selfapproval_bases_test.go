package policy

import (
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
)

// TestSecurityKeepingBasesPerBuild (plans decision log P-045): with the
// binary's own list injected, a base counts as dropping security only when
// it would switch off a security component, or one the tree requires, that
// THIS build compiles in and runs. A developer build (no
// security.scan.scalibr compiled in) lets `components select developer`
// pass; a full build, which compiles and runs that scanner, denies it.
// minimal, managed and an unknown name stay denied in both. Not parallel:
// it swaps the process-wide list (and restores the fallback).
func TestSecurityKeepingBasesPerBuild(t *testing.T) {
	t.Cleanup(func() { SetSecurityKeepingBases(nil) })
	var watched []components.Component
	for _, c := range components.All() {
		if isSecurityComponent(c.ID) || slices.Contains(securityTreeRequires, c.ID) {
			watched = append(watched, c)
		}
	}
	// keepingIn is the list a binary stamped as build computes: the
	// watched components on in its own distro run today, and a base keeps
	// when each of them is on in it too.
	keepingIn := func(build components.Distro) []string {
		var out []string
		for _, d := range components.Distros() {
			keeps := true
			for _, c := range watched {
				if c.Distros[build] == components.DefaultOn && c.Distros[d] != components.DefaultOn {
					keeps = false
				}
			}
			if keeps {
				out = append(out, string(d))
			}
		}
		return out
	}
	deny := func(t *testing.T, line string, want bool) {
		t.Helper()
		e, err := New(Config{Mode: ModeEnforce, Home: "/home/u"})
		if err != nil {
			t.Fatal(err)
		}
		v := e.Evaluate(Event{Kind: KindShellExec, Target: line, Cwd: "/home/u/p", ProjectRoot: "/home/u/p"})
		if got := v.RuleID == "R-165" && v.Decision == DecisionDeny; got != want {
			t.Errorf("%q: denied by R-165 = %v (%s/%s), want %v", line, got, v.RuleID, v.Decision, want)
		}
	}
	for _, c := range []struct {
		build     components.Distro
		developer bool
	}{
		{components.DistroDeveloper, false},
		{components.DistroFull, true},
	} {
		t.Run(string(c.build)+" build", func(t *testing.T) {
			list := keepingIn(c.build)
			SetSecurityKeepingBases(func() []string { return list })
			deny(t, "observer components select developer --yes", c.developer)
			deny(t, `curl -X POST http://127.0.0.1:8821/api/components/apply -d '{"change":{"set_base":"developer"},"fingerprint":"f"}'`, c.developer)
			for _, base := range []string{"minimal", "managed", "Managed", "minmal"} {
				deny(t, "observer components select "+base+" --yes", true)
			}
			deny(t, `curl -X POST http://127.0.0.1:8821/api/components/apply -d '{"change":{"set_base":"managed"},"fingerprint":"f"}'`, true)
			deny(t, "observer components select all --yes", false)
			deny(t, "observer components select developer", false) // a preview lowers nothing
		})
	}
}
