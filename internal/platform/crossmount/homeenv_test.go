package crossmount

import (
	"path/filepath"
	"testing"
)

// TestHomeEnvRuleTables pins the pure rule tables of the R-188 F1
// pinned-home environment rule.
func TestHomeEnvRuleTables(t *testing.T) {
	t.Parallel()
	follows := []struct {
		name      string
		pinned    bool
		isolation string
		want      bool
	}{
		{"not pinned, not isolated", false, "", true},
		{"not pinned, isolated HOME", false, "the home /tmp/x is not the real user home /home/u", false},
		{"not pinned, --no-crossmount", false, "--no-crossmount", false},
		{"pinned, not isolated", true, "", false},
		{"pinned, isolated", true, "OBSERVER_CROSSMOUNT_DISABLE is set", false},
	}
	for _, tc := range follows {
		if got := homeEnvFollowsProcess(tc.pinned, tc.isolation); got != tc.want {
			t.Errorf("%s: homeEnvFollowsProcess(%v, %q) = %v, want %v", tc.name, tc.pinned, tc.isolation, got, tc.want)
		}
	}

	own := filepath.Join(t.TempDir(), "own")
	other := filepath.Join(t.TempDir(), "other")
	named := []struct {
		name          string
		home, ownHome string
		want          bool
	}{
		{"the own home", own, own, false},
		{"the own home, unclean spelling", own + string(filepath.Separator), own, false},
		{"another home", other, own, true},
		{"no home named", "", own, true},
		{"own home unknown", own, "", true},
	}
	for _, tc := range named {
		if got := namedHomePinned(tc.home, tc.ownHome); got != tc.want {
			t.Errorf("%s: namedHomePinned(%q, %q) = %v, want %v", tc.name, tc.home, tc.ownHome, got, tc.want)
		}
	}
}

// TestHomeEnv runs HomeEnv and HomeEnvAt against the live process: home
// pinned or not, an isolation reason or none (a staged layout whose
// RealHome is not HOME, the shape of `HOME=/tmp/x observer init` in a real
// binary), nil or an injected Getenv. Not parallel: it sets HOME /
// USERPROFILE and stages process-wide crossmount state.
func TestHomeEnv(t *testing.T) {
	const probe = "SBO_R188_HOMEENV_PROBE"
	injected := func(k string) string {
		if k == probe {
			return "injected"
		}
		return ""
	}
	cases := []struct {
		name     string
		at       bool   // HomeEnvAt instead of HomeEnv
		home     string // "", "own" or "other"
		isolated bool
		getenv   func(string) string
		want     string
	}{
		{name: "HomeEnv nil, not pinned, not isolated: process environment", want: "process"},
		{name: "HomeEnv nil, pinned to another home: no variable", home: "other", want: ""},
		{name: "HomeEnv nil, pinned to the own home: no variable", home: "own", want: ""},
		{name: "HomeEnv nil, not pinned, isolated: no variable", isolated: true, want: ""},
		{name: "HomeEnv given, not pinned, not isolated: the given lookup", getenv: injected, want: "injected"},
		{name: "HomeEnv given, pinned: the given lookup", home: "other", getenv: injected, want: "injected"},
		{name: "HomeEnv given, isolated: the given lookup", isolated: true, getenv: injected, want: "injected"},
		{name: "HomeEnvAt nil, the own home, not isolated: process environment", at: true, home: "own", want: "process"},
		{name: "HomeEnvAt nil, another home: no variable", at: true, home: "other", want: ""},
		{name: "HomeEnvAt nil, the own home, isolated: no variable", at: true, home: "own", isolated: true, want: ""},
		{name: "HomeEnvAt given, another home: the given lookup", at: true, home: "other", getenv: injected, want: "injected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ownHome := t.TempDir()
			t.Setenv("HOME", ownHome)
			t.Setenv("USERPROFILE", ownHome)
			t.Setenv(probe, "process")
			if tc.isolated {
				StageForeignLayoutForTest(t, ForeignLayoutForTest{Root: t.TempDir(), RealHome: t.TempDir()})
				if IsolationReason() == "" {
					t.Fatal("the staged layout did not isolate the process home; the case proves nothing")
				}
			} else if r := IsolationReason(); r != "" {
				t.Fatalf("unexpected isolation reason %q", r)
			}
			home := ""
			switch tc.home {
			case "own":
				home = ownHome
			case "other":
				home = t.TempDir()
			}
			fn := HomeEnv
			if tc.at {
				fn = HomeEnvAt
			}
			if got := fn(home, tc.getenv)(probe); got != tc.want {
				t.Errorf("(%q, ...)(%s) = %q, want %q", home, probe, got, tc.want)
			}
		})
	}
}
