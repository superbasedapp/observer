package workspace

import (
	"slices"
	"strings"
	"testing"
)

// TestDecideCloneWhere: one case per row of cloneWhereRules, plus the
// cases the lane's brief names (public -> box, a refused listing -> home,
// tier none + auto -> home).
func TestDecideCloneWhere(t *testing.T) {
	cases := []struct {
		name   string
		in     CloneWhereInput
		where  CloneWhere
		reason string
		anon   bool
	}{
		{"row clones in the box, any setting", CloneWhereInput{Setting: CloneWhereHome, BoxOK: true, HomeOK: true}, CloneWhereBox, ReasonRowClonesInBox, false},
		{"set box, even when the box cannot", CloneWhereInput{Setting: CloneWhereBox, HomeCapable: true, HomeOK: true}, CloneWhereBox, ReasonSetBox, false},
		{"set home, even for a public address", CloneWhereInput{Setting: CloneWhereHome, HomeCapable: true, BoxOK: true, HomeOK: true, Anon: AnonPublic}, CloneWhereHome, ReasonSetHome, false},
		{"auto, tier none (the box cannot clone) goes home", CloneWhereInput{Setting: CloneWhereAuto, HomeCapable: true, HomeOK: true}, CloneWhereHome, ReasonBoxCannotClone, false},
		{"auto, the listing is owed", CloneWhereInput{Setting: CloneWhereAuto, HomeCapable: true, BoxOK: true, HomeOK: true}, "", ReasonListingRequired, true},
		{"auto, public goes to the box", CloneWhereInput{Setting: CloneWhereAuto, HomeCapable: true, BoxOK: true, HomeOK: true, Anon: AnonPublic}, CloneWhereBox, ReasonPublic, false},
		{"auto, a refused listing goes home", CloneWhereInput{Setting: CloneWhereAuto, HomeCapable: true, BoxOK: true, HomeOK: true, Anon: AnonRefused}, CloneWhereHome, ReasonNeedsLogin, false},
		{"an unknown setting reads as auto", CloneWhereInput{Setting: "elsewhere", HomeCapable: true, BoxOK: true, Anon: AnonPublic}, CloneWhereBox, ReasonPublic, false},
	}
	for _, c := range cases {
		got := DecideCloneWhere(c.in)
		if got.Where != c.where || got.Reason != c.reason || got.NeedsAnon != c.anon {
			t.Errorf("%s: %+v, want %s %s %v", c.name, got, c.where, c.reason, c.anon)
		}
	}
	if len(cloneWhereRules) != 7 {
		t.Errorf("the table has %d rows; give a new row its case here", len(cloneWhereRules))
	}
	for _, r := range cloneWhereRules {
		if CloneWhereReasonText[r.out.Reason] == "" || strings.Contains(CloneWhereReasonText[r.out.Reason], "_") {
			t.Errorf("row %q: reason %q has no plain words", r.name, r.out.Reason)
		}
	}
}

func TestParseCloneWhere(t *testing.T) {
	for in, want := range map[string]CloneWhere{"": CloneWhereAuto, "auto": CloneWhereAuto, "box": CloneWhereBox, "home": CloneWhereHome, "\tbox": CloneWhereBox} {
		if got, err := ParseCloneWhere(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"Box", "local", "remote", "both"} {
		if _, err := ParseCloneWhere(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	if !slices.Equal(CloneWhereValues, []CloneWhere{"auto", "box", "home"}) {
		t.Errorf("values %v", CloneWhereValues)
	}
}

// TestAnonymousListArgv: the listing names no credential source, puts "--"
// before the address, and lists only a credential-free https address.
func TestAnonymousListArgv(t *testing.T) {
	argv, err := AnonymousListArgv("https://github.com/acme/app.git")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(argv, " ")
	for _, want := range []string{"credential.helper=", "core.askPass=", "ls-remote -- https://github.com/acme/app.git HEAD"} {
		if !strings.Contains(joined, want) {
			t.Errorf("argv %q lacks %q", joined, want)
		}
	}
	for _, bad := range []string{"", "git@github.com:acme/app.git", "ssh://github.com/acme/app.git", "https://x:t@github.com/a.git", "https://github.com/a.git?t=1", "https://github.com/a b.git", "http://github.com/a.git"} {
		if _, err := AnonymousListArgv(bad); err == nil {
			t.Errorf("%q listed", bad)
		}
	}
	env := AnonymousListEnv("/tmp/empty")
	if env["HOME"] != "/tmp/empty" || env["XDG_CONFIG_HOME"] != "/tmp/empty" || env["GIT_TERMINAL_PROMPT"] != "0" || env["GIT_CONFIG_NOSYSTEM"] != "1" {
		t.Errorf("env %v", env)
	}
}
