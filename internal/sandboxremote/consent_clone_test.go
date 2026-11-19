package sandboxremote

import (
	"strings"
	"testing"
)

// TestConsentScreenBoxClone (lane CLONE): a box-side clone's consent screen
// says nothing is uploaded, names the URL in full, and says what the box
// clones with: no credential on a vendor row (so a private repository
// fails), the organization's own read-only one at most on the org row. An
// upload's screen has no such line.
func TestConsentScreenBoxClone(t *testing.T) {
	const url = "https://github.com/acme/app.git"
	clone := Manifest{Root: "/home/dev/app", ScopeKey: RemoteCloneScopeKey(url)}
	line := func(scr ConsentScreen, label string) string {
		for _, l := range scr.Lines {
			if l.Label == label {
				return l.Value
			}
		}
		return ""
	}
	for _, c := range []struct {
		id   string
		want string
	}{
		{VendorDaytona, "only a public repository clones"},
		{VendorE2B, "no git credential is sent to the box"},
		{VendorOpenShellOrg, "your organization attaches its own read-only credential"},
	} {
		v, _ := VendorFor(c.id)
		scr := BuildConsentScreen(v, ConsentFacts{Provider: v.ID, Custody: "home_relay", ScopeKey: clone.ScopeKey}, clone, Estimate{})
		if got := line(scr, "What is uploaded"); !strings.Contains(got, "nothing from this machine") || !strings.Contains(got, url) {
			t.Errorf("%s: what is uploaded %q", c.id, got)
		}
		if got := line(scr, "Repository access"); !strings.Contains(got, c.want) {
			t.Errorf("%s: repository access %q, want %q", c.id, got, c.want)
		}
	}
	v, _ := VendorFor(VendorDaytona)
	up := BuildConsentScreen(v, ConsentFacts{Provider: v.ID, ScopeKey: "tree:x"}, Manifest{Root: "/home/dev/app", ScopeKey: "tree:x"}, Estimate{})
	if line(up, "Repository access") != "" {
		t.Error("an upload's screen has a repository access line")
	}
}

// TestConsentScreenHomeClone (decision SBXD-5): a clone made on this
// machine says what is uploaded and with whose login, and its scope differs
// from the box-side clone of the same URL, so switching asks again.
func TestConsentScreenHomeClone(t *testing.T) {
	const url = "https://github.com/acme/private.git"
	home := Manifest{Root: "/home/dev/app", ScopeKey: HomeCloneScopeKey(url)}
	if home.ScopeKey == RemoteCloneScopeKey(url) {
		t.Fatal("the home clone and the box clone share a scope")
	}
	if got, ok := HomeCloneURL(home.ScopeKey); !ok || got != url {
		t.Errorf("HomeCloneURL %q %v", got, ok)
	}
	if _, ok := HomeCloneURL(RemoteCloneScopeKey(url)); ok {
		t.Error("a box clone's scope read as a home clone")
	}
	if _, ok := RemoteCloneURL(home.ScopeKey); ok {
		t.Error("a home clone's scope read as a box clone")
	}
	if _, ok := HomeCloneURL("home_clone:v0:" + url); ok {
		t.Error("a scope of another manifest rule version was accepted")
	}
	v, _ := VendorFor(VendorDaytona)
	f := ConsentFacts{Provider: v.ID, Custody: "home_relay", ScopeKey: home.ScopeKey}
	scr := BuildConsentScreen(v, f, home, Estimate{})
	uploaded, access := line(scr, "What is uploaded"), line(scr, "Repository access")
	if !strings.Contains(uploaded, url) || !strings.Contains(uploaded, "cloned on this machine") || !strings.Contains(uploaded, "credential-shaped files are left out") {
		t.Errorf("what is uploaded %q", uploaded)
	}
	if !strings.Contains(access, "no git credential is sent to the box") || !strings.Contains(access, "private repository works") {
		t.Errorf("repository access %q", access)
	}
	if scr.CloneWhere != "home" {
		t.Errorf("screen clone_where %q, want home", scr.CloneWhere)
	}
	box := f
	box.ScopeKey = RemoteCloneScopeKey(url)
	if got := BuildConsentScreen(v, box, Manifest{Root: "/home/dev/app", ScopeKey: box.ScopeKey}, Estimate{}).CloneWhere; got != "box" {
		t.Errorf("box screen clone_where %q", got)
	}
	if got := CheckConsent(&ConsentRecord{Version: ConsentVersion, Facts: box, Digest: ConsentDigest(box)}, f); got != ConsentChangedPrefix+"scope" {
		t.Errorf("a box-clone agreement against the home clone: %s", got)
	}
}

// line is the value of the screen line with this label ("" for none).
func line(scr ConsentScreen, label string) string {
	for _, l := range scr.Lines {
		if l.Label == label {
			return l.Value
		}
	}
	return ""
}
