package sandboxremote

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestTierNetworkNotes: a claimed tier says the box's traffic is the
// vendor's and names the cloud metadata address (denied, not deniable, or
// allowed by the setting); a documented tier says only what live runs saw;
// an empty tier is internet.
func TestTierNetworkNotes(t *testing.T) {
	for _, id := range VendorIDs() {
		v, _ := VendorFor(id)
		for _, allow := range []bool{false, true} {
			for _, tier := range []vocab.Tier{"", vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone} {
				notes := TierNetworkNotes(v, tier, allow)
				eff := tier
				if eff == "" {
					eff = vocab.TierInternet
				}
				m, offered := v.Tiers[eff]
				claimed := offered && m.Mechanism != "" && m.Source != vocab.SourceDocumented
				says := len(notes) > 0 && strings.Contains(notes[0], "cloud metadata address")
				if says != claimed {
					t.Errorf("%s %q allow=%v: metadata sentence %v, want %v (%v)", id, tier, allow, says, claimed, notes)
				}
				if got := len(notes) - btoi(claimed); got != len(v.NetworkNotes) {
					t.Errorf("%s %q: %d vendor notes, want %d", id, tier, got, len(v.NetworkNotes))
				}
			}
		}
	}
	// Every vendor row's internet tier but the org's own gateway is claimed.
	for _, id := range []string{VendorE2B, VendorModal, VendorVercel, VendorDockerSandboxes, VendorInstaBox, VendorDaytona} {
		v, _ := VendorFor(id)
		if n := TierNetworkNotes(v, vocab.TierInternet, false); len(n) == 0 || !strings.Contains(n[0], v.Name+"'s own network") {
			t.Errorf("%s: the internet tier is not disclosed: %v", id, n)
		}
	}
	org, _ := VendorFor(VendorOpenShellOrg)
	for _, n := range TierNetworkNotes(org, vocab.TierInternet, false) {
		if strings.Contains(n, "cloud metadata") {
			t.Errorf("the org row's documented internet tier is called unrefused: %q", n)
		}
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// TestConsentScreenStatesTierAndHooks (H9, H10): the consent screen names
// the tier's mechanism, says on a claimed tier that the metadata address is
// not known to be refused, and states that guard does not gate the box.
func TestConsentScreenStatesTierAndHooks(t *testing.T) {
	v, _ := VendorFor(VendorModal)
	f := baseFacts()
	f.Provider, f.Tier = v.ID, string(vocab.TierInternet)
	s := BuildConsentScreen(v, f, Manifest{Root: "/w/p"}, v.EstimateCost(60))
	text := fmt.Sprint(s.Lines)
	for _, want := range []string{"internet: the default open egress", "cloud metadata address", "takes no rule that would refuse them", HostedHookNote} {
		if !strings.Contains(text, want) {
			t.Errorf("screen lacks %q: %s", want, text)
		}
	}
	f.Tier = string(vocab.TierNone)
	if text := fmt.Sprint(BuildConsentScreen(v, f, Manifest{Root: "/w/p"}, v.EstimateCost(60)).Lines); strings.Contains(text, "cloud metadata") {
		t.Errorf("a blocked tier is called unrefused: %s", text)
	}
}

// TestCheckUploadRootRules: one case per row, plus the pass.
func TestCheckUploadRootRules(t *testing.T) {
	cases := []struct {
		name string
		f    UploadRootFacts
		code string
		says string
	}{
		{"not below /", UploadRootFacts{Root: "/", Home: "/home/u", IsRepository: true}, ErrScopeRoot.Error(), "Pick a project folder"},
		{"relative", UploadRootFacts{Root: "w", IsRepository: true}, ErrScopeRoot.Error(), "Pick a project folder"},
		{"home", UploadRootFacts{Root: "/home/u", Home: "/home/u", IsRepository: true, RepositoryTop: "/home/u"}, ErrScopeHome.Error(), "home folder"},
		{"holds home", UploadRootFacts{Root: "/home", Home: "/home/u", IsRepository: true}, ErrScopeHome.Error(), "home folder"},
		{"not a repository", UploadRootFacts{Root: "/mnt/d/tests", Home: "/home/u"}, ErrScopeNotRepository.Error(), "not one"},
		{"not a repository, uploaded (SBXD-8)", UploadRootFacts{Root: "/mnt/d/tests", Home: "/home/u", UploadNonGit: true}, UploadNonRepositoryNote, "not a git repository: Observer uploads its files"},
		{"inside a repository", UploadRootFacts{Root: "/w/repo/sub", Home: "/home/u", IsRepository: true, RepositoryTop: "/w/repo"}, ErrScopeInsideRepository, "Pick /w/repo instead"},
		{"the repository root", UploadRootFacts{Root: "/w/repo/", Home: "/home/u", IsRepository: true, RepositoryTop: "/w/repo"}, "", ""},
	}
	codes := map[string]bool{}
	for _, c := range cases {
		v := CheckUploadRoot(c.f)
		codes[v.Code] = true
		if v.Code != c.code || v.OK != (c.code == "" || c.code == UploadNonRepositoryNote) || !strings.Contains(v.Message, c.says) {
			t.Errorf("%s: %+v", c.name, v)
		}
		if c.code != "" && (!strings.HasPrefix(v.Technical, c.code+": ") || internalWordRE.MatchString(v.Message)) {
			t.Errorf("%s: technical %q, message %q", c.name, v.Technical, v.Message)
		}
	}
	for _, r := range uploadRootRules {
		if !codes[r.code] {
			t.Errorf("rule %s has no case", r.code)
		}
	}
}

// TestCheckUploadRootAgreesWithPlanManifest: for the rows the two share, the
// dialog's check refuses exactly what the launch's manifest refuses.
func TestCheckUploadRootAgreesWithPlanManifest(t *testing.T) {
	for _, f := range []UploadRootFacts{
		{Root: "/", Home: "/home/u", IsRepository: true},
		{Root: "/home/u", Home: "/home/u", IsRepository: true},
		{Root: "/home", Home: "/home/u", IsRepository: true},
		{Root: "/w/a", Home: "/home/u"},
		{Root: "/w/a", Home: "/home/u", IsRepository: true},
		// SBXD-8: with upload_non_git on, the plain folder is planned
		// through the non-repository listing; the home folder and / stay
		// refused.
		{Root: "/w/a", Home: "/home/u", UploadNonGit: true},
		{Root: "/home/u", Home: "/home/u", UploadNonGit: true},
		{Root: "/", Home: "/home/u", UploadNonGit: true},
	} {
		v := CheckUploadRoot(f)
		_, err := PlanManifest(ManifestInput{Root: f.Root, Home: f.Home, Repository: f.IsRepository, NonRepository: !f.IsRepository && f.UploadNonGit})
		switch {
		case v.OK && err != nil:
			t.Errorf("%+v: the check passes, the manifest refuses %v", f, err)
		case !v.OK && (err == nil || !errors.Is(err, errorFor(v.Code))):
			t.Errorf("%+v: the check refuses %s, the manifest answers %v", f, v.Code, err)
		}
	}
}

func errorFor(code string) error {
	for _, e := range []error{ErrScopeRoot, ErrScopeHome, ErrScopeNotRepository} {
		if e.Error() == code {
			return e
		}
	}
	return errors.New(code)
}
