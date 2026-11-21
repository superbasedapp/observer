package openshellorg

import "testing"

// TestMintRefusesAMissingGitProfile (FX3 item 4, live finding F-L6P4-2): a
// private clone whose git_providers row names a provider profile the last
// sync did not find on the gateway is refused at the mint with a reason that
// names no profile; an unknown listing refuses nothing, and a repository with
// no row (the unauthenticated control-repository path) still clones.
func TestMintRefusesAMissingGitProfile(t *testing.T) {
	rows := []struct {
		name    string
		known   bool
		listed  []string
		url     string
		want    Reason
		private bool
	}{
		{name: "profile missing", known: true, listed: []string{"github", "claude-code"}, url: "https://git.example.com/org/repo", want: ReasonGitProfileMissing},
		{name: "profile present", known: true, listed: []string{"p"}, url: "https://git.example.com/org/repo", want: ReasonNone, private: true},
		{name: "listing unknown", known: false, url: "https://git.example.com/org/repo", want: ReasonNone, private: true},
		{name: "no row: unauthenticated clone", known: true, listed: nil, url: "https://git.example.com/org/public", want: ReasonNone},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			f := goodFacts()
			f.Request.Tier, f.Request.Source = TierInternet, SourceCloneRemote
			f.Request.CloneURL = r.url
			f.Sync.ProfilesKnown, f.Sync.ProviderProfiles = r.known, r.listed
			d := DecideMint(f)
			if d.Reason != r.want {
				t.Fatalf("reason %q, want %q (%s)", d.Reason, r.want, d.Rule)
			}
			if r.want == ReasonNone && (d.Inputs.GitProvider != nil) != r.private {
				t.Fatalf("git provider %+v", d.Inputs.GitProvider)
			}
		})
	}
	if !ReasonGitProfileMissing.Valid() {
		t.Error("the reason is not in the closed set")
	}
}
