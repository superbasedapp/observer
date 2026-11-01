package secengine

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// TestCheckReleaseSet (WINFIX4 audit finding 6): the engine manifest's
// publish gate refuses a set missing a release platform, accepts all five,
// and exempts only an explicit revocation that revokes something.
func TestCheckReleaseSet(t *testing.T) {
	full := content.Manifest{Kind: content.Engine}
	for i, p := range ReleasePlatforms {
		full.Entries = append(full.Entries, content.Entry{Name: "opengrep_" + p.OS + "_" + p.Arch, OS: p.OS, Arch: p.Arch, SHA256: strings.Repeat(string(rune('a'+i)), 64)})
	}
	one := content.Manifest{Kind: content.Engine, Entries: full.Entries[:1]}
	revokesLinux := full
	revokesLinux.Revoked = []content.Revocation{{SHA256: full.Entries[0].SHA256}}
	revocation := content.Manifest{Kind: content.Engine, Entries: full.Entries[:1], Revoked: []content.Revocation{{SHA256: strings.Repeat("f", 64)}}}
	cases := []struct {
		name       string
		m          content.Manifest
		revocation bool
		ok         bool
	}{
		{"all five", full, false, true},
		{"one platform", one, false, false},
		{"a platform's only pin revoked", revokesLinux, false, false},
		{"an explicit revocation", revocation, true, true},
		{"a revocation that revokes nothing", one, true, false},
		{"another kind", content.Manifest{Kind: content.RulePack, Entries: full.Entries}, false, false},
	}
	for _, c := range cases {
		if err := CheckReleaseSet(c.m, c.revocation); (err == nil) != c.ok {
			t.Errorf("%s: %v, want ok=%v", c.name, err, c.ok)
		}
	}
}
