package delivery

import "testing"

// TestLinkServes pins the one link-to-remote predicate, one case per rule.
func TestLinkServes(t *testing.T) {
	t.Parallel()
	gh := ProviderLink{Provider: ProviderGitHub, Host: "github.com"}
	remote := func(p Provider, host, slug string) Remote { return Remote{Provider: p, Host: host, RepoSlug: slug} }
	for _, tc := range []struct {
		name string
		l    ProviderLink
		r    Remote
		want bool
	}{
		{"github remote on the link host", gh, remote(ProviderGitHub, "github.com", "acme/widget"), true},
		{"host compared case-insensitively", gh, remote(ProviderGitHub, "GitHub.com", "acme/widget"), true},
		{"enterprise host is another link", gh, remote(ProviderGitHub, "git.acme.example", "acme/widget"), false},
		{"gitlab remote", gh, remote(ProviderGitLab, "github.com", "acme/widget"), false},
		{"non-github link", ProviderLink{Provider: ProviderGitLab, Host: "github.com"}, remote(ProviderGitHub, "github.com", "acme/widget"), false},
		{"empty slug", gh, remote(ProviderGitHub, "github.com", ""), false},
		{"three-part slug", gh, remote(ProviderGitHub, "github.com", "acme/group/widget"), false},
		{"dot-dot segment", gh, remote(ProviderGitHub, "github.com", "acme/.."), false},
		{"space in slug", gh, remote(ProviderGitHub, "github.com", "acme/wid get"), false},
	} {
		if got := LinkServes(tc.l, tc.r); got != tc.want {
			t.Errorf("%s: LinkServes = %v, want %v", tc.name, got, tc.want)
		}
	}
}
