package delivery

import (
	"strings"
	"testing"
)

func TestParseRemoteURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name            string
		raw             string
		url, host, slug string
		provider        Provider
		ok              bool
	}{
		{"scp github", "git@github.com:Owner/Repo.git", "git@github.com:Owner/Repo.git", "github.com", "Owner/Repo", ProviderGitHub, true},
		{"https github", "https://github.com/o/r.git", "https://github.com/o/r.git", "github.com", "o/r", ProviderGitHub, true},
		{"https no .git, trailing slash", "https://GitHub.com/o/r/", "https://github.com/o/r", "github.com", "o/r", ProviderGitHub, true},
		{"ssh url with port", "ssh://git@ssh.github.com:443/o/r.git", "ssh://git@ssh.github.com:443/o/r.git", "github.com", "o/r", ProviderGitHub, true},
		{"ghes", "https://github.example.com/team/svc.git", "https://github.example.com/team/svc.git", "github.example.com", "team/svc", ProviderGitHub, true},
		{"gitlab subgroup", "https://gitlab.com/group/sub/proj.git", "https://gitlab.com/group/sub/proj.git", "gitlab.com", "group/sub/proj", ProviderGitLab, true},
		{"bitbucket scp", "git@bitbucket.org:ws/repo.git", "git@bitbucket.org:ws/repo.git", "bitbucket.org", "ws/repo", ProviderBitbucket, true},
		{"azure https", "https://org@dev.azure.com/org/proj/_git/repo", "https://dev.azure.com/org/proj/_git/repo", "dev.azure.com", "org/proj/repo", ProviderAzureDevOps, true},
		{"azure ssh", "git@ssh.dev.azure.com:v3/org/proj/repo", "git@ssh.dev.azure.com:v3/org/proj/repo", "dev.azure.com", "org/proj/repo", ProviderAzureDevOps, true},
		{"azure legacy host", "https://org.visualstudio.com/proj/_git/repo", "https://org.visualstudio.com/proj/_git/repo", "org.visualstudio.com", "org/proj/repo", ProviderAzureDevOps, true},
		{"unknown host", "https://git.example.org/a/b.git", "https://git.example.org/a/b.git", "git.example.org", "a/b", ProviderUnknown, true},
		{"non-git ssh user dropped", "ssh://alice@git.example.org/a/b.git", "ssh://git.example.org/a/b.git", "git.example.org", "a/b", ProviderUnknown, true},
		{"local path", "/home/me/repo.git", "", "", "", "", false},
		{"relative path", "../repo", "", "", "", "", false},
		{"file url", "file:///srv/repo.git", "", "", "", "", false},
		{"windows drive", `C:\repos\x`, "", "", "", "", false},
		{"windows drive slash", "c:/repos/x", "", "", "", "", false},
		{"ext transport", "ext::sh -c foo", "", "", "", "", false},
		{"empty", "  ", "", "", "", "", false},
		{"no path", "https://github.com", "", "", "", "", false},
		{"dotdot", "https://github.com/o/../r", "", "", "", "", false},
		{"query", "https://github.com/o/r?x=1", "", "", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			url, host, provider, slug, ok := ParseRemoteURL(tc.raw)
			if ok != tc.ok || url != tc.url || host != tc.host || slug != tc.slug || provider != tc.provider {
				t.Fatalf("ParseRemoteURL(%q) = (%q, %q, %q, %q, %v), want (%q, %q, %q, %q, %v)",
					tc.raw, url, host, provider, slug, ok, tc.url, tc.host, tc.provider, tc.slug, tc.ok)
			}
		})
	}
}

// TestParseRemoteURLStripsCredentials pins plan 7.5: a credential embedded
// in a remote URL never survives the parse, in any position.
func TestParseRemoteURLStripsCredentials(t *testing.T) {
	t.Parallel()
	const token = "ghp_SEEDEDTOKEN0123456789abcdef"
	raws := []string{
		"https://user:" + token + "@github.com/o/r.git",
		"https://" + token + "@github.com/o/r.git",
		"https://x-access-token:" + token + "@github.com/o/r.git",
		"ssh://git:" + token + "@github.com/o/r.git",
		"http://oauth2:" + token + "@gitlab.example.com:8080/g/p.git",
	}
	for _, raw := range raws {
		url, host, _, slug, ok := ParseRemoteURL(raw)
		if !ok {
			t.Fatalf("ParseRemoteURL(%q) not ok", raw)
		}
		for _, v := range []string{url, host, slug} {
			if strings.Contains(v, token) || strings.Contains(v, "@github.com") && !strings.HasPrefix(v, "git@") {
				t.Fatalf("credential survived parse of %q: %q", raw, v)
			}
		}
	}
}

func TestClassifyHost(t *testing.T) {
	t.Parallel()
	cases := map[string]Provider{
		"github.com":            ProviderGitHub,
		"GITHUB.COM":            ProviderGitHub,
		"ssh.github.com":        ProviderGitHub,
		"gitlab.com":            ProviderGitLab,
		"bitbucket.org":         ProviderBitbucket,
		"dev.azure.com":         ProviderAzureDevOps,
		"acme.visualstudio.com": ProviderAzureDevOps,
		"github.acme.io":        ProviderGitHub,
		"code.github.acme.io":   ProviderGitHub,
		"gitlab.acme.io":        ProviderGitLab,
		"bitbucket.acme.io":     ProviderBitbucket,
		"git.acme.io":           ProviderUnknown,
	}
	for host, want := range cases {
		if got := ClassifyHost(host); got != want {
			t.Errorf("ClassifyHost(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestMirrorKeyAndRepoSlugHash(t *testing.T) {
	t.Parallel()
	if k := MirrorKey("https://github.com/o/r.git"); len(k) != 16 {
		t.Fatalf("MirrorKey length = %d, want 16", len(k))
	}
	if MirrorKey("a") == MirrorKey("b") {
		t.Fatal("MirrorKey collided")
	}
	if RepoSlugHash("GitHub.com", "Owner/Repo") != RepoSlugHash("github.com", "owner/repo") {
		t.Fatal("RepoSlugHash must be case-insensitive")
	}
	if h := RepoSlugHash("github.com", "o/r"); len(h) != 64 {
		t.Fatalf("RepoSlugHash length = %d, want 64", len(h))
	}
}
