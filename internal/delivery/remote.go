package delivery

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// remote.go parses a git remote URL into the parts the delivery arc stores
// (plan 2.1 "Remote identity", 7.5 "Remote URLs with embedded credentials").
//
// USERINFO IS STRIPPED BEFORE ANYTHING ELSE LOOKS AT THE URL. A remote such
// as https://user:ghp_token@github.com/o/r.git carries a credential; the
// returned url never does. The one exception is the literal ssh user "git"
// (git@github.com:o/r.git), which every hosting service requires for ssh
// and which is not a secret: dropping it would make an Observer mirror clone
// of an ssh remote log in as the local user name. Pinned by
// TestParseRemoteURLStripsCredentials with a seeded token.

// remoteSchemes are the URL schemes a remote may use. Anything else (file://,
// ext::, a local path) is not a code host and parses as ok=false.
var remoteSchemes = map[string]bool{
	"https":   true,
	"http":    true,
	"ssh":     true,
	"git":     true,
	"git+ssh": true,
	"ssh+git": true,
}

// sshSchemes are the schemes whose "git" user name is kept.
var sshSchemes = map[string]bool{"ssh": true, "git+ssh": true, "ssh+git": true}

// hostAliases folds a provider's alternate ssh hosts onto the host its API
// lives under, so github.com over ssh-on-443 classifies and matches as
// github.com.
var hostAliases = map[string]string{
	"ssh.github.com":          "github.com",
	"www.github.com":          "github.com",
	"altssh.gitlab.com":       "gitlab.com",
	"altssh.bitbucket.org":    "bitbucket.org",
	"ssh.dev.azure.com":       "dev.azure.com",
	"vs-ssh.visualstudio.com": "dev.azure.com",
}

// providerRule is one row of providerRules: the first row whose match
// accepts the (already lowercased, alias-folded) host decides the provider.
type providerRule struct {
	provider Provider
	match    func(host string) bool
}

// providerRules is the ordered host classification table. Exact public hosts
// first, then the self-hosted naming conventions (GitHub Enterprise Server
// and self-managed GitLab / Bitbucket hosts are usually named after the
// product), then unknown.
var providerRules = []providerRule{
	{ProviderGitHub, func(h string) bool { return h == "github.com" }},
	{ProviderGitLab, func(h string) bool { return h == "gitlab.com" }},
	{ProviderBitbucket, func(h string) bool { return h == "bitbucket.org" }},
	{ProviderAzureDevOps, func(h string) bool { return h == "dev.azure.com" || strings.HasSuffix(h, ".visualstudio.com") }},
	{ProviderGitHub, func(h string) bool { return strings.HasPrefix(h, "github.") || strings.Contains(h, ".github.") }},
	{ProviderGitLab, func(h string) bool { return strings.HasPrefix(h, "gitlab.") || strings.Contains(h, ".gitlab.") }},
	{ProviderBitbucket, func(h string) bool { return strings.HasPrefix(h, "bitbucket.") }},
	{ProviderUnknown, func(string) bool { return true }},
}

// ClassifyHost returns the provider a (lowercase) host belongs to, walking
// providerRules top-down.
func ClassifyHost(host string) Provider {
	h := strings.ToLower(host)
	if a, ok := hostAliases[h]; ok {
		h = a
	}
	for _, r := range providerRules {
		if r.match(h) {
			return r.provider
		}
	}
	return ProviderUnknown
}

// ParseRemoteURL parses one git remote URL. It handles https://, http://,
// ssh://, git:// and scp-style (git@github.com:owner/repo.git) remotes, a
// trailing ".git" and host case. It returns:
//
//   - url: the normalised remote, userinfo stripped (the ssh user "git" kept,
//     see the file comment), host lowercased, path unchanged;
//   - host: the lowercase host without a port, alternate ssh hosts folded
//     onto the API host (ssh.github.com is github.com);
//   - provider: the closed provider id from ClassifyHost;
//   - slug: "owner/repo" (GitLab groups keep their full path; Azure DevOps
//     is "org/project/repo"), without ".git";
//   - ok: false for anything that is not a remote code host (a local path,
//     file://, ext::, an empty or malformed value). Every other return is
//     zero when ok is false.
func ParseRemoteURL(raw string) (url, host string, provider Provider, slug string, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.ContainsAny(s, " \t\r\n?#\\") {
		return "", "", "", "", false
	}
	var scheme, authority, path string
	scp := false
	if i := strings.Index(s, "://"); i >= 0 {
		scheme = strings.ToLower(s[:i])
		rest := s[i+3:]
		j := strings.IndexByte(rest, '/')
		if j < 0 {
			return "", "", "", "", false
		}
		authority, path = rest[:j], rest[j+1:]
	} else {
		colon := strings.IndexByte(s, ':')
		slash := strings.IndexByte(s, '/')
		if colon <= 0 || (slash >= 0 && slash < colon) {
			return "", "", "", "", false
		}
		authority, path = s[:colon], s[colon+1:]
		scheme, scp = "ssh", true
	}
	if !remoteSchemes[scheme] {
		return "", "", "", "", false
	}

	user := ""
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		user, authority = authority[:at], authority[at+1:]
	}
	hostPort := strings.ToLower(authority)
	h, port, good := splitHostPort(hostPort)
	if !good || (scp && len(h) == 1) { // "c:/path" is a Windows drive, not a host
		return "", "", "", "", false
	}
	path = strings.Trim(path, "/")
	slugPath := strings.TrimSuffix(path, ".git")
	if slugPath == "" || strings.Contains(slugPath, "..") {
		return "", "", "", "", false
	}

	host = h
	if a, isAlias := hostAliases[host]; isAlias {
		host = a
	}
	provider = ClassifyHost(host)
	slug = slugFor(provider, h, slugPath)
	if slug == "" {
		return "", "", "", "", false
	}

	keepUser := ""
	if user == "git" && (scp || sshSchemes[scheme]) {
		keepUser = "git@"
	}
	if scp {
		url = keepUser + h + ":" + path
	} else {
		url = scheme + "://" + keepUser + h
		if port != "" {
			url += ":" + port
		}
		url += "/" + path
	}
	return url, host, provider, slug, true
}

// splitHostPort splits "host[:port]" (or "[v6]:port"), validating the host's
// characters. good is false for an empty or malformed host.
func splitHostPort(hp string) (host, port string, good bool) {
	if strings.HasPrefix(hp, "[") {
		end := strings.IndexByte(hp, ']')
		if end < 0 {
			return "", "", false
		}
		host, rest := hp[:end+1], hp[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return "", "", false
			}
			port = rest[1:]
		}
		return host, port, len(host) > 2 && digitsOnly(port)
	}
	host = hp
	if k := strings.LastIndexByte(hp, ':'); k >= 0 {
		host, port = hp[:k], hp[k+1:]
	}
	if host == "" || !digitsOnly(port) {
		return "", "", false
	}
	for _, r := range host {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
			return "", "", false
		}
	}
	return host, port, true
}

// digitsOnly reports whether s is empty or all ASCII digits.
func digitsOnly(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// slugFor derives the repository slug from a path with ".git" already
// removed. Azure DevOps paths carry a "_git" segment (https) or a "v3/"
// prefix (ssh), and the legacy *.visualstudio.com host carries the
// organisation in the host; all three fold to "org/project/repo".
func slugFor(p Provider, rawHost, path string) string {
	if p != ProviderAzureDevOps {
		return path
	}
	parts := strings.Split(strings.TrimPrefix(path, "v3/"), "/")
	kept := parts[:0]
	for _, seg := range parts {
		if seg != "_git" && seg != "" {
			kept = append(kept, seg)
		}
	}
	if strings.HasSuffix(rawHost, ".visualstudio.com") && rawHost != "vs-ssh.visualstudio.com" {
		org := strings.TrimSuffix(rawHost, ".visualstudio.com")
		if len(kept) == 2 {
			kept = append([]string{org}, kept...)
		}
	}
	return strings.Join(kept, "/")
}

// MirrorKey is the Observer mirror directory key for a normalised remote URL:
// the first 16 hex characters of its sha256 (plan 12.2,
// ~/.observer/delivery/mirrors/<key>.git). Pass the url ParseRemoteURL
// returned, never a raw one.
func MirrorKey(normalisedURL string) string {
	sum := sha256.Sum256([]byte(normalisedURL))
	return hex.EncodeToString(sum[:])[:16]
}

// RepoSlugHash is the org-wire key of a repository: sha256 hex of the
// lowercase "host/owner/repo" (orgcontract.PullRequestRow.RepoSlugHash).
func RepoSlugHash(host, slug string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(host + "/" + slug)))
	return hex.EncodeToString(sum[:])
}
