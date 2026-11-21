package openshellorg

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// WorkspacePrefix starts every OpenShell workspace Observer owns; the sync
// touches no workspace without it (section 7.2).
const WorkspacePrefix = "obs-"

// AdminWorkspace is the admin-only workspace that holds the org's repository
// credentials as providers (section 7.8). No member is ever added to it.
const AdminWorkspace = "obs-admin"

var memberWorkspaceRE = regexp.MustCompile(`^obs-[0-9a-f]{12}$`)

// WorkspaceName is a member's own OpenShell workspace: "obs-" plus the first
// 12 hex characters of the SHA-256 of the member id. It never carries the id
// itself, so the gateway's workspace list names nobody.
func WorkspaceName(memberID string) string {
	sum := sha256.Sum256([]byte("sbo-openshell-workspace-v1\n" + memberID))
	return WorkspacePrefix + hex.EncodeToString(sum[:])[:12]
}

// IsMemberWorkspace reports whether name has the member workspace grammar.
func IsMemberWorkspace(name string) bool { return memberWorkspaceRE.MatchString(name) }

// GatewayIDValid reports whether id has the [a-z0-9-]{1,32} grammar of the
// gateway_id key (section 2.5).
func GatewayIDValid(id string) bool {
	if id == "" || len(id) > 32 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// NormalizeRepository normalizes a repository URL the way a git_providers
// row and a clone URL are compared (section 4.3): the scheme kept, the host
// lowercased, the path without a trailing slash or ".git". The scp form
// user@host:path becomes ssh://user@host/path. It answers "" for a value that
// is not an https or ssh repository URL.
func NormalizeRepository(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || strings.ContainsAny(s, " \t\r\n") {
		return ""
	}
	var scheme, rest string
	switch {
	case strings.HasPrefix(s, "https://"):
		scheme, rest = "https", s[len("https://"):]
	case strings.HasPrefix(s, "ssh://"):
		scheme, rest = "ssh", s[len("ssh://"):]
	default:
		// scp form: user@host:path (no scheme, a colon before any slash).
		at := strings.Index(s, "@")
		colon := strings.Index(s, ":")
		slash := strings.Index(s, "/")
		if at <= 0 || colon <= at+1 || (slash >= 0 && slash < colon) {
			return ""
		}
		scheme, rest = "ssh", s[:colon]+"/"+strings.TrimPrefix(s[colon+1:], "/")
	}
	authority, path, _ := strings.Cut(rest, "/")
	if authority == "" || path == "" {
		return ""
	}
	user, host, hasUser := strings.Cut(authority, "@")
	if !hasUser {
		host, user = user, ""
	}
	if host == "" {
		return ""
	}
	host = strings.ToLower(host)
	path = strings.TrimRight(path, "/")
	path = strings.TrimSuffix(path, ".git")
	path = strings.TrimRight(path, "/")
	if path == "" {
		return ""
	}
	if user != "" {
		return scheme + "://" + user + "@" + host + "/" + path
	}
	return scheme + "://" + host + "/" + path
}

// GitRowID is a git_providers row's id: the first 16 lowercase hex characters
// of the SHA-256 of its normalized repository URL, so a TOML-seeded row and a
// dashboard row for the same repository get the same id (G1-R21). The org's
// operator names the row's secret "openshell-git-<row id>".
func GitRowID(repository string) string {
	sum := sha256.Sum256([]byte(NormalizeRepository(repository)))
	return hex.EncodeToString(sum[:])[:16]
}

// GitSecretName is the secret-store name of a git_providers row's read-only
// credential under rung (b) of section 7.8.
func GitSecretName(repository string) string { return "openshell-git-" + GitRowID(repository) }
