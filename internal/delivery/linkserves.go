package delivery

import (
	"regexp"
	"strings"
)

// linkserves.go is the ONE definition of "this provider link answers for
// this remote". internal/deliverysvc polls by it and internal/dashapi labels
// the Projects page by it, so a source chip can never disagree with what
// "Check now" actually asks the provider about.

// reSlugPart is one segment of an owner/repo slug.
var reSlugPart = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)

// ValidSlug reports whether slug is a plain "owner/repo": exactly two
// segments of letters, digits, dot, underscore or dash, neither "." nor
// "..". It is the shape a provider API path may carry.
func ValidSlug(slug string) bool {
	parts := strings.Split(slug, "/")
	if len(parts) != 2 {
		return false
	}
	for _, p := range parts {
		if !reSlugPart.MatchString(p) || p == "." || p == ".." {
			return false
		}
	}
	return true
}

// LinkServes reports whether provider link l answers for remote r: a GitHub
// remote on the link's host (case-insensitive) with a valid owner/repo slug.
// Whether the link is healthy or stopped is a separate question its callers
// ask.
func LinkServes(l ProviderLink, r Remote) bool {
	return l.Provider == ProviderGitHub && r.Provider == ProviderGitHub &&
		strings.EqualFold(l.Host, r.Host) && ValidSlug(r.RepoSlug)
}
