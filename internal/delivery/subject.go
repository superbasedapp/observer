package delivery

import (
	"regexp"
	"strconv"
	"strings"
)

// subject.go reads a PR number and a merge method out of a default-branch
// commit's subject, for local-only mode (plan 2.1, grounded for GitHub in
// 12.1). Only GitHub's two default templates are grounded; the GitLab,
// Azure DevOps and Bitbucket templates in plan 2.1 are from memory and stay
// out of the table until a later phase grounds them.

// subjectTemplate is one row of subjectTemplates.
type subjectTemplate struct {
	name   string
	re     *regexp.Regexp
	method MergeMethod
	// minParents is the parent count the template's merge method implies
	// (2 for a merge commit, 1 for a squash commit).
	minParents, maxParents int
}

// subjectTemplates is the ordered table of grounded GitHub subject templates.
//
//   - merge commit: "Merge pull request #14706 from owner/branch", two parents
//     (cli/cli, 12.1);
//   - squash commit: a subject ending in " (#100206)", one parent
//     (vercel/next.js, 12.1).
//
// A rebase merge leaves no PR number in any subject (12.1), so it has no row.
var subjectTemplates = []subjectTemplate{
	{"github_merge", regexp.MustCompile(`^Merge pull request #([0-9]+) from \S`), MergeCommit, 2, 1 << 30},
	{"github_squash", regexp.MustCompile(`\(#([0-9]+)\)\s*$`), MergeSquash, 1, 1},
}

// matchSubject returns the first template matching subject and the PR number
// it names.
func matchSubject(subject string) (subjectTemplate, int64, bool) {
	s := strings.TrimSpace(subject)
	for _, t := range subjectTemplates {
		m := t.re.FindStringSubmatch(s)
		if m == nil {
			continue
		}
		n, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil || n <= 0 {
			continue
		}
		return t, n, true
	}
	return subjectTemplate{}, 0, false
}

// PRNumberFromSubject returns the PR number a default-branch commit subject
// names under a grounded GitHub template (merge commit "Merge pull request
// #N from ..." or squash suffix " (#N)"). ok is false when no template
// matches.
func PRNumberFromSubject(subject string) (int64, bool) {
	_, n, ok := matchSubject(subject)
	return n, ok
}

// MergeMethodFromCommit infers how a PR landed from the landing commit's
// parent count and subject: a two-parent "Merge pull request #N" commit is a
// merge commit; a one-parent commit ending in " (#N)" is a squash. When
// prNumber > 0 the subject must name that same PR. Anything else, including
// every rebase merge, is "" (unknown): local git cannot tell a rebase merge
// from a fast-forward.
func MergeMethodFromCommit(parents int, subject string, prNumber int64) MergeMethod {
	t, n, ok := matchSubject(subject)
	if !ok || (prNumber > 0 && n != prNumber) {
		return ""
	}
	if parents < t.minParents || parents > t.maxParents {
		return ""
	}
	return t.method
}
