//go:build !sbo_omit_security && !sbo_omit_security_trust

package main

import (
	"slices"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/sectrust"
)

// security_feedback_trust.go adds repository trust's row to the feedback
// rule table (feedbackRuleTables, audit finding F5, lane sec-polish): built
// only with the trust module, so a build without it names none of its
// rules and links none of its tables.

func init() { feedbackRuleTables[repoTrustComponent] = feedbackTrustRule }

// feedbackTrustRule knows the trust finding ids: the two config baseline
// rules, repo-trust/<code> for a code of the trust code table, and
// agent-version/<CVE> for a row of the shipped vulnerable-version table.
func feedbackTrustRule(id string) bool {
	if id == repoTrustBaselineRule || id == repoTrustBaselineUserRule {
		return true
	}
	if code, ok := strings.CutPrefix(id, "repo-trust/"); ok {
		return slices.ContainsFunc(sectrust.Codes(), func(r sectrust.CodeRow) bool { return r.Code == code })
	}
	if cve, ok := strings.CutPrefix(id, repoTrustVersionRule); ok {
		return slices.ContainsFunc(sectrust.VulnerableVersions(), func(v sectrust.VulnerableVersion) bool { return v.CVE == cve })
	}
	return false
}
