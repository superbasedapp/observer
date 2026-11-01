package orgcontract

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ciresult.go is the CI result upload's wire contract (security plan 7.9
// "upload of the result to the org" and Q16, lane GATES-SEC): the separate
// upload job of the verify workflow posts the verdict job's result to
// POST CIResultPath under the org's CI machine credential, bound to one
// commit of one repository and one run attempt. The org stores it per
// (org, repository, head sha, attempt) and the GitHub App
// (org.security.githubapp) computes its `superbased/security` commit status
// from it. Every string is checked against a closed shape before it is
// stored; nothing here is free text.

// CIResultPath is the upload route.
const CIResultPath = "/api/ci/security/results"

// CIResultOIDCHeader carries the upload job's GitHub Actions OIDC token
// (audit finding F1): the org stores a result only when the token binds it
// to the repository, the commit and the policy workflow, and takes the run
// attempt from the token.
const CIResultOIDCHeader = "X-Observer-CI-OIDC-Token"

// CIResultSchema is the only body schema this build reads.
const CIResultSchema = "sbo.ci-result.v1"

// MaxCIResultBytes caps an upload body.
const MaxCIResultBytes = 64 << 10

// MaxCIResultRules caps the rule counts of one upload.
const MaxCIResultRules = 500

// The CI result verdicts: the verify verdicts (pass, fail, unknown) and
// pending (a run that registered before its verdict job finished).
const (
	CIResultPass    = "pass"
	CIResultFail    = "fail"
	CIResultUnknown = "unknown"
	CIResultPending = "pending"
)

// CIResultVerdicts is the closed verdict vocabulary.
var CIResultVerdicts = []string{CIResultPass, CIResultFail, CIResultUnknown, CIResultPending}

// CIResultUpload is one upload.
type CIResultUpload struct {
	Schema string `json:"schema"`
	// Repository is "owner/name" on github.com.
	Repository string `json:"repository"`
	// HeadSHA is the commit the result is for; BaseSHA the base it was
	// compared against.
	HeadSHA string `json:"head_sha"`
	BaseSHA string `json:"base_sha,omitempty"`
	// Attempt is the CI run attempt (GitHub's run_attempt, from 1).
	Attempt int `json:"attempt"`
	// RunURL is the run's page on github.com, of the same repository.
	RunURL      string `json:"run_url"`
	Verdict     string `json:"verdict"`
	VerdictRule string `json:"verdict_rule,omitempty"`
	// RuleCounts counts the results per rule id.
	RuleCounts    map[string]int `json:"rule_counts,omitempty"`
	PolicySource  string         `json:"policy_source,omitempty"`
	PolicyMode    string         `json:"policy_mode,omitempty"`
	PolicyVersion string         `json:"policy_version,omitempty"`
	PackVersion   string         `json:"pack_version,omitempty"`
}

// CIResultAnswer is the upload's answer.
type CIResultAnswer struct {
	Repository string `json:"repository"`
	HeadSHA    string `json:"head_sha"`
	Attempt    int    `json:"attempt"`
	Verdict    string `json:"verdict"`
	// Stored is false when an identical result was already on record.
	Stored bool `json:"stored"`
	// VersionLabel names how the policy and pack versions the run reported
	// read against the org's current CI policy (CIVersion* words); empty
	// when they match (lane LEFT2-SEC item R-019, additive).
	VersionLabel string `json:"version_label,omitempty"`
}

// CIPolicySourceOrg is the verify policy source word of the org's signed
// CI policy (internal/secverify.SourceOrg), as a result upload reports it.
const CIPolicySourceOrg = "org_signed_policy"

// The words of the CI result's version check (lane LEFT2-SEC item R-019):
// CIVersionPolicyUnknown refuses the upload (a policy version the org
// never issued); the others label a stored result.
const (
	CIVersionPolicyUnknown    = "policy_version_unknown"
	CIVersionPolicyMissing    = "policy_version_missing"
	CIVersionPolicyNotOrg     = "policy_not_org"
	CIVersionPolicySuperseded = "policy_superseded"
	CIVersionPackMissing      = "pack_version_missing"
)

var (
	ciRepoRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$`)
	ciSHARE     = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	ciWordRE    = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,128}$`)
	ciVersionRE = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)
	ciRunPathRE = regexp.MustCompile(`^/actions/runs/[0-9]{1,20}(/attempts/[0-9]{1,6})?/?$`)
)

// NormalizeCIResult checks an upload against its closed shapes and returns
// it normalized (lowercase shas, trimmed words); ok is false when any
// field is refused.
func NormalizeCIResult(u CIResultUpload) (CIResultUpload, bool) {
	u.Repository = strings.TrimSpace(u.Repository)
	u.HeadSHA = strings.ToLower(strings.TrimSpace(u.HeadSHA))
	u.BaseSHA = strings.ToLower(strings.TrimSpace(u.BaseSHA))
	u.Verdict = strings.TrimSpace(u.Verdict)
	switch {
	case u.Schema != CIResultSchema, !ciRepoRE.MatchString(u.Repository), !ciSHARE.MatchString(u.HeadSHA):
		return u, false
	case u.BaseSHA != "" && !ciSHARE.MatchString(u.BaseSHA):
		return u, false
	case u.Attempt < 1 || u.Attempt > 1_000_000:
		return u, false
	case !validVerdict(u.Verdict):
		return u, false
	case !validRunURL(u.RunURL, u.Repository):
		return u, false
	case len(u.RuleCounts) > MaxCIResultRules:
		return u, false
	}
	for _, w := range []string{u.VerdictRule, u.PolicySource, u.PolicyMode} {
		if w != "" && !ciWordRE.MatchString(w) {
			return u, false
		}
	}
	for _, v := range []string{u.PolicyVersion, u.PackVersion} {
		if v != "" && !ciVersionRE.MatchString(v) {
			return u, false
		}
	}
	for rule, n := range u.RuleCounts {
		if !ciWordRE.MatchString(rule) || n < 0 || n > 1_000_000 {
			return u, false
		}
	}
	return u, true
}

func validVerdict(v string) bool {
	for _, k := range CIResultVerdicts {
		if v == k {
			return true
		}
	}
	return false
}

// validRunURL: an https page of the same repository's Actions run on
// github.com, so a status never links anywhere else.
func validRunURL(raw, repo string) bool {
	prefix := "https://github.com/" + repo
	if !strings.HasPrefix(raw, prefix+"/actions/runs/") || len(raw) > 256 {
		return false
	}
	return ciRunPathRE.MatchString(strings.TrimPrefix(raw, prefix))
}

// RuleCountsKey is the rule counts in one stable spelling ("id=n,id=n",
// sorted), for storage and comparison.
func RuleCountsKey(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k + "=" + strconv.Itoa(m[k]))
	}
	return b.String()
}
