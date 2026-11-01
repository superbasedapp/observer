package secverify

import (
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// resultupload.go is the verify workflow's optional result upload (lane
// GATES-SEC, org.security.githubapp): the separate upload job reads the
// verdict job's SARIF artifact and turns it into the one CI result the org
// stores for the commit. It reads only what the verdict job wrote and never
// decides a verdict of its own: a missing, unreadable or foreign SARIF
// uploads `unknown`, so the org's commit status can never read success
// without a passing verdict for that exact commit.

// ResultUploadInput is what the upload job knows besides the SARIF: the
// repository, the commits, the run attempt and the run's page, all from
// the CI runner.
type ResultUploadInput struct {
	Repository string
	Base, Head string
	Attempt    int
	RunURL     string
}

// The verdict rules of an upload that had no usable SARIF.
const (
	UploadRuleSARIFMissing = "upload.sarif_missing"
	UploadRuleSARIFInvalid = "upload.sarif_invalid"
	UploadRuleHeadMismatch = "upload.head_mismatch"
)

// The upload's bounds.
const (
	uploadMaxRuleIDBytes    = 128
	uploadMaxSARIFResultCap = 100000
)

// ErrResultUpload wraps a refused upload input.
var ErrResultUpload = errors.New("secverify: the CI result upload input is refused")

// ResultFromSARIF maps the verdict job's SARIF (nil when the artifact is
// missing) to the upload body for in. It returns an error only when in
// itself is refused; a bad SARIF is an `unknown` result.
func ResultFromSARIF(sarif []byte, in ResultUploadInput) (orgcontract.CIResultUpload, error) {
	u := orgcontract.CIResultUpload{
		Schema: orgcontract.CIResultSchema, Repository: in.Repository,
		HeadSHA: strings.ToLower(in.Head), BaseSHA: strings.ToLower(in.Base),
		Attempt: in.Attempt, RunURL: in.RunURL, Verdict: orgcontract.CIResultUnknown,
	}
	if _, ok := orgcontract.NormalizeCIResult(u); !ok {
		return u, ErrResultUpload
	}
	if rule, ok := fillFromSARIF(&u, sarif); !ok {
		u.Verdict, u.VerdictRule, u.RuleCounts = orgcontract.CIResultUnknown, rule, nil
		u.PolicySource, u.PolicyMode = "", ""
	}
	n, ok := orgcontract.NormalizeCIResult(u)
	if !ok {
		// A field the SARIF carried is outside the wire's shapes: unknown.
		u = orgcontract.CIResultUpload{
			Schema: u.Schema, Repository: u.Repository, HeadSHA: u.HeadSHA, BaseSHA: u.BaseSHA,
			Attempt: u.Attempt, RunURL: u.RunURL, Verdict: orgcontract.CIResultUnknown, VerdictRule: UploadRuleSARIFInvalid,
		}
		n, _ = orgcontract.NormalizeCIResult(u)
	}
	return n, nil
}

// PendingResult is the run's pending registration (audit finding F2): the
// verify workflow's register job uploads it when the run starts, so the
// org's status reads pending and, if no verdict replaces it within the
// org's bounded wait, error. It carries no verdict of its own.
func PendingResult(in ResultUploadInput) (orgcontract.CIResultUpload, error) {
	u := orgcontract.CIResultUpload{
		Schema: orgcontract.CIResultSchema, Repository: in.Repository,
		HeadSHA: strings.ToLower(in.Head), BaseSHA: strings.ToLower(in.Base),
		Attempt: in.Attempt, RunURL: in.RunURL, Verdict: orgcontract.CIResultPending,
	}
	n, ok := orgcontract.NormalizeCIResult(u)
	if !ok {
		return u, ErrResultUpload
	}
	return n, nil
}

// fillFromSARIF copies the verdict, its rule, the policy words and the
// per-rule result counts of the verify run; ok false names the reason.
func fillFromSARIF(u *orgcontract.CIResultUpload, sarif []byte) (string, bool) {
	if sarif == nil {
		return UploadRuleSARIFMissing, false
	}
	var log sarifLog
	if err := json.Unmarshal(sarif, &log); err != nil || len(log.Runs) != 1 || log.Runs[0].Tool.Driver.Name != ToolName {
		return UploadRuleSARIFInvalid, false
	}
	run := log.Runs[0]
	word := func(k string) string {
		s, _ := run.Properties[k].(string)
		return s
	}
	if !strings.EqualFold(word("superbased/head"), u.HeadSHA) {
		return UploadRuleHeadMismatch, false
	}
	switch v := Verdict(word("superbased/verdict")); v {
	case VerdictPass, VerdictFail, VerdictUnknown:
		u.Verdict = string(v)
	default:
		return UploadRuleSARIFInvalid, false
	}
	if len(run.Results) > uploadMaxSARIFResultCap {
		return UploadRuleSARIFInvalid, false
	}
	u.VerdictRule = word("superbased/verdict_rule")
	u.PolicySource, u.PolicyMode = word("superbased/policy_source"), word("superbased/mode")
	if v, ok := run.Properties["superbased/policy_version"].(float64); ok && v > 0 {
		u.PolicyVersion = strconv.FormatInt(int64(v), 10)
	}
	u.PackVersion = word("superbased/pack_version")
	counts := map[string]int{}
	for _, r := range run.Results {
		if r.RuleID != "" && len(r.RuleID) <= uploadMaxRuleIDBytes {
			counts[r.RuleID]++
		}
	}
	if len(counts) > orgcontract.MaxCIResultRules {
		keys := make([]string, 0, len(counts))
		for k := range counts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys[orgcontract.MaxCIResultRules:] {
			delete(counts, k)
		}
	}
	if len(counts) > 0 {
		u.RuleCounts = counts
	}
	return "", true
}
