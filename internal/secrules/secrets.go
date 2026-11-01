package secrules

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secdetect"
)

// S-721 (security plan sections 4.7 item 3.1 and 5.3 (a)): a high-
// confidence typed secret in a proposed write, found in the hook by the
// bounded secret scan (secret rows only, a fixed 16 KiB, a deadline whose
// result is scan_incomplete). Observe flags and lets the write proceed;
// enforce denies, except in a fixture or test-data path, where it asks. A
// scan that did not finish matches nothing here: the post-write seam and
// the commit gate cover that content.

const secretAdvice = "Move the value to an environment variable and retry." //nolint:gosec // G101: advice wording, not a credential

// SecretRules returns the S-721 rows. They read Event.Security.Hits, which
// the hook context seam stamps from PreWriteSecurity.
func SecretRules() []policy.Rule {
	const doc = "agent write that adds a secret"
	kinds := []policy.EventKind{policy.KindFileAccess}
	return []policy.Rule{
		{
			ID: "S-721", Category: policy.CategorySecrets, Severity: policy.SeverityHigh,
			AppliesTo: kinds, Match: secretMatch(false),
			Observe: policy.DecisionFlag, Enforce: policy.DecisionDeny,
			Doc: doc, Advice: secretAdvice, Source: policy.SourcePackSecurity,
		},
		{
			ID: "S-721", Category: policy.CategorySecrets, Severity: policy.SeverityHigh,
			AppliesTo: kinds, Match: secretMatch(true),
			Observe: policy.DecisionFlag, Enforce: policy.DecisionAsk,
			Doc: doc + " in a fixture or test-data path", Advice: secretAdvice, Source: policy.SourcePackSecurity,
		},
	}
}

// writeActions are the action types a pre-write scan covers.
var writeActions = map[string]bool{models.ActionWriteFile: true, models.ActionEditFile: true}

// secretMatch matches a blocking secret hit whose fixture class equals
// fixture. The detail is the templated deny text (secdetect.DenyText).
func secretMatch(fixture bool) policy.MatchFn {
	return func(ctx *policy.MatchContext) (bool, string) {
		ev := ctx.Event
		if ev.Security == nil || !writeActions[ev.ActionType] {
			return false, ""
		}
		for _, h := range ev.Security.Hits {
			if h.Category != policy.FindingSecret || h.Confidence != policy.FindingConfidenceHigh {
				continue
			}
			if secdetect.IsFixturePath(h.Path) != fixture {
				continue
			}
			return true, secdetect.DenyText(secdetect.DenyInput{
				RuleID: "S-721", Verb: "flagged", Subject: "this write", Type: strings.TrimPrefix(h.RuleID, secretRulePrefix),
				Path: h.Path, Line: h.Line, Confidence: secdetect.ConfidenceHigh,
			})
		}
		return false, ""
	}
}
