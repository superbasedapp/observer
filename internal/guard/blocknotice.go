package guard

import (
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// BlockNotice is the setting a guard's blocking verdicts are read in. It
// picks the human-first line that leads a blocked call's reason
// (HumanBlockLine, PromptRequestAccessHint), so the line names the policy
// the reader actually has and a way to change it that works from where they
// are. It is a capability of the guard (Options.BlockNotice), never a
// branch on the tool or host.
type BlockNotice string

const (
	// BlockNoticeNode is the zero value: the node-local wording, where an
	// org-overridable rule points at `observer guard approve` and an
	// org-locked one at the request path (dashboard Requests page or
	// `observer request access`). Unchanged by this seam.
	BlockNoticeNode BlockNotice = ""
	// BlockNoticeSandboxNode is a cloud-session gate whose committed policy
	// was signed by the developer's own node (cloud-session origin node):
	// no organization is involved.
	BlockNoticeSandboxNode BlockNotice = "sandbox-node"
	// BlockNoticeSandboxOrg is a cloud-session gate whose committed policy
	// is the organization's (cloud-session origin org).
	BlockNoticeSandboxOrg BlockNotice = "sandbox-org"
)

// blockNoticeRow is one non-default notice: whose policy the committed file
// carries and how the reader changes it. Every row leads EVERY blocking
// verdict that names a rule (inside a sandbox the org lock, the override
// grant and the request path all mean nothing: there is no dashboard, no
// approvals register and no reachable request endpoint), and no row points
// at any of them.
type blockNoticeRow struct {
	// owner names the committed policy's author, in parentheses after it.
	owner string
	// change is the sentence that says how to change a rule the committed
	// policy carries or keeps on.
	change string
}

// blockNotices is THE notice table. BlockNoticeNode has no row: a missing
// row is the node-local wording.
var blockNotices = map[BlockNotice]blockNoticeRow{
	BlockNoticeSandboxNode: {
		owner:  "the developer's own guard policy, signed by their node",
		change: "To change it, edit the guard policy of the node that signed the file, re-run `observer cloud-session init --guard` there and commit the result.",
	},
	BlockNoticeSandboxOrg: {
		owner:  "the organization's guard policy",
		change: "To change it, ask an org admin to change the organization's guard policy, then re-run `observer cloud-session init --guard` and commit the result.",
	},
}

// sandboxRuleSource is how the line describes the winning rule, keyed by the
// verdict's policy layer (policy.Verdict.Source). subject takes the rule id
// and the row's owner; change, when set, replaces the row's change sentence
// (a rule the repository's own project file adds is changed there). A source
// with no row reads as sandboxRuleSourceFallback.
var sandboxRuleSource = map[string]struct{ subject, change string }{
	// The committed policy file is the guard's org layer
	// (cmd/observer/cloudsession_gate.go buildSandboxGuard).
	policy.SourceOrg: {subject: "%s is a rule in this repository's committed cloud-session policy (%s)."},
	policy.SourceBuiltin: {
		subject: "%s is a built-in Observer rule, which this repository's committed cloud-session policy (%s) keeps on.",
	},
	layerProject: {
		subject: "%s is a rule in this repository's own project guard policy file, which can only tighten the committed cloud-session policy (%s).",
		change:  "To change it, edit that file in the repository and commit it.",
	},
}

// sandboxRuleSourceFallback describes a rule from any other layer (a rule
// pack composed in like a built-in).
var sandboxRuleSourceFallback = sandboxRuleSource[policy.SourceBuiltin]

// line renders the notice's human-first line for a verdict: what was
// blocked, where the rule comes from, how to change it. "" for a verdict
// that names no rule or does not block. Hyphens only, one line, no URL.
func (r blockNoticeRow) line(v policy.Verdict, what string) string {
	if v.RuleID == "" || v.Decision < policy.DecisionAsk {
		return ""
	}
	src, ok := sandboxRuleSource[v.Source]
	if !ok {
		src = sandboxRuleSourceFallback
	}
	change := r.change
	if src.change != "" {
		change = src.change
	}
	return fmt.Sprintf("observer: %s blocked %s. ", v.RuleID, what) +
		fmt.Sprintf(src.subject, v.RuleID, r.owner) + " " + change
}
