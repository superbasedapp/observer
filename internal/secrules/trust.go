package secrules

import (
	"slices"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Trust rules S-701 to S-705 (security pillar plan section 5.1, component
// security.trust): the launch chokepoint sends a policy.KindAgentLaunch
// event whose Event.Security carries the repository trust verdict and the
// reason codes behind it, so "refuse to launch an agent in an untrusted
// repository" is a guard rule, not pillar code. They flag in observe mode
// (the settings contract's default "Warn"); enforce asks or refuses, and an
// org floor may raise them through the bundle's override rail.
//
// TrustReasons holds the codes of the reasons at the verdict's own level
// (the untrusted reasons of an untrusted verdict, the flagged reasons of a
// flagged one), each code once. The groups below partition the untrusted
// codes of internal/sectrust's reason table; TestTrustGroupsCoverTheCodeTable
// in this package pins the partition to that table.

// trustGroup is one rule's set of untrusted reason codes.
type trustGroup struct {
	id     string
	codes  []string
	what   string
	advice string
	// enforce is the enforce-mode decision.
	enforce  policy.Decision
	severity policy.Severity
}

// trustGroups are S-701 to S-704, one per kind of untrusted reason.
var trustGroups = []trustGroup{
	{
		id:       "S-701",
		codes:    []string{"hook_command", "statusline_command", "credential_helper_command", "mcp_server_command", "folder_open_task", "plugin_code", "file_over_cap", "parse_error"},
		what:     "the repository makes the agent run commands, or holds config files nothing could judge, that nobody accepted yet",
		advice:   "Review them in the dashboard's New Terminal dialog (Review and accept) or with `observer security trust check`; if they are expected, accept their exact content there or with `observer security trust accept`. Any change to a command asks again.",
		enforce:  policy.DecisionAsk,
		severity: policy.SeverityHigh,
	},
	{
		id:       "S-702",
		codes:    []string{"base_url_override", "config_dir_redirect", "process_injection_env", "plugin_host_override"},
		what:     "the repository redirects the agent's API, its config or Observer's own binary, or injects code into its process",
		advice:   "Remove the override from the repository's settings or .env before launching an agent here; Observer is the local base URL. If it is your own setting in a local file (.env, a settings.local file, .git/config), accept it once in the New Terminal dialog or with `observer security trust accept`.",
		enforce:  policy.DecisionDeny,
		severity: policy.SeverityCritical,
	},
	{
		id:       "S-703",
		codes:    []string{"auto_approve", "trust_disabled", "trust_self_grant", "hooks_off_switch"},
		what:     "the repository switches off the agent's approvals, its folder trust or its hooks",
		advice:   "Remove the switch from the repository's settings; approvals and hooks are the developer's to turn off, not a cloned repository's. If it is your own setting in a local file, accept it once in the New Terminal dialog or with `observer security trust accept`.",
		enforce:  policy.DecisionDeny,
		severity: policy.SeverityCritical,
	},
	{
		id: "S-704",
		codes: []string{
			"symlink_escape", "hidden_unicode_tag", "hidden_unicode_bidi", "git_fsmonitor", "git_command_key",
			"git_filter_driver", "git_diff_driver", "git_merge_driver", "gitattributes_driver_defined",
			"file_over_hash_cap", "truncated_code", "file_unreadable",
		},
		what:     "the repository hides instructions or code, links its config outside the tree, or sets git to run a program",
		advice:   "Inspect the named files; hidden characters and git programs in a repository's own config are how a planted repository attacks the agent. If you set them yourself, accept them once in the New Terminal dialog or with `observer security trust accept`.",
		enforce:  policy.DecisionAsk,
		severity: policy.SeverityHigh,
	},
}

// trustReasonList renders the matched codes for the verdict detail.
func trustReasonList(codes []string) string {
	return strings.Join(codes, ", ")
}

// matchTrustGroup returns the matcher of one group: the event is an
// untrusted verdict holding at least one of the group's codes.
func matchTrustGroup(g trustGroup) policy.MatchFn {
	return func(ctx *policy.MatchContext) (bool, string) {
		sec := ctx.Event.Security
		if sec == nil || sec.Trust != policy.TrustUntrusted {
			return false, ""
		}
		var hit []string
		for _, c := range sec.TrustReasons {
			if slices.Contains(g.codes, c) {
				hit = append(hit, c)
			}
		}
		if len(hit) == 0 {
			return false, ""
		}
		return true, g.what + " (" + trustReasonList(hit) + ")"
	}
}

// matchTrustFlagged is S-705: a flagged verdict (accepted commands, or
// reasons that only warn).
func matchTrustFlagged(ctx *policy.MatchContext) (bool, string) {
	sec := ctx.Event.Security
	if sec == nil || sec.Trust != policy.TrustFlagged {
		return false, ""
	}
	return true, "the repository carries accepted commands or settings worth a look (" + trustReasonList(sec.TrustReasons) + ")"
}

// TrustRules returns the S-701 to S-705 rows, a fresh slice each call.
func TrustRules() []policy.Rule {
	launch := []policy.EventKind{policy.KindAgentLaunch}
	out := make([]policy.Rule, 0, len(trustGroups)+1)
	for _, g := range trustGroups {
		out = append(out, policy.Rule{
			ID: g.id, Category: policy.CategoryCodeSecurity, Severity: g.severity,
			AppliesTo: launch, Match: matchTrustGroup(g),
			Observe: policy.DecisionFlag, Enforce: g.enforce,
			Doc:    "agent launch in an untrusted repository: " + g.what,
			Advice: g.advice,
			Source: policy.SourcePackSecurity,
		})
	}
	return append(out, policy.Rule{
		ID: "S-705", Category: policy.CategoryCodeSecurity, Severity: policy.SeverityWarn,
		AppliesTo: launch, Match: matchTrustFlagged,
		Observe: policy.DecisionFlag, Enforce: policy.DecisionFlag,
		Doc:    "agent launch in a repository with accepted commands or warnings",
		Advice: "Nothing blocks the launch; the New Terminal dialog and `observer security trust check` list what the repository makes the agent run.",
		Source: policy.SourcePackSecurity,
	})
}

// TrustRuleCodes returns the untrusted reason codes each of S-701 to S-704
// matches (rule id to codes), for the doc generator and the partition test.
func TrustRuleCodes() map[string][]string {
	out := make(map[string][]string, len(trustGroups))
	for _, g := range trustGroups {
		out[g.id] = append([]string(nil), g.codes...)
	}
	return out
}
