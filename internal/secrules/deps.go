package secrules

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// The install gate, S-741 to S-749 and S-757 (security plan section 5.4,
// Phase D1; S-757 from the coverage-gaps plan 2026-11-13 section 4).
// The hook context seam fills Event.Security.Installs for an agent's
// install command (or a manifest edit) from the offline index, the
// online-answer cache and, on a cache miss for a public name, the daemon's
// online check within the install-gate wait; these rows decide on it.
//
//	S-741 malicious (an authenticated MAL- listing)  observe ask,  enforce deny
//	S-742 near miss of a popular name                observe ask,  enforce ask
//	S-743 too new (under the minimum package age)    observe flag, enforce flag
//	S-744 unknown (not in the registry, or no index) observe flag, enforce flag
//	S-745 custom registry or index flag              observe flag, enforce flag
//	S-746 reserved: the --ignore-scripts rewrite (needs a guard rewrite verdict; not built)
//	S-747 a manifest edit adds a flagged dependency  observe flag, enforce flag
//	S-748 the online check did not answer            observe flag, enforce ask
//	S-749 some versions are listed as malicious, and
//	      the install may resolve to one (unpinned, or
//	      a listing by version range)                observe flag, enforce flag
//	S-757 the version installed lacks the build
//	      provenance an earlier version carried (npm
//	      provenance, PyPI attestations), whatever
//	      the verdict                                observe flag, enforce flag
//
// S-744 and S-748 each have two stricter variants (lane LEFT-SEC), chosen
// by the node's [security.deps] unknown_action and online_unknown_action
// (InstallCheck.Action, stamped by the hook from the daemon's settings
// file, an org floor raising it): ask (observe ask, enforce ask) and deny
// (observe ask, enforce deny). With the default action only the rows above
// fire. S-741 is the only row that denies by default; a managed floor
// raises the others through the org bundle's overrides. An install the hook could not check
// at all is never treated as known good: S-744 and S-748 say so.

// reasonNotSetUp is secfeed.ReasonNotSetUp (the once-per-session note
// that package checks are not set up yet), spelled here because the rules
// read only the policy contract; a test pins the two together.
const reasonNotSetUp = "not_set_up"

// reasonTooMany is secfeed.ReasonTooMany: the check that stands for the
// packages an event named beyond the check cap (same import rule).
const reasonTooMany = "too_many_packages"

// notSetUpDetail is the note's own wording (lane SEC-D1FIX2 milestone
// 2d): it is not a finding about the package.
const notSetUpDetail = "package checks are not set up yet: no package index is installed and online checks are off or not accepted (Code security > Scanners > Package checks); this install was not checked"

// depsAdvice is addressed to the human. The approve is on the verdict
// (Security > Verdicts) or the CLI, as gateAdvice says.
const depsAdvice = "Check the package name and its source before installing; the developer can review it on Code security and approve it from its verdict on Security > Verdicts or with `observer guard approve`."

// depsRow is one row of the install gate table.
type depsRow struct {
	id       string
	severity policy.Severity
	verdict  policy.InstallVerdict // "" for the registry row
	manifest bool                  // matches manifest edits (S-747) instead of installs
	observe  policy.Decision
	enforce  policy.Decision
	doc      string
	registry bool
	// action is the InstallCheck.Action the row answers ("" is the default
	// action, InstallActionDefault included).
	action string
	// provenance, when set, makes the row match install checks on their
	// InstallCheck.Provenance instead of their verdict (S-757): the
	// provenance state is orthogonal to the verdict.
	provenance policy.InstallProvenance
}

// depsTable is THE install gate table, one test case per row.
var depsTable = []depsRow{
	{
		id: "S-741", severity: policy.SeverityCritical, verdict: policy.InstallMalicious, observe: policy.DecisionAsk, enforce: policy.DecisionDeny,
		doc: "agent install of a package an authenticated source lists as malicious",
	},
	{
		id: "S-742", severity: policy.SeverityHigh, verdict: policy.InstallNearMiss, observe: policy.DecisionAsk, enforce: policy.DecisionAsk,
		doc: "agent install of a package one edit from a popular name (a possible typosquat)",
	},
	{
		id: "S-743", severity: policy.SeverityWarn, verdict: policy.InstallTooNew, observe: policy.DecisionFlag, enforce: policy.DecisionFlag,
		doc: "agent install of a package published more recently than the minimum package age",
	},
	{
		id: "S-744", severity: policy.SeverityWarn, verdict: policy.InstallUnknownName, observe: policy.DecisionFlag, enforce: policy.DecisionFlag,
		doc: "agent install of a package the registry does not know, or that no usable index could check; also the once-per-session note that package checks are not set up",
	},
	{
		id: "S-744", severity: policy.SeverityWarn, verdict: policy.InstallUnknownName, action: policy.InstallActionAsk, observe: policy.DecisionAsk, enforce: policy.DecisionAsk,
		doc: "agent install of a package the registry does not know, or that no usable index could check ([security.deps] unknown_action = ask)",
	},
	{
		id: "S-744", severity: policy.SeverityWarn, verdict: policy.InstallUnknownName, action: policy.InstallActionDeny, observe: policy.DecisionAsk, enforce: policy.DecisionDeny,
		doc: "agent install of a package the registry does not know, or that no usable index could check ([security.deps] unknown_action = deny)",
	},
	{
		id: "S-745", severity: policy.SeverityWarn, registry: true, observe: policy.DecisionFlag, enforce: policy.DecisionFlag,
		doc: "agent install that names a custom registry or package index (dependency confusion)",
	},
	{
		id: "S-747", severity: policy.SeverityWarn, manifest: true, observe: policy.DecisionFlag, enforce: policy.DecisionFlag,
		doc: "agent manifest edit that adds a dependency the install gate flags (a commit that adds one is recorded as finding deps.s-747)",
	},
	{
		id: "S-748", severity: policy.SeverityWarn, verdict: policy.InstallOnlineUnknown, observe: policy.DecisionFlag, enforce: policy.DecisionAsk,
		doc: "agent install the online package check could not answer in time",
	},
	{
		id: "S-748", severity: policy.SeverityWarn, verdict: policy.InstallOnlineUnknown, action: policy.InstallActionAsk, observe: policy.DecisionAsk, enforce: policy.DecisionAsk,
		doc: "agent install the online package check could not answer in time ([security.deps] online_unknown_action = ask)",
	},
	{
		id: "S-748", severity: policy.SeverityWarn, verdict: policy.InstallOnlineUnknown, action: policy.InstallActionDeny, observe: policy.DecisionAsk, enforce: policy.DecisionDeny,
		doc: "agent install the online package check could not answer in time ([security.deps] online_unknown_action = deny)",
	},
	{
		id: "S-749", severity: policy.SeverityHigh, verdict: policy.InstallListedVersion, observe: policy.DecisionFlag, enforce: policy.DecisionFlag,
		doc: "agent install of a package some of whose versions are listed as malicious, without a pin outside them",
	},
	{
		id: "S-757", severity: policy.SeverityHigh, provenance: policy.InstallProvenanceRegressed, observe: policy.DecisionFlag, enforce: policy.DecisionFlag,
		doc: "agent install of a version that lacks the build provenance earlier versions carried (npm provenance, PyPI attestations)",
	},
}

// depsFlagged are the verdicts S-747 reports for a manifest edit.
var depsFlagged = map[policy.InstallVerdict]bool{
	policy.InstallMalicious: true, policy.InstallNearMiss: true, policy.InstallTooNew: true, policy.InstallListedVersion: true,
	policy.InstallUnknownName: true, policy.InstallOnlineUnknown: true,
}

// DepsRules returns the install gate rows.
func DepsRules() []policy.Rule {
	out := make([]policy.Rule, 0, len(depsTable))
	for _, r := range depsTable {
		row := r
		kinds := []policy.EventKind{policy.KindShellExec}
		if row.manifest {
			kinds = []policy.EventKind{policy.KindFileAccess}
		}
		out = append(out, policy.Rule{
			ID: row.id, Category: policy.CategoryCodeSecurity, Severity: row.severity,
			AppliesTo: kinds, Match: depsMatch(row),
			Observe: row.observe, Enforce: row.enforce,
			Doc: row.doc, Advice: depsAdvice, Source: policy.SourcePackSecurity,
		})
	}
	return out
}

// depsMatch returns the row's matcher.
func depsMatch(row depsRow) policy.MatchFn {
	return func(ctx *policy.MatchContext) (bool, string) {
		st := ctx.Event.Security
		if st == nil || st.InstallManifest != row.manifest {
			return false, ""
		}
		if row.registry {
			if !st.InstallCustomRegistry {
				return false, ""
			}
			return true, "the install names a custom registry or index"
		}
		var names []string
		for _, c := range st.Installs {
			hit := depsCheckHit(row, c)
			if hit && c.Reason == reasonNotSetUp && !row.manifest && row.provenance == "" {
				return true, notSetUpDetail
			}
			if hit {
				names = append(names, checkWords(c))
			}
		}
		if len(names) == 0 {
			return false, ""
		}
		if len(names) > 3 {
			names = append(names[:3], "and "+itoa(len(names)-3)+" more")
		}
		return true, strings.Join(names, ", ")
	}
}

// depsCheckMatcher is one row of the per-check match table: the first
// whose applies holds for a gate row decides whether a check hits it.
type depsCheckMatcher struct {
	applies func(row depsRow) bool
	hit     func(row depsRow, c policy.InstallCheck) bool
}

// depsCheckMatchers is THE per-check match table, walked top-down:
//
//   - a manifest row (S-747) hits any flagged verdict but the not-set-up note;
//   - a provenance row (S-757) hits its provenance state whatever the verdict;
//   - every other row hits its verdict, and for S-744 and S-748 the
//     variant of the check's action.
var depsCheckMatchers = []depsCheckMatcher{
	{
		applies: func(row depsRow) bool { return row.manifest },
		hit: func(_ depsRow, c policy.InstallCheck) bool {
			return depsFlagged[c.Verdict] && c.Reason != reasonNotSetUp
		},
	},
	{
		applies: func(row depsRow) bool { return row.provenance != "" },
		hit:     func(row depsRow, c policy.InstallCheck) bool { return c.Provenance == row.provenance },
	},
	{
		applies: func(depsRow) bool { return true },
		hit: func(row depsRow, c policy.InstallCheck) bool {
			return c.Verdict == row.verdict && (!depsActionVerdicts[row.verdict] || checkAction(c) == row.action)
		},
	},
}

// depsCheckHit reports whether check c hits gate row row.
func depsCheckHit(row depsRow, c policy.InstallCheck) bool {
	for _, m := range depsCheckMatchers {
		if m.applies(row) {
			return m.hit(row, c)
		}
	}
	return false
}

// depsActionVerdicts are the verdicts whose rows pick a variant by the
// check's action (S-744 and S-748); every other row ignores it.
var depsActionVerdicts = map[policy.InstallVerdict]bool{policy.InstallUnknownName: true, policy.InstallOnlineUnknown: true}

// checkAction is the action a check's row answers: the default ("")
// unless the node chose a stricter one. A once-per-session not-set-up note
// is not about a package and always takes the default row.
func checkAction(c policy.InstallCheck) string {
	if c.Reason == reasonNotSetUp {
		return ""
	}
	switch c.Action {
	case policy.InstallActionAsk, policy.InstallActionDeny:
		return c.Action
	}
	return ""
}

// checkWords renders one check for the verdict detail: the ecosystem and
// the quoted, capped name (the producer already filtered its charset), and
// for a near miss the popular name it resembles.
func checkWords(c policy.InstallCheck) string {
	if c.Reason == reasonTooMany {
		return "more packages than one check holds (the rest were not checked online)"
	}
	s := c.Ecosystem + " " + quoteName(c.Name)
	if c.NearMiss != "" {
		s += " (one edit from " + quoteName(c.NearMiss) + ")"
	}
	return s
}

// quoteName quotes a package name for deny text, capped at 80 bytes (T8).
func quoteName(n string) string {
	if len(n) > 80 {
		n = n[:80] + "..."
	}
	return "\"" + strings.ReplaceAll(n, "\"", "'") + "\""
}
