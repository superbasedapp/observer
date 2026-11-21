package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/policyfam"
	policyfamadmission "github.com/marmutapp/superbased-observer/internal/policyfam/admission"
	"github.com/marmutapp/superbased-observer/internal/policyfam/planebadmission"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// planeb_admission_status.go is the `observer guard status` view of the
// organization's coding-agent prompt judge (P-228 design P1b; fix round 1).
// The CLI never shares the daemon's memory, so it reads what is durable: the
// grant, this machine's [org_client.policy] lists, the signature-verified
// cached planeb.admission body, whether this build links the admission
// engine, and the last day's J-801 guard_events rows.

// planeBStatusFacts is what the status line is rendered from.
type planeBStatusFacts struct {
	Managed       bool
	HoldsEnforce  bool
	Accepted      bool
	HavePolicy    bool
	Version       int64
	Spec          planebadmission.PolicySpec
	EngineLinked  bool
	PolicyProblem string
	// Preauthorized is planeb.admission in preauthorize_enforce: with a
	// strict enforce policy, a prompt-gate hook that cannot reach the daemon
	// refuses the prompt.
	Preauthorized bool
	// Counts is the last day's J-801 rows by decision (deny, flag).
	Counts map[string]int
}

// planeBOffReason is one row of the "why is it off" table, walked top-down.
type planeBOffReason struct {
	off    func(planeBStatusFacts) bool
	reason func(planeBStatusFacts) string
}

var planeBOffReasons = []planeBOffReason{
	{func(f planeBStatusFacts) bool { return !f.Managed }, func(planeBStatusFacts) string { return "not a managed node; the organization cannot turn it on here" }},
	{func(f planeBStatusFacts) bool { return !f.HoldsEnforce }, func(planeBStatusFacts) string { return "your grant does not hold enforce.admission" }},
	{func(f planeBStatusFacts) bool { return !f.Accepted }, func(planeBStatusFacts) string {
		return "planeb.admission is not in [org_client.policy] accept_families"
	}},
	{func(f planeBStatusFacts) bool { return f.PolicyProblem != "" }, func(f planeBStatusFacts) string {
		return "the cached organization policy cannot be read: " + f.PolicyProblem
	}},
	{func(f planeBStatusFacts) bool { return !f.HavePolicy }, func(planeBStatusFacts) string { return "no organization policy received yet" }},
	{func(f planeBStatusFacts) bool { return !f.Spec.NodeLane }, func(f planeBStatusFacts) string {
		return fmt.Sprintf("policy v%d judges at the AI gateway only (node_lane is off)", f.Version)
	}},
	{func(f planeBStatusFacts) bool { return f.Spec.Admission.Mode == policyfamadmission.ModeOff }, func(f planeBStatusFacts) string {
		return fmt.Sprintf("policy v%d mode is off", f.Version)
	}},
}

// planeBOffReasonFor returns the first reason the judge is off, or "" when it
// is on (the planeBOffReasons table, top-down).
func planeBOffReasonFor(f planeBStatusFacts) string {
	for _, r := range planeBOffReasons {
		if r.off(f) {
			return r.reason(f)
		}
	}
	return ""
}

// planeBJudgeRoute names where the judge's call goes.
func planeBJudgeRoute(f planeBStatusFacts) string {
	if planebadmission.RequiresJudge(f.Spec) {
		return "the organization's server (judge relay, purpose coding_admission)"
	}
	return "deterministic layers only (no judge call)"
}

// planeBUnreachableText is what a prompt-gate hook does when the daemon
// cannot answer: the same rule the hook applies (promptJudgeStateFromFacts).
func planeBUnreachableText(f planeBStatusFacts) string {
	if _, failClosed := promptJudgeStateFromFacts(f); failClosed {
		return "the prompt is refused (strict, enforced)"
	}
	return "the prompt goes through (recorded)"
}

// planeBNoEngineLine is the warning for a build without the admission engine.
const planeBNoEngineLine = "this build has no admission engine, so prompts are flagged (refused under a strict enforce policy), never evaluated"

// planeBGuardStatusLines renders the prompt judge's status lines.
func planeBGuardStatusLines(f planeBStatusFacts) []string {
	var lines []string
	if reason := planeBOffReasonFor(f); reason != "" {
		lines = append(lines, "Prompt judge: off ("+reason+")")
	} else {
		lines = append(lines, fmt.Sprintf("Prompt judge: on (policy v%d, scope %s, node_lane on, mode %s, strict %t), judge route: %s",
			f.Version, f.Spec.Scope, f.Spec.Admission.Mode, f.Spec.Admission.Strict, planeBJudgeRoute(f)))
		if !f.EngineLinked {
			lines = append(lines, "Prompt judge: "+planeBNoEngineLine)
		}
		// The hook lane (adm-2 fixes-1, H3): the same rule the hook applies
		// without a daemon (promptJudgeStateFromFacts), so this line says
		// what runs.
		lines = append(lines, "Prompt judge: every prompt-gate hook asks it, whatever the local [guard] / [guard.prompt] settings say; when the daemon cannot answer, "+planeBUnreachableText(f))
	}
	if len(f.Counts) > 0 {
		lines = append(lines, "Prompt judge (24h): "+planeBCountsText(f.Counts))
	}
	return lines
}

// planeBCountsText renders decision counts as "deny=2 flag=5" in a stable
// order.
func planeBCountsText(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+strconv.Itoa(m[k]))
	}
	return strings.Join(parts, " ")
}

// loadPlaneBStatusFacts gathers the facts from the store and config. Every
// read failure leaves the matching fact at its zero value (the line then says
// "off" for the first missing reason), except a cached body that does not
// verify, which is reported as such.
func loadPlaneBStatusFacts(ctx context.Context, cfg config.Config, st *store.Store, now time.Time) planeBStatusFacts {
	f := planeBStatusFacts{EngineLinked: codingAdmissionEngine != nil}
	if managed, err := orgclient.NodeManaged(ctx, st); err == nil {
		f.Managed = managed
	}
	if loader := governanceIdentityLoader(st); loader != nil {
		if grant, _, err := loader(ctx); err == nil && grant != nil {
			f.HoldsEnforce = containsString(govern.AuthorityEnforceAdmission, grant.Authority)
		}
	}
	f.Accepted = containsString(policyfam.FamilyPlaneBAdmission, cfg.OrgClient.Policy.AcceptedFamilies())
	f.Preauthorized = containsString(policyfam.FamilyPlaneBAdmission, cfg.OrgClient.Policy.PreauthorizedFamilies())
	f.HavePolicy, f.Version, f.Spec, f.PolicyProblem = loadCachedPlaneBAdmission(ctx, cfg, st)
	if rows, err := st.LoadRecentGuardEvents(ctx, now.Add(-24*time.Hour), 5000); err == nil {
		for _, r := range rows {
			if r.RuleID != planeBPromptJudgeRuleID {
				continue
			}
			if f.Counts == nil {
				f.Counts = map[string]int{}
			}
			f.Counts[r.Decision]++
		}
	}
	return f
}

// loadCachedPlaneBAdmission reads the signature-verified cached
// planeb.admission body for the live enrolment. have=false with no problem
// means nothing is cached.
func loadCachedPlaneBAdmission(ctx context.Context, cfg config.Config, st *store.Store) (have bool, version int64, spec planebadmission.PolicySpec, problem string) {
	enr, err := st.LoadEnrolment(ctx)
	if err != nil || enr == nil {
		return false, 0, spec, ""
	}
	orgKey := orgclient.OrgKey(enr.OrgServerURL, enr.OrgID)
	gen, has, err := st.LoadEnrolmentGeneration(ctx, orgKey)
	if err != nil || !has || gen.Tombstoned {
		return false, 0, spec, ""
	}
	family := policyfam.FamilyPlaneBAdmission
	path := filepath.Join(policyResourceCacheDir(cfg), orgKey, strconv.FormatInt(gen.Generation, 10), family+".json")
	if _, statErr := os.Stat(path); statErr != nil {
		return false, 0, spec, ""
	}
	cached, err := verifyCachedPolicyResource(ctx, st, enr.OrgServerURL, family, path, policyResourceNodeAttrs(cfg))
	if err != nil {
		return false, 0, spec, err.Error()
	}
	s, ok := cached.spec.(planebadmission.PolicySpec)
	if !ok {
		return false, 0, spec, ""
	}
	return true, cached.resource.Version, s, ""
}
