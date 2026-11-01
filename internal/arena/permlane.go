package arena

import (
	"context"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// permlane.go: which permission lane an unattended drive runs in
// (OSH-R-005). Nobody answers a prompt during a drive, so the lane is the
// standing answer to "may the agent act without asking". The registry row
// says what each lane is on argv (integration.HeadlessSpec.Permissions);
// this file says which lane a drive may use.

// driveRole names why a harness is being driven. The zero value is a
// candidate, so a request that names no role gets the candidate rules.
type driveRole int

const (
	// roleCandidate: a candidate solving the run's task in its own worktree.
	roleCandidate driveRole = iota
	// roleJudge: the judge scoring a patch it reads from its prompt, in an
	// emptied scratch directory. It needs no tools.
	roleJudge
	// roleMerge: the judge_merge keep, merging a candidate branch and
	// committing in an isolated keep worktree.
	roleMerge
)

// lanePreference is one role's ordered lane lists, walked top-down: the
// first lane the tool's registry row grounds wins. withBypass applies when
// permission skipping is allowed for the drive, withoutBypass otherwise.
type lanePreference struct {
	withBypass    []integration.HeadlessPermLane
	withoutBypass []integration.HeadlessPermLane
}

// laneTable is the decision table (CLAUDE.md #5). A candidate and a merge
// keep the pre-fix bypass behaviour only where it is allowed; the judge is
// never driven with permissions skipped, allowed or not.
var laneTable = map[driveRole]lanePreference{
	roleCandidate: {
		withBypass:    []integration.HeadlessPermLane{integration.HeadlessPermBypass, integration.HeadlessPermEdit},
		withoutBypass: []integration.HeadlessPermLane{integration.HeadlessPermEdit},
	},
	// The judge_merge keep must run git merge, add and commit. No grounded
	// lane keeping the harness's checks on allows that (claude acceptEdits
	// refuses Bash headless; codex workspace-write cannot write a linked
	// worktree's gitdir, which lives under the main repository's .git), so
	// it runs only in the bypass lane and is otherwise refused up front
	// (audit F3) instead of ending in "judge landed no commit".
	roleMerge: {
		withBypass:    []integration.HeadlessPermLane{integration.HeadlessPermBypass},
		withoutBypass: nil,
	},
	roleJudge: {
		withBypass:    []integration.HeadlessPermLane{integration.HeadlessPermReadOnly, integration.HeadlessPermEdit},
		withoutBypass: []integration.HeadlessPermLane{integration.HeadlessPermReadOnly, integration.HeadlessPermEdit},
	},
}

// refusal is why a lane could not be picked: the tool has a skip lane but
// skipping is not allowed here, or it has no lane the role may use at all.
type refusal int

const (
	refusalSkipNotAllowed refusal = iota
	refusalNoLane
)

// roleHints add the way forward to a refusal for a role, per refusal
// kind, when there is one. The setting only helps a harness that HAS a
// skip mode; for one that has none (codex as the merge judge) the way
// forward is another judge or a squash keep (audit round 3).
var roleHints = map[driveRole]map[refusal]string{
	roleMerge: {
		refusalSkipNotAllowed: "; the judge_merge keep has to run git merge, add and commit, which only the skip mode allows: set [benchmark] arena_allow_skip_permissions = true, or keep the candidate with squash",
		refusalNoLane:         "; the judge_merge keep has to run git merge, add and commit, which only a harness's skip mode allows and this harness has none: pick a merge judge that has one (claude-code, grok, aider or opencode), or keep the candidate with squash",
	},
}

// roleNames are the words a refusal uses for a role.
var roleNames = map[driveRole]string{
	roleCandidate: "candidate",
	roleJudge:     "judge",
	roleMerge:     "judge_merge keep",
}

// BypassDecision is the answer to "may this drive skip the harness's own
// permission checks". Why is the plain-language reason when it may not; it
// lands in the refusal the operator reads.
type BypassDecision struct {
	Allowed bool
	Why     string
}

// noBypassPolicy is the reason when a Runner was built without a policy
// callback: the standalone engine never skips permissions.
const noBypassPolicy = "no permission policy is wired into this Arena runner"

// bypassFor asks the Runner's policy whether a drive of tool may skip
// permissions. A Runner with no policy callback answers no.
func (r *Runner) bypassFor(ctx context.Context, tool string) BypassDecision {
	if r == nil || r.opts.PermissionBypass == nil {
		return BypassDecision{Why: noBypassPolicy}
	}
	return r.opts.PermissionBypass(ctx, tool)
}

// permissionArgs picks the lane for one drive and returns its argv tokens.
// A tool with no grounded lane the role may use is refused with the reason
// in words, never driven with a guessed flag.
func permissionArgs(spec *integration.HeadlessSpec, tool string, role driveRole, bypass BypassDecision) (integration.HeadlessPermLane, []string, error) {
	pref, ok := laneTable[role]
	if !ok {
		return "", nil, fmt.Errorf("arena: unknown drive role %d", role)
	}
	lanes := pref.withoutBypass
	if bypass.Allowed {
		lanes = pref.withBypass
	}
	if spec != nil {
		for _, lane := range lanes {
			if args, grounded := spec.Permissions[lane]; grounded {
				return lane, append([]string(nil), args...), nil
			}
		}
	}
	if !bypass.Allowed && spec != nil && role != roleJudge {
		if _, grounded := spec.Permissions[integration.HeadlessPermBypass]; grounded {
			why := bypass.Why
			if why == "" {
				why = "permission skipping is not allowed"
			}
			return "", nil, fmt.Errorf("arena: %s %q runs unattended only with its own permission checks skipped, and that is not allowed here: %s%s", roleNames[role], tool, why, roleHints[role][refusalSkipNotAllowed])
		}
	}
	return "", nil, fmt.Errorf("arena: %s %q has no grounded unattended mode a %s may run in%s", roleNames[role], tool, roleNames[role], roleHints[role][refusalNoLane])
}
