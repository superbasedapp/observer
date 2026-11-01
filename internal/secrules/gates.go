package secrules

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secposture/gatetable"
)

// The commit gate, S-791 to S-794 (security plan section 4.8 decision
// table, D-761, D-764 Q21, D-791 Q27). Each row matches an agent command
// the git_commit classifier (policy.ClassifyGitWritesCtx, the one entry
// that also reads the daemon's alias table) reads as a commit or a push,
// and a project state:
//
//	S-791 commit, blocking(n) beyond history-only     observe ask, enforce deny
//	S-792 push, blocking(n)                           observe ask, enforce deny
//	S-793 commit or push, dirty, quick scan not clean observe ask, enforce ask
//	S-794 commit or push, unknown                     observe ask, enforce ask
//
// A blocking finding only an unpushed commit holds open (no file holds it
// any more, Security.BlockingHistoryOnly) gates the push and not another
// commit: the commit adds nothing to what the push sends of it, and in a
// repository with no remote the hold never releases, so S-791 would
// otherwise ask on every commit for good (lane sec-gate3 audit finding 2).
// The push gate compares against the push's own target (lane sec-gate4
// milestone 1a): a push whose remote the classifier reads off the command
// (policy.PushTargetFor; a plain `git push` goes to the signed default push
// remote, Security.DefaultPushRemote) and whose remote already has every
// held finding (Security.BlockingHistoryOnlyOn) sends nothing new of them
// and is not gated; any other push, an unknown target included, is. While
// the posture is blocking, S-792 also gates an agent's write to the
// remote-tracking refs or the remote configuration
// (policy.RemoteStateWriteOf, audit finding 3): such a write would make the
// next history pass credit a remote that never received the commit.
// absent and clean match nothing, and dirty with a clean quick scan
// matches nothing (the commit proceeds with no prompt, D-764 Q21). The
// commit gate asks even in observe mode (Observe: ask). Where the host
// cannot show an ask, or the run is headless, the tool gate's per-call
// ask host check withdraws the ask and guard.ResolveEmission turns it into
// a deny naming `observer guard approve` (D-791 Q27): so on such a host
// S-791, S-792 and S-794 deny, and S-793 decides from the quick scan. A
// managed floor raises the rows through the org bundle's overrides, or,
// since lane SEC-P4 decision 9, through the project's signed commit gate
// floor (Security.CommitGateFloor): each row then has a floor twin whose
// decision, in observe and enforce alike, is the section 4.8 table's
// managed-floor cell for the row's state (gatetable.Gate, the one table;
// every other column is unchanged).

// gateAdvice is addressed to the human: the agent is never told to
// approve its own commit (R-165). pushAdvice is S-792's: it names the push
// and the rule, says that dropping the commit (amend, rebase or reset)
// releases the hold only once the reflog no longer reaches it, names the
// step that does that (PushReleaseStep), and says that approving sends the
// held commit, whose secret must then be rotated (merge finding F2 of lane
// SEC-GATE5: the hold follows the reflog since that lane).
const (
	gateAdvice = "Fix or review the finding first; the developer can see it on Code security > Findings and approve this commit there or with `observer guard approve`."
	pushAdvice = "Fix or review the finding first; a secret in a commit stays in it after it is removed from the files, and amending, rebasing or resetting does not release this hold while the reflog still reaches the old commit. After dropping the secret from the commit, release it with " + PushReleaseStep + ". The developer can see it on Code security > Findings and approve this push there or with `observer guard approve S-792`; a push approved this way sends the held commit to the remote named above, so rotate the secret afterwards."
)

// PushReleaseStep is the step that releases S-792's hold on a commit the
// developer dropped (amend, rebase or reset): the hold lasts while any
// reflog entry reaches the commit, 30 days by default, and then while the
// object exists (a dangling commit is still pushable by its id, lane
// SEC-P4 decision 5), so the reflog is expired and the unreachable objects
// pruned, both required. The other release is a push the developer
// approves, which sends the commit.
const PushReleaseStep = "`git reflog expire --expire-unreachable=now --all`, then `git gc --prune=now`"

// gateRow is one row of the commit gate table.
type gateRow struct {
	id       string
	severity policy.Severity
	push     bool // matches pushes; else commits
	both     bool // matches commits and pushes
	state    func(*policy.Security, policy.GitWrite) bool
	enforce  policy.Decision
	doc      string
	advice   string
	// posture is the decision table state the row stands for, read for its
	// managed-floor cell (the floor twin's decision).
	posture policy.SecurityPosture
}

// gateTable is THE commit gate table, one test case per row and cell.
var gateTable = []gateRow{
	{
		id: "S-791", severity: policy.SeverityHigh, state: blockingInTree, enforce: policy.DecisionDeny, posture: policy.SecurityPostureBlocking,
		doc: "agent commit while a new high-confidence finding is open in this project",
	},
	{
		id: "S-792", severity: policy.SeverityHigh, push: true, state: pushBlocking, enforce: policy.DecisionDeny, posture: policy.SecurityPostureBlocking,
		doc: "agent push while a new high-confidence finding is open in this project, or held by a commit the push's remote does not have yet", advice: pushAdvice,
	},
	{
		// Lane LEFT-SEC: every held finding is held only by commits a
		// reflog entry past a [security.scanning] reflog cap reaches. The
		// hold no longer denies, but the push is asked, never allowed; its
		// managed-floor cell is the unknown state's (deny).
		id: "S-792", severity: policy.SeverityHigh, push: true, state: pushHeldPastCap, enforce: policy.DecisionAsk, posture: policy.SecurityPostureUnknown,
		doc: "agent push of a commit held only past a reflog cap (no longer held for a deny; asked, never allowed)", advice: pushAdvice,
	},
	{
		id: "S-793", severity: policy.SeverityWarn, both: true, state: anyWrite(dirtyNotClean), enforce: policy.DecisionAsk, posture: policy.SecurityPostureDirty,
		doc: "agent commit with agent changes that the quick scan did not find clean",
	},
	{
		id: "S-794", severity: policy.SeverityWarn, both: true, state: anyWrite(isUnknown), enforce: policy.DecisionAsk, posture: policy.SecurityPostureUnknown,
		doc: "agent commit while this project's security state is unknown",
	},
}

// anyWrite lifts a state that does not depend on the write.
func anyWrite(f func(*policy.Security) bool) func(*policy.Security, policy.GitWrite) bool {
	return func(s *policy.Security, _ policy.GitWrite) bool { return f(s) }
}

func isBlocking(s *policy.Security) bool { return s.Posture == policy.SecurityPostureBlocking }

// historyOnly: every blocking finding is held open only by an unpushed
// commit. A provider that gave no count, or a capped list, is not (never
// looser).
func historyOnly(s *policy.Security) bool {
	return s.BlockingHistoryOnly > 0 && s.BlockingHistoryOnly >= s.Blocking && !s.Overflow
}

// blockingInTree: blocking, and not every blocking finding is held open
// only by an unpushed commit.
func blockingInTree(s *policy.Security, _ policy.GitWrite) bool {
	return isBlocking(s) && !historyOnly(s)
}

// heldOnTarget: every blocking finding is history-only and the push's
// target, read off the command, already has every one of them.
func heldOnTarget(s *policy.Security, w policy.GitWrite) bool {
	t := policy.PushTargetFor(w, s.DefaultPushRemote)
	return t.Known && historyOnly(s) && s.BlockingHistoryOnlyOn[t.Remote] >= s.Blocking
}

// pushBlocking: blocking, unless the push's own remote already has every
// held finding (lane sec-gate4 milestone 1a), or every held finding is held
// only past a reflog cap (pushHeldPastCap decides that one).
func pushBlocking(s *policy.Security, w policy.GitWrite) bool {
	return isBlocking(s) && !heldOnTarget(s, w) && !heldPastCap(s)
}

// heldPastCap: every blocking finding is history-only and held only by
// commits reached past a reflog cap (Security.BlockingHistoryCapped).
func heldPastCap(s *policy.Security) bool {
	return historyOnly(s) && s.BlockingHistoryCapped >= s.Blocking
}

// pushHeldPastCap: blocking, every held finding held only past a reflog
// cap, and the push's own remote does not have them all.
func pushHeldPastCap(s *policy.Security, w policy.GitWrite) bool {
	return isBlocking(s) && heldPastCap(s) && !heldOnTarget(s, w)
}

// isUnknown: the zero posture is treated as unknown (the contract's rule:
// a provider that gave no state is never clean).
func isUnknown(s *policy.Security) bool {
	return s.Posture == policy.SecurityPostureUnknown || s.Posture == ""
}

// dirtyNotClean: unscanned agent changes whose quick scan found something,
// did not finish, or did not run.
func dirtyNotClean(s *policy.Security) bool {
	return s.Posture == policy.SecurityPostureDirty && s.QuickScan != policy.QuickScanClean
}

// remoteStateAdvice is the advice of S-792's remote-state row.
const remoteStateAdvice = "While a blocking finding is open the push gate credits a remote only from its own remote-tracking refs and URLs, so an agent does not write them. Fix or review the finding first; the developer can see it on Code security > Findings and approve this command there or with `observer guard approve S-792`."

// remoteStateMatch is S-792's remote-state row: an agent write to the
// remote-tracking refs or the remote configuration while the posture is
// blocking.
func remoteStateMatch(ctx *policy.MatchContext) (bool, string) {
	st := ctx.Event.Security
	if st == nil || !isBlocking(st) {
		return false, ""
	}
	ok, detail := policy.RemoteStateWriteOf(ctx)
	if !ok {
		return false, ""
	}
	return true, detail + " (" + stateWords(st) + ")"
}

// GateRules returns the commit gate rows. They read Event.Security, which
// the hook context seam fills; an event without it (the module inactive,
// a path the seam does not fill) matches nothing.
func GateRules() []policy.Rule {
	out := make([]policy.Rule, 0, 2*len(gateTable)+1)
	for _, r := range gateTable {
		row := r
		out = append(out, policy.Rule{
			ID: row.id, Category: policy.CategoryCodeSecurity, Severity: row.severity,
			AppliesTo: []policy.EventKind{policy.KindShellExec, policy.KindMCPCall},
			Match:     gateMatch(row, false),
			Observe:   policy.DecisionAsk,
			Enforce:   row.enforce,
			Doc:       row.doc,
			Advice:    adviceFor(row),
			Source:    policy.SourcePackSecurity,
		})
	}
	// The floor twins (lane SEC-P4 decision 9): matched only under the
	// project's commit gate floor, deciding by the managed-floor cell. A
	// dirty row's cell waits for the quick scan, which the row only matches
	// when it was not clean, so the cell is resolved as not clean.
	for _, r := range gateTable {
		row := r
		d, ok := gatetable.FloorDecision(gatetable.AfterQuickScan(gatetable.Gate(row.posture, gatetable.GateManagedFloor), policy.QuickScanUnknown))
		if !ok {
			continue
		}
		out = append(out, policy.Rule{
			ID: row.id, Category: policy.CategoryCodeSecurity, Severity: row.severity,
			AppliesTo: []policy.EventKind{policy.KindShellExec, policy.KindMCPCall},
			Match:     gateMatch(row, true),
			Observe:   d,
			Enforce:   d,
			Doc:       row.doc + " (the org's commit gate floor)",
			Advice:    adviceFor(row),
			Source:    policy.SourcePackSecurity,
		})
	}
	out = append(out, policy.Rule{
		ID: "S-792", Category: policy.CategoryCodeSecurity, Severity: policy.SeverityHigh,
		AppliesTo: []policy.EventKind{policy.KindShellExec, policy.KindFileAccess, policy.KindConfigChange},
		Match:     remoteStateMatch,
		Observe:   policy.DecisionAsk,
		Enforce:   policy.DecisionDeny,
		Doc:       "agent write to the remote-tracking refs or the remote configuration while a new high-confidence finding is open in this project",
		Advice:    remoteStateAdvice,
		Source:    policy.SourcePackSecurity,
	})
	return out
}

// adviceFor is the row's advice: its own, else gateAdvice.
func adviceFor(row gateRow) string {
	if row.advice != "" {
		return row.advice
	}
	return gateAdvice
}

// gateMatch returns the row's matcher: a gating commit or push intent, and
// the row's state. floor selects the row's floor twin: it matches only
// under the commit gate floor, and the plain row only without it.
func gateMatch(row gateRow, floor bool) policy.MatchFn {
	return func(ctx *policy.MatchContext) (bool, string) {
		st := ctx.Event.Security
		if st == nil || st.Posture == policy.SecurityPostureAbsent {
			return false, ""
		}
		if (st.CommitGateFloor == policy.CommitGateFloorQuickScan) != floor {
			return false, ""
		}
		for _, c := range policy.ClassifyGitWritesCtx(ctx) {
			if !policy.GitWriteGates(c.Write) || (!row.both && policy.GitWriteIsPush(c.Write) != row.push) {
				continue
			}
			// The first write of the row's kind whose state matches
			// decides: a line with two pushes is gated by either.
			if !row.state(st, c.Write) {
				continue
			}
			words := stateWords(st)
			if row.push {
				words += heldWords(st, c.Write)
			}
			return true, c.Detail + " (" + words + ")"
		}
		return false, ""
	}
}

// maxHeldNamed bounds the held commits the push wording names.
const maxHeldNamed = 3

// heldWords names, for a push gated by a history-only hold, the held
// commits the push's remote does not have yet and the remote (lane
// sec-gate4 milestone 3a), "" when there is nothing to name.
func heldWords(s *policy.Security, w policy.GitWrite) string {
	if s.BlockingHistoryOnly == 0 || len(s.HeldCommits) == 0 {
		return ""
	}
	t := policy.PushTargetFor(w, s.DefaultPushRemote)
	var names []string
	more := 0
	for _, h := range s.HeldCommits {
		if t.Known && containsRemote(h.Remotes, t.Remote) {
			continue
		}
		if len(names) == maxHeldNamed {
			more++
			continue
		}
		names = append(names, shortCommit(h.Commit))
	}
	if len(names) == 0 {
		return ""
	}
	which := "commit " + names[0]
	if len(names) > 1 {
		which = "commits " + strings.Join(names, ", ")
	}
	if more > 0 {
		which += " and " + itoa(more) + " more"
	}
	if !t.Known {
		return "; held by " + which + ", and this push's remote cannot be read off the command (or the command line may change where it goes), so it is treated as not having them"
	}
	return "; held by " + which + ", not on remote " + t.Remote + " yet"
}

func containsRemote(rs []string, r string) bool {
	for _, x := range rs {
		if x == r {
			return true
		}
	}
	return false
}

// shortCommit is a commit id's first 12 characters.
func shortCommit(c string) string {
	if len(c) > 12 {
		return c[:12]
	}
	return c
}

// daemonStoppedWords is the state text while the daemon is stopped: the
// commit gate still asks (a stopped daemon never silences it), and says
// why and what to do.
const daemonStoppedWords = "the Observer daemon is not running, so this project's security state cannot be checked; start it with `observer start`"

// stateWords renders a gate state for the verdict detail.
func stateWords(s *policy.Security) string {
	if s.DaemonStopped && (s.Posture == policy.SecurityPostureUnknown || s.Posture == "" ||
		(s.Posture == policy.SecurityPostureDirty && s.QuickScan != policy.QuickScanClean && s.QuickScan != policy.QuickScanBlocking)) {
		return daemonStoppedWords
	}
	switch s.Posture {
	case policy.SecurityPostureBlocking:
		if s.Blocking > 0 {
			if s.BlockingHistoryOnly > 0 {
				return "open blocking findings: " + itoa(s.Blocking) + ", " + itoa(s.BlockingHistoryOnly) + " only in unpushed commits"
			}
			return "open blocking findings: " + itoa(s.Blocking)
		}
		return "open blocking findings"
	case policy.SecurityPostureDirty:
		switch s.QuickScan {
		case policy.QuickScanBlocking:
			return "the quick scan found a blocking finding in the changes"
		case policy.QuickScanUnknown:
			return "the quick scan did not finish"
		default:
			return "the changes have not been scanned"
		}
	case policy.SecurityPostureUnknown, "":
		return "the security posture is unknown"
	}
	return string(s.Posture)
}

func itoa(n int) string {
	if n <= 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
