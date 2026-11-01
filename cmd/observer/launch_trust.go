//go:build !sbo_omit_security && !sbo_omit_security_trust

package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/term"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secrules"
	"github.com/marmutapp/superbased-observer/internal/sectrust"
	"github.com/marmutapp/superbased-observer/internal/sectrustitem"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// launch_trust.go is the repository trust row of the launch-gate table
// (security pillar plan section 5.1, security Phase B; the repo.trust row
// of launch_gates.go). Before an agent starts, it runs the repository trust
// check (internal/sectrust) at the repository root and the launch
// directory, reads the developer's accepted digests (internal/store
// sectrust.go), and sends the verdict to Guard as an agent_launch event
// whose Event.Security carries it; the trust rules S-701 to S-705
// (internal/secrules) decide. Observe mode warns; enforce asks or refuses.
//
// It is inert unless the security.trust component is active under the
// optional-module predicate (componentstate.Snapshot.ModuleActive, fail
// invisible) and the guard is on.

// repoTrustComponent is the node component that owns the row.
const repoTrustComponent = "security.trust"

// repoTrustDeps is what the row needs from its launch path. A nil value
// leaves the row inert.
type repoTrustDeps struct {
	// mode is the guard mode the trust rules evaluate under.
	mode policy.Mode
	// disabled are the [guard.rules].disable ids.
	disabled []string
	// store reads accepted digests and records what the check raised; nil
	// reads none and records nothing.
	store *store.Store
	// ask asks the developer at the launch terminal and reports the answer;
	// nil means this launch cannot ask, so an ask refuses (the D-791 Q27
	// headless outcome).
	ask func(question string) bool
	// now stamps recorded items; nil means time.Now.
	now func() time.Time
	// acceptRootHash, when set, is the project-root hash whose accepts this
	// launch honours instead of its own: a sandboxed launch in a managed
	// clone of a repository checks the accepts the developer gave the
	// source repository (repoTrustSourceEnv).
	acceptRootHash string
	// acceptRoot, when set, is the directory of acceptRootHash: where an
	// unattended refusal tells the developer to accept (an Arena run's
	// source, a benchmark task's source repository).
	acceptRoot string
	// recordOwnRoot records what the check raised under the checked
	// directory's own hash rather than acceptRootHash: an Arena worktree or
	// a benchmark workspace holds what an agent wrote, which must not land
	// in the source repository's list (accepts are still read from the
	// source).
	recordOwnRoot bool
	// answer, when set, asks at the launch terminal and returns the answer
	// line ("" when none came): the ask then offers an accept answer for
	// items that carry a digest (repoTrustAskAnswer). Nil keeps ask's
	// yes/no question.
	answer func(question string) string
	// packs is the active pack set the launch's event carries
	// (Event.Security.Packs); empty means only security.trust.
	packs []string
	// trustFloor reads the org's require.prelaunch_trust floor signed into
	// a project's posture (lane SEC-P4 decision 9): the launch's trust step
	// is raised to it, never lowered. Nil (or "") raises nothing.
	trustFloor func(root string) string
	// unattended marks a launch the daemon started itself: nobody can be
	// asked, and an ask's refusal says where to accept instead.
	unattended bool
	// skip, when set, is why this launch is not checked: the row only says
	// so as a warning (daemonLaunch.trustSkip).
	skip string
	// advice, when set, is what an unattended refusal tells the developer
	// to do instead of accepting a directory (daemonLaunch.trustAdvice).
	advice string
	// guard builds the node guard the decision runs through; nil uses an
	// engine of the composed trust rules alone (decideRepoTrust).
	guard func() *guard.Guard
	// hostPins are the plugin host's pinned OBSERVER_BIN and
	// OBSERVER_CONFIG on a managed node (nil elsewhere), and hostEnv
	// reads the launch environment.
	hostPins map[string]string
	hostEnv  func(string) string
	// paths is the trust path table the check reads and devcontainer the
	// parser for its devcontainer rows, both from repoTrustConditional, the
	// one seam every trust surface reads (this launch gate, the dashboard
	// trust review and `observer security trust check`). Since the N2
	// ruling (P-108) the initializeCommand row holds on every install, so
	// paths is never the default table; the full devcontainer row is added
	// where the container sandbox is active.
	paths        []agentconfig.TrustPath
	devcontainer sectrust.DevcontainerParser
	// localStep is the node's own [security.trust] prelaunch ("ask", or
	// "" for the default "warn": the guard mode decides; lane LEFT-SEC):
	// applied before the org floor, raise only, so it never lowers it.
	localStep string
}

// newRepoTrustDeps builds the row's dependencies for one launch, or nil
// when the component is inactive or the guard is off.
func newRepoTrustDeps(cfg config.Config, snap componentstate.Snapshot, st *store.Store, ask func(string) bool) *repoTrustDeps {
	if !repoTrustSelected(snap) || !repoTrustGuardOn(cfg) {
		return nil
	}
	mode, err := policy.ParseMode(modeOrDefaultGuard(cfg.Guard.Mode))
	if err != nil {
		return nil
	}
	deps := &repoTrustDeps{
		mode: mode, disabled: cfg.Guard.Rules.Disable, store: st, ask: ask,
		packs: securityActivePacks(snap),
	}
	deps.paths, deps.devcontainer = repoTrustConditional(cfg, snap)
	deps.acceptRootHash, deps.acceptRoot = cliRepoTrustAcceptRoot()
	if deps.acceptRoot != "" {
		// A benchmark attempt's inner launcher: nobody answers it, and the
		// accept that helps is the task source's.
		deps.unattended, deps.recordOwnRoot = true, true
	}
	deps.guard = func() *guard.Guard { return repoTrustGuard(context.Background(), cfg, st, snap) }
	deps.trustFloor = repoTrustFloorReader(daemonConfigPath())
	deps.localStep = repoTrustLocalStep(cfg.Security.Trust)
	if repoTrustManaged(st) {
		deps.hostPins, deps.hostEnv = repoTrustHostPins(daemonConfigPath()), os.Getenv
	}
	return deps
}

// cliRepoTrustDeps are the row's dependencies for an `observer <tool>`
// launch at its own terminal: the y/N ask and the answer line that offers
// an accept (repoTrustAskAnswer), both nil when stdin and stderr are not
// terminals.
func cliRepoTrustDeps(cfg config.Config, snap componentstate.Snapshot, st *store.Store, stderr io.Writer) *repoTrustDeps {
	deps := newRepoTrustDeps(cfg, snap, st, terminalAsk(os.Stdin, stderr))
	if deps != nil && deps.ask != nil {
		deps.answer = terminalAnswer(os.Stdin, stderr)
	}
	return deps
}

// repoTrustSelected is the one switch of the component's daemon and
// launch work (the launch row, the baseline loop, the session-start flag):
// security.trust selected under securitySelected (security_optin.go). It
// is offered (plans decision log P-044): active with no [components] block,
// off when a block leaves it out.
func repoTrustSelected(snap componentstate.Snapshot) bool {
	return securitySelected(snap, repoTrustComponent)
}

// dashboardRepoTrust is the dashboard launch path's dependencies, built
// fresh for every launch from the current config, so a guard mode change,
// a [guard.rules] edit or a component change binds on the next launch with
// no daemon restart (plans decision log P-004). Its ask defers to the inner
// `observer <tool>` launcher the PTY runs, which walks the row again and
// asks in that terminal (an enforce-mode deny still refuses here, before
// the PTY starts).
func dashboardRepoTrust(cfg config.Config, database *sql.DB) func() *repoTrustDeps {
	var st *store.Store
	if database != nil {
		st = store.New(database)
	}
	path, _ := config.ResolveGlobalPath(daemonConfigPath())
	live := newLiveTrustConfig(cfg, path)
	return func() *repoTrustDeps {
		cur := live.current()
		return newRepoTrustDeps(cur, componentSnapshotForConfig(cur), st, func(string) bool { return true })
	}
}

// liveTrustConfig follows config.toml for the dashboard's trust row: the
// boot-time config, reloaded when the file's stamp (modification time and
// size) moves, the same trigger the terminal config holder uses. A file
// that does not load keeps the last good config.
type liveTrustConfig struct {
	path string
	load func(string) (config.Config, error)

	mu      sync.Mutex
	cfg     config.Config
	mod     time.Time
	size    int64
	stamped bool
}

func newLiveTrustConfig(cfg config.Config, path string) *liveTrustConfig {
	l := &liveTrustConfig{path: strings.TrimSpace(path), cfg: cfg, load: func(p string) (config.Config, error) {
		return config.Load(config.LoadOptions{GlobalPath: p})
	}}
	if fi, err := os.Stat(l.path); l.path != "" && err == nil {
		l.mod, l.size, l.stamped = fi.ModTime(), fi.Size(), true
	}
	return l
}

// current returns the config, reloading it first when the file changed.
func (l *liveTrustConfig) current() config.Config {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.path == "" {
		return l.cfg
	}
	fi, err := os.Stat(l.path)
	if err != nil || (l.stamped && fi.ModTime().Equal(l.mod) && fi.Size() == l.size) {
		return l.cfg
	}
	cfg, err := l.load(l.path)
	if err != nil {
		return l.cfg
	}
	l.cfg, l.mod, l.size, l.stamped = cfg, fi.ModTime(), fi.Size(), true
	return l.cfg
}

// modeOrDefaultGuard is the guard mode with the documented default.
func modeOrDefaultGuard(m string) string {
	if strings.TrimSpace(m) == "" {
		return string(policy.ModeObserve)
	}
	return m
}

// terminalAsk asks on the launch terminal when both stdin and stderr are
// terminals; it returns nil otherwise (a launch that cannot ask). The ask
// waits at most repoTrustAskWait for an answer and then refuses (boundedAsk),
// so an unattended terminal (an Agent Arena or benchmark run, a dashboard
// terminal nobody is watching) never blocks on the question.
func terminalAsk(in *os.File, out io.Writer) func(string) bool {
	if !askTerminals(in, out) {
		return nil
	}
	return boundedAsk(in, out, repoTrustAskWait)
}

// terminalAnswer is terminalAsk's question with the accept answer
// (repoTrustAskAnswer): it returns the answer line, "" when none came, or
// nil when stdin and stderr are not both terminals.
func terminalAnswer(in *os.File, out io.Writer) func(string) string {
	if !askTerminals(in, out) {
		return nil
	}
	return boundedAnswer(in, out, repoTrustAskWait, "[y/a/N]")
}

// askTerminals reports whether in and out are both terminals.
func askTerminals(in *os.File, out io.Writer) bool {
	if in == nil || !term.IsTerminal(int(in.Fd())) {
		return false
	}
	f, ok := out.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// repoTrustAskWait is how long a launch-terminal question waits for its
// answer before it refuses.
const repoTrustAskWait = 2 * time.Minute

// askReader is the one pending answer read of this process: a question that
// timed out leaves its read waiting on the terminal, and a later question
// takes over that read instead of starting a second reader that would race
// it for the developer's keystrokes.
var askReader struct {
	mu      sync.Mutex
	pending chan string
}

// boundedAsk asks question on out and reads one answer line from in,
// refusing (false) when no answer arrives within wait. A refusal says why on
// out, so the launch's refusal is never a silent hang.
func boundedAsk(in io.Reader, out io.Writer, wait time.Duration) func(string) bool {
	answer := boundedAnswer(in, out, wait, "[y/N]")
	return func(question string) bool { return yesAnswer(answer(question)) }
}

// boundedAnswer asks question on out, with choices after it, and returns
// one answer line read from in, or "" when no answer arrives within wait
// (saying so on out).
func boundedAnswer(in io.Reader, out io.Writer, wait time.Duration, choices string) func(string) string {
	return func(question string) string {
		fmt.Fprintf(out, "%s %s (waits %s) ", question, choices, wait)
		askReader.mu.Lock()
		ch := askReader.pending
		if ch == nil {
			ch = make(chan string, 1)
			askReader.pending = ch
			go func() { ch <- readAnswerLine(in) }()
		}
		askReader.mu.Unlock()
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case line := <-ch:
			askReader.mu.Lock()
			askReader.pending = nil
			askReader.mu.Unlock()
			return line
		case <-timer.C:
			fmt.Fprintf(out, "\nno answer within %s: refused\n", wait)
			return ""
		}
	}
}

// maxAnswerBytes bounds one typed answer.
const maxAnswerBytes = 256

// readAnswerLine reads one answer line from r a byte at a time, so nothing
// after the newline is consumed: keystrokes typed ahead stay in the
// terminal for the agent the launch starts (a buffered reader would
// swallow them; plans decision log P-004).
func readAnswerLine(r io.Reader) string {
	var line []byte
	b := make([]byte, 1)
	for len(line) < maxAnswerBytes {
		n, err := r.Read(b)
		if n == 1 {
			if b[0] == '\n' {
				break
			}
			line = append(line, b[0])
		}
		if err != nil {
			break
		}
	}
	return string(line)
}

// yesAnswer reports whether an answer line says yes.
func yesAnswer(line string) bool { return askAnswerOf(line) == askAnswerYes }

// askAnswerKind is what an answer line at the trust ask says.
type askAnswerKind int

const (
	// askAnswerNo refuses (the default: anything not below).
	askAnswerNo askAnswerKind = iota
	// askAnswerYes lets this one launch go on and records nothing.
	askAnswerYes
	// askAnswerAccept records the accept of the items shown and lets the
	// launch go on.
	askAnswerAccept
)

// askAnswers is the answer table, by the trimmed, lower-cased line.
var askAnswers = map[string]askAnswerKind{
	"y": askAnswerYes, "yes": askAnswerYes,
	"a": askAnswerAccept, "accept": askAnswerAccept,
}

// askAnswerOf reads one answer line.
func askAnswerOf(line string) askAnswerKind {
	return askAnswers[strings.ToLower(strings.TrimSpace(line))]
}

// repoTrustAskAnswer asks at the launch terminal for one ask decision and
// reports whether the launch goes on. When the launch can answer with a
// line (deps.answer), records accepts (deps.store) and the check reports
// items with a digest not yet accepted, the question lists them and offers
// "a": accept them, recorded as the CLI and the dashboard record an accept
// (who and when), and launch. "y" stays a pass for this one launch. Any
// other answer, or none, refuses. Without an answer line the plain y/N ask
// (deps.ask) decides.
func repoTrustAskAnswer(out repoTrustOutcome, deps *repoTrustDeps, tool, msg string) bool {
	question := fmt.Sprintf("observer %s: repository trust: %s", tool, msg)
	var items []store.SecTrustItem
	var picked []sectrust.Reason
	if deps.answer != nil && deps.store != nil && out.acceptHash != "" {
		if p, err := out.result.Select(nil, true); err == nil {
			picked, items = p, sectrustitem.FromReasons(p)
		}
	}
	if len(items) == 0 {
		return deps.ask != nil && deps.ask(question+"\nLaunch anyway?")
	}
	var b strings.Builder
	b.WriteString(question)
	fmt.Fprintf(&b, "\n%d item(s) can be accepted in %s:", len(items), terminalSafe(out.target.root))
	for _, r := range picked {
		if r.Digest != "" {
			b.WriteString(trustReviewLines(r))
		}
	}
	b.WriteString("\nLaunch anyway? y = this launch only, a = accept these items (asked again only when one changes), N = refuse")
	switch askAnswerOf(deps.answer(b.String())) {
	case askAnswerYes:
		return true
	case askAnswerAccept:
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		now := time.Now
		if deps.now != nil {
			now = deps.now
		}
		if _, err := deps.store.AcceptSecTrustItems(ctx, out.acceptHash, items, trustAcceptor("terminal"), now()); err != nil {
			// The accept did not record: refuse rather than launch on an
			// accept that is not there.
			return false
		}
		return true
	default:
		return false
	}
}

// trustReviewLines is one item of the terminal question, worded as the
// dashboard's review panel words it (web/src/lib/trustChip.ts reasonLine
// and the rows under it): the level, code, file and key, the short
// secret-masked excerpt, the repository files a command runs and what it
// does. Every field passes terminalSafe, since a repository chose them.
func trustReviewLines(r sectrust.Reason) string {
	where := r.File
	if r.Key != "" {
		where += " " + r.Key
	}
	own := ""
	if r.Local {
		own = " (local settings file)"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n  %s %s: %s%s", r.Level, r.Code, terminalSafe(where), own)
	if r.Excerpt != "" {
		fmt.Fprintf(&b, "\n      %s", terminalSafe(r.Excerpt))
	}
	if len(r.Files) > 0 {
		fmt.Fprintf(&b, "\n      runs %s (their bytes are part of the digest)", terminalSafe(strings.Join(r.Files, ", ")))
	}
	if len(r.Indicators) > 0 {
		fmt.Fprintf(&b, "\n      it %s", terminalSafe(strings.Join(r.Indicators, ", ")))
	}
	return b.String()
}

// terminalSafe replaces every control character (an escape sequence a
// repository planted in a file name or a command would otherwise reach the
// developer's terminal) and every bidirectional formatting character with
// "?".
func terminalSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
			return '?'
		}
		return r
	}, s)
}

// repoTrustTarget is where a launch starts: the repository root (the git
// root of the launch directory, or the directory itself outside a
// repository) and the launch directory relative to it.
type repoTrustTarget struct {
	root      string
	launchRel string
}

// resolveRepoTrustTarget finds the repository root of dir: the checkout's
// own top level (git.FindCheckoutRoot), so a linked worktree's trust check
// reads the worktree's files, not the main checkout's (F0-14).
func resolveRepoTrustTarget(dir string) (repoTrustTarget, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return repoTrustTarget{}, fmt.Errorf("resolveRepoTrustTarget: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	root := abs
	if r, ok := git.FindCheckoutRoot(abs); ok {
		root = r
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return repoTrustTarget{root: abs}, nil
	}
	if rel == "." {
		rel = ""
	}
	return repoTrustTarget{root: root, launchRel: filepath.ToSlash(rel)}, nil
}

// repoTrustOutcome is one launch's trust check and guard verdict.
type repoTrustOutcome struct {
	target  repoTrustTarget
	result  sectrust.Result
	verdict policy.Verdict
	// launched is set by the session-start flag when the session's launch
	// was checked by Observer (repoTrustCheckedEnv).
	launched bool
	// acceptHash is the project-root hash whose accepts the check read: an
	// accept given at the launch terminal is recorded there.
	acceptHash string
	// floorRaised: the org's pre-launch trust floor raised the verdict
	// (raiseTrustStep changed its decision), so the floor, not a local rule
	// or override, decided it (audit SEC-P4 F8).
	floorRaised bool
	// localRaised: the node's own [security.trust] prelaunch setting raised
	// the verdict (raiseTrustStepLocal changed its decision; lane LEFT-SEC
	// audit F5).
	localRaised bool
}

// evaluateRepoTrust runs the check and the trust rules for one launch.
func evaluateRepoTrust(ctx context.Context, deps *repoTrustDeps, tool, dir string) (repoTrustOutcome, error) {
	target, err := resolveRepoTrustTarget(dir)
	if err != nil {
		return repoTrustOutcome{}, err
	}
	ownHash := guard.HashProjectRoot(target.root)
	rootHash := ownHash
	if deps.acceptRootHash != "" {
		rootHash = deps.acceptRootHash
	}
	recordHash := rootHash
	if deps.recordOwnRoot {
		recordHash = ownHash
	}
	accepted := map[string]bool{}
	if deps.store != nil {
		if a, err := deps.store.AcceptedSecTrustDigests(ctx, rootHash); err == nil {
			accepted = a
		}
	}
	// At the home directory the project table reads the developer's own
	// home config, where Observer registers its hooks, status line and MCP
	// server: those entries are left out, so they are neither decided on
	// nor recorded (repoTrustOwnAt; nil anywhere else).
	own := repoTrustOwnAt(target.root)
	res, err := sectrust.Check(ctx, sectrust.OSFS(target.root), sectrust.Request{
		LaunchRel:    target.launchRel,
		Accepted:     func(d string) bool { return accepted[d] },
		HostPins:     deps.hostPins,
		HostEnv:      repoTrustHostEnv(deps),
		Own:          own,
		Paths:        deps.paths,
		Devcontainer: deps.devcontainer,
	})
	if err != nil {
		return repoTrustOutcome{}, fmt.Errorf("evaluateRepoTrust: %w", err)
	}
	if own != nil {
		res = res.WithoutObserver()
	}
	if deps.store != nil {
		if items := secTrustItems(res); len(items) > 0 {
			now := time.Now
			if deps.now != nil {
				now = deps.now
			}
			// Recording is best effort: a failed write must not change the
			// launch decision, which the check already made.
			_ = deps.store.RecordSecTrustItems(ctx, recordHash, items, now())
		}
	}
	packs := deps.packs
	if len(packs) == 0 {
		packs = []string{repoTrustComponent}
	}
	ev := policy.Event{
		Kind: policy.KindAgentLaunch, Tool: tool, Target: target.root, ProjectRoot: target.root, Cwd: dir,
		Security: &policy.Security{Trust: policy.TrustVerdict(res.Verdict), TrustReasons: verdictReasonCodes(res), Packs: packs},
		Now:      time.Now(),
	}
	verdict, err := decideRepoTrust(deps, ev)
	if err != nil {
		return repoTrustOutcome{}, fmt.Errorf("evaluateRepoTrust: %w", err)
	}
	// The node's own step first (lane LEFT-SEC), then the org floor over
	// it, so floorRaised still means the floor decided.
	local := raiseTrustStepLocal(verdict, deps.localStep)
	localRaised := local.Decision != verdict.Decision
	verdict = local
	floorRaised := false
	if deps.trustFloor != nil {
		raised := raiseTrustStep(verdict, deps.trustFloor(target.root))
		floorRaised = raised.Decision != verdict.Decision
		verdict = raised
	}
	return repoTrustOutcome{target: target, result: res, verdict: verdict, acceptHash: rootHash, floorRaised: floorRaised, localRaised: localRaised}, nil
}

// trustFloorSteps is the require.prelaunch_trust floor's least decision per
// value (lane SEC-P4 decision 9): warn is a flag, ask an ask, refuse a
// deny. A value not in the table raises nothing.
var trustFloorSteps = map[string]policy.Decision{
	"warn":                          policy.DecisionFlag,
	secposture.PrelaunchTrustAsk:    policy.DecisionAsk,
	secposture.PrelaunchTrustRefuse: policy.DecisionDeny,
}

// raiseTrustStep raises a trust verdict to the floor's least decision,
// never lowering it. An allow (a clean or accepted repository: no trust
// rule fired) stays an allow; the floor sets how strictly a finding is
// handled, not whether there is one.
func raiseTrustStep(v policy.Verdict, floor string) policy.Verdict {
	d, ok := trustFloorSteps[floor]
	if !ok || v.Decision == policy.DecisionAllow || v.Decision >= d {
		return v
	}
	v.Decision = d
	v.Reason += " (the org's pre-launch trust floor for this project: " + floor + ")"
	return v
}

// repoTrustLocalStep is the launch step [security.trust].prelaunch asks for:
// "ask", or "" for the default "warn" (and any value outside the picker),
// which leaves the guard mode to decide.
func repoTrustLocalStep(c config.SecurityTrustConfig) string {
	if c.Prelaunch == secposture.PrelaunchTrustAsk {
		return secposture.PrelaunchTrustAsk
	}
	return ""
}

// raiseTrustStepLocal is raiseTrustStep for the node's own setting: a
// verdict that is not clean is raised to at least an ask, with its own
// wording; "" raises nothing.
func raiseTrustStepLocal(v policy.Verdict, step string) policy.Verdict {
	d, ok := trustFloorSteps[step]
	if step == "" || !ok || v.Decision == policy.DecisionAllow || v.Decision >= d {
		return v
	}
	v.Decision = d
	v.Reason += " (your [security.trust] prelaunch setting: " + step + ")"
	return v
}

// repoTrustFloorReader reads the pre-launch trust floor the daemon signed
// into a project's posture (the project's security.scanning section, or
// the org-wide floor), for the launch row and the session-start flag. Raise
// only, so any file the reading has is believed (a stale one cannot lower
// anything); no file reads none.
func repoTrustFloorReader(configPath string) func(root string) string {
	return func(root string) string {
		resolved, err := config.ResolveGlobalPath(configPath)
		if err != nil || root == "" {
			return ""
		}
		r := secposture.Load(secposture.LayoutFor(resolved), root, secposture.ModuleActive, time.Now(), secposture.Versions{})
		if r.File == nil {
			return ""
		}
		return r.File.PrelaunchTrustFloor
	}
}

// decideRepoTrust lets Guard decide one agent_launch event. With a node
// guard (deps.guard) the trust rules S-701 to S-705 are the ones
// secrules.Compose put into its pack, so the developer's [guard.rules]
// overrides and an org floor apply, and pack membership
// (Event.Security.Packs) gates them like every pillar rule. A guard that
// cannot be built, or whose pack lacks the trust rules (a guard composed
// before the component was selected), falls back to an engine of the
// same composed rules under the launch's mode and disabled list.
func decideRepoTrust(deps *repoTrustDeps, ev policy.Event) (policy.Verdict, error) {
	if deps.guard != nil {
		if g := deps.guard(); g != nil && guardHasTrustRules(g) {
			v, _ := g.Evaluate(ev)
			return v, nil
		}
	}
	comp, err := secrules.Compose(func(id string) bool { return id == repoTrustComponent })
	if err != nil {
		return policy.Verdict{}, err
	}
	eng, err := policy.New(policy.Config{Mode: deps.mode, Disabled: deps.disabled, ExtraRules: comp.Rules})
	if err != nil {
		return policy.Verdict{}, err
	}
	return eng.Evaluate(ev), nil
}

// guardHasTrustRules reports whether g's composed pack carries the trust
// rules.
func guardHasTrustRules(g *guard.Guard) bool {
	for _, r := range g.EffectiveRules() {
		if r.ID == "S-701" {
			return true
		}
	}
	return false
}

// repoTrustGuard builds the node guard a launch's trust decision runs
// through: the same layers as the CLI launch guard (user overrides, the
// org bundle and its key pin) plus the security pack composed for the
// active components.
func repoTrustGuard(ctx context.Context, cfg config.Config, st *store.Store, snap componentstate.Snapshot) *guard.Guard {
	pin, managed, bundleExpected := nodeGuardPolicyInputs(ctx, st, nil)
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}
	g, err := hookGuardNew(guard.Options{
		Config: cfg.Guard, Home: home, OrgKeyPinHash: pin, ManagedTenancy: managed, OrgBundleExpected: bundleExpected,
		PackRules: securityPackRules(snap.ModuleActive, nil),
	})
	if err != nil {
		return nil
	}
	return g
}

// verdictReasonCodes are the codes of the reasons at the verdict's own
// level, each once (the contract of secrules' trust rules).
func verdictReasonCodes(res sectrust.Result) []string {
	var want sectrust.Level
	switch res.Verdict {
	case sectrust.VerdictUntrusted:
		want = sectrust.LevelUntrusted
	case sectrust.VerdictFlagged:
		want = sectrust.LevelFlagged
	default:
		return nil
	}
	var out []string
	for _, r := range res.Reasons {
		if r.Level == want && !slices.Contains(out, r.Code) {
			out = append(out, r.Code)
		}
	}
	return out
}

// secTrustItems are the reasons that carry a digest, as store items (the
// one mapping, sectrustitem.FromReasons).
func secTrustItems(res sectrust.Result) []store.SecTrustItem {
	return sectrustitem.FromReasons(res.Reasons)
}

// repoTrustRun is the repo.trust row's body for one launch with its
// dependencies: the launch directory, the check and Guard's decision. A
// check that cannot run warns and goes on: the verdict is then unknown, and
// no trust rule decides on unknown.
func repoTrustRun(r *launchGateRun, deps *repoTrustDeps) launchGateStep {
	if deps.skip != "" {
		return launchGateStep{warn: "repository trust: not checked here: " + deps.skip}
	}
	dir, err := r.launchDir()
	if err != nil || dir == "" {
		return launchGateStep{}
	}
	out, err := evaluateRepoTrust(r.ctx, deps, r.tool, dir)
	if err != nil {
		return launchGateStep{warn: "repository trust check did not run: " + err.Error()}
	}
	step := repoTrustStep(out, deps, r.tool)
	if step.refuse == nil && r.markChecked != nil {
		// The agent this launch starts gets the marker: its session-start
		// hook reads it and words its flag for a session whose launch was
		// checked (launch_trust_session.go). Where it is set is the run's
		// own business (launch_gates.go markChecked).
		r.markChecked(r, guard.HashProjectRoot(out.target.root))
	}
	return step
}

// repoTrustCheckedEnv names the variable a launch gives the agent it starts
// once the repository trust row let the launch go on: the project-root hash
// it checked. An `observer <tool>` launcher sets it in its own environment;
// a launch the daemon starts puts it in the started process's environment
// only; the daemon strips any inherited copy from its children
// (isInternalChildEnv). The session-start flag reads it only to word the
// flag; it never decides whether the flag records.
const repoTrustCheckedEnv = "OBSERVER_TRUST_CHECKED_ROOT"

// daemonRepoTrustDeps are the row's dependencies for a launch the daemon
// starts itself (daemonLaunchGateRun): nobody is at the daemon's stdin, so
// the row never asks (an ask refuses and says where to accept), and the
// accepts honoured are those of at.acceptDir's repository when it is set
// (an Arena worktree, or a benchmark attempt's workspace, honours the
// accepts of the repository it was made from), else the run's own; what
// the check raises is then recorded under the checked directory's own
// hash. A launch with at.trustSkip set is not checked and says why.
func daemonRepoTrustDeps(cfg config.Config, snap componentstate.Snapshot, st *store.Store, at daemonLaunch) *repoTrustDeps {
	deps := newRepoTrustDeps(cfg, snap, st, nil)
	if deps == nil {
		return nil
	}
	acceptDir := at.acceptDir
	deps.unattended, deps.skip, deps.advice = true, strings.TrimSpace(at.trustSkip), strings.TrimSpace(at.trustAdvice)
	deps.acceptRootHash, deps.acceptRoot, deps.recordOwnRoot = "", "", false
	if strings.TrimSpace(acceptDir) != "" {
		if t, err := resolveRepoTrustTarget(acceptDir); err == nil {
			deps.acceptRootHash, deps.acceptRoot = guard.HashProjectRoot(t.root), t.root
			deps.recordOwnRoot = true
		}
	}
	return deps
}

// repoTrustStep turns one launch's outcome into the row's step: allow,
// warn (a flag), ask at the terminal (refuse when it cannot ask or the
// developer says no) or refuse.
func repoTrustStep(out repoTrustOutcome, deps *repoTrustDeps, tool string) launchGateStep {
	v := out.verdict
	if v.Decision == policy.DecisionAllow {
		return launchGateStep{}
	}
	msg := fmt.Sprintf("%s (%s); %s", v.Reason, v.RuleID, v.Advice)
	switch v.Decision {
	case policy.DecisionFlag:
		return launchGateStep{warn: "repository trust: " + msg}
	case policy.DecisionAsk:
		if repoTrustAskAnswer(out, deps, tool, msg) {
			return launchGateStep{}
		}
		if deps.unattended {
			return launchGateStep{refuse: unattendedTrustRefusal(out, deps, tool, msg)}
		}
		return launchGateStep{refuse: fmt.Errorf("observer %s: launch refused: repository trust: %s", tool, msg)}
	default:
		return launchGateStep{refuse: fmt.Errorf("observer %s: launch refused: repository trust: %s", tool, msg)}
	}
}

// unattendedTrustRefusal is the refusal of an ask nobody can answer (a
// launch Observer started itself): it names the repository whose accepts
// the launch reads (the accept root when one is set, else the checked
// repository) and the command that accepts there.
func unattendedTrustRefusal(out repoTrustOutcome, deps *repoTrustDeps, tool, msg string) error {
	if deps.advice != "" {
		return fmt.Errorf("observer %s: launch refused: repository trust: %s; this launch was started by Observer itself (a benchmark run), with no terminal to ask in: %s",
			tool, msg, deps.advice)
	}
	root := out.target.root
	if deps.acceptRoot != "" {
		root = deps.acceptRoot
	}
	return fmt.Errorf("observer %s: launch refused: repository trust: %s; this launch was started by Observer itself (the daemon or a benchmark run), with no terminal to ask in: review the items and accept them for %s with `observer security trust accept --all --dir %s` or in the dashboard's New Terminal dialog for that directory, then start it again",
		tool, msg, root, quoteTrustDir(root))
}

// quoteTrustDir quotes a directory for a command line when it holds a
// space or a quote.
func quoteTrustDir(dir string) string {
	if strings.ContainsAny(dir, " \t'\"") {
		return strconv.Quote(dir)
	}
	return dir
}

// repoTrustSourceEnv names the variable a sandboxed launch in a managed
// clone carries: the project-root hash of the source repository whose
// accepts the inner launcher's trust check honours. The daemon sets it
// (repoTrustChildEnv) and strips any inherited copy (isInternalChildEnv),
// and the inner launcher reads it only inside a sandbox the daemon built.
const repoTrustSourceEnv = "OBSERVER_TRUST_SOURCE_ROOT_HASH"

// repoTrustChildEnv is the environment entry a sandboxed launch whose
// workspace is a managed clone of sourceDir carries, or nil.
func repoTrustChildEnv(sourceDir string) []string {
	if strings.TrimSpace(sourceDir) == "" {
		return nil
	}
	target, err := resolveRepoTrustTarget(sourceDir)
	if err != nil {
		return nil
	}
	return []string{repoTrustSourceEnv + "=" + guard.HashProjectRoot(target.root)}
}

// repoTrustBenchmarkSourceEnv names the variable a benchmark driver gives
// the `observer <tool>` launcher it starts for an attempt: the task's local
// source repository, whose accepts the attempt's fresh workspace honours
// (benchmarkTrustLaunch). The daemon strips any inherited copy from its
// children (isInternalChildEnv) and the driver from the launcher's
// inherited environment (benchmarkTrustChildEnv). It is honoured only with
// the driver-set marker (repoTrustBenchmarkMarkerEnv).
const repoTrustBenchmarkSourceEnv = "OBSERVER_TRUST_BENCHMARK_SOURCE"

// repoTrustBenchmarkMarkerEnv names the marker a benchmark driver sets
// beside repoTrustBenchmarkSourceEnv: the attempt's workspace. A CLI launch
// honours the task source only when the marker names the directory it
// launches in (or a directory above it), so the variable left in any other
// shell, or set by hand, changes nothing (plans decision log P-037). Both
// are stripped from the daemon's children like the source.
const repoTrustBenchmarkMarkerEnv = "OBSERVER_TRUST_BENCHMARK_WORKSPACE"

// cliRepoTrustAcceptRoot is the accept root a CLI launch honours, as a
// project-root hash and, when known, its directory: the source
// repository's hash inside a sandbox the daemon built; a benchmark task's
// source repository in a benchmark attempt's launcher; else nothing (the
// launch's own repository).
func cliRepoTrustAcceptRoot() (hash, dir string) {
	if cliSandboxedEnv() {
		h := strings.TrimSpace(os.Getenv(repoTrustSourceEnv))
		if len(h) != 64 || strings.Trim(h, "0123456789abcdef") != "" {
			return "", ""
		}
		return h, ""
	}
	if src := strings.TrimSpace(os.Getenv(repoTrustBenchmarkSourceEnv)); src != "" && filepath.IsAbs(src) && benchmarkMarkerHolds() {
		if t, err := resolveRepoTrustTarget(src); err == nil {
			return guard.HashProjectRoot(t.root), t.root
		}
	}
	return "", ""
}

// benchmarkMarkerHolds reports whether the driver-set marker names the
// directory this CLI launch starts in, or one above it, both resolved.
func benchmarkMarkerHolds() bool {
	ws := strings.TrimSpace(os.Getenv(repoTrustBenchmarkMarkerEnv))
	if ws == "" || !filepath.IsAbs(ws) {
		return false
	}
	dir, err := cliLaunchDir()
	if err != nil || dir == "" {
		return false
	}
	resolve := func(p string) string {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return filepath.Clean(r)
		}
		return filepath.Clean(p)
	}
	ws, dir = resolve(ws), resolve(dir)
	rel, err := filepath.Rel(ws, dir)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// repoTrustManaged reports whether the node holds managed tenancy (a
// variable so tests can stand in a managed node).
var repoTrustManaged = func(st *store.Store) bool {
	if st == nil {
		return false
	}
	managed := managedTenancyLookup(st)
	return managed != nil && managed()
}

// repoTrustHostPins are the plugin host's pinned paths on this node: the
// binary and config argument hook registration bakes into every plugin
// shim (autoRegisterOptions).
func repoTrustHostPins(configPath string) map[string]string {
	pins := map[string]string{}
	if bin, err := absoluteBinaryPath(); err == nil {
		pins["OBSERVER_BIN"] = registrationCommand(bin)
	}
	if resolved, err := config.ResolveGlobalPath(configPath); err == nil {
		pins["OBSERVER_CONFIG"] = resolved
	}
	return pins
}

// repoTrustHostEnv reads the pinned variables from the launch environment,
// dropping a value that names this very binary or config (the same file
// under another spelling of the pin).
func repoTrustHostEnv(deps *repoTrustDeps) map[string]string {
	if deps.hostPins == nil || deps.hostEnv == nil {
		return nil
	}
	self, _ := absoluteBinaryPath()
	out := map[string]string{}
	for name, pin := range deps.hostPins {
		v := strings.TrimSpace(deps.hostEnv(name))
		if v == "" || sameFile(v, pin) || (name == "OBSERVER_BIN" && self != "" && sameFile(v, self)) {
			continue
		}
		out[name] = v
	}
	return out
}

// sameFile reports whether two paths name the same existing file, or are
// the same path when either does not exist.
func sameFile(a, b string) bool {
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	fa, errA := os.Stat(a)
	fb, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(fa, fb)
}

// registrationPinPluginPaths reports whether hook registration renders
// plugin shims with pinned paths: on a managed node with the repository
// trust component selected (security pillar plan section 5.1 item 6).
func registrationPinPluginPaths(configPath string) bool {
	pinCache.mu.Lock()
	defer pinCache.mu.Unlock()
	if e, ok := pinCache.at[configPath]; ok && time.Since(e.when) < pinCacheTTL {
		return e.pin
	}
	pin := registrationPinPluginPathsNow(configPath)
	if pinCache.at == nil {
		pinCache.at = map[string]pinCacheEntry{}
	}
	pinCache.at[configPath] = pinCacheEntry{pin: pin, when: time.Now()}
	return pin
}

// pinCacheTTL bounds how long a pin answer is reused: the dashboard's
// hooks probe builds the registration options on every view.
const pinCacheTTL = time.Minute

type pinCacheEntry struct {
	pin  bool
	when time.Time
}

var pinCache struct {
	mu sync.Mutex
	at map[string]pinCacheEntry
}

// registrationPinPluginPathsNow is registrationPinPluginPaths uncached.
// The component is checked from the config alone first, so a node without
// it never opens the database here (the dashboard's hooks probe calls this
// on every view).
func registrationPinPluginPathsNow(configPath string) bool {
	if !repoTrustSelected(componentSnapshotFor(configPath)) {
		return false
	}
	_, database, cleanup, err := loadConfigAndDB(context.Background(), configPath)
	if err != nil {
		return false
	}
	defer cleanup()
	return repoTrustManaged(store.New(database))
}
