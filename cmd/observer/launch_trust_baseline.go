//go:build !sbo_omit_security && !sbo_omit_security_trust

package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secrules"
	"github.com/marmutapp/superbased-observer/internal/sectrust"
	"github.com/marmutapp/superbased-observer/internal/sectrustitem"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// launch_trust_baseline.go is the config baseline of the repository trust
// component (security pillar plan section 5.1 item 1): a daemon loop
// (security.trust.baseline, a moduleGates row) that snapshots every
// project's agent config files through the trust check's path table,
// compares the snapshot with the stored one, and raises an agent_config
// finding for each added, changed or removed file, attributed to the agent
// write that touched it when one exists. It catches a config changed after
// an agent launched, which the launch check cannot see.

// repoTrustBaselineEvery is the rescan period (the plan's default of five
// minutes).
const repoTrustBaselineEvery = 5 * time.Minute

// repoTrustBaselineMaxRoots caps the projects one pass snapshots.
const repoTrustBaselineMaxRoots = 200

// repoTrustBaselineRule is the finding rule id a baseline change carries.
const repoTrustBaselineRule = "agent-config/changed"

// repoTrustBaselineUserRule is the finding rule id of a user-scope change
// (the home directory's agent config, which applies to every project).
const repoTrustBaselineUserRule = "agent-config/user-changed"

// repoTrustBaselineEventEvery is how often the event pass reads the agent
// writes recorded since the last one (both capture paths, the hooks and the
// watcher, land them in the actions table).
const repoTrustBaselineEventEvery = 15 * time.Second

// repoTrustBaselineEventBatch caps the agent writes one event pass reads;
// the rest wait for the next pass.
const repoTrustBaselineEventBatch = 500

// startRepoTrustBaseline starts the baseline loop on ng while the
// component is selected (repoTrustSelected). One goroutine owns every pass
// (repoTrustBaselineLoop): the full pass on its timer, and the event pass
// that rescans a project, or the home directory, soon after an agent wrote
// one of the files its snapshot reads.
func startRepoTrustBaseline(ctx context.Context, ng *gatedGroup, configPath string, snap componentstate.Snapshot) {
	if !repoTrustSelected(snap) {
		return
	}
	ng.Go("security.trust.baseline", func() error {
		cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
		if err != nil {
			return nil
		}
		defer cleanup()
		logger := newLogger(cfg.Observer.LogLevel)
		home, _ := os.UserHomeDir()
		l := newRepoTrustBaselineLoop(ctx, store.New(database), home, logger)
		l.setTable(repoTrustBaselineTableFor(cfg, snap))
		full := time.NewTicker(repoTrustBaselineEvery)
		defer full.Stop()
		events := time.NewTicker(repoTrustBaselineEventEvery)
		defer events.Stop()
		for {
			l.fullTick(ctx, time.Now())
			for done := false; !done; {
				select {
				case <-ctx.Done():
					return nil
				case <-events.C:
					l.eventTick(ctx, time.Now())
				case <-full.C:
					done = true
				}
			}
		}
	})
}

// repoTrustBaselineTick is one tick of the loop: the baseline pass over
// the limit most recently active projects (store.RecentProjectRoots, so a
// node with many projects watches the ones in use, not the oldest), then
// the agent version check.
func repoTrustBaselineTick(ctx context.Context, st *store.Store, limit int, now time.Time, logger *slog.Logger) {
	repoTrustBaselineTickWith(ctx, st, repoTrustBaselineDefaultTable(), limit, now, logger)
}

// repoTrustBaselineTickWith is repoTrustBaselineTick over the table tbl.
func repoTrustBaselineTickWith(ctx context.Context, st *store.Store, tbl repoTrustBaselineTable, limit int, now time.Time, logger *slog.Logger) {
	roots, err := st.RecentProjectRoots(ctx, limit)
	if err != nil {
		if logger != nil {
			logger.Warn("security.trust: baseline pass skipped: project roots unreadable", "err", err)
		}
	} else if n := repoTrustBaselinePassWith(ctx, st, tbl, roots, now, logger); n > 0 && logger != nil {
		logger.Info("security.trust: agent config changed", "changes", n)
	}
	if n := repoTrustVersionPass(ctx, st, now, logger); n > 0 && logger != nil {
		logger.Info("security.trust: sessions ran agent versions with known flaws", "findings", n)
	}
}

// repoTrustBaselinePass snapshots each existing project root (at most
// repoTrustBaselineMaxRoots; the loop passes the most recently active
// projects first, store.RecentProjectRoots) and records a finding per change
// since the stored snapshot. A project's first snapshot only stores. It
// returns the number of changes recorded.
//
// Each root is followed by the linked worktrees of that repository
// (repoTrustBaselineCheckouts), each snapshotted as a checkout of its own:
// the agent config files are checkout files, and a worktree's own
// `.claude` or `.mcp.json` is what an agent launched there reads (lane
// shr-worktree2, P-044 residual). They count toward the same cap.
func repoTrustBaselinePass(ctx context.Context, st *store.Store, roots []string, now time.Time, logger *slog.Logger) int {
	return repoTrustBaselinePassWith(ctx, st, repoTrustBaselineDefaultTable(), roots, now, logger)
}

// repoTrustBaselinePassWith is repoTrustBaselinePass over the table tbl.
func repoTrustBaselinePassWith(ctx context.Context, st *store.Store, tbl repoTrustBaselineTable, roots []string, now time.Time, logger *slog.Logger) int {
	changes := 0
	n := 0
	for _, root := range repoTrustBaselineCheckouts(roots, repoTrustBaselineMaxRoots) {
		if ctx.Err() != nil || n >= repoTrustBaselineMaxRoots {
			break
		}
		if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
			continue
		}
		n++
		c, err := repoTrustBaselineProjectWith(ctx, st, tbl, root, now)
		if err != nil && logger != nil {
			logger.Warn("security.trust: baseline of one project failed", "err", err)
		}
		changes += c
	}
	return changes
}

// repoTrustBaselineCheckouts is roots with the linked worktrees of each
// right after it (git.LinkedWorktreeCheckouts: git's back pointers under
// `<root>/.git/worktrees`, file reads only, no git process), without
// repeats, at most max in all. A root with no linked worktree adds
// nothing, so the list is roots for every other repository.
func repoTrustBaselineCheckouts(roots []string, max int) []string {
	out := make([]string, 0, len(roots))
	seen := make(map[string]bool, len(roots))
	add := func(p string) {
		if len(out) < max && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, root := range roots {
		if len(out) >= max {
			break
		}
		add(root)
		for _, wt := range git.LinkedWorktreeCheckouts(root, max-len(out)) {
			add(wt)
		}
	}
	return out
}

// repoTrustBaselineTable is the path table and the devcontainer parser the
// project snapshot reads: repoTrustConditional's, the one seam every trust
// surface reads its conditional rows through (lane LEFT-SEC), so the
// baseline sees the devcontainer.json initializeCommand row the launch
// gate decides on. A nil paths is the default table.
type repoTrustBaselineTable struct {
	paths        []agentconfig.TrustPath
	devcontainer sectrust.DevcontainerParser
}

// repoTrustBaselineTableFor is the table under cfg and snap.
func repoTrustBaselineTableFor(cfg config.Config, snap componentstate.Snapshot) repoTrustBaselineTable {
	paths, dc := repoTrustConditional(cfg, snap)
	return repoTrustBaselineTable{paths: paths, devcontainer: dc}
}

// repoTrustBaselineDefaultTable is the table under the default config and
// no selected component: the rows that hold everywhere (the N2 host row).
func repoTrustBaselineDefaultTable() repoTrustBaselineTable {
	return repoTrustBaselineTableFor(config.Default(), componentstate.Snapshot{})
}

// projectPaths is the table's path rows (the default table for nil).
func (t repoTrustBaselineTable) projectPaths() []agentconfig.TrustPath {
	if t.paths == nil {
		return agentconfig.TrustPaths()
	}
	return t.paths
}

// repoTrustBaselineFiles is the snapshot of res: every file it read, but a
// devcontainer file (a conditional row) only while the check raised a
// reason in it. The conditional rows report fields, not the file: a
// devcontainer.json with no reported field (no initializeCommand) is not
// a file the trust check judges, so it is not in the snapshot and raises
// nothing, and one that gains such a field after the baseline is an added
// file (lane LEFT-SEC).
func repoTrustBaselineFiles(res sectrust.Result) []sectrust.FileState {
	reasoned := map[string]bool{}
	for _, r := range res.Reasons {
		if r.Class == agentconfig.TrustDevcontainer {
			reasoned[r.File] = true
		}
	}
	out := make([]sectrust.FileState, 0, len(res.Files))
	for _, f := range res.Files {
		if f.Class == string(agentconfig.TrustDevcontainer) && !reasoned[f.Rel] {
			continue
		}
		out = append(out, f)
	}
	return out
}

// repoTrustBaselineProjectWith is one project's snapshot, diff and
// findings over the table tbl.
func repoTrustBaselineProjectWith(ctx context.Context, st *store.Store, tbl repoTrustBaselineTable, root string, now time.Time) (int, error) {
	rootHash := guard.HashProjectRoot(root)
	prev, had, err := st.LoadSecConfigFiles(ctx, rootHash)
	if err != nil {
		return 0, err
	}
	// At the home directory the project table reads the home config files
	// Observer registers into: Own marks Observer's entries the way the
	// launch row does (repoTrustOwnAt; nil anywhere else), and a changed
	// file whose every entry is Observer's is not reported, so `observer
	// init` and a release that rewrites the registrations raise nothing
	// here (the user-scope baseline grades those files too). A file that
	// also holds an entry that is not Observer's is graded as before.
	own := repoTrustOwnAt(root)
	res, err := sectrust.Check(ctx, sectrust.OSFS(root), sectrust.Request{Paths: tbl.paths, Own: own, Devcontainer: tbl.devcontainer})
	if err != nil {
		return 0, err
	}
	onlyObserver := repoTrustOnlyObserverFiles(res, own != nil)
	files := repoTrustBaselineFiles(res)
	cur := make([]store.SecConfigFile, 0, len(files))
	for _, f := range files {
		cur = append(cur, store.SecConfigFile{RelPath: f.Rel, PathClass: f.Class, SHA256: f.SHA256, Size: f.Size})
	}
	recorded := 0
	if had {
		since := time.Time{}
		before := make([]sectrust.FileState, 0, len(prev))
		for _, f := range prev {
			before = append(before, sectrust.FileState{Rel: f.RelPath, Class: f.PathClass, SHA256: f.SHA256, Size: f.Size})
		}
		if last, err := st.SecLastConfigSnapshot(ctx, rootHash); err == nil {
			since = last
		}
		for _, ch := range sectrust.Diff(before, files, !res.Truncated) {
			if ch.Kind != sectrust.ChangeRemoved && onlyObserver[ch.Rel] {
				continue
			}
			f, report := repoTrustBaselineFinding(ctx, st, root, rootHash, ch, since, now)
			if !report {
				continue
			}
			if _, _, err := st.UpsertSecFinding(ctx, f, now); err != nil {
				return recorded, err
			}
			recorded++
		}
	}
	return recorded, st.ReplaceSecConfigFiles(ctx, rootHash, cur, now)
}

// repoTrustOnlyObserverFiles lists the files of res whose entries are all
// ones Request.Own marked as Observer's (at least one, none other). With
// own false (no Own was set) it is empty.
func repoTrustOnlyObserverFiles(res sectrust.Result, own bool) map[string]bool {
	out := map[string]bool{}
	if !own {
		return out
	}
	foreign := map[string]bool{}
	for _, r := range res.Reasons {
		if r.Observer {
			out[r.File] = true
		} else {
			foreign[r.File] = true
		}
	}
	for f := range foreign {
		delete(out, f)
	}
	return out
}

// repoTrustBaselineGrade is one row of the baseline's grading table: the
// first row whose match holds decides whether a change is reported and at
// what severity.
type repoTrustBaselineGrade struct {
	match    func(ch sectrust.FileChange, byAgent bool) bool
	report   bool
	severity policy.FindingSeverity
}

// repoTrustBaselineGrades grades a change (lane SEC-TRUSTFIX, plans
// decision log P-016). The developer's own files (sectrust.OwnFile:
// .git/config, the dotenv files, project-local scope files such as
// .claude/settings.local.json) change in normal work, written by git
// (`git push -u`), the agent's own tool (a permission grant) or the
// developer, so a change nobody's agent action wrote is not reported; an
// agent's file write to one is medium. Otherwise a removal is low, an
// instruction-like file medium, and a file that can make an agent run
// something or reach somewhere high.
var repoTrustBaselineGrades = []repoTrustBaselineGrade{
	{match: func(ch sectrust.FileChange, byAgent bool) bool { return ch.Local && !byAgent }, report: false},
	{match: func(ch sectrust.FileChange, byAgent bool) bool { return ch.Local }, report: true, severity: policy.FindingSeverityMedium},
	{match: func(ch sectrust.FileChange, _ bool) bool { return ch.Kind == sectrust.ChangeRemoved }, report: true, severity: policy.FindingSeverityLow},
	// A devcontainer file is in the snapshot only while it holds a reported
	// field (repoTrustBaselineFiles), whose reason is flagged and acceptable
	// (devcontainer_ignored_field): medium, the flagged level.
	{match: func(ch sectrust.FileChange, _ bool) bool { return ch.Class == string(agentconfig.TrustDevcontainer) }, report: true, severity: policy.FindingSeverityMedium},
	{match: func(ch sectrust.FileChange, _ bool) bool { return ch.Class == "prose" }, report: true, severity: policy.FindingSeverityMedium},
	{match: func(sectrust.FileChange, bool) bool { return true }, report: true, severity: policy.FindingSeverityHigh},
}

// repoTrustBaselineSeverity walks the grading table for one change.
func repoTrustBaselineSeverity(ch sectrust.FileChange, byAgent bool) (policy.FindingSeverity, bool) {
	for _, g := range repoTrustBaselineGrades {
		if g.match(ch, byAgent) {
			return g.severity, g.report
		}
	}
	return policy.FindingSeverityHigh, true
}

// repoTrustBaselineFinding builds the agent_config finding of one change,
// attributed to the newest agent write to the file since the previous
// snapshot (else unknown), and reports whether the grading table reports it
// at all. The message is fixed text; the path is the finding's location.
func repoTrustBaselineFinding(ctx context.Context, st *store.Store, root, rootHash string, ch sectrust.FileChange, since, now time.Time) (secfinding.Finding, bool) {
	f := secfinding.Finding{
		Rule:       secfinding.Rule{ID: repoTrustBaselineRule, Version: "1", Pack: repoTrustComponent, PackVersion: secrules.PackVersion},
		Engine:     secfinding.Engine{Driver: "sectrust.baseline"},
		Category:   policy.FindingAgentConfig,
		Confidence: policy.FindingConfidenceHigh,
		Scope:      policy.FindingScopeScheduled,
		Project:    secfinding.Project{RootHash: rootHash},
		Location:   secfinding.Location{RelPath: ch.Rel},
		Message: "An agent config file the repository trust check reads was " + string(ch.Kind) + " (" + ch.Class +
			" file). Review it: it changes what a coding agent runs or reads in this project.",
		FixHint:     "Review it in the dashboard's New Terminal dialog for the project, or run `observer security trust check` there; if a repository command changed, accept its new digest only after reading it.",
		Attribution: secfinding.InferredAttribution{Class: policy.FindingAttributionUnknown, Method: "sectrust.baseline.v1", Confidence: policy.FindingConfidenceLow},
		FirstSeen:   now,
		LastSeen:    now,
	}
	f.LocalKey = secfinding.LocalKey(rootHash, repoTrustBaselineRule, secfinding.TextIdentity(ch.Rel+"\x00"+string(ch.Kind)+"\x00"+ch.Old+"\x00"+ch.New))
	targets := []string{filepath.Join(root, filepath.FromSlash(ch.Rel)), ch.Rel}
	byAgent := false
	if a, ok, err := st.LatestAgentWriteTo(ctx, targets, since); err == nil && ok {
		byAgent = true
		f.Attribution = secfinding.InferredAttribution{Class: policy.FindingAttributionAI, Method: "sectrust.baseline.v1", Confidence: policy.FindingConfidenceMedium}
		f.Lineage = secfinding.Lineage{SessionID: a.SessionID, ActionID: strconv.FormatInt(a.ActionID, 10), Tool: a.Tool}
	}
	sev, report := repoTrustBaselineSeverity(ch, byAgent)
	f.Severity = sev
	return secfinding.Normalize(f), report
}

// repoTrustVersionWindow is how far back the agent version check reads
// sessions.
const repoTrustVersionWindow = 30 * 24 * time.Hour

// repoTrustVersionRule prefixes the finding rule id of a known-vulnerable
// agent version; the CVE id completes it.
const repoTrustVersionRule = "agent-version/"

// repoTrustVersionPass is agent version hygiene (security pillar plan
// section 5.1 item 4): every (project, tool, version) a recent session ran
// with is compared with the shipped CVE table (sectrust.KnownVulnerable),
// and each match is an agent_config finding on that project. A version
// that does not parse matches nothing. It returns the findings recorded
// (an existing one is refreshed, not duplicated).
func repoTrustVersionPass(ctx context.Context, st *store.Store, now time.Time, logger *slog.Logger) int {
	rows, err := st.RecentSessionToolVersions(ctx, now.Add(-repoTrustVersionWindow), 500)
	if err != nil {
		if logger != nil {
			logger.Warn("security.trust: agent version check skipped", "err", err)
		}
		return 0
	}
	n := 0
	for _, r := range rows {
		for _, v := range sectrust.KnownVulnerable(r.Tool, r.ToolVersion) {
			f := repoTrustVersionFinding(r, v, now)
			if _, _, err := st.UpsertSecFinding(ctx, f, now); err != nil {
				if logger != nil {
					logger.Warn("security.trust: agent version finding not recorded", "err", err)
				}
				continue
			}
			n++
		}
	}
	return n
}

// repoTrustVersionFinding is the finding of one known-vulnerable version.
// The message is built from the shipped table, never from session text
// beyond the tool id and the parsed version.
func repoTrustVersionFinding(r store.SessionToolVersion, v sectrust.VulnerableVersion, now time.Time) secfinding.Finding {
	rootHash := guard.HashProjectRoot(r.ProjectRoot)
	rule := repoTrustVersionRule + v.CVE
	f := secfinding.Finding{
		Rule:       secfinding.Rule{ID: rule, Version: "1", Pack: repoTrustComponent, PackVersion: secrules.PackVersion},
		Engine:     secfinding.Engine{Driver: "sectrust.versions"},
		Category:   policy.FindingAgentConfig,
		Severity:   policy.FindingSeverityHigh,
		Confidence: policy.FindingConfidenceHigh,
		Scope:      policy.FindingScopeScheduled,
		Project:    secfinding.Project{RootHash: rootHash},
		References: secfinding.References{},
		Message: "A session here ran " + v.Tool + " at a version before " + v.FixedIn + ", affected by " + v.CVE + ": " +
			v.Summary + ".",
		FixHint:     "Update " + v.Tool + " to " + v.FixedIn + " or later (source: " + v.Source + ").",
		Attribution: secfinding.InferredAttribution{Class: policy.FindingAttributionUnknown, Method: "sectrust.versions.v1", Confidence: policy.FindingConfidenceHigh},
		Lineage:     secfinding.Lineage{SessionID: r.SessionID, Tool: r.Tool, ToolVersion: r.ToolVersion},
		FirstSeen:   now,
		LastSeen:    now,
	}
	f.LocalKey = secfinding.LocalKey(rootHash, rule, secfinding.TextIdentity(r.Tool+"\x00"+r.ToolVersion))
	return secfinding.Normalize(f)
}

// repoTrustBaselineLoop is the one owner of the baseline loop's state: the
// action watermark of the event feed and the roots an event marked for a
// rescan.
type repoTrustBaselineLoop struct {
	st     *store.Store
	logger *slog.Logger
	// home is the home directory the user-scope pass reads ("" skips it),
	// and userPaths the user-scope table resolved for this machine.
	home      string
	userPaths []agentconfig.TrustPath
	// table is the path table and devcontainer parser the project snapshot
	// reads (repoTrustConditional), and projectPaths its path rows, which
	// the event feed matches agent writes against.
	table        repoTrustBaselineTable
	projectPaths []agentconfig.TrustPath
	// mark is the highest action id the event feed has read.
	mark int64
	// pending are the project roots, and pendingUser the home directory,
	// an agent wrote a table file of in the previous event pass: rescanned
	// on the next one, so the write the action records has landed.
	pending     map[string]bool
	pendingUser bool
}

// newRepoTrustBaselineLoop starts the event feed at the newest action, so a
// restart never replays history (the full pass covers what happened while
// the daemon was down).
func newRepoTrustBaselineLoop(ctx context.Context, st *store.Store, home string, logger *slog.Logger) *repoTrustBaselineLoop {
	l := &repoTrustBaselineLoop{st: st, logger: logger, pending: map[string]bool{}}
	l.setTable(repoTrustBaselineDefaultTable())
	if home != "" {
		l.home = filepath.Clean(home)
		// The relocation variables are read under the pinned-home rule
		// (crossmount.HomeEnvAt, FU-129).
		l.userPaths = agentconfig.TrustUserPaths(agentconfig.PathEnv{GOOS: runtime.GOOS, Home: l.home, Getenv: crossmount.HomeEnvAt(l.home, nil)})
	}
	if id, err := st.LatestActionID(ctx); err == nil {
		l.mark = id
	} else if logger != nil {
		logger.Warn("security.trust: baseline change feed starts at the first action", "err", err)
	}
	return l
}

// setTable sets the project table the loop reads.
func (l *repoTrustBaselineLoop) setTable(t repoTrustBaselineTable) {
	l.table = t
	l.projectPaths = t.projectPaths()
}

// fullTick is the timer pass: every recent project, then the home
// directory's agent config, then the agent version check.
func (l *repoTrustBaselineLoop) fullTick(ctx context.Context, now time.Time) {
	repoTrustBaselineTickWith(ctx, l.st, l.table, repoTrustBaselineMaxRoots, now, l.logger)
	l.userPass(ctx, now)
}

// userPass is the user-scope baseline, logged.
func (l *repoTrustBaselineLoop) userPass(ctx context.Context, now time.Time) {
	n, err := repoTrustUserBaselinePass(ctx, l.st, l.home, l.userPaths, now)
	if err != nil && l.logger != nil {
		l.logger.Warn("security.trust: user-scope baseline failed", "err", err)
	}
	if n > 0 && l.logger != nil {
		l.logger.Info("security.trust: user-scope agent config changed", "changes", n)
	}
}

// eventTick rescans what the previous event pass marked, then reads the
// agent writes recorded since and marks every project, and the home
// directory, one of them touched a table file of.
func (l *repoTrustBaselineLoop) eventTick(ctx context.Context, now time.Time) {
	roots := make([]string, 0, len(l.pending))
	for root := range l.pending {
		roots = append(roots, root)
	}
	sort.Strings(roots)
	l.pending = map[string]bool{}
	if len(roots) > 0 {
		if n := repoTrustBaselinePassWith(ctx, l.st, l.table, roots, now, l.logger); n > 0 && l.logger != nil {
			l.logger.Info("security.trust: agent config changed", "changes", n)
		}
	}
	if l.pendingUser {
		l.pendingUser = false
		l.userPass(ctx, now)
	}
	writes, err := l.st.AgentFileWritesAfter(ctx, l.mark, repoTrustBaselineEventBatch)
	if err != nil {
		if l.logger != nil {
			l.logger.Warn("security.trust: baseline change feed unreadable", "err", err)
		}
		return
	}
	for _, w := range writes {
		l.mark = w.ActionID
		project, user := repoTrustWriteTouches(w, l.home, l.projectPaths, l.userPaths)
		if project {
			l.pending[w.ProjectRoot] = true
		}
		l.pendingUser = l.pendingUser || user
	}
}

// repoTrustWriteTouches reports whether one agent write touched a file the
// project snapshot reads (the target relative to its project root; a
// relative target is taken as project-relative) and whether it touched one
// the user-scope snapshot reads (an absolute target inside home).
func repoTrustWriteTouches(w store.AgentFileWrite, home string, projectPaths, userPaths []agentconfig.TrustPath) (project, user bool) {
	target := strings.TrimSpace(w.Target)
	if target == "" {
		return false, false
	}
	if rel, ok := repoTrustRelUnder(w.ProjectRoot, target); ok {
		project = sectrust.InTable(rel, projectPaths)
	}
	if filepath.IsAbs(target) {
		if rel, ok := repoTrustRelUnder(home, target); ok {
			user = sectrust.InTable(rel, userPaths)
		}
	}
	return project, user
}

// repoTrustRelUnder is target relative to root, slash-separated, when it is
// inside root; a relative target is taken as already relative to root.
func repoTrustRelUnder(root, target string) (string, bool) {
	if root == "" {
		return "", false
	}
	if !filepath.IsAbs(target) {
		return filepath.ToSlash(filepath.Clean(target)), !strings.HasPrefix(filepath.Clean(target), "..")
	}
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(target))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

// repoTrustUserKey is the key the user-scope snapshot and its items are
// stored under: the hash of a spelling no project root can have, so a
// project opened at the home directory keeps a snapshot of its own.
func repoTrustUserKey(home string) string {
	return guard.HashProjectRoot("user-scope:" + filepath.Clean(home))
}

// repoTrustUserGrade is one row of the user-scope grading table: the first
// row whose match holds decides whether a change is reported and at what
// severity.
type repoTrustUserGrade struct {
	match    func(byAgent, newItem bool) bool
	report   bool
	severity policy.FindingSeverity
}

// repoTrustUserGrades grades a user-scope change. The home directory's
// agent config changes in normal work (the developer's own edits, a tool
// writing its preferences, Observer registering its hooks), so a change is
// reported only when it adds something an agent runs that the baseline had
// not seen (a hook command, an MCP server, a plugin: an item with a new
// digest), which is how a worm persists across every project, or when an
// agent's file write made it.
var repoTrustUserGrades = []repoTrustUserGrade{
	{match: func(byAgent, newItem bool) bool { return byAgent && newItem }, report: true, severity: policy.FindingSeverityHigh},
	{match: func(byAgent, _ bool) bool { return byAgent }, report: true, severity: policy.FindingSeverityMedium},
	{match: func(_, newItem bool) bool { return newItem }, report: true, severity: policy.FindingSeverityMedium},
	{match: func(bool, bool) bool { return true }, report: false},
}

// repoTrustUserSeverity walks the user-scope grading table for one change.
func repoTrustUserSeverity(byAgent, newItem bool) (policy.FindingSeverity, bool) {
	for _, g := range repoTrustUserGrades {
		if g.match(byAgent, newItem) {
			return g.severity, g.report
		}
	}
	return "", false
}

// repoTrustUserBaselinePass is the user-scope config baseline (security
// pillar plan section 5.1 item 1, user scope): the trust check over the
// home directory with the user-scope table, its snapshot compared with the
// stored one, and a finding per change the grading table reports. The
// items with a digest are recorded under the user key, so the next pass
// knows which are new. The first pass only stores. It returns the number
// of changes recorded.
func repoTrustUserBaselinePass(ctx context.Context, st *store.Store, home string, paths []agentconfig.TrustPath, now time.Time) (int, error) {
	if home == "" || len(paths) == 0 {
		return 0, nil
	}
	if fi, err := os.Stat(home); err != nil || !fi.IsDir() {
		return 0, nil
	}
	key := repoTrustUserKey(home)
	prev, had, err := st.LoadSecConfigFiles(ctx, key)
	if err != nil {
		return 0, err
	}
	res, err := sectrust.Check(ctx, sectrust.OSFS(home), sectrust.Request{Paths: paths, Own: repoTrustObserverOwn(home, paths)})
	if err != nil {
		return 0, err
	}
	// Observer's own entries (its hooks, MCP server, status line and
	// plugins) are left out before the new-item test, so `observer init`
	// and a release that changes the registered hooks raise nothing (plans
	// decision log P-037). The file-level change is still graded: an agent's
	// write to one of these files is reported.
	items := sectrustitem.FromUserReasons(repoTrustNotObserverOwn(res.Reasons))
	cur := make([]store.SecConfigFile, 0, len(res.Files))
	for _, f := range res.Files {
		cur = append(cur, store.SecConfigFile{RelPath: f.Rel, PathClass: f.Class, SHA256: f.SHA256, Size: f.Size})
	}
	recorded := 0
	if had {
		known, err := st.ListSecTrustItems(ctx, key)
		if err != nil {
			return 0, err
		}
		seen := make(map[string]bool, len(known))
		for _, k := range known {
			seen[k.ContentHash] = true
		}
		newIn := map[string]bool{}
		for _, it := range items {
			if !seen[it.ContentHash] {
				newIn[it.RelPath] = true
			}
		}
		before := make([]sectrust.FileState, 0, len(prev))
		for _, f := range prev {
			before = append(before, sectrust.FileState{Rel: f.RelPath, Class: f.PathClass, SHA256: f.SHA256, Size: f.Size})
		}
		since := time.Time{}
		if last, err := st.SecLastConfigSnapshot(ctx, key); err == nil {
			since = last
		}
		for _, ch := range sectrust.Diff(before, res.Files, !res.Truncated) {
			f, report := repoTrustUserBaselineFinding(ctx, st, home, key, ch, newIn[ch.Rel], since, now)
			if !report {
				continue
			}
			if _, _, err := st.UpsertSecFinding(ctx, f, now); err != nil {
				return recorded, err
			}
			recorded++
		}
	}
	if err := st.RecordSecTrustItems(ctx, key, items, now); err != nil {
		return recorded, err
	}
	return recorded, st.ReplaceSecConfigFiles(ctx, key, cur, now)
}

// repoTrustNotObserverOwn drops the reasons Request.Own marked as
// Observer's own.
func repoTrustNotObserverOwn(reasons []sectrust.Reason) []sectrust.Reason {
	out := make([]sectrust.Reason, 0, len(reasons))
	for _, r := range reasons {
		if !r.Observer {
			out = append(out, r)
		}
	}
	return out
}

// repoTrustUserBaselineFinding builds the agent_config finding of one
// user-scope change and reports whether the grading table reports it. The
// path is relative to the home directory; the message is fixed text.
func repoTrustUserBaselineFinding(ctx context.Context, st *store.Store, home, key string, ch sectrust.FileChange, newItem bool, since, now time.Time) (secfinding.Finding, bool) {
	msg := "An agent config file in your home directory, which applies to every project, was " + string(ch.Kind) + " (" + ch.Class + " file)."
	if newItem {
		msg += " It now names something a coding agent runs (a hook, an MCP server or a plugin) that was not there before."
	}
	f := secfinding.Finding{
		Rule:       secfinding.Rule{ID: repoTrustBaselineUserRule, Version: "1", Pack: repoTrustComponent, PackVersion: secrules.PackVersion},
		Engine:     secfinding.Engine{Driver: "sectrust.baseline"},
		Category:   policy.FindingAgentConfig,
		Confidence: policy.FindingConfidenceHigh,
		Scope:      policy.FindingScopeScheduled,
		Project:    secfinding.Project{RootHash: key},
		Location:   secfinding.Location{RelPath: ch.Rel},
		Message:    msg + " Review it.",
		FixHint:    "Open the file in your home directory and read the change; if you did not make it (an install script, another tool or an agent may have), remove the entry.",
		Attribution: secfinding.InferredAttribution{
			Class: policy.FindingAttributionUnknown, Method: "sectrust.baseline.user.v1", Confidence: policy.FindingConfidenceLow,
		},
		FirstSeen: now,
		LastSeen:  now,
	}
	f.LocalKey = secfinding.LocalKey(key, repoTrustBaselineUserRule, secfinding.TextIdentity(ch.Rel+"\x00"+string(ch.Kind)+"\x00"+ch.Old+"\x00"+ch.New))
	targets := []string{filepath.Join(home, filepath.FromSlash(ch.Rel)), "~/" + ch.Rel}
	byAgent := false
	if a, ok, err := st.LatestAgentWriteTo(ctx, targets, since); err == nil && ok {
		byAgent = true
		f.Attribution = secfinding.InferredAttribution{Class: policy.FindingAttributionAI, Method: "sectrust.baseline.user.v1", Confidence: policy.FindingConfidenceMedium}
		f.Lineage = secfinding.Lineage{SessionID: a.SessionID, ActionID: strconv.FormatInt(a.ActionID, 10), Tool: a.Tool}
	}
	sev, report := repoTrustUserSeverity(byAgent, newItem)
	f.Severity = sev
	return secfinding.Normalize(f), report
}
