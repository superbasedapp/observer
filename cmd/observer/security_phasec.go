//go:build !sbo_omit_security

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitscan"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secciwf"
	"github.com/marmutapp/superbased-observer/internal/secdetect"
	"github.com/marmutapp/superbased-observer/internal/secdiffobs"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secpostwrite"
	"github.com/marmutapp/superbased-observer/internal/secquickscan"
	"github.com/marmutapp/superbased-observer/internal/secrules"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_phasec.go is the daemon wiring of security Phase C (security
// pillar plan sections 4.8 and 5.3; lane SEC-C2): the commit quick scan
// behind the owner-only endpoint, the clean scan's covered dirty counter,
// the post-write feed and the commit-scan step. The loops run only as
// moduleGates rows (components_gate.go): security.quickscan under the
// module root, security.postwrite under security.secrets. The commit-scan
// step rides the commit scanner's tick and does nothing until the
// postwrite loop has published its scanner, so a node with the child off
// pays one atomic load per tick.

// securityRuntime is the state the module's loops share in the daemon:
// the posture service (for the covered dirty counter and re-sign
// requests), whether the quick scan is serving, and the commit-scan step.
type securityRuntime struct {
	svc        atomic.Pointer[secsvc.Service]
	scanReady  atomic.Bool
	commitScan atomic.Pointer[securityCommitStep]
	// projects lists the node's known project roots (the posture loop
	// publishes its store's ProjectRoots); the quick-scan endpoint answers
	// only for one of them.
	projects atomic.Pointer[func(context.Context) ([]string, error)]
	roots    knownRootCache
}

// knownRootCacheTTL is how long the endpoint reuses a project list.
const knownRootCacheTTL = 30 * time.Second

// knownRootCache holds the last project list the endpoint read.
type knownRootCache struct {
	mu    sync.Mutex
	at    time.Time
	roots map[string]bool
}

// securityAllowRoot reports whether a quick-scan request may name root:
// one of the node's known projects (as stored, or as the commit scanner
// spells a stored Windows root under WSL), in any spelling the hook gives
// it (the shared path normalizer: a WSL-bridged hook's Windows spelling),
// or a root the node does not list yet that git confirms is a working
// tree's root as spelled (a project whose first session is not ingested
// yet; lane sec-gate2). While no project list is published, every root is
// refused (the answer is unknown, never a scan whose clean answer would
// cover the request's DirtySeen; lane SEC-GATEFIX milestone 2h).
func securityAllowRoot(root string) bool {
	return securityRT.allowRoot(root, time.Now())
}

func (r *securityRuntime) allowRoot(root string, now time.Time) bool {
	list := r.projects.Load()
	if list == nil || root == "" {
		return false
	}
	spellings := []string{root}
	if n := commitScanRoot(root); n != "" && n != root {
		spellings = append(spellings, n)
	}
	if r.knownRoot(list, spellings, now) {
		return true
	}
	for _, sp := range spellings {
		if gitRoot, ok := git.FindRoot(sp); ok && filepath.Clean(gitRoot) == filepath.Clean(sp) {
			return true
		}
	}
	return false
}

// knownRoot reports whether one of spellings is a known project root,
// re-reading the project list when the cache is old (or, for a miss, more
// than a second old, so a new project is seen at once).
func (r *securityRuntime) knownRoot(list *func(context.Context) ([]string, error), spellings []string, now time.Time) bool {
	c := &r.roots
	c.mu.Lock()
	defer c.mu.Unlock()
	hit := func() bool {
		for _, sp := range spellings {
			if c.roots[sp] {
				return true
			}
		}
		return false
	}
	if c.roots == nil || now.Sub(c.at) > knownRootCacheTTL || (!hit() && now.Sub(c.at) > time.Second) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		roots, err := (*list)(ctx)
		cancel()
		if err != nil {
			return hit()
		}
		c.roots, c.at = map[string]bool{}, now
		for _, rt := range roots {
			c.roots[rt] = true
			c.roots[commitScanRoot(rt)] = true
		}
	}
	return hit()
}

// securityRT is the daemon's one securityRuntime.
var securityRT securityRuntime

// notify asks the posture loop for a re-sign, when it runs.
func (r *securityRuntime) notify() {
	if svc := r.svc.Load(); svc != nil {
		svc.Notify()
	}
}

// securityFindingKeyName is the per-node key a secret finding's identity is
// keyed under (HMAC(node key, type || value)): beside the posture key, in
// the owner-only security directory, never shipped.
const securityFindingKeyName = "finding.key"

// securityIdentify returns the detector's Identify for the node key at
// resolved, or nil when the key cannot be read or made (then no secret
// finding is stored; the commit gate still decides on the quick scan).
func securityIdentify(resolved string) func(typ, value string) string {
	key, err := secposture.LoadOrCreateKey(filepath.Join(secposture.LayoutFor(resolved).Dir, securityFindingKeyName))
	if err != nil {
		slog.Default().Warn("security: finding key unavailable; secret findings are not stored", "err", err)
		return nil
	}
	dir := secposture.LayoutFor(resolved).Dir
	return func(typ, value string) string {
		id, err := secfinding.SecretIdentity(key, typ, value)
		if err != nil {
			return ""
		}
		// The org dedupe key's digest while the value is in hand (lane
		// LEFT-SHARED, security_orgkey.go; nothing without a held key).
		securityNoteOrgIdentity(dir, id.Value, typ, value)
		return id.Value
	}
}

// newSecurityQuickScanEngine is the quick scan over the read-only gitview
// envelope (no external diff, textconv, renames or hooks), keyed by the
// rule pack version so a pack change never reuses an old clean answer. It
// never lazily fetches a missing object in a partial clone (the daemon's
// commit scan runs it unattended, and a fetch runs the repository's own
// transport configuration; RB1 sweep finding P2): a missing object is an
// error, which the scan answers as unknown, never clean.
func newSecurityQuickScanEngine(identify func(string, string) string) *secquickscan.Engine {
	return &secquickscan.Engine{
		Git:      gitview.RunReadOnlyNoLazyFetch,
		Version:  secrules.PackVersion,
		Scanner:  secdetect.Scanner{Identify: identify},
		ReadFile: securityReadWorkingFile,
		// The install gate reads a changed manifest's diff for S-747 at
		// commit (false without security.deps compiled in).
		Retain: depsRetainPath,
	}
}

// securityReadWorkingFile reads a working-tree file for the quick scan's
// workflow check through the post-write seam's defensive reader (no
// symlink, nothing outside the root, a regular file, capped).
func securityReadWorkingFile(root, rel string, maxBytes int) ([]byte, bool, error) {
	b, err := secpostwrite.ReadFile(root, rel, maxBytes)
	if errors.Is(err, secpostwrite.ErrTooLarge) {
		return nil, true, nil
	}
	return b, false, err
}

// securityQuickScanner serves the hook's request: the engine's seam
// adapter, then, for a clean answer, the covered dirty counter recorded in
// the posture service so the next commit is clean without a wait. The
// covered value is the smaller of what the hook saw and the counter the
// daemon reads itself before the scan, so a request can never claim
// coverage for activity that had not happened when the scan read the diff.
func securityQuickScanner(layout secposture.Layout, e *secquickscan.Engine) hookctx.QuickScanner {
	inner := e.QuickScannerObserved(recordQuickScanCode)
	return func(ctx context.Context, req hookctx.QuickScanRequest) (hookctx.QuickScanResult, error) {
		hash := secposture.ProjectRootHash(req.ProjectRoot)
		before, err := secposture.ReadDirty(layout, hash)
		if err != nil {
			before = 0
		}
		res, err := inner(ctx, req)
		if err != nil || res.Verdict != policy.QuickScanClean {
			res.DirtyCovered = 0
			return res, err
		}
		covered := min(res.DirtyCovered, before)
		res.DirtyCovered = covered
		if covered > 0 {
			if svc := securityRT.svc.Load(); svc != nil {
				svc.RecordCleanScan(req.ProjectRoot, covered)
			}
		}
		return res, nil
	}
}

// recordQuickScanCode stores what a commit's quick scan saw that the
// seam's verdict does not carry: its workflow rule hits and diff
// observations, as staged findings, while security.code is active and the
// postwrite loop has published its store (lane SEC-GATEFIX milestone 2i).
// It runs off the hook's reply path.
func recordQuickScanCode(root string, r secquickscan.Result) {
	step := securityRT.commitScan.Load()
	if step != nil && step.st != nil && len(r.Retained) > 0 {
		// S-747 at commit (lane SEC-D1FIX2): the staged manifest additions
		// the install gate flags, while security.deps runs.
		go recordDepsManifests(context.Background(), step.st, root, "", policy.FindingScopeStaged, r.Retained, step.logger)
	}
	if step == nil || !step.code || step.st == nil || r.Verdict == secquickscan.VerdictUnknown {
		return
	}
	if len(r.CI) == 0 && len(r.Observations) == 0 && r.CIUnchecked == 0 && len(r.CIChecked) == 0 {
		return
	}
	go recordSecurityCode(context.Background(), step.st, root, secposture.ProjectRootHash(root), "", policy.FindingScopeStaged, r, step.logger)
}

// securityPostWriteEvery is how often the post-write feed reads new writes.
const securityPostWriteEvery = 2 * time.Second

// securityPostWriteBatch bounds one read of the feed.
const securityPostWriteBatch = 256

// runSecurityPostWrite is the security.postwrite loop: it reads every
// successful file write stored after the daemon started (from any writer,
// including the hook process, whose rows the watcher skips as duplicates),
// queues it on the bounded, deduplicating post-write queue, scans the file
// with the secret rows and records each blocking hit as a finding. It also
// publishes the commit-scan step for the commit scanner's tick.
func runSecurityPostWrite(ctx context.Context, st *store.Store, resolved string, capKiB func() int, sw securityCommitSwitches, logger *slog.Logger) {
	identify := securityIdentify(resolved)
	scanner := secdetect.Scanner{Identify: identify}
	securityRT.commitScan.Store(&securityCommitStep{scan: &secquickscan.CommitScan{Engine: newSecurityQuickScanEngine(identify)}, st: st, logger: logger, code: sw.code, skipSecrets: !sw.secrets})
	defer securityRT.commitScan.Store(nil)
	q := &secpostwrite.Queue{
		CapNow:  capKiB,
		Scanner: scanner,
		Sink: func(ctx context.Context, r secpostwrite.Result) {
			recordPostWrite(ctx, st, r, logger)
		},
	}
	go q.Run(ctx)
	last, err := st.MaxActionID(ctx)
	if err != nil {
		logger.Warn("security: post-write feed not started", "err", err)
		return
	}
	rescan := &securityRescan{st: st, q: q, code: sw.code, logger: logger}
	// A history pass still running when the loop ends sees the cancelled
	// context and stops; the loop waits for it before the store goes away.
	defer rescan.waitHistory()
	rescanT := time.NewTicker(securityRescanEvery)
	defer rescanT.Stop()
	headT := time.NewTicker(securityHeadWatchEvery)
	defer headT.Stop()
	t := time.NewTicker(securityPostWriteEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-rescanT.C:
			rescan.tick(ctx, time.Now())
			// The hosted runs' saved staged diffs (lane LEFT-SEC); nil in a
			// build without the sandbox module.
			if securityHostedReturnsTick != nil {
				securityHostedReturnsTick(ctx, securityRT.commitScan.Load(), secposture.LayoutFor(resolved).Dir)
			}
			continue
		case <-headT.C:
			rescan.watchPushDefaultHeads(ctx)
			continue
		case <-t.C:
		}
		for {
			writes, next, err := st.PostWritesAfter(ctx, last, securityPostWriteBatch)
			if err != nil {
				logger.Warn("security: post-write feed read failed", "err", err)
				break
			}
			last = next
			for _, w := range writes {
				// A write in a sandbox copy workspace is read where it
				// really is (lane sec-box, security_box.go).
				q.Submit(securityPostWriteFor(ctx, st, w))
			}
			if len(writes) < securityPostWriteBatch {
				break
			}
		}
		if n := q.Dropped(); n > 0 {
			logger.Debug("security: post-write queue full", "dropped_total", n)
		}
	}
}

// The rescan of open findings' files (lane sec-gate2 milestone 1b): a
// human's edit or `rm` writes no action row, so the post-write feed never
// sees it. Each tick reads up to securityRescanBatch files that open
// findings are sighted in, least recently seen first, and rescans them as
// a post-write scan would: a secret no longer there, or a file that is
// gone, closes its sighting.
const (
	securityRescanEvery = time.Minute
	securityRescanBatch = 32
	// securityRescanQuiet is how long a rescanned file is left alone, so
	// a file that stays unreadable cannot starve the others.
	securityRescanQuiet = 10 * time.Minute
	// securityRecheckMaxBytes caps a whole-file observation recheck.
	securityRecheckMaxBytes = 256 << 10
)

// securityRescan is the rescan's state: the store, the post-write queue a
// secret rescan goes through, whether the code rows are recorded, when
// each file was last rescanned, where the walk over the open sightings and
// the held commits stands, and the history check.
type securityRescan struct {
	st     *store.Store
	q      *secpostwrite.Queue
	code   bool
	logger *slog.Logger
	last   map[string]time.Time
	// after is the last sighting the previous tick examined: each tick
	// reads the page after it, and wraps to the start at the end, so no
	// row (an unreadable file, a file quiet after a rescan) can hold the
	// head of the list (lane sec-gate3 milestone 1a).
	after store.SecOpenSighting
	// held is the walk's place in the commits that hold open findings.
	held store.SecFindingCommit
	// history answers whether a held commit is still unpushed, and which
	// remotes already have it (nil: the production checker over the
	// read-only git envelope).
	history func(ctx context.Context, root, sha string) secquickscan.HistoryVerdict
	// pushDefault resolves a repository's default push remote (nil: the
	// production resolver over the read-only git envelope).
	pushDefault func(ctx context.Context, root string) (string, bool)
	// historyBudget bounds one history pass (zero: securityHistoryBudget).
	// The pass runs in its own goroutine, at most one at a time, so a hung
	// git never stalls the post-write loop that ticks it (lane sec-gate4
	// milestone 2a).
	historyBudget  time.Duration
	historyRunning atomic.Bool
	// headWatchRunning: a HEAD watch look is running
	// (watchPushDefaultHeads).
	headWatchRunning atomic.Bool
	historyWG        sync.WaitGroup
}

// The history check's bounds: how many held commits one pass checks, the
// whole pass's budget and one git call's timeout. A pass that runs out of
// budget stops where it is; the next tick resumes after the last commit
// it checked.
const (
	securityHistoryBatch       = 8
	securityHistoryBudget      = 20 * time.Second
	securityHistoryCallTimeout = 2 * time.Second
)

// securityRescanKind is what a rescan of one sighting reads.
type securityRescanKind int

const (
	rescanNone securityRescanKind = iota
	rescanSecret
	rescanWorkflow
	rescanVerification
)

// rescanKindFor maps a sighting onto its rescan: a secret through the
// post-write queue, a workflow rule hit through the workflow rules, a
// recheckable observation through the observation rules; nothing else.
func rescanKindFor(o store.SecOpenSighting) securityRescanKind {
	switch {
	case o.RulePack == securitySecretsPack:
		return rescanSecret
	case o.RulePack == securityCodePack && strings.HasPrefix(o.RuleID, securityCIRulePrefix):
		return rescanWorkflow
	case o.RulePack == securityCodePack && slices.Contains(securityRecheckObservations, o.RuleID):
		return rescanVerification
	}
	return rescanNone
}

// rescanClasses are the finding classes a rescan can answer, the same set
// rescanKindFor maps (the secrets always, the code rows while they are
// recorded), handed to the store so the rows no rescan can answer (S-767,
// S-768, S-747, a scanner's rows) are never read.
func rescanClasses(code bool) []store.SecRescanClass {
	out := []store.SecRescanClass{{Pack: securitySecretsPack}}
	if code {
		out = append(out, store.SecRescanClass{Pack: securityCodePack, RulePrefixes: []string{securityCIRulePrefix}, RuleIDs: securityRecheckObservations})
	}
	return out
}

// rescanRoots maps each project root hash the node knows to the root the
// rescan reads, in both the stored spelling and the commit scanner's
// (commitScanRoot), so a finding the commit step recorded under the
// translated root is rescanned too.
func rescanRoots(roots []string) map[string]string {
	byHash := make(map[string]string, 2*len(roots))
	for _, rt := range roots {
		byHash[secposture.ProjectRootHash(rt)] = rt
		if tr := commitScanRoot(rt); tr != rt {
			if _, ok := byHash[secposture.ProjectRootHash(tr)]; !ok {
				byHash[secposture.ProjectRootHash(tr)] = tr
			}
		}
	}
	return byHash
}

// tick rescans one batch and checks one batch of held commits.
func (r *securityRescan) tick(ctx context.Context, now time.Time) {
	if r.st == nil {
		return
	}
	roots, err := r.st.ProjectRoots(ctx)
	if err != nil || len(roots) == 0 {
		return
	}
	byHash := rescanRoots(roots)
	hashes := make([]string, 0, len(byHash))
	for h := range byHash {
		hashes = append(hashes, h)
	}
	slices.Sort(hashes)
	r.startHistory(ctx, byHash, hashes, now)
	rows, err := r.st.SecRescanSightings(ctx, store.SecRescanQuery{
		Driver: "native", Classes: rescanClasses(r.code), RootHashes: hashes, After: r.after, Limit: securityRescanBatch * 4,
	})
	if err != nil {
		return
	}
	if len(rows) < securityRescanBatch*4 {
		// The end of the list is on this page: once it is examined whole,
		// the next tick starts at the first row again.
		defer func() {
			if len(rows) == 0 || r.after == rows[len(rows)-1] {
				r.after = store.SecOpenSighting{}
			}
		}()
	}
	if len(rows) == 0 {
		return
	}
	if r.last == nil {
		r.last = map[string]time.Time{}
	}
	for k, at := range r.last {
		if now.Sub(at) > securityRescanQuiet {
			delete(r.last, k)
		}
	}
	n := 0
	for _, o := range rows {
		if n >= securityRescanBatch {
			break
		}
		r.after = o
		kind := rescanKindFor(o)
		root := byHash[o.ProjectRootHash]
		if kind == rescanNone || root == "" || ((kind == rescanWorkflow || kind == rescanVerification) && !r.code) {
			continue
		}
		key := fmt.Sprintf("%s\x00%s\x00%d", root, o.Path, kind)
		if _, recent := r.last[key]; recent {
			continue
		}
		r.last[key] = now
		n++
		switch kind {
		case rescanSecret:
			r.q.Submit(securityRescanWrite(root, o.Path))
		case rescanWorkflow:
			r.recheckWorkflow(ctx, root, o.Path)
		case rescanVerification:
			r.recheckVerification(ctx, root, o.Path)
		}
	}
}

// startHistory starts one history pass in its own goroutine under the
// pass budget, unless the previous pass is still running (then this tick
// skips it). It never waits for the pass.
func (r *securityRescan) startHistory(ctx context.Context, byHash map[string]string, hashes []string, now time.Time) {
	if !r.historyRunning.CompareAndSwap(false, true) {
		return
	}
	budget := r.historyBudget
	if budget <= 0 {
		budget = securityHistoryBudget
	}
	r.historyWG.Add(1)
	go func() {
		defer r.historyWG.Done()
		defer r.historyRunning.Store(false)
		hctx, cancel := context.WithTimeout(ctx, budget)
		defer cancel()
		r.checkHistory(hctx, byHash, hashes, now)
	}()
}

// waitHistory waits for a running history pass to end.
func (r *securityRescan) waitHistory() { r.historyWG.Wait() }

// pushDefaultTable holds the default push remote the history pass last
// resolved per project root hash (lane sec-gate4 audit finding 5). One
// owner: the history pass and the HEAD watch (watchPushDefaultHeads) write
// it, the posture writer reads it (secsvc.Options.PushDefault) and signs
// it into the project's posture. A restart starts empty, so a plain push
// stays an unknown target until the first pass.
//
// Each entry remembers the repository and when it was resolved: a branch
// switch after that (a checkout's HEAD written since, git.LatestHeadWrite)
// makes it stale, and a stale entry reads "" (an unknown target, never the
// previous branch's remote) until the HEAD watch resolves it again (lane
// SEC-GATE5 milestone 2, SECP-18).
type pushDefaultTable struct {
	mu sync.Mutex
	m  map[string]pushDefaultEntry
}

// pushDefaultEntry is one resolved default.
type pushDefaultEntry struct {
	remote, root string
	at           time.Time
}

// pushDefaultHeadWrite is when a checkout of the repository at root last
// wrote its HEAD (a seam for tests).
var pushDefaultHeadWrite = git.LatestHeadWrite

// pushDefaultHeadFuture is how far past now a checkout's HEAD write may
// lie before it is read as a clock in the future (clock skew, DrvFs, a
// network file system) rather than a switch.
const pushDefaultHeadFuture = 2 * time.Second

// pushDefaultResolvedAt is when an entry resolved from reads that started
// at at counts as resolved: at, unless a checkout's HEAD write lies in the
// future, in which case it is that write (just after it). Without the
// clamp such an entry is stale on every look, so the HEAD watch would run
// git and re-sign every few seconds for as long as the clock disagrees
// (merge finding F7 of lane SEC-GATE5, the audit's HEAD clock finding). A later switch writes HEAD after
// that, so it still makes the entry stale.
func pushDefaultResolvedAt(root string, at time.Time) time.Time {
	latest, ok := pushDefaultHeadWrite(root)
	if !ok {
		return at
	}
	return clampFutureHeadWrite(latest, at, time.Now())
}

// clampFutureHeadWrite is the one clamp of a HEAD write in the future,
// shared by the daemon's push-default table (pushDefaultResolvedAt) and
// the hook (hookDropStalePushDefault): at, unless latest lies more than
// pushDefaultHeadFuture past now and not before at, in which case just
// after latest, so that write counts as resolved.
func clampFutureHeadWrite(latest, at, now time.Time) time.Time {
	if !latest.After(now.Add(pushDefaultHeadFuture)) || latest.Before(at) {
		return at
	}
	if latest.Nanosecond() == 0 {
		// A whole-second write compares at one-second granularity
		// (git.HeadWriteBefore): the next second counts it resolved.
		return latest.Add(time.Second)
	}
	return latest.Add(time.Nanosecond)
}

// set records hash's default for the repository at root, resolved from git
// reads that started at at ("" or !ok forgets it), and reports a change.
// A HEAD write in the future is clamped (pushDefaultResolvedAt).
func (t *pushDefaultTable) set(hash, root, remote string, ok bool, at time.Time) bool {
	if ok && remote != "" {
		at = pushDefaultResolvedAt(root, at)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !ok {
		remote = ""
	}
	prev := t.m[hash].remote
	if remote == "" {
		delete(t.m, hash)
	} else {
		if t.m == nil {
			t.m = map[string]pushDefaultEntry{}
		}
		t.m[hash] = pushDefaultEntry{remote: remote, root: root, at: at}
	}
	return prev != remote
}

// get returns hash's default push remote, "" when none or when a
// checkout's HEAD was written at or after it was resolved (or the HEADs
// cannot be read).
func (t *pushDefaultTable) get(hash string) string {
	t.mu.Lock()
	e, ok := t.m[hash]
	t.mu.Unlock()
	if !ok || e.remote == "" {
		return ""
	}
	if latest, ok := pushDefaultHeadWrite(e.root); !ok || !git.HeadWriteBefore(latest, e.at) {
		return ""
	}
	return e.remote
}

// stale returns the entries a checkout's HEAD was written at or after,
// at most limit, in hash order.
func (t *pushDefaultTable) stale(limit int) map[string]string {
	t.mu.Lock()
	snap := make(map[string]pushDefaultEntry, len(t.m))
	for h, e := range t.m {
		snap[h] = e
	}
	t.mu.Unlock()
	hashes := make([]string, 0, len(snap))
	for h := range snap {
		hashes = append(hashes, h)
	}
	slices.Sort(hashes)
	out := map[string]string{}
	for _, h := range hashes {
		if len(out) == limit {
			break
		}
		e := snap[h]
		if latest, ok := pushDefaultHeadWrite(e.root); !ok || !git.HeadWriteBefore(latest, e.at) {
			out[h] = e.root
		}
	}
	return out
}

// The HEAD watch's bounds: how often it looks, and how many repositories
// one look re-resolves.
const (
	securityHeadWatchEvery = 3 * time.Second
	securityHeadWatchBatch = 8
)

// watchPushDefaultHeads re-resolves the default push remote of every
// repository whose checkout switched branch since it was resolved, and
// asks for a re-sign, so a plain push after a switch is judged against the
// new branch's remote within seconds instead of at the next history pass
// (lane SEC-GATE5 milestone 2, SECP-18). Until then the stale entry reads
// "" and the hook drops a signed default older than the switch, so the
// window is closed both ways. It runs in its own goroutine (like the
// history pass) and skips a tick while the previous look still runs.
func (r *securityRescan) watchPushDefaultHeads(ctx context.Context) {
	if !r.headWatchRunning.CompareAndSwap(false, true) {
		return
	}
	stale := securityPushDefaults.stale(securityHeadWatchBatch)
	if len(stale) == 0 {
		r.headWatchRunning.Store(false)
		return
	}
	pushDefault := r.pushDefault
	if pushDefault == nil {
		pushDefault = productionPushDefault
	}
	r.historyWG.Add(1)
	go func() {
		defer r.historyWG.Done()
		defer r.headWatchRunning.Store(false)
		wctx, cancel := context.WithTimeout(ctx, securityHistoryBudget)
		defer cancel()
		for hash, root := range stale {
			if wctx.Err() != nil {
				return
			}
			at := time.Now()
			remote, ok := pushDefault(wctx, commitScanRoot(root))
			if wctx.Err() != nil {
				return
			}
			securityPushDefaults.set(hash, root, remote, ok, at)
		}
		// The posture signed before the switch is dropped by the hook
		// (its issue time is older than the HEAD write), so re-sign even
		// when the remote did not change.
		securityRT.notify()
	}()
}

// securityPushDefaults is the daemon's one pushDefaultTable.
var securityPushDefaults = &pushDefaultTable{}

// productionPushDefault resolves a repository's default push remote over
// the history check's git envelope.
func productionPushDefault(ctx context.Context, root string) (string, bool) {
	return productionHistoryChecker().DefaultPushRemote(ctx, root)
}

// historyGit is the history check's git envelope: read-only, with
// GIT_NO_LAZY_FETCH=1, so a partial clone never fetches from its promisor
// remote to answer `cat-file -e` of a commit it does not have (lane
// sec-gate3 audit finding 3). The missing object is still a non-zero
// exit, which decides gone.
var historyGit secquickscan.GitFunc = gitview.RunReadOnlyNoLazyFetch

// securityReflogBase is the [security] block the post-write loop started
// with: the fallback the history check's reflog caps are read from while the
// floors node has not loaded config.toml (securityLocalNow). Nil, as in a
// process that never started the loop, is no cap.
var securityReflogBase atomic.Pointer[config.SecurityConfig]

// securityReflogCapsNow are the reflog caps the history check applies now
// ([security.scanning] reflog_hold_max_age_days and reflog_hold_max_entries,
// lane LEFT-SEC); zero is no cap, the default.
func securityReflogCapsNow() (time.Duration, int) {
	base := securityReflogBase.Load()
	if base == nil {
		return 0, 0
	}
	sc := securityScanningAt(securityLocalNow(*base), "")
	return time.Duration(sc.ReflogHoldMaxAgeDays) * 24 * time.Hour, sc.ReflogHoldMaxEntries
}

// productionHistoryChecker is the history checker over the read-only git
// envelope.
func productionHistoryChecker() secquickscan.HistoryChecker {
	age, entries := securityReflogCapsNow()
	return secquickscan.HistoryChecker{
		ReflogMaxAge:     age,
		ReflogMaxEntries: entries,
		Git:              historyGit,
		ExitCode: func(err error) (int, bool) {
			f, ok := gitview.InspectError(err)
			if !ok || f.TimedOut || f.ExitCode < 0 {
				return 0, false
			}
			return f.ExitCode, true
		},
		Timeout: securityHistoryCallTimeout,
	}
}

// productionHistory is the history check over the read-only git envelope.
func productionHistory(ctx context.Context, root, sha string) secquickscan.HistoryVerdict {
	return productionHistoryChecker().Inspect(ctx, root, sha)
}

// checkHistory checks one batch of the commits that hold open findings
// open (lane sec-gate3 milestone 1b, per remote since lane sec-gate4): an
// unpushed commit keeps holding and records the remotes that already
// have it (the push gate counts it as pushed only for those, and a
// finding whose commit reached any remote carries the rotate note); a
// commit no push can send anywhere new (every configured remote is
// credited with it) stops holding, and its findings stay open with the
// rotate note; a commit only a remote-tracking ref holds keeps holding for
// the remotes not credited; a commit rewritten away before it reached a
// remote stops holding, and a finding left with no file sighting closes.
// An unknown answer changes nothing. Each pass also resolves the default
// push remote of every repository in its batch (securityPushDefaults).
func (r *securityRescan) checkHistory(ctx context.Context, byHash map[string]string, hashes []string, now time.Time) {
	held, err := r.st.SecHeldCommits(ctx, hashes, r.held, securityHistoryBatch)
	if err != nil {
		return
	}
	if len(held) < securityHistoryBatch {
		defer func() { r.held = store.SecFindingCommit{} }()
	}
	if len(held) == 0 {
		return
	}
	check := r.history
	if check == nil {
		check = productionHistory
	}
	pushDefault := r.pushDefault
	if pushDefault == nil {
		pushDefault = productionPushDefault
	}
	changed := 0
	// The default push remote of each repository this batch holds commits
	// in, resolved once per pass and signed into its posture (audit
	// finding 5).
	resolved := map[string]bool{}
	for _, c := range held {
		root := byHash[c.ProjectRootHash]
		if root == "" || resolved[c.ProjectRootHash] || ctx.Err() != nil {
			continue
		}
		resolved[c.ProjectRootHash] = true
		at := time.Now()
		remote, ok := pushDefault(ctx, commitScanRoot(root))
		if ctx.Err() != nil {
			break
		}
		if securityPushDefaults.set(c.ProjectRootHash, root, remote, ok, at) {
			changed++
		}
	}
	for _, c := range held {
		if ctx.Err() != nil {
			// Out of budget: the next pass resumes after the last commit
			// checked.
			break
		}
		root := byHash[c.ProjectRootHash]
		if root == "" {
			r.held = c
			continue
		}
		v := check(ctx, commitScanRoot(root), c.CommitSHA)
		if ctx.Err() != nil {
			// The budget ran out during this commit's check, so its answer
			// may be cut short: the cursor stays before it and the next
			// pass checks it again (audit finding 9). A per-call timeout
			// with budget left is an unknown answer, and the walk moves on
			// so one slow commit cannot starve the rest.
			break
		}
		r.held = c
		n, err := applyHistory(ctx, r.st, c, v, now)
		if err != nil {
			if r.logger != nil {
				r.logger.Debug("security: history check", "err", err)
			}
			continue
		}
		changed += n
	}
	if changed > 0 {
		securityRT.notify()
	}
}

// applyHistory records one history verdict: an unpushed commit's remotes,
// or the drop of a commit no push can send anywhere new (pushed) or that
// is gone. It returns how many rows changed.
func applyHistory(ctx context.Context, st *store.Store, c store.SecFindingCommit, v secquickscan.HistoryVerdict, now time.Time) (int, error) {
	switch v.State {
	case secquickscan.HistoryUnpushed:
		n, err := st.SetSecFindingCommitRemotes(ctx, c, v.Remotes, now)
		if err != nil {
			return n, err
		}
		m, err := applyReflogCap(ctx, st, c, v.Reason, now)
		return n + m, err
	case secquickscan.HistoryPushed:
		// A drop always changes the held set the posture reads.
		if _, err := st.DropSecFindingCommit(ctx, c, store.SecHistoryReasonPushed, v.Remotes, now); err != nil {
			return 0, err
		}
		return 1, nil
	case secquickscan.HistoryGone:
		if _, err := st.DropSecFindingCommit(ctx, c, store.SecHistoryReasonGone, nil, now); err != nil {
			return 0, err
		}
		return 1, nil
	case secquickscan.HistoryUnknown:
		if v.Reason == secquickscan.HistoryReasonReflogListingCap {
			return 0, applyReflogListingCap(ctx, st, c, now)
		}
	}
	return 0, nil
}

// securityListingCapNoted remembers the held commits an unknown
// listing-cap run was recorded for in this daemon's life, so a busy
// repository records one run per commit, not one per pass.
var securityListingCapNoted struct {
	mu   sync.Mutex
	seen map[string]bool
}

// securityListingCapNotedMax bounds that memory; past it, it starts over.
const securityListingCapNotedMax = 4096

// applyReflogListingCap records one unknown scan run naming the reflog
// listing cap for a held commit whose reflog caps could not apply because
// the listing they need is over its byte cap (lane LEFT-SEC audit F6). The
// commit stays held as before (the caps never loosen it then); the run says
// why the caps did nothing, once per commit per daemon start.
func applyReflogListingCap(ctx context.Context, st *store.Store, c store.SecFindingCommit, now time.Time) error {
	key := c.ProjectRootHash + "|" + strings.ToLower(c.CommitSHA)
	securityListingCapNoted.mu.Lock()
	if securityListingCapNoted.seen[key] {
		securityListingCapNoted.mu.Unlock()
		return nil
	}
	if securityListingCapNoted.seen == nil || len(securityListingCapNoted.seen) >= securityListingCapNotedMax {
		securityListingCapNoted.seen = map[string]bool{}
	}
	securityListingCapNoted.seen[key] = true
	securityListingCapNoted.mu.Unlock()
	err := st.InsertSecScanRun(ctx, store.SecScanRun{
		ProjectRootHash: c.ProjectRootHash, Driver: securityReflogCapDriver, Scope: policy.FindingScopeCommit,
		Target:   map[string]string{"commit": strings.ToLower(c.CommitSHA)},
		Coverage: secscan.Coverage{Outcome: secscan.OutcomeUnknown, Reason: secquickscan.HistoryReasonReflogListingCap},
		Outcome:  string(secscan.OutcomeUnknown), StartedAt: now,
	})
	if err != nil {
		securityListingCapNoted.mu.Lock()
		delete(securityListingCapNoted.seen, key)
		securityListingCapNoted.mu.Unlock()
	}
	return err
}

// securityReflogCapDriver is the scan-run driver the reflog cap records
// under: a diff driver, so it never moves the project's last working-tree
// scan (store.SecLastScan).
const securityReflogCapDriver = store.SecDiffDriverPrefix + "history.reflog_cap"

// applyReflogCap records (or clears) that an unpushed commit is held only
// past a reflog cap (lane LEFT-SEC, SECP-18): the hold then asks at the
// push gate instead of denying, never allows. When a commit first crosses a
// cap one unknown scan run names the cap, so the change is never silent.
func applyReflogCap(ctx context.Context, st *store.Store, c store.SecFindingCommit, reason string, now time.Time) (int, error) {
	capReason := ""
	switch reason {
	case secquickscan.HistoryReasonReflogCapAge:
		capReason = store.SecReflogCapAge
	case secquickscan.HistoryReasonReflogCapEntries:
		capReason = store.SecReflogCapEntries
	}
	n, err := st.SetSecFindingCommitReflogCap(ctx, c, capReason)
	if err != nil || n == 0 || capReason == "" {
		return n, err
	}
	err = st.InsertSecScanRun(ctx, store.SecScanRun{
		ProjectRootHash: c.ProjectRootHash, Driver: securityReflogCapDriver, Scope: policy.FindingScopeCommit,
		Target:   map[string]string{"commit": strings.ToLower(c.CommitSHA)},
		Coverage: secscan.Coverage{Outcome: secscan.OutcomeUnknown, Reason: capReason},
		Outcome:  string(secscan.OutcomeUnknown), StartedAt: now,
	})
	return n, err
}

// recheckWorkflow runs the workflow rules over a workflow file as it is
// now: its hits are recorded again and a rule that no longer fires there
// closes; a deleted file closes everything sighted there; a file that
// cannot be checked whole proves nothing.
func (r *securityRescan) recheckWorkflow(ctx context.Context, root, rel string) {
	if securityFileDeleted(root, rel) {
		recordSecurityFindings(ctx, r.st, root, policy.FindingScopePostWrite, nil,
			secscan.Coverage{Outcome: secscan.OutcomeClean, Reason: "file_deleted"}, securityDeletedGone([]string{rel}), r.logger)
		return
	}
	b, err := secpostwrite.ReadFile(root, rel, secciwf.MaxWorkflowBytes)
	if err != nil {
		return
	}
	rep := secciwf.Check(b)
	if !rep.Complete() {
		return
	}
	hash := secposture.ProjectRootHash(root)
	var fs []secfinding.Finding
	for _, h := range rep.Findings {
		f := securityCIFinding(hash, "", secquickscan.CIFinding{Path: rel, RuleID: h.RuleID, Line: h.Line, Severity: h.Severity, FlagOnly: h.FlagOnly})
		f.Scope = policy.FindingScopePostWrite
		fs = append(fs, f)
	}
	recordSecurityFindings(ctx, r.st, root, policy.FindingScopePostWrite, fs, secscan.Coverage{Outcome: secscan.OutcomeClean, FilesScanned: 1},
		secsvc.Gone{Pack: securityCodePack, Paths: []string{rel}, RulePrefixes: []string{securityCIRulePrefix}}, r.logger)
}

// recheckVerification reads a file whole (capped) and runs the observation
// rules over it as if every line were added: a recheckable observation
// that no longer fires there closes; a deleted file closes the state
// observations sighted there; a file over the cap proves nothing.
func (r *securityRescan) recheckVerification(ctx context.Context, root, rel string) {
	if securityFileDeleted(root, rel) {
		recordSecurityFindings(ctx, r.st, root, policy.FindingScopePostWrite, nil,
			secscan.Coverage{Outcome: secscan.OutcomeClean, Reason: "file_deleted"}, securityDeletedGone([]string{rel}), r.logger)
		return
	}
	b, err := secpostwrite.ReadFile(root, rel, securityRecheckMaxBytes)
	if err != nil {
		return
	}
	whole := secdiffobs.FromEdit(rel, "", string(b))
	hash := secposture.ProjectRootHash(root)
	var fs []secfinding.Finding
	for _, o := range secdiffobs.Observe([]secdiffobs.FileDiff{whole}) {
		f := securityObservationFinding(hash, "", o)
		if !slices.Contains(securityRecheckObservations, f.Rule.ID) {
			continue
		}
		f.Scope = policy.FindingScopePostWrite
		fs = append(fs, f)
	}
	recordSecurityFindings(ctx, r.st, root, policy.FindingScopePostWrite, fs, secscan.Coverage{Outcome: secscan.OutcomeClean, FilesScanned: 1},
		secsvc.Gone{Pack: securityCodePack, Paths: []string{rel}, RulePrefixes: securityRecheckObservations}, r.logger)
}

// recordPostWrite records one post-write scan as a run: its high-confidence
// hits as findings (a fixture-path hit at low severity, never blocking),
// or none, and, when the scan read the whole file to its end, the open
// secret findings at that file it did not see again are closed as not
// reproduced (a removed secret closes its finding). A write that was not
// scanned stores nothing (the commit gate and the commit scan cover it).
func recordPostWrite(ctx context.Context, st *store.Store, r secpostwrite.Result, logger *slog.Logger) {
	if r.NotScanned == secpostwrite.NotScannedGone && !r.Write.CopyWorkspace && securityWriteDeleted(r.Write) {
		// The file is gone (an agent's or a human's `rm`): nothing it held
		// is seen there any more (lane sec-gate2 milestone 1b).
		recordSecurityFindings(ctx, st, r.Write.ProjectRoot, policy.FindingScopePostWrite, nil,
			secscan.Coverage{Outcome: secscan.OutcomeClean, Reason: "file_deleted"}, securityDeletedGone([]string{r.Write.Path}), logger)
		return
	}
	if r.NotScanned == secpostwrite.NotScannedCopyWorkspace {
		// A tree only inside a box (lane sec-box): on record, never clean.
		recordPostWriteNotScanned(ctx, st, r, logger)
		return
	}
	if r.NotScanned != secpostwrite.NotScannedNone {
		return
	}
	hash := secposture.ProjectRootHash(r.Write.ProjectRoot)
	var fs []secfinding.Finding
	for _, h := range r.Scan.Hits {
		if f, ok := securitySecretFinding(secdetect.FindingInput{
			ProjectRootHash: hash, Path: r.Write.Path, Line: h.Line, Hit: h,
			Scope: policy.FindingScopePostWrite, SessionID: r.Write.SessionID, ActionID: r.Write.ActionID,
		}); ok {
			fs = append(fs, f)
		}
	}
	var gone secsvc.Gone
	if r.Scan.Status != secdetect.StatusIncomplete && !r.Write.CopyWorkspace {
		// A copy's read speaks for the copy, not for the recorded root's
		// own file, so it closes nothing there (lane sec-box).
		gone = secsvc.Gone{Pack: securitySecretsPack, Paths: []string{r.Write.Path}}
	}
	recordSecurityFindings(ctx, st, r.Write.ProjectRoot, policy.FindingScopePostWrite, fs, scanCoverage(r.Scan), gone, logger)
}

// securityWriteDeleted reports a write whose file is gone: under its
// out-of-tree checkout when it has one (lane LEFT-SEC), else under its
// project root. A worktree sighting whose checkout the rescan could no
// longer find (securityRescanWrite leaves Checkout empty) is gone only when
// the repository's worktree admin entries were read whole and none maps to
// its key (store.WorktreeSightingGone, audit F1): an unreadable gitdir, a
// checkout off disk or a listing past its cap keeps the sighting open.
func securityWriteDeleted(w secpostwrite.Write) bool {
	if w.Checkout != "" {
		return securityFileDeleted(w.Checkout, w.CheckoutPath)
	}
	if key, _, ok := store.SplitWorktreeSighting(w.Path); ok {
		// Gone with its checkout, while the repository itself is still
		// there (a missing repository proves nothing).
		st, err := os.Stat(w.ProjectRoot)
		if err != nil || !st.IsDir() {
			return false
		}
		return store.WorktreeSightingGone(commitScanRoot(w.ProjectRoot), key)
	}
	return securityFileDeleted(w.ProjectRoot, w.Path)
}

// securityRescanWrite is the rescan's Write for an open sighting at path in
// the project at root: a per-checkout worktree sighting (lane LEFT-SEC) is
// reopened in THAT checkout, found among root's linked worktrees by its key;
// any other sighting under root as before.
func securityRescanWrite(root, path string) secpostwrite.Write {
	w := secpostwrite.Write{ProjectRoot: root, Path: path}
	if key, rel, ok := store.SplitWorktreeSighting(path); ok {
		if dir, found := store.WorktreeCheckoutFor(commitScanRoot(root), key); found {
			w.Checkout, w.CheckoutPath = dir, rel
		}
	}
	return w
}

// securitySecretsPack is the pack secret findings are recorded under.
const securitySecretsPack = "security.secrets"

// securityCodePack is the pack workflow rule hits and diff observations are
// recorded under.
const securityCodePack = "security.code"

// securityCIRulePrefix is the rule id prefix of a workflow rule finding
// (securityCIFinding).
const securityCIRulePrefix = "ci."

// securityStateObservations are the diff observation rules whose finding
// is a fact about the file as it is (disabled TLS verification, a
// suppression or always-true fallback), so the file's deletion closes it.
// A test deletion (S-767) or removed assertions (S-768) describe a change,
// not the file, and close only by triage.
var securityStateObservations = []string{"code.s-761", "code.s-769"}

// securityRecheckObservations are the observation rules a whole-file
// recheck can answer (lane sec-gate2 milestone 1d): disabled verification
// is a pattern in the file, so the rescan reads the file whole and closes
// the finding once the pattern is gone. S-769's suppression form shares its
// rule id with a lowered coverage threshold, which a whole file cannot
// show, so it is not rechecked.
var securityRecheckObservations = []string{"code.s-761"}

// securityDeletedGone is the close a deleted file proves: every secret
// sighted there, and the workflow rule and state observation findings
// sighted there.
func securityDeletedGone(paths []string) secsvc.Gone {
	return secsvc.Gone{
		Pack: securitySecretsPack, Paths: paths,
		Also: []secsvc.Gone{{Pack: securityCodePack, Paths: paths, RulePrefixes: append([]string{securityCIRulePrefix}, securityStateObservations...)}},
	}
}

// securityFileDeleted reports whether rel is gone from an existing project
// root: the root is a directory and the path does not exist. An unreadable
// root (an unmounted drive) is not a deletion.
func securityFileDeleted(root, rel string) bool {
	if root == "" || rel == "" {
		return false
	}
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return false
	}
	_, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel)))
	return errors.Is(err, os.ErrNotExist)
}

// securitySecretFinding is secdetect.SecretFinding with the fixture rule
// applied (lane SEC-GATEFIX milestone 2c): a hit in a fixture or test-data
// path is recorded at low severity, so it never joins the blocking set,
// as S-721 asks there instead of denying and verify lowers it to a flag.
func securitySecretFinding(in secdetect.FindingInput) (secfinding.Finding, bool) {
	// The version-tagged org_key noted at detection (lane LEFT-SHARED), the
	// same stamping the history scans use (secsvc.OrgKeyMemo).
	f, ok := secOrgIdentities.SecretFinding(in)
	if !ok || !in.Hit.Fixture {
		return f, ok
	}
	f.Severity = policy.FindingSeverityLow
	f.Message += " The file is in a fixture or test-data path."
	return secfinding.Normalize(f), true
}

// scanCoverage maps a detector result onto a run's coverage outcome.
func scanCoverage(r secdetect.Result) secscan.Coverage {
	switch r.Status {
	case secdetect.StatusIncomplete:
		return secscan.Coverage{Outcome: secscan.OutcomeUnknown, Reason: string(r.Reason), FilesScanned: 1}
	case secdetect.StatusHits:
		return secscan.Coverage{Outcome: secscan.OutcomeFindings, FilesScanned: 1}
	}
	return secscan.Coverage{Outcome: secscan.OutcomeClean, FilesScanned: 1}
}

// recordSecurityFindings writes one native run through the one findings
// writer (secsvc.RecordRun), with or without findings: a zero-finding run
// is the evidence a scan ran, and what lets gone close what was removed.
func recordSecurityFindings(ctx context.Context, st *store.Store, root string, scope policy.FindingScope, fs []secfinding.Finding, cov secscan.Coverage, gone secsvc.Gone, logger *slog.Logger) {
	if st == nil {
		return
	}
	if len(fs) > 0 && cov.Outcome == secscan.OutcomeClean {
		cov.Outcome = secscan.OutcomeFindings
	}
	started := time.Now()
	res := secscan.Result{Findings: fs, Coverage: cov, Engine: secscan.EngineIdentity{Name: "native", RulePackVersion: secrules.PackVersion}}
	if _, err := secsvc.RecordRun(ctx, st, secscan.Target{ProjectRoot: root, Scope: scope}, res, started, 0, gone, securityRT.notify); err != nil {
		noteRecordFailure(ctx)
		logger.Warn("security: findings not recorded", "scope", scope, "err", err)
	}
}

// recordFailuresKey carries a caller's note of a failed record write
// (withRecordFailures).
type recordFailuresKey struct{}

// withRecordFailures returns ctx carrying a note that the record writes
// under it set when one fails (noteRecordFailure), so a caller that marks
// work handled (the hosted saved diffs, lane LEFT-SEC audit F7) does so only
// after every write succeeded.
func withRecordFailures(ctx context.Context) (context.Context, *atomic.Bool) {
	failed := &atomic.Bool{}
	return context.WithValue(ctx, recordFailuresKey{}, failed), failed
}

// noteRecordFailure sets ctx's failed-write note, if it carries one.
func noteRecordFailure(ctx context.Context) {
	if f, ok := ctx.Value(recordFailuresKey{}).(*atomic.Bool); ok {
		f.Store(true)
	}
}

// securityCommitStep is the commit scanner's after-scan step (S-723): every
// commit that landed since the last tick, human or agent, scanned one by
// one under the commit scan's own budget, each recorded as a run.
type securityCommitStep struct {
	scan   *secquickscan.CommitScan
	st     *store.Store
	logger *slog.Logger
	// code records the workflow rule hits and the diff observations too
	// (security.code active).
	code bool
	// skipSecrets leaves the secret run out ([security.secrets].commit_check
	// off). The zero value records secrets, so a caller that builds the
	// step without it keeps the secret run.
	skipSecrets bool
}

// securityCommitSwitches are what the commit-scan step records (lane
// sec-c3): the workflow rule hits while security.code is active, the
// secret hits while the commit check is on.
type securityCommitSwitches struct {
	code, secrets bool
}

// newSecurityCommitAfterScan returns the step for the commit scanner. It
// reads the published step at each tick, so it is a no-op until the
// security.postwrite loop runs (security.secrets active) and again after
// it stops.
func newSecurityCommitAfterScan(st *store.Store) func(context.Context, commitscan.Root, commitscan.Result) {
	return func(ctx context.Context, root commitscan.Root, res commitscan.Result) {
		step := securityRT.commitScan.Load()
		if step == nil {
			return
		}
		rec := *step
		if st != nil {
			rec.st = st
		}
		if res.HeadSHA != "" {
			if r, ran := step.scan.AfterScan(ctx, root.RootPath, res.HeadSHA); ran {
				rec.record(ctx, root.RootPath, r)
			}
		}
		// Box work on refs/observer/sandbox/* and the worktree source's
		// branches (lane sec-box, security_box.go).
		rec.walkBoxRefs(ctx, root.RootPath, securityBoxRefs)
	}
}

// record stores one walk: a run per commit, and an unknown run for the
// commits the walk skipped (over the cap, out of budget, or a range that
// could not be listed), so the gap is on record and is not walked again.
func (step *securityCommitStep) record(ctx context.Context, root string, r secquickscan.CommitScanResult) {
	hash := secposture.ProjectRootHash(root)
	for _, c := range r.Commits {
		step.recordCommit(ctx, root, hash, c)
	}
	if r.Skipped > 0 || r.RangeUnread {
		reason := string(r.SkipReason)
		if reason == "" {
			reason = "range_unread"
		}
		recordSecurityFindings(ctx, step.st, root, policy.FindingScopeCommit, nil, secscan.Coverage{Outcome: secscan.OutcomeUnknown, Reason: reason}, secsvc.Gone{}, step.logger)
	}
}

// recordCommit records one commit: the secret run (its high-confidence
// hits, the secrets it removed closing their findings; an unknown commit
// as an unknown run), and with security.code active the code run (its
// workflow rule hits and diff observations; a workflow it could not check
// whole makes that run unknown, never silent).
func (step *securityCommitStep) recordCommit(ctx context.Context, root, hash string, c secquickscan.CommitResult) {
	recordDepsManifests(ctx, step.st, root, c.SHA, policy.FindingScopeCommit, c.Retained, step.logger)
	if c.Verdict == secquickscan.VerdictUnknown {
		if !step.skipSecrets {
			recordSecurityFindings(ctx, step.st, root, policy.FindingScopeCommit, nil, secscan.Coverage{Outcome: secscan.OutcomeUnknown, Reason: string(c.Reason), FilesScanned: c.Files}, secsvc.Gone{}, step.logger)
		}
		return
	}
	if !step.skipSecrets {
		step.recordCommitSecrets(ctx, root, hash, c)
	}
	if step.code {
		recordSecurityCode(ctx, step.st, root, hash, c.SHA, policy.FindingScopeCommit, c.Result, step.logger)
	}
}

// recordCommitSecrets records a scanned commit's secret run: its
// high-confidence hits, and the secrets it removed closing their findings.
func (step *securityCommitStep) recordCommitSecrets(ctx context.Context, root, hash string, c secquickscan.CommitResult) {
	var fs []secfinding.Finding
	for _, f := range c.Findings {
		if fd, ok := securitySecretFinding(secdetect.FindingInput{
			ProjectRootHash: hash, Path: f.Path, Line: f.Line,
			Hit:   secdetect.Hit{Type: f.Type, Line: f.Line, Confidence: f.Confidence, Fixture: f.Fixture, Identity: f.Identity},
			Scope: policy.FindingScopeCommit, CommitSHA: c.SHA,
		}); ok {
			fs = append(fs, fd)
		}
	}
	// Closes are keyed by path and identity (lane sec-gate2): a secret
	// removed from one file, or a file the commit deleted, drops that
	// sighting only, so a finding still seen in another file stays open.
	gone := secsvc.Gone{Pack: securitySecretsPack, Paths: c.Deleted}
	for _, f := range c.Removed {
		if f.Identity != "" {
			gone.Removed = append(gone.Removed, store.SecSighting{
				Key:  secfinding.LocalKey(hash, secdetect.SecretRulePrefix+f.Type, secfinding.MatchIdentity{Kind: secfinding.MatchSecret, Value: f.Identity}),
				Path: f.Path,
			})
		}
	}
	recordSecurityFindings(ctx, step.st, root, policy.FindingScopeCommit, fs, secscan.Coverage{Outcome: secscan.OutcomeClean, FilesScanned: c.Files}, gone, step.logger)
}

// recordSecurityCode records a scan's code run (security.code): the native
// workflow rule hits and the flag-only diff observations as findings that
// never block (medium confidence), and the changed workflows it could not
// check whole as an unknown outcome (reason workflow_unchecked), never as
// clean (lane SEC-GATEFIX milestone 2i).
func recordSecurityCode(ctx context.Context, st *store.Store, root, hash, sha string, scope policy.FindingScope, r secquickscan.Result, logger *slog.Logger) {
	var fs []secfinding.Finding
	for _, c := range r.CI {
		f := securityCIFinding(hash, sha, c)
		f.Scope = scope
		fs = append(fs, f)
	}
	for _, o := range r.Observations {
		f := securityObservationFinding(hash, sha, o)
		f.Scope = scope
		fs = append(fs, f)
	}
	cov := secscan.Coverage{Outcome: secscan.OutcomeClean, FilesScanned: r.Files}
	if r.CIUnchecked > 0 {
		cov.Outcome, cov.Reason = secscan.OutcomeUnknown, "workflow_unchecked"
	}
	if len(fs) == 0 && cov.Outcome == secscan.OutcomeClean && r.Files == 0 && len(r.Deleted) == 0 {
		return // nothing changed that the code rows read
	}
	// A workflow checked whole speaks for the ci.* rows sighted there, and
	// a deleted file for every state finding there (lane sec-gate2
	// milestone 1d). An unknown run closes nothing (secsvc.RecordRun), and
	// the checked list carries only workflows read whole.
	gone := secsvc.Gone{Pack: securityCodePack, Paths: r.CIChecked, RulePrefixes: []string{securityCIRulePrefix}}
	if len(r.Deleted) > 0 {
		gone.Also = []secsvc.Gone{securityDeletedGone(r.Deleted).Also[0]}
	}
	recordSecurityFindings(ctx, st, root, scope, fs, cov, gone, logger)
}

// observationCategories maps a diff observation's rule onto its finding
// category: switched-off verification is a security regression, the rest
// test tampering (security plan sections 5.7 and 5.8).
var observationCategories = map[string]policy.FindingCategory{
	"S-761": policy.FindingSecurityRegression,
}

// securityObservationFinding is a flag-only diff observation as a finding:
// medium severity and confidence (never blocking), keyed by the rule and
// the file, with the rule's fixed message.
func securityObservationFinding(rootHash, sha string, o secdiffobs.Observation) secfinding.Finding {
	rule := "code." + strings.ToLower(o.RuleID)
	cat, ok := observationCategories[o.RuleID]
	if !ok {
		cat = policy.FindingTestTampering
	}
	return secfinding.Normalize(secfinding.Finding{
		LocalKey:   secfinding.LocalKey(rootHash, rule, secfinding.TextIdentity(o.Path)),
		Location:   secfinding.Location{RelPath: o.Path, StartLine: o.Line, EndLine: o.Line},
		Rule:       secfinding.Rule{ID: rule, Pack: "security.code", PackVersion: secrules.PackVersion},
		Engine:     secfinding.Engine{Driver: "native"},
		Category:   cat,
		Severity:   policy.FindingSeverityMedium,
		Confidence: policy.FindingConfidenceMedium,
		Scope:      policy.FindingScopeCommit,
		Project:    secfinding.Project{RootHash: rootHash},
		Message:    o.RuleID + ": " + o.Message,
		Baseline:   policy.FindingBaselineNew,
		Commit:     secfinding.Commit{SHA: sha},
		Status:     policy.FindingStatusOpen,
	})
}

// securityCIFinding is a landed workflow rule hit as a finding: category
// ci_config at the rule's severity, medium confidence (the rules have no
// precision figure yet, so they never count toward S-791's blocking set),
// keyed by the rule and the workflow file, with the rule's fixed message.
func securityCIFinding(rootHash, sha string, c secquickscan.CIFinding) secfinding.Finding {
	rule := "ci." + strings.ToLower(c.RuleID)
	sev := policy.FindingSeverityHigh
	switch {
	case c.FlagOnly || c.Severity == secciwf.SeverityLow:
		sev = policy.FindingSeverityLow
	case c.Severity == secciwf.SeverityMedium:
		sev = policy.FindingSeverityMedium
	}
	msg := c.RuleID
	for _, r := range secciwf.Rules {
		if r.ID == c.RuleID {
			msg = c.RuleID + ": " + r.Message
		}
	}
	return secfinding.Normalize(secfinding.Finding{
		LocalKey:   secfinding.LocalKey(rootHash, rule, secfinding.TextIdentity(c.Path)),
		Location:   secfinding.Location{RelPath: c.Path, StartLine: c.Line, EndLine: c.Line},
		Rule:       secfinding.Rule{ID: rule, Pack: "security.code", PackVersion: secrules.PackVersion},
		Engine:     secfinding.Engine{Driver: "native"},
		Category:   policy.FindingCIConfig,
		Severity:   sev,
		Confidence: policy.FindingConfidenceMedium,
		Scope:      policy.FindingScopeCommit,
		Project:    secfinding.Project{RootHash: rootHash},
		Message:    msg,
		Baseline:   policy.FindingBaselineNew,
		Commit:     secfinding.Commit{SHA: sha},
		Status:     policy.FindingStatusOpen,
	})
}

// startSecurityPhaseC starts the quick-scan endpoint's real scanner and the
// security.postwrite loop on ng. The quick-scan row replaces Phase A's
// nil-scanner endpoint.
func startSecurityPhaseC(ctx context.Context, ng *gatedGroup, configPath string, codeActive bool) {
	ng.Go("security.postwrite", func() error {
		cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
		if err != nil {
			return nil
		}
		defer cleanup()
		resolved, err := config.ResolveGlobalPath(configPath)
		if err != nil {
			return nil
		}
		// The post-write cap picker and the commit check are
		// [security.secrets] keys (lane sec-c3, the settings contract); the
		// cap is read through the floors' seam, so a managed node keeps 256
		// KiB (lane LEFT-SEC, SECP-18).
		sec := cfg.Security
		securityReflogBase.Store(&sec)
		runSecurityPostWrite(ctx, store.New(database), resolved, func() int { return securityPostWriteCapInForce(sec) }, securityCommitSwitches{code: codeActive, secrets: cfg.Security.Secrets.CommitCheck}, newLogger(cfg.Observer.LogLevel))
		return nil
	})
}
