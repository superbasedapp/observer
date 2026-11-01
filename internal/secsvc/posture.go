//go:build !sbo_omit_security

package secsvc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// FindingStore is the part of the findings store the posture writer reads
// (internal/store implements it).
type FindingStore interface {
	SecBlockingKeys(ctx context.Context, q store.SecBlockingQuery, limit int) ([]string, error)
	SecHeldHistory(ctx context.Context, q store.SecBlockingQuery, limit int) ([]store.SecHeldRow, error)
	SecOpenCounts(ctx context.Context, rootHash string) ([]store.SecCount, error)
	SecLastScan(ctx context.Context, rootHash string) (time.Time, error)
}

// Options configure the service.
type Options struct {
	Layout secposture.Layout
	Store  FindingStore
	// Projects lists the project roots active since the given time (a
	// session started or ended, or the project was first seen). The posture
	// is written for every one, so an active project never scanned reads
	// as dirty or clean, never as a missing file. A project the hook
	// marked dirty since then is signed too, even before its session is
	// ingested.
	Projects func(ctx context.Context, since time.Time) ([]string, error)
	// ActiveWithin is how far back a project counts as active (default
	// DefaultActiveWithin). Posture files of every other project are
	// pruned; an idle project reads as unknown until it is active again,
	// never as clean.
	ActiveWithin time.Duration
	// Baseline, when set, runs the lazy baseline rescan (section 4.5.2
	// item 2) for every active project before its posture is computed, so
	// a relabelled finding reaches the same pass's blocking list.
	Baseline *BaselineRescanner
	// OnError reports a failed pass of the loop (a store read, a write);
	// the loop retries at its next tick. Nil drops it.
	OnError func(error)
	// Packs lists the active pillar children (component ids). An empty set
	// signs a file that reads as absent.
	Packs func() []string
	// QuickScanAvailable reports whether the quick-scan service serves a
	// real scanner (false until security Phase C supplies one).
	QuickScanAvailable func() bool
	// IncludeUntrusted counts untrusted_baseline findings as blocking (a
	// managed floor, section 4.8).
	IncludeUntrusted bool
	// ProjectMatch, when set, reads a project root's project audience match
	// (security plan section 7.11, lane sec-p) by its root hash: the org
	// project ids and the assignment epoch, copied into the reserved posture
	// fields. Nil leaves them empty.
	ProjectMatch func(projectRootHash string) ([]string, uint64)
	// MinBlocking is the least severity that blocks (default high).
	MinBlocking secfinding.Severity
	// Now is the clock (default time.Now).
	Now func() time.Time
	// TTL is the signed lifetime (default secposture.DefaultTTL).
	TTL time.Duration
	// PushDefault returns the default push remote the daemon last resolved
	// for a project root hash ("" when none; lane sec-gate4 audit finding
	// 5), signed into a posture that has a history-only hold. Nil signs
	// none, so a plain push stays an unknown target.
	PushDefault func(rootHash string) string
	// Floors returns the org security.scanning floors in force for a
	// project root (lane SEC-P4 decision 9: the commit gate's and the
	// launch trust step's), signed into its posture. Nil, or a root the
	// pass only knows by its hash, signs none.
	Floors func(projectRoot string) (commitGate, prelaunchTrust string)
	// Scanning returns the [security.scanning] values in force for a
	// project root (lane LEFT-SEC): the quick-scan budget and the scan
	// staleness signed into its posture, and the least blocking severity
	// its blocking list is computed with. A root the pass knows only by its
	// hash is asked with "" (the node-wide value). Nil keeps the built-in
	// values (2 s, off, MinBlocking).
	Scanning func(projectRoot string) ScanningFloors
}

// ScanningFloors are the [security.scanning] values the posture writer
// reads per project (Options.Scanning). The zero value is the built-in
// behaviour.
type ScanningFloors struct {
	// QuickScanBudgetS is the commit quick scan's budget in seconds (0 or
	// 2: the built-in 2 s).
	QuickScanBudgetS int
	// MaxScanStalenessMin is the oldest scan the gate trusts (0: off).
	MaxScanStalenessMin int
	// MinBlocking is the least severity that blocks ("": Options'
	// MinBlocking).
	MinBlocking secfinding.Severity
}

// DefaultActiveWithin is how long after its last session a project keeps
// a signed posture.
const DefaultActiveWithin = 30 * 24 * time.Hour

// resignSlack is how much lifetime beyond one loop interval an unchanged
// posture must still have to be left as it is: the next tick then still
// finds it fresh, with this much to spare for a late tick.
const resignSlack = time.Minute

// Service writes and holds the per-project postures.
type Service struct {
	o   Options
	key []byte

	mu sync.Mutex
	// seq is the last sequence signed; strictly increasing per process and
	// seeded from the wall clock, so it keeps rising across restarts.
	seq uint64
	// clean is the dirty counter value the last clean quick scan covered,
	// per project root hash.
	clean map[string]uint64
	// memory is the last posture written per project root hash, the
	// daemon's in-memory posture for the relay path.
	memory map[string]secposture.File
	// written is the exact bytes last written per project root hash: the
	// unchanged-body skip leaves a file alone only while the file on disk
	// is still those bytes.
	written map[string][]byte

	notify chan struct{}
	// interval is the loop's re-sign interval (Run sets it).
	interval time.Duration
}

// New loads (or creates) the posture key and returns the service. It seeds
// each project's clean-scan record from its own verified posture file, so
// a restart does not forget a clean scan.
func New(ctx context.Context, o Options) (*Service, error) {
	if o.Layout.Dir == "" || o.Store == nil || o.Projects == nil {
		return nil, errors.New("secsvc.New: layout, store and project list are required")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.TTL <= 0 {
		o.TTL = secposture.DefaultTTL
	}
	if o.MinBlocking == "" {
		o.MinBlocking = policy.FindingSeverityHigh
	}
	if o.Packs == nil {
		o.Packs = func() []string { return nil }
	}
	if o.ActiveWithin <= 0 {
		o.ActiveWithin = DefaultActiveWithin
	}
	key, err := secposture.LoadOrCreateKey(o.Layout.KeyPath())
	if err != nil {
		return nil, fmt.Errorf("secsvc.New: %w", err)
	}
	s := &Service{o: o, key: key, clean: map[string]uint64{}, memory: map[string]secposture.File{}, written: map[string][]byte{}, notify: make(chan struct{}, 1), interval: secposture.ResignEvery}
	now := o.Now()
	roots, _ := o.Projects(ctx, now.Add(-o.ActiveWithin))
	for _, root := range roots {
		r := secposture.Load(o.Layout, root, secposture.ModuleActive, now, secposture.Versions{})
		if r.File != nil {
			s.clean[r.File.ProjectRootHash] = r.File.DirtyCleanEpoch
			if r.File.Sequence > s.seq {
				s.seq = r.File.Sequence
			}
		}
	}
	return s, nil
}

// blockingAt are the severities at or above min ("": Options' MinBlocking,
// default high).
func (s *Service) blockingAt(min secfinding.Severity) []secfinding.Severity {
	if min == "" {
		min = s.o.MinBlocking
	}
	all := policy.FindingSeverities()
	for i, sv := range all {
		if sv == min {
			return append([]secfinding.Severity(nil), all[i:]...)
		}
	}
	return []secfinding.Severity{policy.FindingSeverityHigh, policy.FindingSeverityCritical}
}

func (s *Service) nextSeq(now time.Time) uint64 {
	n := uint64(now.UnixMilli())
	if n <= s.seq {
		n = s.seq + 1
	}
	s.seq = n
	return n
}

// Compute builds one project's posture file (unsigned).
func (s *Service) Compute(ctx context.Context, projectRoot string, now time.Time) (secposture.File, error) {
	hash := secposture.ProjectRootHash(projectRoot)
	if hash == "" {
		return secposture.File{}, errors.New("secsvc.Compute: empty project root")
	}
	return s.compute(ctx, hash, projectRoot, now)
}

// compute builds the posture file of one project root hash (unsigned);
// root is its project root, "" when the pass knows only the hash.
func (s *Service) compute(ctx context.Context, hash, root string, now time.Time) (secposture.File, error) {
	var scanning ScanningFloors
	if s.o.Scanning != nil {
		scanning = s.o.Scanning(root)
	}
	sevs := s.blockingAt(scanning.MinBlocking)
	keys, err := s.o.Store.SecBlockingKeys(ctx, store.SecBlockingQuery{
		ProjectRootHash: hash, Severities: sevs, IncludeUntrusted: s.o.IncludeUntrusted,
	}, secposture.MaxBlocking+1)
	if err != nil {
		return secposture.File{}, err
	}
	// The blocking findings only an unpushed commit holds open gate the
	// push, not another commit (lane sec-gate3 audit finding 2).
	held, err := s.o.Store.SecBlockingKeys(ctx, store.SecBlockingQuery{
		ProjectRootHash: hash, Severities: sevs, IncludeUntrusted: s.o.IncludeUntrusted, HistoryOnly: true,
	}, secposture.MaxBlocking+1)
	if err != nil {
		return secposture.File{}, err
	}
	var on map[string]int
	var heldCommits []secposture.HeldCommit
	var heldCapped bool
	var reflogCapped []string
	if len(held) > 0 {
		rows, err := s.o.Store.SecHeldHistory(ctx, store.SecBlockingQuery{
			ProjectRootHash: hash, Severities: sevs, IncludeUntrusted: s.o.IncludeUntrusted, HistoryOnly: true,
		}, maxHeldRows+1)
		if err != nil {
			return secposture.File{}, err
		}
		capped := len(rows) > maxHeldRows || len(held) > secposture.MaxBlocking
		on, heldCommits, heldCapped = HeldPosture(held, rows, capped)
		if !capped {
			reflogCapped = ReflogCappedKeys(held, rows)
		}
	}
	var pushDefault string
	if len(held) > 0 && s.o.PushDefault != nil {
		pushDefault = s.o.PushDefault(hash)
	}
	counts, err := s.o.Store.SecOpenCounts(ctx, hash)
	if err != nil {
		return secposture.File{}, err
	}
	last, err := s.o.Store.SecLastScan(ctx, hash)
	if err != nil {
		return secposture.File{}, err
	}
	f := secposture.File{
		ProjectRootHash: hash, Packs: s.o.Packs(), IssuedAt: now, ExpiresAt: now.Add(s.o.TTL),
		Blocking: keys, HistoryOnly: held, ScannedAt: last,
		HistoryOnlyOn: on, Held: heldCommits, HeldOverflow: heldCapped, DefaultPushRemote: pushDefault,
		HistoryCapped:    reflogCapped,
		QuickScanBudgetS: scanning.QuickScanBudgetS, MaxScanStalenessMin: scanning.MaxScanStalenessMin,
	}
	if len(keys) > secposture.MaxBlocking {
		f.Blocking, f.Overflow = keys[:secposture.MaxBlocking], true
	}
	for _, c := range counts {
		f.Counts = append(f.Counts, secposture.Count{Category: c.Category, Severity: c.Severity, N: c.N})
	}
	if s.o.QuickScanAvailable != nil {
		f.QuickScanAvailable = s.o.QuickScanAvailable()
	}
	if s.o.ProjectMatch != nil {
		f.OrgProjectIDs, f.AssignmentEpoch = s.o.ProjectMatch(hash)
	}
	if s.o.Floors != nil && root != "" {
		f.CommitGateFloor, f.PrelaunchTrustFloor = s.o.Floors(root)
	}
	s.mu.Lock()
	f.DirtyCleanEpoch = s.clean[hash]
	s.mu.Unlock()
	return f, nil
}

// maxHeldRows bounds the (finding, held commit) rows one posture reads.
const maxHeldRows = 4096

// HeldPosture turns the held-commit rows of the history-only findings into
// the posture's per-remote counts and held commit list (lane sec-gate4
// milestone 1a). A key is on a remote when every commit that holds it is
// on that remote; a key with no row (past a cap) is on none. capped (the
// rows or keys were cut short) leaves the counts empty, so no remote is
// read as having every held finding, and marks the list capped.
func HeldPosture(keys []string, rows []store.SecHeldRow, capped bool) (map[string]int, []secposture.HeldCommit, bool) {
	if len(keys) == 0 {
		return nil, nil, false
	}
	if len(rows) > maxHeldRows {
		rows, capped = rows[:maxHeldRows], true
	}
	want := make(map[string]bool, len(keys))
	for _, k := range keys {
		want[k] = true
	}
	perKey := map[string]map[string]bool{}
	byCommit := map[string][]string{}
	var commits []string
	for _, r := range rows {
		if !want[r.LocalKey] {
			continue
		}
		set := map[string]bool{}
		for _, rm := range r.Remotes {
			set[rm] = true
		}
		if have, ok := perKey[r.LocalKey]; ok {
			for rm := range have {
				if !set[rm] {
					delete(have, rm)
				}
			}
		} else {
			perKey[r.LocalKey] = set
		}
		if _, seen := byCommit[r.CommitSHA]; !seen {
			commits = append(commits, r.CommitSHA)
		}
		byCommit[r.CommitSHA] = r.Remotes
	}
	sort.Strings(commits)
	var held []secposture.HeldCommit
	for _, c := range commits {
		held = append(held, secposture.HeldCommit{Commit: c, Remotes: append([]string(nil), byCommit[c]...)})
	}
	if capped {
		return nil, held, true
	}
	on := map[string]int{}
	for _, k := range keys {
		for rm := range perKey[k] {
			on[rm]++
		}
	}
	if len(on) == 0 {
		on = nil
	}
	return on, held, len(held) > secposture.MaxHeld
}

// ReflogCappedKeys returns the held keys every holding commit of which is
// held only past a reflog cap (store.SecHeldRow.ReflogCap set), sorted; a
// key with any commit held otherwise, or with no row, is not. A capped row
// list is the caller's to refuse (it passes none then), so a key past the
// rows is never read as capped.
func ReflogCappedKeys(keys []string, rows []store.SecHeldRow) []string {
	want := make(map[string]bool, len(keys))
	for _, k := range keys {
		want[k] = true
	}
	capped := map[string]bool{}
	for _, r := range rows {
		if !want[r.LocalKey] {
			continue
		}
		prev, seen := capped[r.LocalKey]
		capped[r.LocalKey] = r.ReflogCap != "" && (!seen || prev)
	}
	var out []string
	for k, c := range capped {
		if c {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// WriteAll computes, signs and writes the posture of every active project
// (Options.Projects plus every project the hook marked dirty within
// ActiveWithin), skipping a project whose body is unchanged while its file
// is still on disk and fresh for longer than one more interval, and then
// prunes the posture files of every other project. It returns how many
// files were written; a project that fails is skipped (its old file
// expires and reads as unknown, never clean).
func (s *Service) WriteAll(ctx context.Context) (int, error) {
	now := s.o.Now()
	since := now.Add(-s.o.ActiveWithin)
	roots, err := s.o.Projects(ctx, since)
	if err != nil {
		return 0, fmt.Errorf("secsvc.WriteAll: %w", err)
	}
	active := map[string]bool{}
	var hashes []string
	rootOf := map[string]string{}
	add := func(h string) {
		if h != "" && !active[h] {
			active[h] = true
			hashes = append(hashes, h)
		}
	}
	for _, root := range roots {
		h := secposture.ProjectRootHash(root)
		add(h)
		if _, ok := rootOf[h]; !ok {
			rootOf[h] = root
		}
	}
	dirty, dirtyErr := secposture.DirtySince(s.o.Layout, since)
	for _, h := range dirty {
		add(h)
	}
	n := 0
	firstErr := dirtyErr
	if s.o.Baseline != nil {
		for _, root := range roots {
			if _, err := s.o.Baseline.Rescan(ctx, root); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	for _, hash := range hashes {
		f, err := s.compute(ctx, hash, rootOf[hash], now)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if s.unchanged(f, now) {
			continue
		}
		s.mu.Lock()
		f.Sequence = s.nextSeq(now)
		s.mu.Unlock()
		data, err := secposture.Write(s.o.Layout, f, s.key)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		s.mu.Lock()
		s.memory[f.ProjectRootHash] = f
		s.written[f.ProjectRootHash] = data
		s.mu.Unlock()
		n++
	}
	if err := s.prune(active); err != nil && firstErr == nil {
		firstErr = err
	}
	if firstErr != nil {
		return n, fmt.Errorf("secsvc.WriteAll: %w", firstErr)
	}
	return n, nil
}

// unchanged reports whether f has the body of the posture last written for
// its project, the file on disk is still byte for byte the one this
// service wrote, and it stays fresh past the next tick (one interval plus
// resignSlack): then nothing needs signing. What the skip saves is the
// signing and the write (a temp file, a rename and a new sequence, so the
// hook's seen mark does not churn on every tick); the body is still
// computed every tick (its store reads run), which is what lets a change
// re-sign at once. A file that was deleted, replaced or edited, even with
// a valid MAC under a stolen key, no longer matches and is rewritten in
// the same pass (lane SEC-GATEFIX, SECP-17).
func (s *Service) unchanged(f secposture.File, now time.Time) bool {
	s.mu.Lock()
	prev, ok := s.memory[f.ProjectRootHash]
	data := s.written[f.ProjectRootHash]
	interval := s.interval
	s.mu.Unlock()
	if !ok || len(data) == 0 || !now.Add(interval+resignSlack).Before(prev.ExpiresAt) {
		return false
	}
	if !sameBody(prev, f) {
		return false
	}
	disk, err := readCapped(s.o.Layout.PosturePath(f.ProjectRootHash), secposture.MaxFileBytes)
	return err == nil && bytes.Equal(disk, data)
}

// readCapped reads at most limit+1 bytes of path (a bigger file never
// matches what was written).
func readCapped(path string, limit int) ([]byte, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = fh.Close() }()
	return io.ReadAll(io.LimitReader(fh, int64(limit)+1))
}

// sameBody compares two posture files without their signing fields (the
// sequence, the issue and expiry times, the MAC).
func sameBody(a, b secposture.File) bool {
	strip := func(f secposture.File) []byte {
		f.Sequence, f.IssuedAt, f.ExpiresAt, f.MAC = 0, time.Time{}, time.Time{}, ""
		data, err := secposture.Encode(f)
		if err != nil {
			return nil
		}
		return data
	}
	x, y := strip(a), strip(b)
	return x != nil && bytes.Equal(x, y)
}

// prune removes the posture file of every project not in active and
// forgets its in-memory posture. The dirty markers and seen marks stay:
// they are monotonic and carry no findings.
func (s *Service) prune(active map[string]bool) error {
	stale, err := secposture.PostureHashes(s.o.Layout)
	if err != nil {
		return err
	}
	var firstErr error
	for _, h := range stale {
		if active[h] {
			continue
		}
		if err := secposture.Remove(s.o.Layout, h); err != nil && firstErr == nil {
			firstErr = err
		}
		s.mu.Lock()
		delete(s.memory, h)
		delete(s.written, h)
		s.mu.Unlock()
	}
	return firstErr
}

// RecordCleanScan records that a clean quick scan covered the project's
// dirty counter up to covered (the quick scan, security Phase C, calls
// it), and asks for a re-sign. The record only rises.
func (s *Service) RecordCleanScan(projectRoot string, covered uint64) {
	hash := secposture.ProjectRootHash(projectRoot)
	if hash == "" {
		return
	}
	s.mu.Lock()
	if covered > s.clean[hash] {
		s.clean[hash] = covered
	}
	s.mu.Unlock()
	s.Notify()
}

// Notify asks the loop for a re-sign now (findings changed). It never
// blocks.
func (s *Service) Notify() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

// Run is the security.posture loop: it re-signs every project's posture
// at least every interval (default secposture.ResignEvery) and on every
// Notify, until ctx ends.
func (s *Service) Run(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = secposture.ResignEvery
	}
	s.mu.Lock()
	s.interval = interval
	s.mu.Unlock()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if _, err := s.WriteAll(ctx); err != nil && s.o.OnError != nil && ctx.Err() == nil {
			s.o.OnError(err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		case <-s.notify:
		}
	}
}

// Memory returns the daemon's in-memory posture state for a project, the
// relay path's posture (section 4.8 "Relay path"): the same state
// function over the last file written, with the dirty counter the caller
// read, and no file, key or seen mark involved.
func (s *Service) Memory(projectRoot string, dirty uint64, dirtyOK bool) policy.Security {
	hash := secposture.ProjectRootHash(projectRoot)
	s.mu.Lock()
	f, ok := s.memory[hash]
	s.mu.Unlock()
	in := secposture.Input{Module: secposture.ModuleActive, Now: s.o.Now(), SeenOK: true, Dirty: dirty, DirtyOK: dirtyOK}
	if ok {
		in.Read, in.File = secposture.ReadOK, &f
		in.Seen = f.Sequence
	} else {
		in.Read = secposture.ReadMissing
	}
	r := secposture.Reading{Input: in, State: secposture.Derive(in)}
	if ok {
		r.File = &f
	}
	return secposture.Facts(r)
}

// RunStore is the part of the findings store a recorded run writes
// (internal/store implements it).
type RunStore interface {
	UpsertSecFinding(ctx context.Context, f secfinding.Finding, now time.Time) (string, bool, error)
	InsertSecScanRun(ctx context.Context, r store.SecScanRun) error
	CloseGoneSecFindings(ctx context.Context, q store.SecGoneQuery, now time.Time) (int, error)
}

// Gone is what a completed run proved absent (lane SEC-GATEFIX milestone
// 2d; by path and identity since lane sec-gate2), so RecordRun can close
// it: the whole files it read or saw deleted (an open finding of its driver
// and Pack sighted there that it did not report again is no longer seen
// there) and the finding keys whose content it saw removed from one file.
// A finding closes only when no sighting is left (store.SecGoneQuery). The
// zero value closes nothing.
type Gone struct {
	// Pack is the rule pack whose findings the run speaks for
	// ("security.secrets"); empty closes nothing.
	Pack    string
	Paths   []string
	Removed []store.SecSighting
	// RulePrefixes limits the close to the rules the run speaks for
	// (store.SecGoneQuery.RulePrefixes); empty is every rule of Pack.
	RulePrefixes []string
	// Also are further closes the same run proves, each with its own paths
	// and rules (a commit's workflow checks and its deleted files).
	Also []Gone
}

// RecordRun writes one driver run's normalized findings and its scan-run
// row, then asks for a re-sign (the one caller that writes findings,
// section 4.6). Every finding is normalized and stamped with the target's
// project before it is stored. A run with no findings is recorded too
// (its row is the evidence the scan ran), and a run that completed
// (outcome clean or findings) closes what gone names as not reproduced,
// except what it reported again; an unknown run proves nothing gone. It
// returns how many findings were new.
func RecordRun(ctx context.Context, st RunStore, t secscan.Target, res secscan.Result, started time.Time, took time.Duration, gone Gone, notify func()) (int, error) {
	hash := secposture.ProjectRootHash(t.ProjectRoot)
	if hash == "" {
		return 0, errors.New("secsvc.RecordRun: empty project root")
	}
	created := 0
	box, isBox := BoxCommitFrom(ctx)
	for _, f := range res.Findings {
		f.Project.RootHash = hash
		if f.Scope == "" {
			f.Scope = t.Scope
		}
		if isBox && f.Lineage.RunID == "" {
			f.Lineage.RunID = box.RunID
			if f.Lineage.RunID == "" {
				// Box work always carries a run id, so the store keeps it
				// off the working tree (lane sec-box audit finding 1).
				f.Lineage.RunID = secfinding.UnknownRunID
			}
		}
		f = secfinding.Normalize(f)
		_, isNew, err := st.UpsertSecFinding(ctx, f, started)
		if err != nil {
			return created, err
		}
		if isNew {
			created++
		}
	}
	if err := st.InsertSecScanRun(ctx, store.SecScanRun{
		ProjectRootHash: hash, Driver: res.Engine.Name, Scope: t.Scope, Target: boxRunTarget(ctx), Coverage: res.Coverage, Engine: res.Engine,
		Outcome: string(res.Coverage.Outcome), Findings: len(res.Findings), StartedAt: started, Duration: took,
	}); err != nil {
		return created, err
	}
	// A box commit's run closes nothing (boxcommit.go).
	if complete := res.Coverage.Outcome == secscan.OutcomeClean || res.Coverage.Outcome == secscan.OutcomeFindings; complete && !isBox {
		keep := make([]store.SecSighting, 0, len(res.Findings))
		for _, f := range res.Findings {
			keep = append(keep, store.SecSighting{Key: f.LocalKey, Path: f.Location.RelPath})
		}
		for _, g := range append([]Gone{gone}, gone.Also...) {
			if g.Pack == "" {
				continue
			}
			if _, err := st.CloseGoneSecFindings(ctx, store.SecGoneQuery{
				ProjectRootHash: hash, Driver: res.Engine.Name, RulePack: g.Pack,
				Paths: g.Paths, Removed: g.Removed, Keep: keep, RulePrefixes: g.RulePrefixes,
				PackVersion: res.Engine.RulePackVersion,
			}, started); err != nil {
				return created, err
			}
		}
	}
	if notify != nil {
		notify()
	}
	return created, nil
}
