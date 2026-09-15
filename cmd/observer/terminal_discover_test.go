package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// --- pure-function tests -----------------------------------------------------

func TestUniqueRunSessionPairs(t *testing.T) {
	cases := []struct {
		name  string
		cands map[string][]string
		want  map[string]string
	}{
		{"empty", map[string][]string{}, map[string]string{}},
		{
			"one-to-one links",
			map[string][]string{"r1": {"s1"}, "r2": {"s2"}},
			map[string]string{"r1": "s1", "r2": "s2"},
		},
		{
			"run with two candidates → absent",
			map[string][]string{"r1": {"s1", "s2"}},
			map[string]string{},
		},
		{
			"session shared by two runs → BOTH absent",
			map[string][]string{"r1": {"s1"}, "r2": {"s1"}},
			map[string]string{},
		},
		{
			"run with zero candidates → absent",
			map[string][]string{"r1": {}},
			map[string]string{},
		},
		{
			"mixed: one unique pair, one ambiguous run, one shared session",
			map[string][]string{
				"r1": {"s1"},       // unique → link
				"r2": {"s2", "s3"}, // two candidates → absent
				"r3": {"s4"},       // s4 also candidate of r4 → both absent
				"r4": {"s4"},
			},
			map[string]string{"r1": "s1"},
		},
		{
			"within-run duplicate collapses to a single distinct candidate → link",
			map[string][]string{"r1": {"s1", "s1"}},
			map[string]string{"r1": "s1"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := uniqueRunSessionPairs(tc.cands)
			if len(got) != len(tc.want) {
				t.Fatalf("uniqueRunSessionPairs = %v, want %v", got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Fatalf("pair[%q] = %q, want %q (full: %v)", k, got[k], v, got)
				}
			}
		})
	}
}

func TestCanonicalToolForRun(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"claude-code", "claude-code"},                 // registry key passes through
		{"claude", "claude-code"},                      // launcher verb reverse-maps
		{"codex", "codex"},                             // registry key passes through
		{"totally-unknown-xyz", "totally-unknown-xyz"}, // unknown passes through
		{"", ""}, // empty passes through
	}
	for _, tc := range cases {
		if got := canonicalToolForRun(tc.in); got != tc.want {
			t.Fatalf("canonicalToolForRun(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// --- fakes -------------------------------------------------------------------

// discTick scripts one sweep pass: the runs the store returns (and an optional
// error), plus the candidate result for each launch dir the sweep will query.
type discTick struct {
	runs    []store.UncorrelatedTerminalRun
	runsErr error
	// cands is keyed by rawDir (the sweep passes the launch dir to the candidate
	// query; the fake keys off it since the method has no runID parameter).
	cands map[string]discCand
}

type discCand struct {
	sessions []store.DiscoveryCandidateSession
	err      error
}

// fakeDiscoverStore replays a scripted list of ticks and records the arguments
// of every candidate query.
type fakeDiscoverStore struct {
	capturedTool string
	ticks        []discTick
	cur          int
	active       discTick

	listCalls int
	candArgs  []candArg

	// sourceRoots scripts ProjectRootForSession (sessionID -> stored root); a
	// matching sourceRootErr entry forces an error. projectRootArgs records the
	// session ids the handoff fallback looked up (to assert it is NOT called for a
	// non-handoff run).
	sourceRoots     map[string]string
	sourceRootErr   map[string]error
	projectRootArgs []string

	// linkedSessions scripts SessionLinkedToAnyRun (sessionID -> claimed); a
	// matching linkedSessionErr entry forces an error. Default (nil maps) returns
	// (false, nil) so the session-side recheck passes and the happy path links.
	// linkedSessionArgs records the session ids the recheck queried.
	linkedSessions    map[string]bool
	linkedSessionErr  map[string]error
	linkedSessionArgs []string
}

type candArg struct {
	tool, gitRoot, rawDir, excludeSession string
	after, until                          time.Time
	minConfidence                         float64
	limit                                 int
}

func (f *fakeDiscoverStore) ListLiveUncorrelatedRuns(_ context.Context, _ float64, _ int) ([]store.UncorrelatedTerminalRun, error) {
	f.listCalls++
	if f.cur >= len(f.ticks) {
		f.active = discTick{} // past the script: no runs
	} else {
		f.active = f.ticks[f.cur]
		f.cur++
	}
	return f.active.runs, f.active.runsErr
}

func (f *fakeDiscoverStore) CandidateSessionsForTerminalRun(_ context.Context, tool, gitRoot, rawDir string, after, until time.Time, excludeSessionID string, minConfidence float64, limit int) ([]store.DiscoveryCandidateSession, error) {
	f.candArgs = append(f.candArgs, candArg{tool, gitRoot, rawDir, excludeSessionID, after, until, minConfidence, limit})
	c := f.active.cands[rawDir]
	return c.sessions, c.err
}

func (f *fakeDiscoverStore) ProjectRootForSession(_ context.Context, sessionID string) (string, error) {
	f.projectRootArgs = append(f.projectRootArgs, sessionID)
	if f.sourceRootErr != nil {
		if err := f.sourceRootErr[sessionID]; err != nil {
			return "", err
		}
	}
	if f.sourceRoots == nil {
		return "", nil
	}
	return f.sourceRoots[sessionID], nil
}

func (f *fakeDiscoverStore) SessionLinkedToAnyRun(_ context.Context, sessionID string, _ float64) (bool, error) {
	f.linkedSessionArgs = append(f.linkedSessionArgs, sessionID)
	if f.linkedSessionErr != nil {
		if err := f.linkedSessionErr[sessionID]; err != nil {
			return false, err
		}
	}
	if f.linkedSessions == nil {
		return false, nil
	}
	return f.linkedSessions[sessionID], nil
}

type corrCall struct {
	runID, sessionID string
	source           termrun.Source
	at               time.Time
}

// discSeams bundles the injected function seams + their recordings.
type discSeams struct {
	handles  map[string]string // runID -> handle ("" => miss)
	roots    map[string]string // handle -> dir ("" => miss)
	rootHits map[string]int    // dir -> resolveGitRoot invocations
	corr     []corrCall
	corrErr  func(runID string) error
	now      time.Time

	// handleCalls counts handleForRun invocations per run; handleMissAfter marks
	// a run whose handle disappears mid-tick — handleForRun returns ok only for
	// the first N calls, then !ok (models a run exiting between step 2's collect
	// and step 4's revalidation).
	handleCalls     map[string]int
	handleMissAfter map[string]int
	// linked scripts sessionLinkForRun: a run present here reports an ESTABLISHED
	// link (ok=true) — a stronger source that won mid-dwell.
	linked map[string]string
}

func newDiscSeams() *discSeams {
	return &discSeams{
		handles:         map[string]string{},
		roots:           map[string]string{},
		rootHits:        map[string]int{},
		handleCalls:     map[string]int{},
		handleMissAfter: map[string]int{},
		linked:          map[string]string{},
		now:             time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC),
	}
}

func newTestDiscoverer(st terminalDiscoverStore, s *discSeams, cfg terminalDiscoverConfig) *terminalDiscoverer {
	return newTerminalDiscoverer(
		st,
		func(runID string) (string, bool) {
			s.handleCalls[runID]++
			if n, ok := s.handleMissAfter[runID]; ok && s.handleCalls[runID] > n {
				return "", false // handle disappeared mid-tick
			}
			h, ok := s.handles[runID]
			return h, ok && h != ""
		},
		nil,
		func(runID string) (string, float64, bool) {
			if sid, ok := s.linked[runID]; ok {
				return sid, 0.9, true
			}
			return "", 0, false
		},
		func(handle string) (string, bool) { d, ok := s.roots[handle]; return d, ok && d != "" },
		func(_ context.Context, runID, sessionID string, source termrun.Source, at time.Time) error {
			s.corr = append(s.corr, corrCall{runID, sessionID, source, at})
			if s.corrErr != nil {
				return s.corrErr(runID)
			}
			return nil
		},
		func(dir string) string { s.rootHits[dir]++; return dir }, // identity + count
		func() time.Time { return s.now },
		nil,
		cfg,
	)
}

// wireRun registers a run's live handle + launch dir on the seams, using the
// conventional handle/dir derived from the run id.
func wireRun(s *discSeams, runID string) (handle, dir string) {
	handle = "h-" + runID
	dir = "/work/" + runID
	s.handles[runID] = handle
	s.roots[handle] = dir
	return handle, dir
}

func mkRun(runID, tool string, launched time.Time) store.UncorrelatedTerminalRun {
	return store.UncorrelatedTerminalRun{RunID: runID, Tool: tool, Kind: "fresh", LaunchedAt: launched}
}

func sess(id string) store.DiscoveryCandidateSession {
	return store.DiscoveryCandidateSession{SessionID: id}
}

func testCfg() terminalDiscoverConfig {
	return terminalDiscoverConfig{interval: time.Millisecond, skew: 5 * time.Second, dwellTicks: 2, runLimit: 64, candLimit: 8, window: 30 * time.Minute}
}

// --- tick dwell tests --------------------------------------------------------

func TestTerminalDiscoverDwellLinksOnce(t *testing.T) {
	s := newDiscSeams()
	_, dir := wireRun(s, "r1")
	launched := s.now.Add(-time.Minute)
	tickPlan := discTick{
		runs:  []store.UncorrelatedTerminalRun{mkRun("r1", "claude-code", launched)},
		cands: map[string]discCand{dir: {sessions: []store.DiscoveryCandidateSession{sess("s1")}}},
	}
	// Present on tick 0 and tick 1, absent thereafter (mirrors prod: once linked,
	// the run is no longer returned as uncorrelated).
	st := &fakeDiscoverStore{ticks: []discTick{tickPlan, tickPlan}}
	d := newTestDiscoverer(st, s, testCfg())

	if n := d.tick(context.Background()); n != 0 {
		t.Fatalf("tick 0 links = %d, want 0 (dwell not yet satisfied)", n)
	}
	if len(s.corr) != 0 {
		t.Fatalf("tick 0 correlate calls = %d, want 0", len(s.corr))
	}
	if n := d.tick(context.Background()); n != 1 {
		t.Fatalf("tick 1 links = %d, want 1", n)
	}
	if len(s.corr) != 1 {
		t.Fatalf("correlate calls = %d, want exactly 1", len(s.corr))
	}
	got := s.corr[0]
	if got.runID != "r1" || got.sessionID != "s1" || got.source != termrun.SourceDiscovered {
		t.Fatalf("correlate = %+v, want r1/s1/discovered", got)
	}
	if !got.at.Equal(s.now.UTC()) {
		t.Fatalf("correlate at = %v, want %v", got.at, s.now.UTC())
	}
	// A third tick (run now absent) must not re-link.
	d.tick(context.Background())
	if len(s.corr) != 1 {
		t.Fatalf("after run vanished, correlate calls = %d, want still 1", len(s.corr))
	}
}

// TestTerminalDiscoverPassesForwardWindow pins that the sweep hands the store a
// candidate window whose ceiling is launched_at + cfg.window (the forward bound
// Fix 1 added), while the floor stays launched_at - cfg.skew.
func TestTerminalDiscoverPassesForwardWindow(t *testing.T) {
	s := newDiscSeams()
	_, dir := wireRun(s, "r1")
	launched := s.now.Add(-time.Minute)
	tickPlan := discTick{
		runs:  []store.UncorrelatedTerminalRun{mkRun("r1", "claude-code", launched)},
		cands: map[string]discCand{dir: {sessions: []store.DiscoveryCandidateSession{sess("s1")}}},
	}
	st := &fakeDiscoverStore{ticks: []discTick{tickPlan}}
	cfg := testCfg()
	d := newTestDiscoverer(st, s, cfg)

	d.tick(context.Background())
	if len(st.candArgs) != 1 {
		t.Fatalf("candidate query calls = %d, want 1", len(st.candArgs))
	}
	arg := st.candArgs[0]
	if wantUntil := launched.Add(cfg.window); !arg.until.Equal(wantUntil) {
		t.Fatalf("until = %v, want launched+window = %v", arg.until, wantUntil)
	}
	if wantAfter := launched.Add(-cfg.skew); !arg.after.Equal(wantAfter) {
		t.Fatalf("after = %v, want launched-skew = %v", arg.after, wantAfter)
	}
}

// TestDefaultTerminalDiscoverConfigWindow pins the production forward window
// at 2h (widened 2026-09-02 from 30m). A live opencode Session Cockpit was
// observed stuck uncorrelated forever because the tool — a CursorWatermark-
// shaped adapter, so it never gets the fast post-launch discovery path in
// terminal_discover_generic.go and depends on this sweep exclusively — did
// not write its first session row until ~48 minutes after terminal launch,
// already past the old 30m ceiling with no way to recover once past it. This
// test is a tripwire: if the production default regresses back toward 30m
// this fails loudly instead of silently reintroducing the bug.
func TestDefaultTerminalDiscoverConfigWindow(t *testing.T) {
	cfg := defaultTerminalDiscoverConfig()
	if cfg.window != 2*time.Hour {
		t.Fatalf("defaultTerminalDiscoverConfig().window = %v, want 2h", cfg.window)
	}
	// The observed live gap (opencode, 2026-09-02) must fall inside the window.
	const observedLiveGap = 48 * time.Minute
	if observedLiveGap >= cfg.window {
		t.Fatalf("observed live launch-to-session gap %v must be well inside the production window %v", observedLiveGap, cfg.window)
	}
}

// TestTerminalDiscoverProductionWindowLinksLateLazySession runs an end-to-end
// tick() against the REAL production default config (not testCfg()'s 30m) and
// reproduces the exact shape of the live bug this fixed: a run launched, then
// its session only starts ~48 minutes later (a lazily-session-creating
// CLI/TUI tool that doesn't write anything until the operator's first real
// message). Under the old 30m default this run would have permanently and
// silently lost its one chance to correlate; under the widened window it
// still links once the dwell requirement is satisfied.
func TestTerminalDiscoverProductionWindowLinksLateLazySession(t *testing.T) {
	s := newDiscSeams()
	_, dir := wireRun(s, "r1")
	cfg := defaultTerminalDiscoverConfig()
	// s.now is "the moment the sweep observes things" — put the launch far
	// enough in the past that the gap to s.now (standing in for the session's
	// start) is the observed live 48-minute gap, comfortably inside 2h but
	// well past the old 30m ceiling.
	launched := s.now.Add(-48 * time.Minute)
	tickPlan := discTick{
		runs:  []store.UncorrelatedTerminalRun{mkRun("r1", "opencode", launched)},
		cands: map[string]discCand{dir: {sessions: []store.DiscoveryCandidateSession{sess("s1")}}},
	}
	st := &fakeDiscoverStore{ticks: []discTick{tickPlan, tickPlan}}
	// Use a fast interval for the test driver only; every other field
	// (skew/dwellTicks/runLimit/candLimit/window) is the real production value.
	cfg.interval = time.Millisecond
	d := newTestDiscoverer(st, s, cfg)

	if n := d.tick(context.Background()); n != 0 {
		t.Fatalf("tick 0 links = %d, want 0 (dwell not yet satisfied)", n)
	}
	if len(st.candArgs) != 1 {
		t.Fatalf("candidate query calls after tick 0 = %d, want 1 (production window must not skip this run)", len(st.candArgs))
	}
	if n := d.tick(context.Background()); n != 1 {
		t.Fatalf("tick 1 links = %d, want 1 (production window must allow a 48m-late session to link)", n)
	}
	if len(s.corr) != 1 || s.corr[0].runID != "r1" || s.corr[0].sessionID != "s1" {
		t.Fatalf("correlate calls = %+v, want exactly one r1/s1 link", s.corr)
	}
}

// TestTerminalDiscoverExpiredWindowSkipsQuery pins the structural skip: once
// now() is past launched_at + cfg.window the run can never link, so the sweep
// must NOT even issue the candidate query for it.
func TestTerminalDiscoverExpiredWindowSkipsQuery(t *testing.T) {
	s := newDiscSeams()
	_, dir := wireRun(s, "r1")
	cfg := testCfg()
	// Launch far enough in the past that launched+window is already behind now.
	launched := s.now.Add(-cfg.window - time.Minute)
	tickPlan := discTick{
		runs:  []store.UncorrelatedTerminalRun{mkRun("r1", "claude-code", launched)},
		cands: map[string]discCand{dir: {sessions: []store.DiscoveryCandidateSession{sess("s1")}}},
	}
	st := &fakeDiscoverStore{ticks: []discTick{tickPlan}}
	d := newTestDiscoverer(st, s, cfg)

	if n := d.tick(context.Background()); n != 0 {
		t.Fatalf("expired-window tick links = %d, want 0", n)
	}
	if len(st.candArgs) != 0 {
		t.Fatalf("candidate query calls = %d, want 0 (expired window must skip the query)", len(st.candArgs))
	}
	if len(s.corr) != 0 {
		t.Fatalf("correlate calls = %d, want 0", len(s.corr))
	}
}

func TestTerminalDiscoverPairChangeResetsStreak(t *testing.T) {
	s := newDiscSeams()
	_, dir := wireRun(s, "r1")
	launched := s.now.Add(-time.Minute)
	run := mkRun("r1", "claude-code", launched)
	st := &fakeDiscoverStore{ticks: []discTick{
		{runs: []store.UncorrelatedTerminalRun{run}, cands: map[string]discCand{dir: {sessions: []store.DiscoveryCandidateSession{sess("s1")}}}},
		{runs: []store.UncorrelatedTerminalRun{run}, cands: map[string]discCand{dir: {sessions: []store.DiscoveryCandidateSession{sess("s2")}}}},
	}}
	d := newTestDiscoverer(st, s, testCfg())

	d.tick(context.Background()) // streak s1=1
	d.tick(context.Background()) // pair changed to s2 → streak resets to 1, no link
	if len(s.corr) != 0 {
		t.Fatalf("a changed pair must reset the streak (no link), got %d correlate calls", len(s.corr))
	}
	if d.pending["r1"].sessionID != "s2" || d.pending["r1"].streak != 1 {
		t.Fatalf("pending after change = %+v, want {s2,1}", d.pending["r1"])
	}
}

func TestTerminalDiscoverAbsentRunDropsPendingThenRestarts(t *testing.T) {
	s := newDiscSeams()
	_, dir := wireRun(s, "r1")
	launched := s.now.Add(-time.Minute)
	run := mkRun("r1", "claude-code", launched)
	withCand := discTick{runs: []store.UncorrelatedTerminalRun{run}, cands: map[string]discCand{dir: {sessions: []store.DiscoveryCandidateSession{sess("s1")}}}}
	empty := discTick{} // run absent
	st := &fakeDiscoverStore{ticks: []discTick{withCand, empty, withCand, withCand}}
	d := newTestDiscoverer(st, s, testCfg())

	d.tick(context.Background()) // streak 1
	if _, ok := d.pending["r1"]; !ok {
		t.Fatalf("pending should hold r1 after tick 0")
	}
	d.tick(context.Background()) // run absent → pending cleared (zero runs path)
	if _, ok := d.pending["r1"]; ok {
		t.Fatalf("pending should be dropped when the run is absent")
	}
	d.tick(context.Background()) // reappears → streak restarts at 1, no link
	if len(s.corr) != 0 {
		t.Fatalf("reappearing run must restart dwell (no link yet), got %d", len(s.corr))
	}
	if d.pending["r1"].streak != 1 {
		t.Fatalf("streak after reappear = %d, want 1", d.pending["r1"].streak)
	}
	d.tick(context.Background()) // now dwell satisfied → link
	if len(s.corr) != 1 {
		t.Fatalf("link after re-dwell: correlate calls = %d, want 1", len(s.corr))
	}
}

func TestTerminalDiscoverCorrelateErrorRetried(t *testing.T) {
	s := newDiscSeams()
	_, dir := wireRun(s, "r1")
	launched := s.now.Add(-time.Minute)
	run := mkRun("r1", "claude-code", launched)
	tp := discTick{runs: []store.UncorrelatedTerminalRun{run}, cands: map[string]discCand{dir: {sessions: []store.DiscoveryCandidateSession{sess("s1")}}}}
	st := &fakeDiscoverStore{ticks: []discTick{tp, tp, tp}}
	d := newTestDiscoverer(st, s, testCfg())

	failFirst := true
	s.corrErr = func(string) error {
		if failFirst {
			failFirst = false
			return context.DeadlineExceeded
		}
		return nil
	}

	d.tick(context.Background()) // streak 1
	if n := d.tick(context.Background()); n != 0 {
		t.Fatalf("tick 1 (correlate errors) links = %d, want 0", n)
	}
	if _, ok := d.pending["r1"]; !ok {
		t.Fatalf("a correlate error must RETAIN the pending entry for retry")
	}
	if n := d.tick(context.Background()); n != 1 {
		t.Fatalf("tick 2 retry links = %d, want 1", n)
	}
	if len(s.corr) != 2 {
		t.Fatalf("correlate attempts = %d, want 2 (one failed, one succeeded)", len(s.corr))
	}
}

// --- tick filter tests -------------------------------------------------------

func TestTerminalDiscoverHandleMissSkipsRun(t *testing.T) {
	s := newDiscSeams()
	// r1 has NO live handle (never wired).
	launched := s.now.Add(-time.Minute)
	st := &fakeDiscoverStore{ticks: []discTick{{runs: []store.UncorrelatedTerminalRun{mkRun("r1", "claude-code", launched)}}}}
	d := newTestDiscoverer(st, s, testCfg())

	d.tick(context.Background())
	if len(st.candArgs) != 0 {
		t.Fatalf("candidate query must NOT be called for a run with no live handle, got %d calls", len(st.candArgs))
	}
	if len(s.corr) != 0 {
		t.Fatalf("no link expected, got %d", len(s.corr))
	}
}

func TestTerminalDiscoverProjectRootMissSkipsRun(t *testing.T) {
	s := newDiscSeams()
	// Live handle present but no project root (default-cwd launch).
	s.handles["r1"] = "h-r1"
	// deliberately do NOT set s.roots["h-r1"]
	launched := s.now.Add(-time.Minute)
	st := &fakeDiscoverStore{ticks: []discTick{{runs: []store.UncorrelatedTerminalRun{mkRun("r1", "claude-code", launched)}}}}
	d := newTestDiscoverer(st, s, testCfg())

	d.tick(context.Background())
	if len(st.candArgs) != 0 {
		t.Fatalf("candidate query must NOT be called for a default-cwd run, got %d calls", len(st.candArgs))
	}
}

func TestTerminalDiscoverCanonicalToolPassedToStore(t *testing.T) {
	s := newDiscSeams()
	_, dir := wireRun(s, "r1")
	launched := s.now.Add(-time.Minute)
	// Tool label is the launcher verb "claude" — the store must be queried with
	// the canonical "claude-code".
	st := &fakeDiscoverStore{ticks: []discTick{{
		runs:  []store.UncorrelatedTerminalRun{mkRun("r1", "claude", launched)},
		cands: map[string]discCand{dir: {}},
	}}}
	d := newTestDiscoverer(st, s, testCfg())

	d.tick(context.Background())
	if len(st.candArgs) != 1 {
		t.Fatalf("candidate query calls = %d, want 1", len(st.candArgs))
	}
	arg := st.candArgs[0]
	if arg.tool != "claude-code" {
		t.Fatalf("store queried with tool %q, want canonical claude-code", arg.tool)
	}
	if arg.gitRoot != dir || arg.rawDir != dir {
		t.Fatalf("store gitRoot/rawDir = %q/%q, want identity %q", arg.gitRoot, arg.rawDir, dir)
	}
	wantAfter := launched.Add(-testCfg().skew)
	if !arg.after.Equal(wantAfter) {
		t.Fatalf("store after = %v, want launched-skew %v", arg.after, wantAfter)
	}
}

func TestTerminalDiscoverUnknownToolPassesThrough(t *testing.T) {
	s := newDiscSeams()
	_, dir := wireRun(s, "r1")
	launched := s.now.Add(-time.Minute)
	st := &fakeDiscoverStore{ticks: []discTick{{
		runs:  []store.UncorrelatedTerminalRun{mkRun("r1", "mystery-tool", launched)},
		cands: map[string]discCand{dir: {}},
	}}}
	d := newTestDiscoverer(st, s, testCfg())

	d.tick(context.Background())
	if len(st.candArgs) != 1 || st.candArgs[0].tool != "mystery-tool" {
		t.Fatalf("unknown tool must pass through unchanged, got args %+v", st.candArgs)
	}
}

func TestTerminalDiscoverExcludeSourceSession(t *testing.T) {
	s := newDiscSeams()
	_, dir := wireRun(s, "r1")
	launched := s.now.Add(-time.Minute)
	run := store.UncorrelatedTerminalRun{RunID: "r1", Tool: "claude-code", Kind: "handoff", SourceSessionID: "src-1", LaunchedAt: launched}
	st := &fakeDiscoverStore{ticks: []discTick{{runs: []store.UncorrelatedTerminalRun{run}, cands: map[string]discCand{dir: {}}}}}
	d := newTestDiscoverer(st, s, testCfg())

	d.tick(context.Background())
	if len(st.candArgs) != 1 || st.candArgs[0].excludeSession != "src-1" {
		t.Fatalf("source session must be forwarded as the exclusion, got %+v", st.candArgs)
	}
}

// --- tick edge tests ---------------------------------------------------------

func TestTerminalDiscoverZeroRunsClearsPending(t *testing.T) {
	s := newDiscSeams()
	_, dir := wireRun(s, "r1")
	launched := s.now.Add(-time.Minute)
	run := mkRun("r1", "claude-code", launched)
	withCand := discTick{runs: []store.UncorrelatedTerminalRun{run}, cands: map[string]discCand{dir: {sessions: []store.DiscoveryCandidateSession{sess("s1")}}}}
	empty := discTick{}
	st := &fakeDiscoverStore{ticks: []discTick{withCand, empty, withCand}}
	d := newTestDiscoverer(st, s, testCfg())

	d.tick(context.Background()) // seed pending (streak 1)
	if len(d.pending) != 1 {
		t.Fatalf("pending should be seeded, got %d", len(d.pending))
	}
	candBefore := len(st.candArgs)
	d.tick(context.Background()) // zero live runs → clear pending, never query candidates
	if len(d.pending) != 0 {
		t.Fatalf("zero live runs must clear ALL pending, got %d", len(d.pending))
	}
	if len(st.candArgs) != candBefore {
		t.Fatalf("candidate query must NOT run on a zero-runs tick (%d new calls)", len(st.candArgs)-candBefore)
	}
	d.tick(context.Background()) // re-seed → streak restarts at 1
	if d.pending["r1"].streak != 1 {
		t.Fatalf("streak after re-seed = %d, want 1", d.pending["r1"].streak)
	}
}

func TestTerminalDiscoverListErrorClearsPending(t *testing.T) {
	s := newDiscSeams()
	_, dir := wireRun(s, "r1")
	launched := s.now.Add(-time.Minute)
	run := mkRun("r1", "claude-code", launched)
	withCand := discTick{runs: []store.UncorrelatedTerminalRun{run}, cands: map[string]discCand{dir: {sessions: []store.DiscoveryCandidateSession{sess("s1")}}}}
	listErr := discTick{runsErr: context.DeadlineExceeded}
	// streak 1, then a list-error tick (unsound → clears dwell), then two good
	// ticks: the correlate must happen on the SECOND good tick (dwell restarted at
	// the first), never the first — the outage's ambiguity was never observed, so
	// the two observations straddling it are NOT "consecutive".
	st := &fakeDiscoverStore{ticks: []discTick{withCand, listErr, withCand, withCand}}
	d := newTestDiscoverer(st, s, testCfg())

	d.tick(context.Background()) // streak 1
	d.tick(context.Background()) // list error → UNSOUND tick → pending cleared
	if len(d.pending) != 0 {
		t.Fatalf("a list error is an unsound tick and must clear ALL dwell state, got pending %+v", d.pending)
	}
	if n := d.tick(context.Background()); n != 0 { // dwell restarted at 1 → no link
		t.Fatalf("first good tick after a list error must restart dwell (no link), got %d links", n)
	}
	if d.pending["r1"].streak != 1 {
		t.Fatalf("dwell must restart at 1 after the outage, got pending %+v", d.pending)
	}
	if n := d.tick(context.Background()); n != 1 { // dwell satisfied → link
		t.Fatalf("second good tick after a list error must link, got %d links", n)
	}
	if len(s.corr) != 1 {
		t.Fatalf("exactly one link expected after the outage recovered, got %d", len(s.corr))
	}
}

func TestTerminalDiscoverResolveGitRootMemoized(t *testing.T) {
	s := newDiscSeams()
	_, dir := wireRun(s, "r1")
	launched := s.now.Add(-time.Minute)
	run := mkRun("r1", "claude-code", launched)
	tp := discTick{runs: []store.UncorrelatedTerminalRun{run}, cands: map[string]discCand{dir: {}}}
	st := &fakeDiscoverStore{ticks: []discTick{tp, tp, tp}}
	d := newTestDiscoverer(st, s, testCfg())

	d.tick(context.Background())
	d.tick(context.Background())
	d.tick(context.Background())
	if s.rootHits[dir] != 1 {
		t.Fatalf("resolveGitRoot for %q called %d times across ticks, want 1 (memoized)", dir, s.rootHits[dir])
	}
}

// --- Fix 1: handoff-fallback source-root tests -------------------------------

func TestTerminalDiscoverHandoffFallbackUsesSourceRoot(t *testing.T) {
	s := newDiscSeams()
	// Live handle present, but NO launch dir (LaunchHandoff records none, so
	// ProjectRoot misses).
	s.handles["r1"] = "h-r1"
	// deliberately do NOT set s.roots["h-r1"]
	launched := s.now.Add(-time.Minute)
	run := store.UncorrelatedTerminalRun{RunID: "r1", Tool: "claude-code", Kind: "handoff", SourceSessionID: "src-1", LaunchedAt: launched}
	st := &fakeDiscoverStore{
		ticks:       []discTick{{runs: []store.UncorrelatedTerminalRun{run}}},
		sourceRoots: map[string]string{"src-1": "/src/root"},
	}
	d := newTestDiscoverer(st, s, testCfg())

	d.tick(context.Background())
	if len(st.candArgs) != 1 {
		t.Fatalf("candidate query calls = %d, want 1 (handoff fallback resolves the source root)", len(st.candArgs))
	}
	arg := st.candArgs[0]
	if arg.gitRoot != "/src/root" || arg.rawDir != "/src/root" {
		t.Fatalf("handoff fallback gitRoot/rawDir = %q/%q, want both /src/root", arg.gitRoot, arg.rawDir)
	}
	if len(st.projectRootArgs) != 1 || st.projectRootArgs[0] != "src-1" {
		t.Fatalf("ProjectRootForSession args = %v, want [src-1]", st.projectRootArgs)
	}
	// The fallback path must NOT run git.Resolve / touch rootCache — the stored
	// root is already the exact spelling the query matches.
	if s.rootHits["/src/root"] != 0 {
		t.Fatalf("handoff fallback must NOT call resolveGitRoot, got %d hits", s.rootHits["/src/root"])
	}
}

// A handoff source-root lookup ERROR is a TRANSIENT failure: the run is
// unresolved and hidden from the cross-run uniqueness check, so the whole tick
// abstains (clear ALL pending, no links) — same shape as the cap abstains.
func TestTerminalDiscoverHandoffFallbackErrorAbstainsTick(t *testing.T) {
	s := newDiscSeams()
	s.handles["r1"] = "h-r1" // handle present, no launch dir
	launched := s.now.Add(-time.Minute)
	run := store.UncorrelatedTerminalRun{RunID: "r1", Tool: "claude-code", Kind: "handoff", SourceSessionID: "src-1", LaunchedAt: launched}
	st := &fakeDiscoverStore{
		ticks:         []discTick{{runs: []store.UncorrelatedTerminalRun{run}}},
		sourceRootErr: map[string]error{"src-1": context.DeadlineExceeded},
	}
	d := newTestDiscoverer(st, s, testCfg())
	d.pending["stale"] = pendingDiscovery{sessionID: "x", streak: 1} // must be cleared

	if n := d.tick(context.Background()); n != 0 {
		t.Fatalf("handoff source-root error must abstain (0 links), got %d", n)
	}
	if len(st.candArgs) != 0 {
		t.Fatalf("candidate query must NOT run when the source root lookup errors, got %d", len(st.candArgs))
	}
	if len(d.pending) != 0 {
		t.Fatalf("a transient handoff-root error must clear ALL pending, got %+v", d.pending)
	}
}

// A handoff source root that resolves to EMPTY with a NIL error is a STRUCTURAL
// state (source session unknown to the corpus): skip only THAT run — another run
// in the same tick still links normally.
func TestTerminalDiscoverHandoffFallbackEmptyRootSkipsOnlyThatRun(t *testing.T) {
	s := newDiscSeams()
	s.handles["r1"] = "h-r1" // handoff run: handle present, no launch dir
	_, dir2 := wireRun(s, "r2")
	launched := s.now.Add(-time.Minute)
	r1 := store.UncorrelatedTerminalRun{RunID: "r1", Tool: "claude-code", Kind: "handoff", SourceSessionID: "src-1", LaunchedAt: launched}
	r2 := mkRun("r2", "claude-code", launched)
	cfg := testCfg()
	cfg.dwellTicks = 1 // link r2 in a single tick
	st := &fakeDiscoverStore{
		ticks: []discTick{{
			runs:  []store.UncorrelatedTerminalRun{r1, r2},
			cands: map[string]discCand{dir2: {sessions: []store.DiscoveryCandidateSession{sess("s2")}}},
		}},
		sourceRoots: map[string]string{"src-1": ""}, // empty + nil error → structural skip
	}
	d := newTestDiscoverer(st, s, cfg)

	if n := d.tick(context.Background()); n != 1 {
		t.Fatalf("empty handoff root must skip only r1; r2 should still link, got %d links", n)
	}
	if len(s.corr) != 1 || s.corr[0].runID != "r2" {
		t.Fatalf("expected exactly r2 linked, got %+v", s.corr)
	}
	// r1's candidate query never ran (skipped before the query); only r2's did.
	if len(st.candArgs) != 1 {
		t.Fatalf("only r2's candidate query should have run, got %d", len(st.candArgs))
	}
}

func TestTerminalDiscoverNonHandoffProjectRootMissNoSourceLookup(t *testing.T) {
	s := newDiscSeams()
	s.handles["r1"] = "h-r1" // handle present, no launch dir
	launched := s.now.Add(-time.Minute)
	// Kind "fresh" with a SourceSessionID present, proving the fallback guard is
	// Kind == handoff, not merely a non-empty source id.
	run := store.UncorrelatedTerminalRun{RunID: "r1", Tool: "claude-code", Kind: "fresh", SourceSessionID: "src-1", LaunchedAt: launched}
	st := &fakeDiscoverStore{
		ticks:       []discTick{{runs: []store.UncorrelatedTerminalRun{run}}},
		sourceRoots: map[string]string{"src-1": "/src/root"},
	}
	d := newTestDiscoverer(st, s, testCfg())

	d.tick(context.Background())
	if len(st.projectRootArgs) != 0 {
		t.Fatalf("a NON-handoff run must not trigger the source-root lookup, got %v", st.projectRootArgs)
	}
	if len(st.candArgs) != 0 {
		t.Fatalf("a non-handoff run with no launch dir must be skipped, got %d cand calls", len(st.candArgs))
	}
}

// --- Fix 2: pre-correlate revalidation tests ---------------------------------

func TestTerminalDiscoverRevalidateHandleGoneDropsPending(t *testing.T) {
	s := newDiscSeams()
	_, dir := wireRun(s, "r1")
	s.handleMissAfter["r1"] = 1 // ok on the step-2 collect, gone on the step-4 recheck
	launched := s.now.Add(-time.Minute)
	run := mkRun("r1", "claude-code", launched)
	cfg := testCfg()
	cfg.dwellTicks = 1 // reach the link moment in a single tick
	st := &fakeDiscoverStore{ticks: []discTick{{
		runs:  []store.UncorrelatedTerminalRun{run},
		cands: map[string]discCand{dir: {sessions: []store.DiscoveryCandidateSession{sess("s1")}}},
	}}}
	d := newTestDiscoverer(st, s, cfg)

	d.tick(context.Background())
	if len(s.corr) != 0 {
		t.Fatalf("a run that exits between tick start and link must NOT be correlated, got %d", len(s.corr))
	}
	if _, ok := d.pending["r1"]; ok {
		t.Fatalf("pending must be dropped when the handle is gone at the link moment")
	}
}

func TestTerminalDiscoverRevalidateAlreadyLinkedDropsPending(t *testing.T) {
	s := newDiscSeams()
	_, dir := wireRun(s, "r1")
	s.linked["r1"] = "s-other" // a stronger source established a link mid-dwell
	launched := s.now.Add(-time.Minute)
	run := mkRun("r1", "claude-code", launched)
	cfg := testCfg()
	cfg.dwellTicks = 1
	st := &fakeDiscoverStore{ticks: []discTick{{
		runs:  []store.UncorrelatedTerminalRun{run},
		cands: map[string]discCand{dir: {sessions: []store.DiscoveryCandidateSession{sess("s1")}}},
	}}}
	d := newTestDiscoverer(st, s, cfg)

	d.tick(context.Background())
	if len(s.corr) != 0 {
		t.Fatalf("a run already linked by a stronger source must NOT be re-correlated, got %d", len(s.corr))
	}
	if _, ok := d.pending["r1"]; ok {
		t.Fatalf("pending must be dropped when a stronger link exists at the link moment")
	}
}

// --- Fix A: transient per-run failure abstains the tick ----------------------

// A candidate-query error on ONE run makes the whole tick unsound (the run is
// hidden from the cross-run uniqueness check), so NO run links that tick and all
// pending is cleared — even a run that would otherwise have reached dwell.
func TestTerminalDiscoverCandidateQueryErrorAbstainsTick(t *testing.T) {
	s := newDiscSeams()
	_, dir1 := wireRun(s, "r1")
	_, dir2 := wireRun(s, "r2")
	launched := s.now.Add(-time.Minute)
	r1 := mkRun("r1", "claude-code", launched)
	r2 := mkRun("r2", "claude-code", launched)
	// Tick 0: only r1 → dwell streak 1 (one shy of the 2-tick dwell).
	tick0 := discTick{runs: []store.UncorrelatedTerminalRun{r1}, cands: map[string]discCand{dir1: {sessions: []store.DiscoveryCandidateSession{sess("s1")}}}}
	// Tick 1: r1 would reach dwell and link, BUT r2's candidate query errors →
	// the whole tick is unsound → no links anywhere + all pending cleared.
	tick1 := discTick{
		runs: []store.UncorrelatedTerminalRun{r1, r2},
		cands: map[string]discCand{
			dir1: {sessions: []store.DiscoveryCandidateSession{sess("s1")}},
			dir2: {err: context.DeadlineExceeded},
		},
	}
	st := &fakeDiscoverStore{ticks: []discTick{tick0, tick1}}
	d := newTestDiscoverer(st, s, testCfg())

	if n := d.tick(context.Background()); n != 0 {
		t.Fatalf("tick 0 links = %d, want 0 (dwell 1)", n)
	}
	if d.pending["r1"].streak != 1 {
		t.Fatalf("r1 should be at streak 1 after tick 0, got %+v", d.pending)
	}
	if n := d.tick(context.Background()); n != 0 {
		t.Fatalf("a candidate-query error must abstain the whole tick (0 links), got %d", n)
	}
	if len(s.corr) != 0 {
		t.Fatalf("no correlate expected on an unsound tick, got %d", len(s.corr))
	}
	if len(d.pending) != 0 {
		t.Fatalf("a candidate-query error must clear ALL pending, got %+v", d.pending)
	}
}

// --- Fix B: session-side recheck at link time --------------------------------

// The candidate set can go stale w.r.t. the SESSION: an OOB echo links the
// session to a DIFFERENT run after the candidate query. The link-moment recheck
// (SessionLinkedToAnyRun) catches it → no correlate, pending dropped.
func TestTerminalDiscoverSessionRecheckClaimedDropsPending(t *testing.T) {
	s := newDiscSeams()
	_, dir := wireRun(s, "r1")
	launched := s.now.Add(-time.Minute)
	run := mkRun("r1", "claude-code", launched)
	cfg := testCfg()
	cfg.dwellTicks = 1
	st := &fakeDiscoverStore{
		ticks:          []discTick{{runs: []store.UncorrelatedTerminalRun{run}, cands: map[string]discCand{dir: {sessions: []store.DiscoveryCandidateSession{sess("s1")}}}}},
		linkedSessions: map[string]bool{"s1": true}, // claimed by another run mid-tick
	}
	d := newTestDiscoverer(st, s, cfg)

	d.tick(context.Background())
	if len(s.corr) != 0 {
		t.Fatalf("a session already linked to another run must NOT be correlated, got %d", len(s.corr))
	}
	if _, ok := d.pending["r1"]; ok {
		t.Fatalf("pending must be dropped when the session is already claimed")
	}
	if len(st.linkedSessionArgs) != 1 || st.linkedSessionArgs[0] != "s1" {
		t.Fatalf("session-side recheck must query s1, got %v", st.linkedSessionArgs)
	}
}

// A session-side recheck ERROR is treated conservatively: do NOT link, drop the
// pending entry.
func TestTerminalDiscoverSessionRecheckErrorDropsPending(t *testing.T) {
	s := newDiscSeams()
	_, dir := wireRun(s, "r1")
	launched := s.now.Add(-time.Minute)
	run := mkRun("r1", "claude-code", launched)
	cfg := testCfg()
	cfg.dwellTicks = 1
	st := &fakeDiscoverStore{
		ticks:            []discTick{{runs: []store.UncorrelatedTerminalRun{run}, cands: map[string]discCand{dir: {sessions: []store.DiscoveryCandidateSession{sess("s1")}}}}},
		linkedSessionErr: map[string]error{"s1": context.DeadlineExceeded},
	}
	d := newTestDiscoverer(st, s, cfg)

	d.tick(context.Background())
	if len(s.corr) != 0 {
		t.Fatalf("a session-side recheck error must NOT link, got %d", len(s.corr))
	}
	if _, ok := d.pending["r1"]; ok {
		t.Fatalf("pending must be dropped when the session-side recheck errors")
	}
}

// The happy path: the session-side recheck returns false → the link proceeds,
// and the recheck was actually consulted.
func TestTerminalDiscoverSessionRecheckFalseLinks(t *testing.T) {
	s := newDiscSeams()
	_, dir := wireRun(s, "r1")
	launched := s.now.Add(-time.Minute)
	run := mkRun("r1", "claude-code", launched)
	cfg := testCfg()
	cfg.dwellTicks = 1
	st := &fakeDiscoverStore{
		ticks:          []discTick{{runs: []store.UncorrelatedTerminalRun{run}, cands: map[string]discCand{dir: {sessions: []store.DiscoveryCandidateSession{sess("s1")}}}}},
		linkedSessions: map[string]bool{"s1": false}, // not claimed → link proceeds
	}
	d := newTestDiscoverer(st, s, cfg)

	if n := d.tick(context.Background()); n != 1 {
		t.Fatalf("a clean session-side recheck (false) must link, got %d", n)
	}
	if len(st.linkedSessionArgs) != 1 {
		t.Fatalf("the session-side recheck must be consulted before linking, got %d calls", len(st.linkedSessionArgs))
	}
}

// --- Fix 3: truncation-cap abstain tests -------------------------------------

func TestTerminalDiscoverRunLimitAbstains(t *testing.T) {
	s := newDiscSeams()
	_, dir1 := wireRun(s, "r1")
	_, dir2 := wireRun(s, "r2")
	launched := s.now.Add(-time.Minute)
	cfg := testCfg()
	cfg.runLimit = 2 // list at cap ⇒ possible truncation ⇒ abstain tick-wide
	st := &fakeDiscoverStore{ticks: []discTick{{
		runs: []store.UncorrelatedTerminalRun{mkRun("r1", "claude-code", launched), mkRun("r2", "claude-code", launched)},
		cands: map[string]discCand{
			dir1: {sessions: []store.DiscoveryCandidateSession{sess("s1")}},
			dir2: {sessions: []store.DiscoveryCandidateSession{sess("s2")}},
		},
	}}}
	d := newTestDiscoverer(st, s, cfg)
	d.pending["stale"] = pendingDiscovery{sessionID: "x", streak: 1} // must be cleared

	if n := d.tick(context.Background()); n != 0 {
		t.Fatalf("runLimit abstain links = %d, want 0", n)
	}
	if len(st.candArgs) != 0 {
		t.Fatalf("runLimit abstain must NOT query candidates, got %d", len(st.candArgs))
	}
	if len(d.pending) != 0 {
		t.Fatalf("runLimit abstain must clear ALL pending, got %d", len(d.pending))
	}
}

func TestTerminalDiscoverCandLimitAbstains(t *testing.T) {
	s := newDiscSeams()
	_, dir1 := wireRun(s, "r1")
	_, dir2 := wireRun(s, "r2")
	launched := s.now.Add(-time.Minute)
	cfg := testCfg()
	cfg.candLimit = 2 // a run's list at cap ⇒ hidden candidates possible ⇒ abstain
	st := &fakeDiscoverStore{ticks: []discTick{{
		runs: []store.UncorrelatedTerminalRun{mkRun("r1", "claude-code", launched), mkRun("r2", "claude-code", launched)},
		cands: map[string]discCand{
			dir1: {sessions: []store.DiscoveryCandidateSession{sess("s1"), sess("s2")}}, // at cap → truncation risk
			dir2: {sessions: []store.DiscoveryCandidateSession{sess("s3")}},             // would-be unique pair
		},
	}}}
	d := newTestDiscoverer(st, s, cfg)
	d.pending["stale"] = pendingDiscovery{sessionID: "x", streak: 1}

	if n := d.tick(context.Background()); n != 0 {
		t.Fatalf("candLimit abstain links = %d, want 0 (no links anywhere that tick)", n)
	}
	if _, ok := d.pending["r2"]; ok {
		t.Fatalf("candLimit abstain must not seed pending for the would-be-unique r2")
	}
	if len(d.pending) != 0 {
		t.Fatalf("candLimit abstain must clear ALL pending, got %d", len(d.pending))
	}
}

// --- run loop test -----------------------------------------------------------

func TestTerminalDiscoverRunCancels(t *testing.T) {
	s := newDiscSeams()
	st := &fakeDiscoverStore{} // no runs ever
	d := newTestDiscoverer(st, s, testCfg())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		d.run(ctx)
		close(done)
	}()
	// Let a few ticks fire, then cancel and require prompt return.
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return promptly after ctx cancel")
	}
	if st.listCalls == 0 {
		t.Fatal("expected the loop to have ticked at least once")
	}
}

// TestTerminalDiscoverLinksDefaultCwdLaunch is the devbox regression, replayed
// with the REAL row values captured from the affected node
// (sb-devbox, 2026-08-28):
//
//	terminal_run     run_id=cn45TulV3RMBt8ybO16FCfLf7ZqffW1r_f66lCrZa3Q
//	                 tool=opencode kind=fresh
//	                 project_root_hash='' (default-cwd launch — the node has no
//	                 [terminal.launch].allowed_project_roots configured, so the
//	                 dashboard could not authorize a root)
//	                 launched_at=2026-08-28T14:37:39.823Z, ended_at=NULL
//	launch_seeds     pid=44993 tool=opencode cwd=/home/azureuser
//	                 (the launcher child's own os.Getwd — proof the child runs
//	                 in the daemon's cwd)
//	sessions         id=ses_fb73193f7ffexyKthX20fRk905 tool=opencode
//	                 started_at=2026-08-28T14:38:02.796Z
//	projects         root_path=/home/azureuser
//	terminal_run_session  (empty — the run NEVER linked)
//
// Every field agrees; the sweep still skipped the run because its directory
// seam was svc.ProjectRoot, which answers the AUTHORIZATION question and is
// empty for a launch with no requested root. Wiring the seam to svc.SpawnDir —
// the directory the child actually runs in — makes the pair resolvable. The
// second case is the working shape from the operator's local node (an
// explicitly authorized root), pinned so the fix cannot regress it.
func TestTerminalDiscoverLinksDefaultCwdLaunch(t *testing.T) {
	const (
		devboxRun   = "cn45TulV3RMBt8ybO16FCfLf7ZqffW1r_f66lCrZa3Q"
		devboxSess  = "ses_fb73193f7ffexyKthX20fRk905"
		devboxCwd   = "/home/azureuser"
		localRun    = "qGYa812kgLjyIo_tSLJ-r5xNYUXTzlBHH8CEeZyND2M"
		localSess   = "ses_fc0ab5dc9ffecR35EEOAks23tZ"
		localRoot   = "/home/marmutapp/superbased-observer"
		devboxTool  = "opencode"
		devboxSkew  = 5 * time.Second
		devboxDwell = 2
	)
	launched := time.Date(2026, 8, 28, 14, 37, 39, 823151220, time.UTC)
	// The session the opencode adapter ingested 23s after the launch.
	sessionStart := time.Date(2026, 8, 28, 14, 38, 2, 796000000, time.UTC)

	tests := []struct {
		name string
		run  string
		// runDir is what the sweep's directory seam reports for the run's live
		// handle. "" models the pre-fix ProjectRoot answer for a default-cwd
		// launch (and, post-fix, an unreadable daemon cwd).
		runDir      string
		sessionID   string
		wantLinks   int
		wantCandDir string
	}{
		{
			name:        "devbox default-cwd launch links on the daemon cwd",
			run:         devboxRun,
			runDir:      devboxCwd,
			sessionID:   devboxSess,
			wantLinks:   1,
			wantCandDir: devboxCwd,
		},
		{
			name:        "local launch with an authorized project root still links",
			run:         localRun,
			runDir:      localRoot,
			sessionID:   localSess,
			wantLinks:   1,
			wantCandDir: localRoot,
		},
		{
			name:      "no working directory at all: honestly uncorrelated",
			run:       devboxRun,
			runDir:    "",
			sessionID: devboxSess,
			wantLinks: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newDiscSeams()
			s.now = sessionStart.Add(30 * time.Second) // mid-window, as the sweep saw it
			handle := "h-" + tc.run
			s.handles[tc.run] = handle
			s.roots[handle] = tc.runDir
			plan := discTick{
				runs: []store.UncorrelatedTerminalRun{mkRun(tc.run, devboxTool, launched)},
				cands: map[string]discCand{tc.runDir: {sessions: []store.DiscoveryCandidateSession{
					{SessionID: tc.sessionID, StartedAt: sessionStart},
				}}},
			}
			st := &fakeDiscoverStore{ticks: []discTick{plan, plan}}
			d := newTestDiscoverer(st, s, testCfg())

			if n := d.tick(context.Background()); n != 0 {
				t.Fatalf("tick 0 links = %d, want 0 (dwell of %d not yet satisfied)", n, devboxDwell)
			}
			got := d.tick(context.Background())
			if got != tc.wantLinks {
				t.Fatalf("tick 1 links = %d, want %d", got, tc.wantLinks)
			}
			if tc.wantLinks == 0 {
				if len(st.candArgs) != 0 {
					t.Fatalf("candidate query ran %d times for a dir-less run, want 0", len(st.candArgs))
				}
				if len(s.corr) != 0 {
					t.Fatalf("correlate calls = %d, want 0", len(s.corr))
				}
				return
			}
			if len(s.corr) != 1 {
				t.Fatalf("correlate calls = %d, want 1", len(s.corr))
			}
			c := s.corr[0]
			if c.runID != tc.run || c.sessionID != tc.sessionID {
				t.Fatalf("correlated (%q,%q), want (%q,%q)", c.runID, c.sessionID, tc.run, tc.sessionID)
			}
			if c.source != termrun.SourceDiscovered {
				t.Fatalf("source = %q, want %q", c.source, termrun.SourceDiscovered)
			}
			// Pin the candidate filter the store was asked for: the run's own
			// directory (both as raw dir and as its git root) and a window that
			// actually contains the session's start stamp.
			if len(st.candArgs) == 0 {
				t.Fatalf("no candidate query was issued")
			}
			a := st.candArgs[0]
			if a.tool != devboxTool || a.rawDir != tc.wantCandDir || a.gitRoot != tc.wantCandDir {
				t.Fatalf("candidate filter = (tool %q, gitRoot %q, rawDir %q), want (%q, %q, %q)",
					a.tool, a.gitRoot, a.rawDir, devboxTool, tc.wantCandDir, tc.wantCandDir)
			}
			if want := launched.Add(-devboxSkew); !a.after.Equal(want) {
				t.Fatalf("candidate window start = %s, want %s", a.after, want)
			}
			if sessionStart.Before(a.after) || sessionStart.After(a.until) {
				t.Fatalf("session start %s falls outside the queried window [%s, %s]", sessionStart, a.after, a.until)
			}
		})
	}
}

// TestTerminalDiscoverWiredToServiceLinksDefaultCwdLaunch assembles the REAL
// termsvc.Service with the REAL sweep and pins the wiring decision itself: the
// discoverer's directory seam must be svc.SpawnDir, not svc.ProjectRoot.
//
// Only the launcher, recorder and store are fakes — the directory answer comes
// from the service exactly as it does in buildTerminalStack. Rewiring the seam
// back to svc.ProjectRoot makes this fail, because a launch with no requested
// project root (the devbox's only possible shape: no allowed_project_roots are
// configured, so any requested root is denied outright) has no authorized root
// while its child still runs in — and its session is still created in — the
// daemon's cwd.
func TestTerminalDiscoverWiredToServiceLinksDefaultCwdLaunch(t *testing.T) {
	daemonCwd := t.TempDir() // stands in for the devbox daemon's cwd, /home/azureuser
	canonCwd, err := filepath.EvalSymlinks(daemonCwd)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	const wantSession = "ses_fb73193f7ffexyKthX20fRk905" // the devbox session that never linked

	svc := termsvc.New(termsvc.Options{
		Recorder: assembledRecorder{},
		Launcher: &recordingLauncher{},
		Policy: termsvc.Policy{
			AllowFresh:   true,
			AllowedTools: []string{"opencode"},
			// Deliberately EMPTY, exactly like the devbox's config: with no
			// allowed_project_roots there is no root the dashboard could pass.
			AllowedProjectRoots: nil,
		},
		Getwd: func() (string, error) { return daemonCwd, nil },
	})
	res, err := svc.LaunchFresh(context.Background(), termsvc.FreshRequest{Tool: "opencode", Subcommand: "opencode"})
	if err != nil {
		t.Fatalf("LaunchFresh: %v", err)
	}
	if _, ok := svc.ProjectRoot(res.Handle); ok {
		t.Fatalf("ProjectRoot reported a root for a default-cwd launch; the devbox shape has none")
	}

	launched := time.Date(2026, 8, 28, 14, 37, 39, 823151220, time.UTC)
	sessionStart := launched.Add(23 * time.Second)
	plan := discTick{
		runs: []store.UncorrelatedTerminalRun{mkRun(res.RunID, "opencode", launched)},
		cands: map[string]discCand{canonCwd: {sessions: []store.DiscoveryCandidateSession{
			{SessionID: wantSession, StartedAt: sessionStart},
		}}},
	}
	st := &fakeDiscoverStore{ticks: []discTick{plan, plan}}

	var corr []corrCall
	d := newTerminalDiscoverer(
		st,
		svc.HandleForRun,
		nil,
		svc.SessionLinkForRun,
		svc.SpawnDir, // THE wiring under test
		func(_ context.Context, runID, sessionID string, source termrun.Source, at time.Time) error {
			corr = append(corr, corrCall{runID, sessionID, source, at})
			return nil
		},
		func(dir string) string { return dir }, // /home/azureuser is not a repo: git.Resolve returns the dir itself
		func() time.Time { return sessionStart.Add(30 * time.Second) },
		nil,
		testCfg(),
	)

	if n := d.tick(context.Background()); n != 0 {
		t.Fatalf("tick 0 links = %d, want 0 (dwell)", n)
	}
	if n := d.tick(context.Background()); n != 1 {
		t.Fatalf("tick 1 links = %d, want 1 — the default-cwd launch never correlated", n)
	}
	if len(corr) != 1 || corr[0].sessionID != wantSession || corr[0].runID != res.RunID {
		t.Fatalf("correlations = %+v, want one (%s → %s)", corr, res.RunID, wantSession)
	}
	if corr[0].source != termrun.SourceDiscovered {
		t.Fatalf("source = %q, want %q", corr[0].source, termrun.SourceDiscovered)
	}
	if len(st.candArgs) == 0 || st.candArgs[0].rawDir != canonCwd {
		t.Fatalf("candidate query rawDir = %+v, want %q", st.candArgs, canonCwd)
	}
}

func (f *fakeDiscoverStore) CapturedSessionForTool(_ context.Context, sessionID, tool string) (bool, error) {
	wantTool := f.capturedTool
	if wantTool == "" {
		wantTool = "codex"
	}
	return sessionID != "not-captured" && tool == wantTool, nil
}

func (f *fakeDiscoverStore) LiveRunForSession(ctx context.Context, sessionID string, confidence float64) (bool, error) {
	return f.SessionLinkedToAnyRun(ctx, sessionID, confidence)
}

func TestTerminalDiscoverNativeCodexIdentity(t *testing.T) {
	for _, tc := range []struct {
		name          string
		first, second string
		uncertain     bool
		claimed       bool
		want          int
	}{
		{name: "late simultaneous same project sessions", first: "main-a", second: "main-b", want: 2},
		{name: "same session in two live processes", first: "same", second: "same"},
		{name: "idle terminal does not block captured terminal", first: "main-a", second: "main-b", uncertain: true, want: 1},
		{name: "wait for captured corpus", first: "not-captured", second: "main-b", want: 1},
		{name: "another live run already claimed session", first: "main-a", second: "main-b", claimed: true, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newDiscSeams()
			_, dirA := wireRun(s, "a")
			_, dirB := wireRun(s, "b")
			launched := s.now.Add(-3 * time.Hour)
			st := &fakeDiscoverStore{ticks: []discTick{{
				runs:  []store.UncorrelatedTerminalRun{mkRun("a", "codex", launched), mkRun("b", "codex", launched)},
				cands: map[string]discCand{dirA: {sessions: []store.DiscoveryCandidateSession{sess("wrong")}}, dirB: {sessions: []store.DiscoveryCandidateSession{sess("wrong")}}},
			}}, linkedSessions: map[string]bool{"main-a": tc.claimed}}
			d := newTestDiscoverer(st, s, testCfg())
			d.nativeSession = func(_ context.Context, runID string) (terminalNativeIdentity, error) {
				if runID == "b" && tc.uncertain {
					return terminalNativeIdentity{}, errTerminalIdentityUncertain
				}
				id := tc.first
				if runID == "b" {
					id = tc.second
				}
				return terminalNativeIdentity{sessionID: id, evidence: "/captured/" + id}, nil
			}
			if got := d.tick(context.Background()); got != tc.want {
				t.Fatalf("links=%d, want %d", got, tc.want)
			}
			if len(s.corr) != tc.want {
				t.Fatalf("correlations=%v, want %d", s.corr, tc.want)
			}
			for _, call := range s.corr {
				want := tc.first
				if call.runID == "b" {
					want = tc.second
				}
				if call.sessionID != want || call.source != termrun.SourceDiscovered {
					t.Fatalf("wrong link: %+v", call)
				}
			}
			if len(st.candArgs) != 0 {
				t.Fatal("native Codex identity fell back to timestamp guessing")
			}
		})
	}
}

func TestTerminalDiscoverNativeCodexRevalidates(t *testing.T) {
	for _, reason := range []string{"exit", "session changed", "handoff source", "stronger link"} {
		t.Run(reason, func(t *testing.T) {
			s := newDiscSeams()
			wireRun(s, "a")
			run := mkRun("a", "codex", s.now.Add(-time.Minute))
			if reason == "handoff source" {
				run.Kind = string(termrun.KindHandoff)
				run.SourceSessionID = "main"
			}
			st := &fakeDiscoverStore{ticks: []discTick{{runs: []store.UncorrelatedTerminalRun{run}}}}
			d := newTestDiscoverer(st, s, testCfg())
			calls := 0
			d.nativeSession = func(_ context.Context, _ string) (terminalNativeIdentity, error) {
				calls++
				if reason == "exit" {
					delete(s.handles, "a")
				}
				if reason == "stronger link" {
					s.linked["a"] = "known"
				}
				id := "main"
				if calls > 1 && reason == "session changed" {
					id = "new"
				}
				return terminalNativeIdentity{sessionID: id, evidence: "/rollout"}, nil
			}
			if got := d.tick(context.Background()); got != 0 || len(s.corr) != 0 {
				t.Fatalf("linked stale identity: %v", s.corr)
			}
		})
	}
}

func TestTerminalDiscoverNativeToolAgreement(t *testing.T) {
	for _, tc := range []struct {
		tool, capturedTool string
		want               int
	}{
		{"qwen", "qwen-code", 1},
		{"qwen-code", "qwen-code", 1},
		{"open-interpreter", "open-interpreter", 1},
		{"interpreter", "open-interpreter", 0},
		{"codex", "open-interpreter", 0},
		{"qwen-code", "codex", 0},
	} {
		t.Run(tc.tool+"/"+tc.capturedTool, func(t *testing.T) {
			seams := newDiscSeams()
			wireRun(seams, "run")
			st := &fakeDiscoverStore{capturedTool: tc.capturedTool, ticks: []discTick{{runs: []store.UncorrelatedTerminalRun{mkRun("run", tc.tool, seams.now.Add(-3*time.Hour))}}}}
			d := newTestDiscoverer(st, seams, testCfg())
			d.nativeSession = func(context.Context, string) (terminalNativeIdentity, error) {
				return terminalNativeIdentity{sessionID: "exact", evidence: "native"}, nil
			}
			if got := d.tick(context.Background()); got != tc.want {
				t.Fatalf("links=%d want=%d", got, tc.want)
			}
			if len(st.candArgs) != 0 {
				t.Fatal("native run fell back to time inference")
			}
		})
	}
}
