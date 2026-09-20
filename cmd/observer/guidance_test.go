package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/guidance"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// fakeGuidanceSeams builds a seam set over in-memory fakes: no DB, no
// filesystem. Every call is recorded so the pass's orchestration (which roots
// it touched, in what order, with what timestamp) is assertable.
type fakeGuidanceSeams struct {
	roots     []string
	rootsErr  error
	missing   map[string]bool
	scanned   []string
	scanErr   map[string]error
	persisted []string
	persErr   map[string]error
	files     map[string][]guidance.File
	at        time.Time
	// stampedAt records the timestamp each root was persisted under, so a
	// per-root stamp is assertable (the whole point of persisting as each
	// root completes rather than once at the end).
	stampedAt map[string]time.Time
	// hang, when set for a root, makes that root's scan block until its
	// ctx is done — the slow-DrvFs shape, without a slow filesystem.
	hang map[string]bool
	// incomplete, when set for a root, returns an incomplete Result
	// IMMEDIATELY (no blocking) — the adaptive-budget shape without any real
	// wall-clock waiting: the row is still reported Incomplete and not
	// persisted, exactly as a time-budget overrun would be.
	incomplete map[string]bool
	// scanOutcomes scripts a root's outcome pass-by-pass: each entry is
	// "incomplete" or "ok" (anything else / exhausted -> the default healthy
	// scan). It exists so a test can drive overrun -> persist -> overrun
	// across passes of a single blocking guidanceRunLoop call.
	scanOutcomes map[string][]string
	// budgets records, per root, the per-root time budget the pass granted it
	// on each scan — the raw remaining time read from the scan ctx's
	// deadline. This is how the adaptive-budget growth is asserted (via
	// guidanceBudgetInBand, which tolerates a few ms of overhead).
	budgets map[string][]time.Duration
	// skip is the injected root filter.
	skip map[string]string
	// clock advances one second per read so per-root stamps differ.
	clock time.Time
}

// guidanceFakeEpoch is the fixed clock the fakes start from.
var guidanceFakeEpoch = time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

func (f *fakeGuidanceSeams) seams() guidanceSeams {
	f.missing = orEmptyBoolMap(f.missing)
	f.scanErr = orEmptyErrMap(f.scanErr)
	f.persErr = orEmptyErrMap(f.persErr)
	f.hang = orEmptyBoolMap(f.hang)
	f.incomplete = orEmptyBoolMap(f.incomplete)
	if f.stampedAt == nil {
		f.stampedAt = map[string]time.Time{}
	}
	if f.scanOutcomes == nil {
		f.scanOutcomes = map[string][]string{}
	}
	if f.budgets == nil {
		f.budgets = map[string][]time.Duration{}
	}
	f.clock = guidanceFakeEpoch
	return guidanceSeams{
		Roots: func(context.Context) ([]string, error) { return f.roots, f.rootsErr },
		Exists: func(root string) bool {
			return !f.missing[root]
		},
		SkipRoot: func(root string) (string, bool) {
			reason, ok := f.skip[root]
			return reason, ok
		},
		Scan: func(ctx context.Context, root string) (guidance.Result, error) {
			f.scanned = append(f.scanned, root)
			// Record the budget this pass granted (the ctx deadline's remaining
			// time), so the adaptive growth is observable without any real
			// waiting. Stored RAW — the tests assert a tolerance band rather
			// than an exact value, so a few microseconds of scheduling
			// overhead between context.WithTimeout and this read never flakes.
			if d, ok := ctx.Deadline(); ok {
				f.budgets[root] = append(f.budgets[root], time.Until(d))
			}
			// A scripted outcome takes precedence, so a single loop can drive
			// overrun -> persist -> overrun across passes.
			if outs := f.scanOutcomes[root]; len(outs) > 0 {
				o := outs[0]
				f.scanOutcomes[root] = outs[1:]
				if o == "incomplete" {
					return guidance.Result{Incomplete: true}, nil
				}
			}
			if f.hang[root] {
				// The live shape: a root on a slow mount that keeps
				// walking until something stops it.
				<-ctx.Done()
				return guidance.Result{Incomplete: true}, ctx.Err()
			}
			if f.incomplete[root] {
				// Overruns every pass, but returns at once so the test does
				// no real waiting.
				return guidance.Result{Incomplete: true}, nil
			}
			if err := f.scanErr[root]; err != nil {
				return guidance.Result{}, err
			}
			return guidance.Result{Files: f.files[root]}, nil
		},
		Persist: func(_ context.Context, root string, files []guidance.File, at time.Time) (store.GuidanceScanSummary, error) {
			f.persisted = append(f.persisted, root)
			f.at = at
			f.stampedAt[root] = at
			if err := f.persErr[root]; err != nil {
				return store.GuidanceScanSummary{}, err
			}
			return store.GuidanceScanSummary{Added: len(files)}, nil
		},
		// Each read advances a second, so "every root got its own stamp"
		// is observable.
		Now: func() time.Time {
			t := f.clock
			f.clock = f.clock.Add(time.Second)
			return t
		},
		// No real waiting in tests; the pause is exercised as a call, not
		// as wall-clock time.
		Sleep: func(context.Context, time.Duration) {},
	}
}

func orEmptyBoolMap(m map[string]bool) map[string]bool {
	if m == nil {
		return map[string]bool{}
	}
	return m
}

func orEmptyErrMap(m map[string]error) map[string]error {
	if m == nil {
		return map[string]error{}
	}
	return m
}

// guidanceBudgetInBand reports whether a recorded per-root budget (the ctx
// deadline's REMAINING time at scan start) matches the expected grant. The
// remaining is always <= want and at most a few ms below it (the overhead
// between context.WithTimeout and the read); a 40ms band absorbs even a slow
// Windows scheduler while staying well clear of the next budget step (the
// grants differ by a factor of two, i.e. >= want itself apart).
func guidanceBudgetInBand(got, want time.Duration) bool {
	return got <= want && got > want-40*time.Millisecond
}

// TestGuidanceScanPass is the table-driven pin over the pass's orchestration:
// which roots it scans, which it skips, and how a per-root failure is
// contained.
func TestGuidanceScanPass(t *testing.T) {
	cases := []struct {
		name string
		fake fakeGuidanceSeams
		only []string
		// wantScanned is the exact root list the pass scanned, in order.
		wantScanned    []string
		wantRows       int
		wantSkipped    int
		wantRowWithErr string
		wantErr        bool
	}{
		{
			name:        "every known root",
			fake:        fakeGuidanceSeams{roots: []string{"/a", "/b"}},
			wantScanned: []string{"/a", "/b"},
			wantRows:    2,
		},
		{
			name:        "explicit root overrides the list",
			fake:        fakeGuidanceSeams{roots: []string{"/a", "/b"}},
			only:        []string{"/c"},
			wantScanned: []string{"/c"},
			wantRows:    1,
		},
		{
			name:        "duplicate spellings collapse",
			fake:        fakeGuidanceSeams{roots: []string{"/a", "/a/", "/a/./"}},
			wantScanned: []string{"/a"},
			wantRows:    1,
		},
		{
			name: "a root that is not here is skipped, not tombstoned",
			fake: fakeGuidanceSeams{
				roots:   []string{"/a", "/gone"},
				missing: map[string]bool{"/gone": true},
			},
			wantScanned: []string{"/a"},
			wantRows:    1,
			wantSkipped: 1,
		},
		{
			name: "one root's scan failure does not stop the others",
			fake: fakeGuidanceSeams{
				roots:   []string{"/a", "/bad", "/c"},
				scanErr: map[string]error{"/bad": errors.New("permission denied")},
			},
			wantScanned:    []string{"/a", "/bad", "/c"},
			wantRows:       3,
			wantRowWithErr: "/bad",
		},
		{
			name: "one root's persist failure does not stop the others",
			fake: fakeGuidanceSeams{
				roots:   []string{"/a", "/bad"},
				persErr: map[string]error{"/bad": errors.New("db locked")},
			},
			wantScanned:    []string{"/a", "/bad"},
			wantRows:       2,
			wantRowWithErr: "/bad",
		},
		{
			name:    "an unreadable root LIST is a whole-pass error",
			fake:    fakeGuidanceSeams{rootsErr: errors.New("no such table")},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			fake := tc.fake
			res, err := guidanceScanPass(context.Background(), fake.seams(), tc.only)
			if tc.wantErr {
				if err == nil {
					t.Fatal("want an error for an unreadable root list")
				}
				return
			}
			if err != nil {
				t.Fatalf("guidanceScanPass: %v", err)
			}
			if strings.Join(fake.scanned, ",") != strings.Join(tc.wantScanned, ",") {
				t.Errorf("scanned = %v, want %v", fake.scanned, tc.wantScanned)
			}
			if len(res.Roots) != tc.wantRows {
				t.Errorf("rows = %d, want %d", len(res.Roots), tc.wantRows)
			}
			if res.SkippedMissing != tc.wantSkipped {
				t.Errorf("skipped_missing = %d, want %d", res.SkippedMissing, tc.wantSkipped)
			}
			if tc.wantRowWithErr != "" {
				var found bool
				for _, r := range res.Roots {
					if r.Root == tc.wantRowWithErr && r.Err != "" {
						found = true
					}
				}
				if !found {
					t.Errorf("no failing row recorded for %q: %+v", tc.wantRowWithErr, res.Roots)
				}
			}
		})
	}
}

// TestGuidanceScanPassStampsEachRootSeparately pins the incremental-persist
// fix: each root is stamped and written the moment IT finishes, rather than
// every root sharing one end-of-pass timestamp.
//
// The live defect this replaced: a start-up pass over 404 roots ran for four
// CPU-minutes and persisted NOTHING, because the single write happened only
// after the last root — and the pass never got there.
func TestGuidanceScanPassStampsEachRootSeparately(t *testing.T) {
	fake := fakeGuidanceSeams{roots: []string{"/a", "/b"}}
	res, err := guidanceScanPass(context.Background(), fake.seams(), nil)
	if err != nil {
		t.Fatalf("guidanceScanPass: %v", err)
	}
	a, b := fake.stampedAt["/a"], fake.stampedAt["/b"]
	if a.IsZero() || b.IsZero() {
		t.Fatalf("both roots must be persisted: %v", fake.stampedAt)
	}
	if !b.After(a) {
		t.Errorf("/b stamped %v, /a stamped %v — each root must carry its OWN scan time", b, a)
	}
	for _, r := range res.Roots {
		if r.ScannedAt == "" {
			t.Errorf("row %s carries no scanned_at", r.Root)
		}
		if !r.Persisted() {
			t.Errorf("row %s should be Persisted(): %+v", r.Root, r)
		}
	}
	if res.ScannedAt != guidanceFakeEpoch.Format(time.RFC3339) {
		t.Errorf("pass scanned_at = %q, want the pass START %q",
			res.ScannedAt, guidanceFakeEpoch.Format(time.RFC3339))
	}
}

// TestGuidanceScanPassPersistsAroundAHangingRoot is the whole design in one
// test: root 2 blocks until its per-root budget expires, and roots 1 and 3
// still land — each under its own timestamp — while root 2 is reported
// incomplete and is NOT persisted.
//
// Not persisting it is the load-bearing half: store.UpsertGuidanceScan
// tombstones every row a scan did not re-see, so writing a half-walked tree
// would mark guidance files that are still on disk as gone.
func TestGuidanceScanPassPersistsAroundAHangingRoot(t *testing.T) {
	fake := fakeGuidanceSeams{
		roots: []string{"/one", "/slow", "/three"},
		hang:  map[string]bool{"/slow": true},
	}
	seams := fake.seams()
	seams.RootTimeout = 30 * time.Millisecond
	seams.PassTimeout = 10 * time.Second

	res, err := guidanceScanPass(context.Background(), seams, nil)
	if err != nil {
		t.Fatalf("a root that overruns its budget is not a pass error: %v", err)
	}
	if strings.Join(fake.persisted, ",") != "/one,/three" {
		t.Errorf("persisted = %v, want the two healthy roots only", fake.persisted)
	}
	if fake.stampedAt["/one"].Equal(fake.stampedAt["/three"]) {
		t.Errorf("both healthy roots share a timestamp %v — they must be stamped independently",
			fake.stampedAt["/one"])
	}
	if res.Incomplete != 1 {
		t.Errorf("incomplete = %d, want 1", res.Incomplete)
	}
	rows := map[string]guidanceRootResult{}
	for _, r := range res.Roots {
		rows[r.Root] = r
	}
	slow := rows["/slow"]
	if !slow.Incomplete {
		t.Errorf("/slow row = %+v, want Incomplete", slow)
	}
	if slow.Persisted() || slow.ScannedAt != "" {
		t.Errorf("/slow must not be persisted: %+v", slow)
	}
	if slow.Err == "" {
		t.Error("/slow must carry a reason, not a silent skip")
	}
	for _, root := range []string{"/one", "/three"} {
		if !rows[root].Persisted() {
			t.Errorf("%s should be persisted: %+v", root, rows[root])
		}
	}
}

// TestGuidanceScanPassBudgetsAndRotation pins the pass budget and the start
// offset: a pass that runs out of time reports what it did not reach instead
// of failing, and the offset moves the window so the tail is not starved.
func TestGuidanceScanPassBudgetsAndRotation(t *testing.T) {
	t.Run("pass budget stops the pass cleanly", func(t *testing.T) {
		fake := fakeGuidanceSeams{
			roots: []string{"/one", "/slow", "/three", "/four"},
			hang:  map[string]bool{"/slow": true},
		}
		seams := fake.seams()
		seams.RootTimeout = time.Minute
		seams.PassTimeout = 30 * time.Millisecond
		res, err := guidanceScanPass(context.Background(), seams, nil)
		if err != nil {
			t.Fatalf("an exhausted pass budget is not an error: %v", err)
		}
		if res.NotReached == 0 {
			t.Error("the roots after the budget expired must be reported as not reached")
		}
		if !contains(fake.persisted, "/one") {
			t.Errorf("the root scanned BEFORE the budget expired must still be persisted: %v", fake.persisted)
		}
	})

	t.Run("start offset rotates the window", func(t *testing.T) {
		fake := fakeGuidanceSeams{roots: []string{"/a", "/b", "/c"}}
		seams := fake.seams()
		seams.StartOffset = 2
		res, err := guidanceScanPass(context.Background(), seams, nil)
		if err != nil {
			t.Fatalf("guidanceScanPass: %v", err)
		}
		if strings.Join(fake.scanned, ",") != "/c,/a,/b" {
			t.Errorf("scanned = %v, want the list rotated to start at offset 2", fake.scanned)
		}
		if res.Total != 3 || res.Consumed != 3 {
			t.Errorf("total/consumed = %d/%d, want 3/3", res.Total, res.Consumed)
		}
	})

	t.Run("an explicitly named root is never rotated or filtered", func(t *testing.T) {
		fake := fakeGuidanceSeams{
			roots: []string{"/a"},
			skip:  map[string]string{"/tmp/repro": "temp_dir"},
		}
		seams := fake.seams()
		seams.StartOffset = 5
		if _, err := guidanceScanPass(context.Background(), seams, []string{"/tmp/repro"}); err != nil {
			t.Fatalf("guidanceScanPass: %v", err)
		}
		if strings.Join(fake.scanned, ",") != "/tmp/repro" {
			t.Errorf("scanned = %v — `--project` must be honoured verbatim", fake.scanned)
		}
	})
}

// TestGuidanceScanPassFiltersNoisyRoots pins that the injected root filter
// runs BEFORE any scan, and that what it excluded is reported by reason
// rather than silently dropped.
func TestGuidanceScanPassFiltersNoisyRoots(t *testing.T) {
	fake := fakeGuidanceSeams{
		roots: []string{"/real", "/tmp/x", "/home/dev/.observer/arena/1"},
		skip: map[string]string{
			"/tmp/x":                      "temp_dir",
			"/home/dev/.observer/arena/1": "observer_dir",
		},
	}
	res, err := guidanceScanPass(context.Background(), fake.seams(), nil)
	if err != nil {
		t.Fatalf("guidanceScanPass: %v", err)
	}
	if strings.Join(fake.scanned, ",") != "/real" {
		t.Errorf("scanned = %v, want only the real project — a filtered root must cost no filesystem work", fake.scanned)
	}
	if res.SkippedFiltered != 2 {
		t.Errorf("skipped_filtered = %d, want 2", res.SkippedFiltered)
	}
	if res.SkipReasons["temp_dir"] != 1 || res.SkipReasons["observer_dir"] != 1 {
		t.Errorf("skip reasons = %v, want one of each", res.SkipReasons)
	}
	// The sentinel home root must ride through the filter untouched.
	fake2 := fakeGuidanceSeams{roots: []string{"/real"}, skip: map[string]string{"~": "temp_dir"}}
	seams := fake2.seams()
	seams.UserScopeRoot = "~"
	if _, err := guidanceScanPass(context.Background(), seams, nil); err != nil {
		t.Fatalf("guidanceScanPass: %v", err)
	}
	if !contains(fake2.scanned, "~") {
		t.Errorf("the user-scope sentinel must never be filtered out: %v", fake2.scanned)
	}
}

// TestGuidanceScanPassStreamsEachRoot pins the OnRoot seam `guidance scan
// --all` streams through: a pass that runs for minutes must emit a line as
// each root completes, not one table at the end.
func TestGuidanceScanPassStreamsEachRoot(t *testing.T) {
	fake := fakeGuidanceSeams{roots: []string{"/a", "/b"}}
	seams := fake.seams()
	var streamed []string
	seams.OnRoot = func(r guidanceRootResult) {
		// Streaming means the row arrives BEFORE the pass returns, i.e.
		// as soon as its root has been persisted.
		if !contains(fake.persisted, r.Root) {
			t.Errorf("row for %s streamed before it was persisted", r.Root)
		}
		streamed = append(streamed, r.Root)
	}
	if _, err := guidanceScanPass(context.Background(), seams, nil); err != nil {
		t.Fatalf("guidanceScanPass: %v", err)
	}
	if strings.Join(streamed, ",") != "/a,/b" {
		t.Errorf("streamed = %v, want one callback per root in order", streamed)
	}
}

// TestGuidanceScanPassCancellation pins that a cancelled context stops the
// pass rather than grinding through every remaining root.
func TestGuidanceScanPassCancellation(t *testing.T) {
	fake := fakeGuidanceSeams{roots: []string{"/a", "/b", "/c"}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := guidanceScanPass(ctx, fake.seams(), nil); err == nil {
		t.Fatal("want a context error")
	}
	if len(fake.scanned) != 0 {
		t.Errorf("scanned %v after cancellation", fake.scanned)
	}
}

// TestGuidanceOptionsFromConfig covers the config→scanner projection,
// including the "zero means the package default" rule.
func TestGuidanceOptionsFromConfig(t *testing.T) {
	def := guidance.DefaultOptions()
	cases := []struct {
		name      string
		cfg       config.GuidanceConfig
		wantBytes int64
		wantDepth int
		wantUser  bool
	}{
		{
			name:      "zero values fall back to the package defaults",
			cfg:       config.GuidanceConfig{},
			wantBytes: def.MaxFileBytes,
			wantDepth: def.MaxDepth,
			wantUser:  false,
		},
		{
			name:      "seeded config",
			cfg:       config.Default().Guidance,
			wantBytes: 512 * 1024,
			wantDepth: 4,
			wantUser:  true,
		},
		{
			name:      "operator overrides",
			cfg:       config.GuidanceConfig{MaxFileBytes: 1024, MaxDepth: 9, IncludeUserScope: false},
			wantBytes: 1024,
			wantDepth: 9,
			wantUser:  false,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := guidanceOptions(tc.cfg)
			if got.MaxFileBytes != tc.wantBytes {
				t.Errorf("MaxFileBytes = %d, want %d", got.MaxFileBytes, tc.wantBytes)
			}
			if got.MaxDepth != tc.wantDepth {
				t.Errorf("MaxDepth = %d, want %d", got.MaxDepth, tc.wantDepth)
			}
			if got.IncludeUserScope != tc.wantUser {
				t.Errorf("IncludeUserScope = %v, want %v", got.IncludeUserScope, tc.wantUser)
			}
		})
	}
}

// TestGuidanceCmdRegistered pins the command into the root set and that its
// constructor returns a FRESH command (observerSubcommands is called twice).
func TestGuidanceCmdRegistered(t *testing.T) {
	var found bool
	for _, c := range observerSubcommandsWith(defaultUsageDeps()) {
		if c.Name() == "guidance" {
			found = true
		}
	}
	if !found {
		t.Error("`observer guidance` is not registered in observerSubcommandsWith")
	}
	if a, b := newGuidanceCmd(), newGuidanceCmd(); a == b {
		t.Error("newGuidanceCmd returned the same instance twice")
	}
	sub := map[string]bool{}
	for _, c := range newGuidanceCmd().Commands() {
		sub[c.Name()] = true
	}
	for _, want := range []string{"scan", "list"} {
		if !sub[want] {
			t.Errorf("`observer guidance %s` is missing", want)
		}
	}
}

// TestGuidanceScanPassAlwaysIncludesUserScopeRoot pins the once-per-pass home
// inventory: it rides along with a whole-fleet pass AND with a single
// --project pass, and it is scanned exactly once either way.
func TestGuidanceScanPassAlwaysIncludesUserScopeRoot(t *testing.T) {
	cases := []struct {
		name        string
		roots       []string
		only        []string
		userRoot    string
		wantScanned []string
	}{
		{
			name:        "whole pass",
			roots:       []string{"/a", "/b"},
			userRoot:    "~",
			wantScanned: []string{"/a", "/b", "~"},
		},
		{
			name:        "single project still refreshes home scope",
			roots:       []string{"/a", "/b"},
			only:        []string{"/c"},
			userRoot:    "~",
			wantScanned: []string{"/c", "~"},
		},
		{
			name:        "user scope disabled",
			roots:       []string{"/a"},
			wantScanned: []string{"/a"},
		},
		{
			name:        "already listed, never scanned twice",
			roots:       []string{"/a", "~"},
			userRoot:    "~",
			wantScanned: []string{"/a", "~"},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			fake := fakeGuidanceSeams{roots: tc.roots}
			seams := fake.seams()
			seams.UserScopeRoot = tc.userRoot
			if _, err := guidanceScanPass(context.Background(), seams, tc.only); err != nil {
				t.Fatalf("guidanceScanPass: %v", err)
			}
			if strings.Join(fake.scanned, ",") != strings.Join(tc.wantScanned, ",") {
				t.Errorf("scanned = %v, want %v", fake.scanned, tc.wantScanned)
			}
		})
	}
}

// TestScrubGuidanceMetadata pins the boundary redaction (P1-2): everything a
// scan derived from a file's BODY is scrubbed before it can be persisted and
// served on the inventory route.
func TestScrubGuidanceMetadata(t *testing.T) {
	files := []guidance.File{
		{
			Tool:        "claude-code",
			RelPath:     "CLAUDE.md",
			Name:        "CLAUDE",
			Description: "Use ANTHROPIC_API_KEY=sk-ant-api03-AbCd1234EfGh5678IjKl9MnOp when testing.",
			Frontmatter: map[string]string{
				"model":       "opus",
				"description": "export SECRET_TOKEN=sk-ant-api03-AbCd1234EfGh5678IjKl9MnOp",
			},
		},
	}
	scrubGuidanceMetadata(scrub.New(), files)

	got := files[0]
	if strings.Contains(got.Description, "sk-ant-api03-AbCd1234EfGh5678IjKl9MnOp") {
		t.Errorf("description still carries the key: %q", got.Description)
	}
	if !strings.Contains(got.Description, scrub.Redacted) {
		t.Errorf("description was not redacted: %q", got.Description)
	}
	if strings.Contains(got.Frontmatter["description"], "sk-ant-api03-AbCd1234EfGh5678IjKl9MnOp") {
		t.Errorf("front-matter value still carries the key: %q", got.Frontmatter["description"])
	}
	if got.Frontmatter["model"] != "opus" {
		t.Errorf("an innocent front-matter value was mangled: %q", got.Frontmatter["model"])
	}
	if got.Name != "CLAUDE" {
		t.Errorf("Name is an identifier and must be left alone, got %q", got.Name)
	}
	// A nil scrubber must not panic — the seam is optional.
	scrubGuidanceMetadata(nil, files)
}

// TestGuidanceProductionScanScrubsAndPersists is the end-to-end pin over the
// production seams: a real temp project, a real store, and a CLAUDE.md whose
// first line is an API key. What lands in the DB must be redacted.
func TestGuidanceProductionScanScrubsAndPersists(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	const key = "sk-ant-api03-AbCd1234EfGh5678IjKl9MnOp"
	if err := os.WriteFile(filepath.Join(root, "CLAUDE.md"),
		[]byte("ANTHROPIC_API_KEY="+key+"\n\nRun make lint.\n"), 0o644); err != nil {
		t.Fatalf("write CLAUDE.md: %v", err)
	}

	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "observer.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()
	st := store.New(database)

	seams := guidanceSeamsFor(st, config.GuidanceConfig{MaxFileBytes: 1 << 20, MaxDepth: 2}, nil)
	if _, err := guidanceScanPass(ctx, seams, []string{root}); err != nil {
		t.Fatalf("guidanceScanPass: %v", err)
	}

	rows, err := st.ListGuidance(ctx, root, false)
	if err != nil {
		t.Fatalf("ListGuidance: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("nothing was persisted")
	}
	var saw bool
	for _, r := range rows {
		if strings.Contains(r.Description, key) {
			t.Errorf("%s persisted an unredacted key: %q", r.RelPath, r.Description)
		}
		for k, v := range r.Frontmatter {
			if strings.Contains(v, key) {
				t.Errorf("%s frontmatter[%s] persisted an unredacted key: %q", r.RelPath, k, v)
			}
		}
		if r.RelPath == "CLAUDE.md" {
			saw = true
			if !strings.Contains(r.Description, scrub.Redacted) {
				t.Errorf("CLAUDE.md description was not redacted: %q", r.Description)
			}
		}
	}
	if !saw {
		t.Errorf("CLAUDE.md was not inventoried: %+v", rows)
	}

	// A second pass over the unchanged tree must report it as unchanged —
	// the Known cache reused the row rather than re-hashing it.
	res, err := guidanceScanPass(ctx, seams, []string{root})
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	for _, r := range res.Roots {
		if r.Root != root {
			continue
		}
		if r.Unchanged == 0 || r.Updated != 0 || r.Added != 0 {
			t.Errorf("second pass over an unchanged tree = %+v, want everything unchanged", r)
		}
	}
}

// -----------------------------------------------------------------------------
// The daemon loop: start-up delay, rotation across passes, one log line.
// -----------------------------------------------------------------------------

// TestGuidanceRunLoopDelaysFirstPassAndLogsOnce pins the two start-up
// behaviours an operator actually observes. Before this, a daemon restart ran
// a whole-estate walk immediately (while the proxy, watcher and dashboard were
// still coming up) and wrote NO guidance line at all, so a pass that burned
// minutes was invisible in the log.
func TestGuidanceRunLoopDelaysFirstPassAndLogsOnce(t *testing.T) {
	fake := fakeGuidanceSeams{roots: []string{"/a", "/b"}}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// A fake timer: it records what it was asked to wait for and fires at
	// once, so the 90-second delay is asserted rather than waited out.
	var waits []time.Duration
	ctx, cancel := context.WithCancel(context.Background())
	after := func(d time.Duration) <-chan time.Time {
		waits = append(waits, d)
		// One pass only: cancel before the rescan tick can fire again.
		if len(waits) > 1 {
			cancel()
			return make(chan time.Time)
		}
		ch := make(chan time.Time, 1)
		ch <- time.Now()
		return ch
	}

	guidanceRunLoop(ctx, guidanceLoopDeps{
		Seams:        fake.seams(),
		StartupDelay: 90 * time.Second,
		Rescan:       15 * time.Minute,
		Logger:       logger,
		After:        after,
	})
	cancel()

	if len(waits) == 0 || waits[0] != 90*time.Second {
		t.Fatalf("waits = %v, want the start-up delay first", waits)
	}
	if len(fake.scanned) == 0 {
		t.Fatal("the first pass never ran")
	}
	lines := 0
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if strings.Contains(l, "guidance scan pass") {
			lines++
			for _, key := range []string{"roots=", "skipped_filtered=", "incomplete=", "not_reached=", "duration_ms="} {
				if !strings.Contains(l, key) {
					t.Errorf("the pass log line is missing %q: %s", key, l)
				}
			}
		}
	}
	if lines != 1 {
		t.Errorf("got %d guidance pass log lines, want exactly 1:\n%s", lines, buf.String())
	}
}

// TestGuidanceRunLoopRunsImmediatelyWithoutDelay pins that startup_delay = 0
// means "scan now" — the delay is a courtesy, not a floor.
func TestGuidanceRunLoopRunsImmediatelyWithoutDelay(t *testing.T) {
	fake := fakeGuidanceSeams{roots: []string{"/a"}}
	var waits []time.Duration
	guidanceRunLoop(context.Background(), guidanceLoopDeps{
		Seams:  fake.seams(),
		Rescan: 0, // one pass, then return
		After: func(d time.Duration) <-chan time.Time {
			waits = append(waits, d)
			ch := make(chan time.Time, 1)
			ch <- time.Now()
			return ch
		},
	})
	if len(waits) != 0 {
		t.Errorf("waits = %v, want none", waits)
	}
	if strings.Join(fake.scanned, ",") != "/a" {
		t.Errorf("scanned = %v, want the pass to have run", fake.scanned)
	}
}

// TestGuidanceRunLoopAdvancesRotation pins that consecutive passes start at
// different offsets, so a capped root list does not re-walk the same head
// forever while the tail is never inventoried at all.
func TestGuidanceRunLoopAdvancesRotation(t *testing.T) {
	fake := fakeGuidanceSeams{roots: []string{"/a", "/b", "/c"}}
	seams := fake.seams()
	// Only the first two roots fit in a pass; the third is left for next
	// time, which is precisely what rotation has to pick up.
	seams.PassTimeout = time.Hour

	var offsets []int
	consume := func(off int) {
		s := seams
		s.StartOffset = off
		if _, err := guidanceScanPass(context.Background(), s, nil); err != nil {
			t.Fatalf("pass: %v", err)
		}
		offsets = append(offsets, off)
	}
	consume(0)
	first := strings.Join(fake.scanned, ",")
	fake.scanned = nil
	consume(2)
	second := strings.Join(fake.scanned, ",")
	if first == second {
		t.Errorf("both passes scanned %q — the offset did not rotate the window", first)
	}
	if second != "/c,/a,/b" {
		t.Errorf("rotated pass scanned %q, want /c,/a,/b", second)
	}
}

// TestGuidanceBudgetsResolveDefaults pins the "<= 0 means the seeded default"
// rule: a half-written [guidance] section must be BOUNDED, never unbounded —
// an unbounded root is the failure these budgets exist to prevent.
func TestGuidanceBudgetsResolveDefaults(t *testing.T) {
	cases := []struct {
		name       string
		cfg        config.GuidanceConfig
		wantRoots  int
		wantRoot   time.Duration
		wantPass   time.Duration
		wantRootMx time.Duration
	}{
		{
			name:       "zero value falls back to the seeded budgets",
			cfg:        config.GuidanceConfig{},
			wantRoots:  guidanceDefaultMaxRootsPerPass,
			wantRoot:   guidanceDefaultRootTimeout,
			wantPass:   guidanceDefaultPassTimeout,
			wantRootMx: guidanceDefaultRootTimeoutMax,
		},
		{
			name:       "the shipped seed",
			cfg:        config.Default().Guidance,
			wantRoots:  50,
			wantRoot:   20 * time.Second,
			wantPass:   10 * time.Minute,
			wantRootMx: 180 * time.Second,
		},
		{
			name: "operator overrides",
			cfg: config.GuidanceConfig{
				MaxRootsPerPass: 5, RootTimeoutSeconds: 3, PassTimeoutMinutes: 2, RootTimeoutMaxSeconds: 60,
			},
			wantRoots:  5,
			wantRoot:   3 * time.Second,
			wantPass:   2 * time.Minute,
			wantRootMx: 60 * time.Second,
		},
		{
			name: "negatives are clamped, not honoured as unbounded",
			cfg: config.GuidanceConfig{
				MaxRootsPerPass: -1, RootTimeoutSeconds: -1, PassTimeoutMinutes: -1, RootTimeoutMaxSeconds: -1,
			},
			wantRoots:  guidanceDefaultMaxRootsPerPass,
			wantRoot:   guidanceDefaultRootTimeout,
			wantPass:   guidanceDefaultPassTimeout,
			wantRootMx: guidanceDefaultRootTimeoutMax,
		},
		{
			name: "a ceiling below the base is clamped up to the base",
			cfg: config.GuidanceConfig{
				RootTimeoutSeconds: 30, RootTimeoutMaxSeconds: 5,
			},
			wantRoots:  guidanceDefaultMaxRootsPerPass,
			wantRoot:   30 * time.Second,
			wantPass:   guidanceDefaultPassTimeout,
			wantRootMx: 30 * time.Second, // never below where growth starts
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			roots, rootTO, passTO, rootMx := guidanceBudgets(tc.cfg)
			if roots != tc.wantRoots || rootTO != tc.wantRoot || passTO != tc.wantPass || rootMx != tc.wantRootMx {
				t.Errorf("guidanceBudgets = (%d, %v, %v, %v), want (%d, %v, %v, %v)",
					roots, rootTO, passTO, rootMx, tc.wantRoots, tc.wantRoot, tc.wantPass, tc.wantRootMx)
			}
		})
	}

	// Start-up delay is the one where 0 is meaningful ("scan now").
	if d := guidanceStartupDelay(config.Default().Guidance); d != 90*time.Second {
		t.Errorf("seeded startup delay = %v, want 90s", d)
	}
	if d := guidanceStartupDelay(config.GuidanceConfig{StartupDelaySeconds: 0}); d != 0 {
		t.Errorf("startup_delay_seconds = 0 must mean scan now, got %v", d)
	}
	if d := guidanceStartupDelay(config.GuidanceConfig{StartupDelaySeconds: -5}); d != 0 {
		t.Errorf("a negative startup delay must clamp to 0, got %v", d)
	}
}

// TestGuidanceRootFilterIsWired pins that the production seams actually carry
// the filter table — a filter nothing consults is the defect, not the fix.
func TestGuidanceRootFilterIsWired(t *testing.T) {
	f := guidanceRootFilter()
	if f.TempDir == "" {
		t.Error("the production filter must know the OS temp dir")
	}
	if len(f.SentinelRoots) == 0 || f.SentinelRoots[0] != store.GuidanceUserScopeRoot {
		t.Errorf("the user-scope sentinel must be exempt: %v", f.SentinelRoots)
	}
	seams := guidanceSeamsFor(nil, config.Default().Guidance, nil)
	if seams.SkipRoot == nil {
		t.Fatal("guidanceSeamsFor did not wire SkipRoot")
	}
	if _, skip := seams.SkipRoot(filepath.Join(os.TempDir(), "x", "proj")); !skip {
		t.Error("a root under the OS temp dir must be filtered")
	}
	if _, skip := seams.SkipRoot("/mnt/c/Users/dev/proj"); skip {
		t.Error("a /mnt project must stay eligible — it is slow, not illegitimate")
	}
	if seams.RootTimeout != 20*time.Second || seams.PassTimeout != 10*time.Minute {
		t.Errorf("budgets not wired: root=%v pass=%v", seams.RootTimeout, seams.PassTimeout)
	}
	if seams.PauseBetween != guidancePauseBetweenRoots {
		t.Errorf("PauseBetween = %v, want %v", seams.PauseBetween, guidancePauseBetweenRoots)
	}
}

// TestGuidanceFirstScanTargets is the pure first-scan decision table. The
// rows that matter are the three "considered but not scanned" shapes: an
// already-attempted root (the guidance-free project that would otherwise be
// re-walked every minute forever), a filtered root, and a root that is not a
// directory on this machine. All three must still be marked attempted by the
// caller, which is why they come back in `considered`.
func TestGuidanceFirstScanTargets(t *testing.T) {
	skip := func(root string) (string, bool) {
		if strings.Contains(root, "scratchpad") {
			return "scratchpad", true
		}
		return "", false
	}
	exists := func(root string) bool { return root != "/gone" }

	cases := []struct {
		name           string
		candidates     []string
		attempted      []string
		limit          int
		wantTargets    []string
		wantConsidered []string
	}{
		{
			name:           "plain candidates are scanned",
			candidates:     []string{"/a", "/b"},
			limit:          5,
			wantTargets:    []string{"/a", "/b"},
			wantConsidered: []string{"/a", "/b"},
		},
		{
			name:           "already attempted is neither scanned nor reconsidered",
			candidates:     []string{"/a", "/b"},
			attempted:      []string{"/a"},
			limit:          5,
			wantTargets:    []string{"/b"},
			wantConsidered: []string{"/b"},
		},
		{
			name:           "filtered root is considered but not scanned",
			candidates:     []string{"/tmp/x/scratchpad/y", "/b"},
			limit:          5,
			wantTargets:    []string{"/b"},
			wantConsidered: []string{"/tmp/x/scratchpad/y", "/b"},
		},
		{
			name:           "absent root is considered but not scanned",
			candidates:     []string{"/gone", "/b"},
			limit:          5,
			wantTargets:    []string{"/b"},
			wantConsidered: []string{"/gone", "/b"},
		},
		{
			name:           "one capped batch, never loop-until-done",
			candidates:     []string{"/a", "/b", "/c", "/d"},
			limit:          2,
			wantTargets:    []string{"/a", "/b"},
			wantConsidered: []string{"/a", "/b"},
		},
		{
			name:           "empty spellings are dropped",
			candidates:     []string{"", "/a"},
			limit:          5,
			wantTargets:    []string{"/a"},
			wantConsidered: []string{"/a"},
		},
		{
			name:       "nothing to do",
			candidates: nil,
			limit:      5,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attempted := map[string]bool{}
			for _, r := range tc.attempted {
				attempted[r] = true
			}
			targets, considered := guidanceFirstScanTargets(tc.candidates, attempted, skip, exists, tc.limit)
			if strings.Join(targets, ",") != strings.Join(tc.wantTargets, ",") {
				t.Errorf("targets = %v, want %v", targets, tc.wantTargets)
			}
			if strings.Join(considered, ",") != strings.Join(tc.wantConsidered, ",") {
				t.Errorf("considered = %v, want %v", considered, tc.wantConsidered)
			}
		})
	}
}

// TestGuidanceRunLoopFirstScanPoll pins the wave-2 trigger end to end: the
// loop polls for NEVER-scanned roots, inventories just those (never the home
// sentinel, never the periodic root list), logs one line per triggered root,
// and does NOT re-scan the same root on the next poll.
func TestGuidanceRunLoopFirstScanPoll(t *testing.T) {
	// The periodic pass has no roots at all, so everything scanned below
	// came from the poll.
	fake := fakeGuidanceSeams{roots: nil}
	seams := fake.seams()
	seams.UserScopeRoot = "~"
	polls := 0
	// The exclusion is applied by the STORE in production; the fake records
	// what it was handed so the loop's half of that contract is pinned too.
	var excludes [][]string
	seams.NeverScannedRoots = func(_ context.Context, exclude []string) ([]string, error) {
		polls++
		excludes = append(excludes, exclude)
		for _, e := range exclude {
			if e == "/new" {
				// Production's query would have filtered it; the fake must
				// behave the same or the test proves nothing.
				return nil, nil
			}
		}
		return []string{"/new"}, nil
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	var waits []time.Duration
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	after := func(d time.Duration) <-chan time.Time {
		waits = append(waits, d)
		// Two polls, then stop: the second one proves the attempted set
		// suppresses a re-scan rather than the loop simply not ticking.
		if len(waits) > 2 {
			cancel()
			return make(chan time.Time)
		}
		ch := make(chan time.Time, 1)
		ch <- time.Now()
		return ch
	}

	guidanceRunLoop(ctx, guidanceLoopDeps{
		Seams:         seams,
		Rescan:        0, // the periodic tick is off; only the poll runs
		FirstScanPoll: 10 * time.Second,
		Logger:        logger,
		After:         after,
	})

	if polls < 2 {
		t.Fatalf("polls = %d, want at least 2 (waits %v)", polls, waits)
	}
	// The first poll has nothing to exclude; the second must push the root
	// it already attempted DOWN into the query rather than filtering the
	// page in Go afterwards (which starves everything behind a full page).
	if len(excludes) < 2 {
		t.Fatalf("excludes = %v, want one per poll", excludes)
	}
	if len(excludes[0]) != 0 {
		t.Errorf("first poll excluded %v, want nothing", excludes[0])
	}
	if strings.Join(excludes[1], ",") != "/new" {
		t.Errorf("second poll excluded %v, want [/new] pushed into the query", excludes[1])
	}
	// The single "~" is the STARTUP periodic pass (which always carries the
	// home sentinel); the poll then adds /new exactly once. A second "~"
	// would mean the poll widened its own root set, and a second "/new"
	// would mean the attempted set failed to suppress a re-scan.
	if strings.Join(fake.scanned, ",") != "~,/new" {
		t.Errorf("scanned = %v, want ~,/new (the poll must neither re-walk the home sentinel "+
			"nor re-scan an attempted root)", fake.scanned)
	}
	if strings.Join(fake.persisted, ",") != "~,/new" {
		t.Errorf("persisted = %v, want ~,/new", fake.persisted)
	}
	lines := 0
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if strings.Contains(l, "guidance first scan") {
			lines++
			if !strings.Contains(l, "/new") {
				t.Errorf("first-scan log line does not name the root: %s", l)
			}
		}
	}
	if lines != 1 {
		t.Errorf("got %d first-scan log lines, want exactly 1:\n%s", lines, buf.String())
	}
}

// TestGuidanceAdaptiveRootTimeout is the pure escalation curve: a healthy root
// gets the base, each consecutive overrun doubles it, and growth saturates at
// the ceiling — monotonic and overflow-safe.
func TestGuidanceAdaptiveRootTimeout(t *testing.T) {
	const base = 20 * time.Second
	const ceiling = 180 * time.Second
	cases := []struct {
		streak int
		want   time.Duration
	}{
		{0, base},              // healthy root
		{1, 40 * time.Second},  // base << 1
		{2, 80 * time.Second},  // base << 2
		{3, 160 * time.Second}, // base << 3
		{4, ceiling},           // base << 4 == 320 -> capped
		{5, ceiling},           // stays capped
		{100, ceiling},         // no overflow at a large streak
	}
	for _, c := range cases {
		if got := guidanceAdaptiveRootTimeout(base, ceiling, c.streak); got != c.want {
			t.Errorf("guidanceAdaptiveRootTimeout(base, ceiling, %d) = %v, want %v", c.streak, got, c.want)
		}
	}

	// Growth is strictly monotonic non-decreasing up to the ceiling.
	prev := guidanceAdaptiveRootTimeout(base, ceiling, 0)
	for n := 1; n <= 10; n++ {
		cur := guidanceAdaptiveRootTimeout(base, ceiling, n)
		if cur < prev {
			t.Errorf("budget went DOWN at streak %d: %v < %v", n, cur, prev)
		}
		if cur > ceiling {
			t.Errorf("budget exceeded the ceiling at streak %d: %v", n, cur)
		}
		prev = cur
	}

	// An unbounded base (0 => no per-root timeout) stays unbounded — a root
	// that never overruns by time must not be handed a suddenly-bounded ctx.
	if got := guidanceAdaptiveRootTimeout(0, ceiling, 3); got != 0 {
		t.Errorf("an unbounded base must stay unbounded, got %v", got)
	}
	// base == ceiling disables adaptation: the root never gets more than base.
	if got := guidanceAdaptiveRootTimeout(base, base, 5); got != base {
		t.Errorf("base==ceiling must return base, got %v", got)
	}
}

// TestGuidanceUpdateOverrunState pins the loud, deduped warning cadence and the
// streak bookkeeping directly, feeding the helper synthetic pass results.
func TestGuidanceUpdateOverrunState(t *testing.T) {
	const base = 100 * time.Millisecond
	const ceiling = 400 * time.Millisecond // steps: 100, 200, 400 (then capped)

	overrun := map[string]int{}
	terminalWarned := map[string]int{}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	incompletePass := guidancePassResult{Roots: []guidanceRootResult{{Root: "/slow", Incomplete: true}}}

	countLines := func(needle string) int {
		n := 0
		for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			if l != "" && strings.Contains(l, needle) {
				n++
			}
		}
		return n
	}

	const escalate = "granting it a larger scan budget"
	const terminal = "cannot be inventoried within the max budget"

	// Four consecutive overruns.
	//   n=1: ran under 100, next 200  -> escalate
	//   n=2: ran under 200, next 400  -> escalate
	//   n=3: ran under 400 (==ceiling), next 400 -> terminal (fires once)
	//   n=4: ran under 400, next 400  -> terminal already warned -> silent
	for i := 0; i < 4; i++ {
		guidanceUpdateOverrunState(incompletePass, overrun, terminalWarned, base, ceiling, logger)
	}
	if overrun["/slow"] != 4 {
		t.Errorf("streak = %d, want 4", overrun["/slow"])
	}
	if got := countLines(escalate); got != 2 {
		t.Errorf("escalation warnings = %d, want 2 (one per growth step):\n%s", got, buf.String())
	}
	if got := countLines(terminal); got != 1 {
		t.Errorf("terminal warnings = %d, want exactly 1 (deduped across passes):\n%s", got, buf.String())
	}

	// A clean persist resets the streak and the terminal flag.
	persistPass := guidancePassResult{Roots: []guidanceRootResult{{Root: "/slow", ScannedAt: "2026-09-15T12:00:00Z"}}}
	guidanceUpdateOverrunState(persistPass, overrun, terminalWarned, base, ceiling, logger)
	if _, ok := overrun["/slow"]; ok {
		t.Errorf("a persisted root must clear its overrun streak: %v", overrun)
	}
	if _, ok := terminalWarned["/slow"]; ok {
		t.Errorf("a persisted root must clear its terminal-warned flag: %v", terminalWarned)
	}

	// After the reset a fresh overrun escalates AGAIN from the base — proof
	// the budget returned to base rather than jumping back to the ceiling.
	guidanceUpdateOverrunState(incompletePass, overrun, terminalWarned, base, ceiling, logger)
	if overrun["/slow"] != 1 {
		t.Errorf("streak after reset+overrun = %d, want 1", overrun["/slow"])
	}
	if got := countLines(escalate); got != 3 {
		t.Errorf("escalation warnings after reset = %d, want 3 (a new step fired):\n%s", got, buf.String())
	}
}

// TestGuidanceRunLoopAdaptiveBudget is the whole feature end to end through the
// daemon loop: a root that overruns every pass is granted a strictly growing
// per-root budget across passes, capped at the ceiling, and an incomplete walk
// is NEVER persisted regardless of how big its budget grows.
func TestGuidanceRunLoopAdaptiveBudget(t *testing.T) {
	// The pass cleans root spellings (filepath.Clean), and the fake consults
	// its maps with that cleaned spelling — so key everything by the cleaned
	// form to stay host-independent ("\slow" on Windows, "/slow" on unix).
	slow := filepath.Clean("/slow")
	fake := fakeGuidanceSeams{
		roots:      []string{slow},
		incomplete: map[string]bool{slow: true}, // overruns every pass, returns at once
	}
	seams := fake.seams()
	seams.RootTimeout = 100 * time.Millisecond // base
	seams.PassTimeout = time.Hour

	// Five passes total (startup + 4 rescans): the After seam delivers on the
	// first four rescan-arming calls, then cancels.
	calls := 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	after := func(time.Duration) <-chan time.Time {
		calls++
		if calls > 4 {
			cancel()
			return make(chan time.Time)
		}
		ch := make(chan time.Time, 1)
		ch <- time.Now()
		return ch
	}

	guidanceRunLoop(ctx, guidanceLoopDeps{
		Seams:          seams,
		Rescan:         time.Minute,
		RootTimeoutMax: 800 * time.Millisecond, // ceiling == base << 3
		After:          after,
	})

	got := fake.budgets[slow]
	want := []time.Duration{
		100 * time.Millisecond, // startup, streak 0
		200 * time.Millisecond, // streak 1
		400 * time.Millisecond, // streak 2
		800 * time.Millisecond, // streak 3 -> ceiling
		800 * time.Millisecond, // streak 4 -> stays capped
	}
	if len(got) != len(want) {
		t.Fatalf("granted budgets = %v, want %d passes %v", got, len(want), want)
	}
	for i := range want {
		if !guidanceBudgetInBand(got[i], want[i]) {
			t.Errorf("pass %d budget = %v, want ~%v (full: %v)", i, got[i], want[i], got)
		}
	}
	// The bands (100/200/400/800) do not overlap, so matching them already
	// proves the strictly-growing-then-capped curve.
	//
	// The load-bearing invariant: no matter how large the budget grew, an
	// incomplete walk is never persisted (a partial inventory would tombstone
	// real files).
	if len(fake.persisted) != 0 {
		t.Errorf("an incomplete root was persisted: %v", fake.persisted)
	}
}

// TestGuidanceRunLoopAdaptiveResetsOnPersist proves a root that finally
// persists drops back to the base budget: its scripted outcomes are
// overrun, overrun, persist, overrun — and the budget granted on the fourth
// pass is the base again, not the escalated value.
func TestGuidanceRunLoopAdaptiveResetsOnPersist(t *testing.T) {
	// Key by the cleaned root spelling (see TestGuidanceRunLoopAdaptiveBudget).
	slow := filepath.Clean("/slow")
	fake := fakeGuidanceSeams{
		roots:        []string{slow},
		scanOutcomes: map[string][]string{slow: {"incomplete", "incomplete", "ok", "incomplete"}},
	}
	seams := fake.seams()
	seams.RootTimeout = 100 * time.Millisecond
	seams.PassTimeout = time.Hour

	// Four passes: startup + 3 rescans.
	calls := 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	after := func(time.Duration) <-chan time.Time {
		calls++
		if calls > 3 {
			cancel()
			return make(chan time.Time)
		}
		ch := make(chan time.Time, 1)
		ch <- time.Now()
		return ch
	}

	guidanceRunLoop(ctx, guidanceLoopDeps{
		Seams:          seams,
		Rescan:         time.Minute,
		RootTimeoutMax: 800 * time.Millisecond,
		After:          after,
	})

	got := fake.budgets[slow]
	want := []time.Duration{
		100 * time.Millisecond, // streak 0, overrun -> streak 1
		200 * time.Millisecond, // streak 1, overrun -> streak 2
		400 * time.Millisecond, // streak 2, OK -> persist -> streak reset
		100 * time.Millisecond, // streak 0 again -> BACK TO BASE
	}
	if len(got) != len(want) {
		t.Fatalf("granted budgets = %v, want %v", got, want)
	}
	for i := range want {
		if !guidanceBudgetInBand(got[i], want[i]) {
			t.Errorf("pass %d budget = %v, want ~%v (full: %v)", i, got[i], want[i], got)
		}
	}
	// The one healthy pass persisted; the incomplete ones did not.
	if strings.Join(fake.persisted, ",") != slow {
		t.Errorf("persisted = %v, want exactly the one healthy pass", fake.persisted)
	}
}

// TestGuidanceFirstScanPollCadence pins the config projection: 0 is a real
// setting ("never poll"), not a missing value to be replaced by the seed.
func TestGuidanceFirstScanPollCadence(t *testing.T) {
	cases := []struct {
		in   int
		want time.Duration
	}{
		{60, 60 * time.Second},
		{5, 5 * time.Second},
		{0, 0},
		{-3, guidanceDefaultFirstScanPoll},
	}
	for _, c := range cases {
		got := guidanceFirstScanPoll(config.GuidanceConfig{FirstScanPollSeconds: c.in})
		if got != c.want {
			t.Errorf("guidanceFirstScanPoll(%d) = %v, want %v", c.in, got, c.want)
		}
	}
}
