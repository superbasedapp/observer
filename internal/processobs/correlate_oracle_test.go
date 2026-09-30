package processobs

import (
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test-only ORACLE: the pre-index O(runs × actions) correlator, kept verbatim
// (only renamed) so the sorted/binary-searched production path can be proven
// result-identical against it. Do not "fix" this copy — it is the reference.
// ---------------------------------------------------------------------------

func oracleCorrelateActions(runs []ProcRunRef, actions []ActionRef, window time.Duration) []ActionLink {
	if window <= 0 {
		window = CorrelationWindow
	}

	byKey := make(map[string]*ProcRunRef, len(runs))
	children := make(map[string][]string)
	for i := range runs {
		r := &runs[i]
		byKey[r.ProcessKey] = r
		if r.ParentProcessKey != "" {
			children[r.ParentProcessKey] = append(children[r.ParentProcessKey], r.ProcessKey)
		}
	}

	prepped := prepActions(actions)

	anchors := make(map[string]ActionRef)
	for i := range runs {
		r := &runs[i]
		if r.Linked {
			continue
		}
		if a, ok := oracleBestAction(r, prepped, window); ok {
			anchors[r.ProcessKey] = a
		}
	}

	links := make([]ActionLink, 0, len(anchors))
	assigned := make(map[string]bool)
	for anchorKey, act := range anchors {
		stack := []string{anchorKey}
		for len(stack) > 0 {
			k := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if assigned[k] {
				continue
			}
			if k != anchorKey {
				if _, isOtherAnchor := anchors[k]; isOtherAnchor {
					continue
				}
			}
			r := byKey[k]
			if r == nil || r.Linked {
				continue
			}
			assigned[k] = true
			links = append(links, ActionLink{ProcessKey: k, ActionID: act.ActionID, TurnIndex: act.TurnIndex})
			stack = append(stack, children[k]...)
		}
	}
	return links
}

func oracleBestAction(r *ProcRunRef, actions []preppedAction, window time.Duration) (ActionRef, bool) {
	ne := normExe(r.ExeBasename)
	na := stripQuotes(strings.ToLower(r.ArgvPreview))
	topScore := 0
	var top []preppedAction
	for i := range actions {
		a := &actions[i]
		delta := r.StartedAt.Sub(a.ref.Timestamp)
		backSkew := correlationBackSkew + a.ref.Duration
		if delta < -backSkew || delta > window {
			continue
		}
		score := matchScore(ne, na, a)
		if score == 0 {
			continue
		}
		if score > topScore {
			topScore = score
			top = top[:0]
			top = append(top, *a)
		} else if score == topScore {
			top = append(top, *a)
		}
	}
	if topScore == 0 || len(top) == 0 {
		return ActionRef{}, false
	}
	if len(top) == 1 {
		return top[0].ref, true
	}
	return ActionRef{}, false
}

// ---------------------------------------------------------------------------
// Randomized equality: new == oracle.
// ---------------------------------------------------------------------------

var fuzzCommands = []string{
	"go build",
	"go build ./...",
	"go test ./...",
	"cd /x && go build",
	"cd /x && go test ./... && git status",
	"bash -lc 'npm test'",
	"npm test",
	"git status",
	"git diff",
	"python script.py",
	"node index.js",
	"sh -c \"make all\"",
	"make all",
	"ls -la",
}

var fuzzExes = []string{"go", "go.exe", "bash", "sh", "npm", "node", "git", "python", "python3", "make", "ls", "cat", ""}

var fuzzArgvs = []string{
	"", "go build", "go build ./...", "go test ./...", "bash -lc cd /x && go build",
	"npm test", "node index.js", "git status", "git diff", "python script.py",
	"sh -c make all", "make all", "ls -la", "/usr/bin/cat foo",
	"bash -c cd /x && go test ./... && git status",
}

// genCorrelateCase builds a random session: actions with tied timestamps,
// durations 0..minutes, and runs placed at random offsets AND exactly at /
// one nanosecond past each action's gate edges, in a random forest (unique
// keys, parents drawn from earlier runs, some parents missing from the set),
// with some runs pre-linked.
func genCorrelateCase(rng *rand.Rand) ([]ProcRunRef, []ActionRef, time.Duration) {
	base := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	window := CorrelationWindow
	if rng.Intn(4) == 0 {
		window = time.Duration(1+rng.Intn(120)) * time.Second
	}
	span := time.Duration(1+rng.Intn(600)) * time.Second

	nActions := rng.Intn(60)
	actions := make([]ActionRef, nActions)
	for i := range actions {
		var ts time.Time
		switch {
		case i > 0 && rng.Intn(4) == 0:
			ts = actions[rng.Intn(i)].Timestamp // exact timestamp tie
		case rng.Intn(3) == 0:
			ts = base.Add(time.Duration(rng.Intn(int(span/time.Second)+1)) * time.Second)
		default:
			ts = base.Add(time.Duration(rng.Int63n(int64(span) + 1)))
		}
		var dur time.Duration
		switch rng.Intn(4) {
		case 0:
			dur = time.Duration(rng.Int63n(int64(5 * time.Minute)))
		case 1:
			dur = time.Duration(rng.Intn(300)) * time.Second
		}
		var turn *int
		if rng.Intn(3) != 0 {
			v := rng.Intn(20)
			turn = &v
		}
		cmd := fuzzCommands[rng.Intn(len(fuzzCommands))]
		if i > 0 && rng.Intn(5) == 0 {
			cmd = actions[rng.Intn(i)].Command // repeated identical command
		}
		actions[i] = ActionRef{
			ActionID:  int64(1000 + i),
			TurnIndex: turn,
			Command:   cmd,
			Timestamp: ts,
			Duration:  dur,
			Success:   rng.Intn(2) == 0,
		}
	}

	nRuns := rng.Intn(80)
	runs := make([]ProcRunRef, nRuns)
	for i := range runs {
		var start time.Time
		if nActions > 0 && rng.Intn(2) == 0 {
			a := actions[rng.Intn(nActions)]
			back := correlationBackSkew + a.Duration
			switch rng.Intn(7) {
			case 0:
				start = a.Timestamp.Add(window) // forward edge (passes)
			case 1:
				start = a.Timestamp.Add(window + 1) // just past forward edge
			case 2:
				start = a.Timestamp.Add(-back) // back edge (passes)
			case 3:
				start = a.Timestamp.Add(-back - 1) // just past back edge
			case 4:
				start = a.Timestamp // exact
			default:
				start = a.Timestamp.Add(time.Duration(rng.Int63n(int64(2*window))) - window/2)
			}
		} else {
			start = base.Add(time.Duration(rng.Int63n(int64(span)+int64(time.Minute))) - 30*time.Second)
		}
		parent := ""
		switch {
		case i > 0 && rng.Intn(3) != 0:
			parent = fmt.Sprintf("p%d", rng.Intn(i))
		case rng.Intn(5) == 0:
			parent = "ghost-parent" // not in the set
		}
		argv := fuzzArgvs[rng.Intn(len(fuzzArgvs))]
		if nActions > 0 && rng.Intn(4) == 0 {
			argv = "sh -c " + actions[rng.Intn(nActions)].Command
		}
		runs[i] = ProcRunRef{
			ProcessKey:       fmt.Sprintf("p%d", i),
			ParentProcessKey: parent,
			StartedAt:        start,
			ArgvPreview:      argv,
			ExeBasename:      fuzzExes[rng.Intn(len(fuzzExes))],
			Linked:           rng.Intn(10) == 0,
		}
	}
	// The store loads rows in rowid order, not time order; shuffle the action
	// input so the index's own sort is exercised.
	rng.Shuffle(len(actions), func(i, j int) { actions[i], actions[j] = actions[j], actions[i] })
	return runs, actions, window
}

// sortLinks orders links by ProcessKey. CorrelateActions' output order comes
// from ranging a map (anchors) and is not part of the contract: the one
// caller (store.CorrelateProcessActions) applies each link as an independent
// keyed UPDATE.
func sortLinks(ls []ActionLink) []ActionLink {
	out := append([]ActionLink(nil), ls...)
	sort.Slice(out, func(i, j int) bool { return out[i].ProcessKey < out[j].ProcessKey })
	return out
}

func TestCorrelateActionsMatchesQuadraticOracle(t *testing.T) {
	const seeds = 4000
	var totalLinks, totalAnchors, totalAmbiguousOrNone int
	for seed := int64(1); seed <= seeds; seed++ {
		rng := rand.New(rand.NewSource(seed))
		runs, actions, window := genCorrelateCase(rng)

		// Per-run anchor decision must match exactly (strongest check).
		oraclePrepped := prepActions(actions)
		idx := newActionIndex(prepActions(actions))
		for i := range runs {
			r := &runs[i]
			wantA, wantOK := oracleBestAction(r, oraclePrepped, window)
			gotA, gotOK := bestAction(r, idx, window)
			if wantOK != gotOK || !reflect.DeepEqual(wantA, gotA) {
				t.Fatalf("seed %d run %s: bestAction = (%+v,%v), oracle = (%+v,%v)", seed, r.ProcessKey, gotA, gotOK, wantA, wantOK)
			}
			if wantOK {
				totalAnchors++
			} else {
				totalAmbiguousOrNone++
			}
		}

		// Whole-pass link set must match; pass window 0 on some seeds to cover
		// the default-window branch.
		w := window
		if seed%5 == 0 {
			w = 0
		}
		want := sortLinks(oracleCorrelateActions(runs, actions, w))
		got := sortLinks(CorrelateActions(runs, actions, w))
		if len(want) == 0 && len(got) == 0 {
			continue
		}
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("seed %d: link sets differ\n got=%+v\nwant=%+v", seed, got, want)
		}
		totalLinks += len(want)
	}
	if totalLinks == 0 || totalAnchors == 0 || totalAmbiguousOrNone == 0 {
		t.Fatalf("generator too weak: links=%d anchors=%d unanchored=%d", totalLinks, totalAnchors, totalAmbiguousOrNone)
	}
	t.Logf("%d seeds: %d links, %d anchor decisions, %d unanchored decisions — identical to oracle", seeds, totalLinks, totalAnchors, totalAmbiguousOrNone)
}

// TestCorrelateActionsAmbiguityCountsOutsideIndexOrder pins the case the index
// must not break: two identical commands with the same timestamp stay
// ambiguous regardless of input order.
func TestCorrelateActionsAmbiguityCountsOutsideIndexOrder(t *testing.T) {
	base := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	runs := []ProcRunRef{{ProcessKey: "p", StartedAt: base.Add(time.Second), ExeBasename: "go", ArgvPreview: "go build"}}
	for _, order := range [][2]int64{{1, 2}, {2, 1}} {
		acts := []ActionRef{
			{ActionID: order[0], Command: "go build", Timestamp: base},
			{ActionID: order[1], Command: "go build", Timestamp: base},
		}
		if got := CorrelateActions(runs, acts, 0); len(got) != 0 {
			t.Fatalf("order %v: ambiguous tie linked: %+v", order, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Benchmark: 20k runs × 15k actions over a ~10h session.
// ---------------------------------------------------------------------------

func benchCorrelateInput() ([]ProcRunRef, []ActionRef) {
	rng := rand.New(rand.NewSource(42))
	base := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	span := 10 * time.Hour
	actions := make([]ActionRef, 15000)
	for i := range actions {
		v := i / 10
		var dur time.Duration
		if rng.Intn(3) == 0 {
			dur = time.Duration(rng.Intn(120)) * time.Second
		}
		actions[i] = ActionRef{
			ActionID:  int64(i + 1),
			TurnIndex: &v,
			Command:   fuzzCommands[rng.Intn(len(fuzzCommands))],
			Timestamp: base.Add(time.Duration(rng.Int63n(int64(span)))),
			Duration:  dur,
		}
	}
	runs := make([]ProcRunRef, 20000)
	for i := range runs {
		parent := ""
		if i > 0 && rng.Intn(2) == 0 {
			parent = fmt.Sprintf("p%d", rng.Intn(i))
		}
		runs[i] = ProcRunRef{
			ProcessKey:       fmt.Sprintf("p%d", i),
			ParentProcessKey: parent,
			StartedAt:        base.Add(time.Duration(rng.Int63n(int64(span)))),
			ArgvPreview:      fuzzArgvs[rng.Intn(len(fuzzArgvs))],
			ExeBasename:      fuzzExes[rng.Intn(len(fuzzExes))],
		}
	}
	return runs, actions
}

func BenchmarkCorrelateActions20kx15k(b *testing.B) {
	runs, actions := benchCorrelateInput()
	b.Run("oracle-quadratic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = oracleCorrelateActions(runs, actions, 0)
		}
	})
	b.Run("indexed", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = CorrelateActions(runs, actions, 0)
		}
	})
}
