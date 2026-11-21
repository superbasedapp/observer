package sandboxrelayd

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
)

// gatedrift.go is the transcript-versus-gate comparison (sandbox plan v2
// section 5.2 (2), plans decision log P-040, lane sbx-p2d): the daemon
// checks that gate events keep arriving for the tool calls the agent's
// transcript shows. A box whose hooks stopped firing (switched off in a way
// the registration probe cannot see, or a tool that skips them) still writes
// its transcript, which the host reads under the run's roots; a call the
// transcript shows as run, whose gate event the relay never saw within the
// lag window, marks the run hooks_drifted. It catches hooks that stopped
// firing, not a box that forges gate events for the calls it runs.
//
// What is compared is declared per tool in the registry
// (integration.SandboxSpec.GateDrift, read through GateDrift.Spec): the gate
// payload key that names the call, and the rules that find calls that ran in
// one transcript line. A tool with no declaration is not compared. Which
// events are gate events is the registry's tool gate binding
// (GateDrift.IsGate). Nothing here switches on a tool name.
//
// Only lines written after the run first named the transcript are read, so a
// resumed session's earlier calls never count. A transcript first named
// before it existed is read from its start, and there a result counts only
// when its line is newer than the run, or, with no timestamp, when its call
// was read in the same transcript, so copied history never counts. A call
// is counted only once its result says it ran (an interrupted or refused
// call may never have reached the gate). A run is compared only after one of
// its gate events carried a call id: a tool build that sends none is never
// compared, so it never drifts. The comparison only ever lowers a run.
//
// The transcript is guest-writable: it is opened without blocking and
// refused unless it is a regular file (confine.go), it is never read while
// the run's comparison lock is held, and each run is read by its own worker
// under a deadline, so one run's transcript cannot stall the answer path or
// any other run's comparison.

// GateDrift configures the comparison; a nil Daemon.Drift turns it off.
type GateDrift struct {
	// Spec returns the comparison declared for the run's tool; ok=false or
	// a spec that compares nothing turns it off for the run.
	Spec func(tool string) (integration.TranscriptGateSpec, bool)
	// IsGate reports whether a relayed hook request is a gate event that
	// carries a tool call (the tool's HookCapToolGate binding).
	IsGate func(req sandboxrelay.HookRequest) bool
	// Window is how long a call the transcript shows may wait for its gate
	// event (zero: DefaultDriftWindow).
	Window time.Duration
	// Interval is how often Serve compares (zero: DefaultDriftInterval;
	// negative: never, CheckDrift only).
	Interval time.Duration
	// ReadDeadline is how long CheckDrift waits for the runs' reads (zero:
	// DefaultDriftReadDeadline). A run whose read is still going finishes
	// on its own and is skipped by later comparisons until it does.
	ReadDeadline time.Duration
	// after is the deadline's clock (nil: time.After); a test injects one
	// that fires only when it says so, so no comparison depends on how fast
	// a loaded race run reads a file.
	after func(time.Duration) <-chan time.Time
}

// DefaultDriftWindow bounds transcript lag: a gate event normally reaches
// the daemon before the call runs, so a call whose result is in the
// transcript for two minutes with no gate event never had one.
const DefaultDriftWindow = 2 * time.Minute

// DefaultDriftInterval is how often the daemon compares.
const DefaultDriftInterval = 15 * time.Second

// DefaultDriftReadDeadline is how long one comparison waits for the runs'
// transcript reads.
const DefaultDriftReadDeadline = 5 * time.Second

// Bounds of one run's comparison: what the daemon keeps per run and reads
// per comparison never grows with the run's length.
const (
	maxDriftSeen        = 16384
	maxDriftPending     = 4096
	maxDriftCalled      = 4096
	maxDriftTranscripts = 16
	maxDriftRead        = 1 << 20
	// maxDriftLine caps one transcript's partial line; maxDriftRunPartial
	// caps the partial lines of all of one run's transcripts together (the
	// oldest transcript's partial line is dropped first, and counted).
	maxDriftLine       = 1 << 20
	maxDriftRunPartial = 4 << 20
	maxDriftIDLen      = 256
)

// DriftStatus is how far a run's transcript comparison got.
type DriftStatus string

const (
	// DriftOff: the run is not compared (no comparison declared for its
	// tool, or no comparable request yet).
	DriftOff DriftStatus = ""
	// DriftNoCallID: none of the run's gate events carried a call id yet,
	// so nothing is compared (and nothing drifts on that alone).
	DriftNoCallID DriftStatus = "no_call_id"
	// DriftCompared: the run's transcripts are compared with its gate
	// events.
	DriftCompared DriftStatus = "compared"
	// DriftDrifted: a call the transcript shows never reached the gate.
	DriftDrifted DriftStatus = "drifted"
)

// driftState is one run's comparison state (one per RunState, made on the
// run's first comparable request).
type driftState struct {
	// checking serializes one run's reads: held for a whole comparison,
	// file I/O included; the ticker skips a run whose read still runs.
	checking sync.Mutex
	// spec is set at creation and never changes.
	spec integration.TranscriptGateSpec
	// mu guards everything below; no file I/O happens while it is held.
	mu        sync.Mutex
	seen      map[string]struct{}
	seenOrder []string
	// idSeen: a gate event of the run carried a call id.
	idSeen    bool
	tails     map[string]*driftTail
	tailOrder []string
	pending   map[string]time.Time
	drifted   bool
	// droppedPartials counts partial lines dropped for the run's budget.
	droppedPartials int
}

// driftTail is how far one transcript was read. Its read fields are touched
// only by the run's comparison (under driftState.checking).
type driftTail struct {
	offset  int64
	partial []byte
	// skip drops the rest of a line that went over a bound.
	skip bool
	// fromStart: the transcript did not exist when the run first named it,
	// so it is read from byte 0 and copied history must not count.
	fromStart bool
	// since is when the run started (its record's CreatedAt, else when the
	// transcript was named): a fromStart line not newer than it is history.
	since time.Time
	// called holds the call ids of the fresh tool_use lines of a fromStart
	// transcript (bounded, oldest dropped).
	called      map[string]struct{}
	calledOrder []string
}

// observeDrift records what one relayed request tells the comparison: the
// call id a gate event carries (seen whatever the binding decides: the relay
// saw it) and, for a request the binding passed, the transcript the payload
// names (read from its current end on, so earlier history never counts).
// The transcripts are opened with the run's lock released.
func (d *Daemon) observeDrift(st *RunState, rec RunRecord, req sandboxrelay.HookRequest, facts payloadFacts, bound bool) {
	if d.Drift == nil || d.Drift.Spec == nil || req.Kind != sandboxrelay.KindHook || len(req.Args) == 0 {
		return
	}
	ds := d.driftFor(st, rec.Tool)
	if ds == nil {
		return
	}
	var callID string
	// Only a request in the run's own tool's dialect is its gate event.
	if req.Args[0] == rec.Tool && d.Drift.IsGate != nil && d.Drift.IsGate(req) {
		callID = payloadString(req.Stdin, ds.spec.PayloadCallID)
	}
	ds.mu.Lock()
	if callID != "" {
		ds.markSeen(callID)
	}
	var fresh []string
	if bound {
		for _, p := range facts.files {
			if len(ds.tails)+len(fresh) >= maxDriftTranscripts {
				break
			}
			if _, ok := ds.tails[p]; ok || slices.Contains(fresh, p) {
				continue
			}
			fresh = append(fresh, p)
		}
	}
	ds.mu.Unlock()
	if len(fresh) == 0 {
		return
	}
	// The open never blocks: a FIFO or any other file that is not a regular
	// file is refused (confine.go).
	roots := driftRoots(rec)
	sizes := make([]int64, len(fresh))
	for i, p := range fresh {
		sizes[i] = -1
		if f, err := OpenConfinedTail(roots, p); err == nil {
			if fi, err := f.Stat(); err == nil {
				sizes[i] = fi.Size()
			}
			_ = f.Close()
		}
	}
	since := rec.CreatedAt
	if since.IsZero() {
		since = time.Now()
	}
	ds.mu.Lock()
	defer ds.mu.Unlock()
	for i, p := range fresh {
		if _, ok := ds.tails[p]; ok || len(ds.tails) >= maxDriftTranscripts {
			continue
		}
		t := &driftTail{offset: sizes[i], since: since}
		if sizes[i] < 0 {
			// Not there yet: it is read from its start once it appears,
			// with copied history left out.
			t.offset, t.fromStart, t.called = 0, true, map[string]struct{}{}
		}
		ds.tails[p] = t
		ds.tailOrder = append(ds.tailOrder, p)
	}
}

// driftFor returns st's comparison state, made on first use; nil when the
// run's tool declares no comparison.
func (d *Daemon) driftFor(st *RunState, tool string) *driftState {
	d.mu.Lock()
	defer d.mu.Unlock()
	if st.drift != nil || st.noDrift {
		return st.drift
	}
	spec, ok := d.Drift.Spec(tool)
	if !ok || !spec.Compared() {
		st.noDrift = true
		return nil
	}
	st.drift = &driftState{spec: spec, seen: map[string]struct{}{}, tails: map[string]*driftTail{}, pending: map[string]time.Time{}}
	return st.drift
}

// DriftStatus reports how far runID's transcript comparison got.
func (d *Daemon) DriftStatus(runID string) DriftStatus {
	d.mu.Lock()
	var ds *driftState
	if st, ok := d.runs[runID]; ok {
		ds = st.drift
	}
	d.mu.Unlock()
	if ds == nil {
		return DriftOff
	}
	ds.mu.Lock()
	defer ds.mu.Unlock()
	switch {
	case ds.drifted:
		return DriftDrifted
	case !ds.idSeen:
		return DriftNoCallID
	}
	return DriftCompared
}

// markSeen records a gate event's call id (bounded: the oldest goes).
func (ds *driftState) markSeen(id string) {
	if len(id) > maxDriftIDLen {
		return
	}
	ds.idSeen = true
	delete(ds.pending, id)
	if _, ok := ds.seen[id]; ok {
		return
	}
	if len(ds.seenOrder) >= maxDriftSeen {
		delete(ds.seen, ds.seenOrder[0])
		ds.seenOrder = ds.seenOrder[1:]
	}
	ds.seen[id] = struct{}{}
	ds.seenOrder = append(ds.seenOrder, id)
}

// driftRoots are the directories a run's transcript may be read under: the
// same ones the binding lets a payload's files name.
func driftRoots(rec RunRecord) []string { return append(runDirs(rec), rec.ReadRoots()...) }

// CheckDrift compares every run's transcripts with its gate events at now
// and lowers each run that drifted (hooks_drifted); it returns how many
// runs it lowered within the read deadline. Each run is read by its own
// worker: a run whose read outlives the deadline still lowers itself when
// it finishes, and later calls skip it until then, so one run's transcript
// never holds up another's. Serve runs it every GateDrift.Interval.
func (d *Daemon) CheckDrift(now time.Time) int {
	if d.Drift == nil {
		return 0
	}
	window := d.Drift.Window
	if window <= 0 {
		window = DefaultDriftWindow
	}
	deadline := d.Drift.ReadDeadline
	if deadline <= 0 {
		deadline = DefaultDriftReadDeadline
	}
	type item struct {
		st  *RunState
		rec RunRecord
	}
	d.mu.Lock()
	var items []item
	for _, st := range d.runs {
		if st.drift != nil {
			items = append(items, item{st, st.run})
		}
	}
	d.mu.Unlock()
	results := make(chan bool, len(items))
	launched := 0
	for _, it := range items {
		ds := it.st.drift
		if !ds.checking.TryLock() {
			continue // its previous read is still going
		}
		launched++
		go func() {
			lowered := ds.checkLocked(it.rec, now, window)
			if lowered {
				d.lower(it.rec, it.st, 0, CauseHooksDrifted)
			}
			// Released before the result is reported, so a comparison
			// that follows this one's return never finds the run still
			// held and skips it (that skip made the drift tests flake
			// under -race; lane LEFT-SBX).
			ds.checking.Unlock()
			results <- lowered
		}()
	}
	after := d.Drift.after
	if after == nil {
		after = time.After
	}
	expired := after(deadline)
	n := 0
	for range launched {
		select {
		case lowered := <-results:
			if lowered {
				n++
			}
		case <-expired:
			return n
		}
	}
	return n
}

// tailRef is one transcript a comparison reads.
type tailRef struct {
	path string
	t    *driftTail
}

// checkLocked reads what each transcript gained, and reports true the first
// time a call that ran has waited past window for its gate event. The caller
// holds ds.checking; the transcripts are read with ds.mu released.
func (ds *driftState) checkLocked(rec RunRecord, now time.Time, window time.Duration) bool {
	ds.mu.Lock()
	if ds.drifted {
		ds.mu.Unlock()
		return false
	}
	tails := make([]tailRef, 0, len(ds.tailOrder))
	for _, p := range ds.tailOrder {
		tails = append(tails, tailRef{p, ds.tails[p]})
	}
	ds.mu.Unlock()

	roots := driftRoots(rec)
	var ran []string
	for _, tr := range tails {
		ran = append(ran, ds.readTail(roots, tr.path, tr.t)...)
	}
	dropped := budgetPartials(tails)

	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.droppedPartials += dropped
	if !ds.idSeen {
		// No gate event carried a call id: there is nothing to compare
		// against, and nothing waits.
		return false
	}
	for _, id := range ran {
		if _, ok := ds.seen[id]; ok {
			continue
		}
		if _, ok := ds.pending[id]; !ok && len(ds.pending) < maxDriftPending {
			ds.pending[id] = now
		}
	}
	for id, first := range ds.pending {
		if _, ok := ds.seen[id]; ok {
			delete(ds.pending, id)
			continue
		}
		if now.Sub(first) >= window {
			ds.drifted = true
			return true
		}
	}
	return false
}

// budgetPartials holds the partial lines of one run's transcripts to
// maxDriftRunPartial together: the oldest transcript's goes first (the rest
// of its line is skipped). It returns how many it dropped.
func budgetPartials(tails []tailRef) int {
	total := 0
	for _, tr := range tails {
		total += len(tr.t.partial)
	}
	dropped := 0
	for _, tr := range tails {
		if total <= maxDriftRunPartial {
			break
		}
		if len(tr.t.partial) == 0 {
			continue
		}
		total -= len(tr.t.partial)
		tr.t.partial, tr.t.skip = nil, true
		dropped++
	}
	return dropped
}

// readTail reads up to maxDriftRead new bytes of one transcript and returns
// the calls its complete lines show as run. A transcript that shrank was
// rewritten: it is read on from its new end.
func (ds *driftState) readTail(roots []string, path string, t *driftTail) []string {
	f, err := OpenConfinedTail(roots, path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil
	}
	if fi.Size() < t.offset {
		t.offset, t.partial, t.skip = fi.Size(), nil, false
		return nil
	}
	if fi.Size() == t.offset {
		return nil
	}
	if _, err := f.Seek(t.offset, io.SeekStart); err != nil {
		return nil
	}
	buf := make([]byte, min(fi.Size()-t.offset, maxDriftRead))
	got, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil
	}
	t.offset += int64(got)
	data := buf[:got]
	var out []string
	for len(data) > 0 {
		nl := bytes.IndexByte(data, '\n')
		if nl < 0 {
			if t.skip {
				return out
			}
			if len(t.partial)+len(data) > maxDriftLine {
				t.partial, t.skip = nil, true
				return out
			}
			t.partial = append(t.partial, data...)
			return out
		}
		line := data[:nl]
		data = data[nl+1:]
		if t.skip {
			t.skip = false
			continue
		}
		if len(t.partial) > 0 {
			if len(t.partial)+len(line) > maxDriftLine {
				t.partial = nil
				continue
			}
			line = append(t.partial, line...)
			t.partial = nil
		}
		out = append(out, t.lineRan(ds.spec, line)...)
	}
	return out
}

// lineRan returns the calls one complete line shows as run. In a fromStart
// transcript a result counts only when its line is newer than the run, or,
// with no timestamp on the line, when its call's tool_use line was read
// (and was fresh) in the same transcript; anything else there is copied
// history.
func (t *driftTail) lineRan(spec integration.TranscriptGateSpec, line []byte) []string {
	sc := scanLine(spec, line)
	if !t.fromStart {
		return sc.ran
	}
	fresh := !sc.hasTime || sc.at.After(t.since)
	if fresh {
		for _, id := range sc.called {
			t.markCalled(id)
		}
	}
	if sc.hasTime {
		if fresh {
			return sc.ran
		}
		return nil
	}
	var out []string
	for _, id := range sc.ran {
		if _, ok := t.called[id]; ok {
			out = append(out, id)
		}
	}
	return out
}

// markCalled records a fresh call id of a fromStart transcript (bounded:
// the oldest goes).
func (t *driftTail) markCalled(id string) {
	if _, ok := t.called[id]; ok {
		return
	}
	if len(t.calledOrder) >= maxDriftCalled {
		delete(t.called, t.calledOrder[0])
		t.calledOrder = t.calledOrder[1:]
	}
	t.called[id] = struct{}{}
	t.calledOrder = append(t.calledOrder, id)
}

// lineScan is what one transcript line shows.
type lineScan struct {
	ran, called []string
	at          time.Time
	hasTime     bool
}

// RanCallIDs applies spec's rules to one transcript line and returns the
// ids of the tool calls it shows as run. A line that is not a JSON object,
// or matches no rule, shows none.
func RanCallIDs(spec integration.TranscriptGateSpec, line []byte) []string {
	return scanLine(spec, line).ran
}

// scanLine applies spec's Ran and Called rules and its timestamp key to one
// transcript line.
func scanLine(spec integration.TranscriptGateSpec, line []byte) lineScan {
	var out lineScan
	line = bytes.TrimSpace(line)
	if len(line) == 0 || line[0] != '{' {
		return out
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(line, &top) != nil {
		return out
	}
	out.ran = blockIDs(spec.Ran, top, line)
	out.called = blockIDs(spec.Called, top, line)
	if spec.TimestampKey != "" {
		var s string
		if json.Unmarshal(top[spec.TimestampKey], &s) == nil {
			if at, err := time.Parse(time.RFC3339Nano, s); err == nil {
				out.at, out.hasTime = at, true
			}
		}
	}
	return out
}

// blockIDs applies rules to one parsed line (top is its top-level object).
func blockIDs(rules []integration.TranscriptBlockRule, top map[string]json.RawMessage, line []byte) []string {
	var out []string
	for _, r := range rules {
		if !rawStringIs(top[r.LineKey], r.LineValue) {
			continue
		}
		v := json.RawMessage(line)
		ok := true
		for _, k := range r.Path {
			var m map[string]json.RawMessage
			if json.Unmarshal(v, &m) != nil {
				ok = false
				break
			}
			if v, ok = m[k]; !ok {
				break
			}
		}
		if !ok {
			continue
		}
		var blocks []map[string]json.RawMessage
		if json.Unmarshal(v, &blocks) != nil {
			var one map[string]json.RawMessage
			if json.Unmarshal(v, &one) != nil {
				continue
			}
			blocks = []map[string]json.RawMessage{one}
		}
		for _, b := range blocks {
			if !rawStringIs(b[r.BlockKey], r.BlockValue) {
				continue
			}
			if r.SkipIfTrue != "" && string(bytes.TrimSpace(b[r.SkipIfTrue])) == "true" {
				continue
			}
			var id string
			if json.Unmarshal(b[r.IDKey], &id) == nil && id != "" && len(id) <= maxDriftIDLen {
				out = append(out, id)
			}
		}
	}
	return out
}

// rawStringIs reports whether raw is the JSON string want.
func rawStringIs(raw json.RawMessage, want string) bool {
	var s string
	return raw != nil && json.Unmarshal(raw, &s) == nil && s == want
}

// payloadString reads a top-level string value of a JSON payload by its
// exact key (the spelling the tool sends); "" when absent, not a string, or
// the payload is not an object.
func payloadString(stdin []byte, key string) string {
	if key == "" {
		return ""
	}
	body := bytes.TrimPrefix(stdin, []byte{0xEF, 0xBB, 0xBF})
	var top map[string]json.RawMessage
	if json.NewDecoder(bytes.NewReader(body)).Decode(&top) != nil {
		return ""
	}
	var v string
	if json.Unmarshal(top[key], &v) != nil {
		return ""
	}
	return v
}
