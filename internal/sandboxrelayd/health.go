package sandboxrelayd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
)

// health.go is a run's capture health (sandbox plan section 5.2, plans
// decision log P-032, lane sbx-p2c): what lowered the run below the
// capture its launch evidence promised. A guest-reported or helper-reported
// fact can only lower a run, never raise it (review R2-17), so health only
// ever grows: a cause once recorded stays, and the missed-heartbeat count
// only rises.

// DegradedCause is one reason a run's capture is degraded. Closed
// vocabulary: the stored list, the run pill and the docs dispatch on it.
type DegradedCause string

// The closed DegradedCause vocabulary.
const (
	// CauseRefused: the host refused a relayed event (the binding: a path
	// outside the run, another project's session, a replayed gate event).
	CauseRefused DegradedCause = "refused"
	// CauseRateLimited: the run went over its request or byte rate.
	CauseRateLimited DegradedCause = "rate_limited"
	// CauseDropped: an event was lost on the way (a broken or slow frame,
	// a busy run, an execution that failed, an answer that could not be
	// sent).
	CauseDropped DegradedCause = "dropped"
	// CauseReplayed: an event arrived late from the box's spool (the relay
	// was unreachable when it happened).
	CauseReplayed DegradedCause = "replayed"
	// CauseHooksDrifted: the box's hook configuration no longer matches
	// what the launch wrote, so later events may never be sent.
	CauseHooksDrifted DegradedCause = "hooks_drifted"
	// CauseHeartbeatMissed: a side of the relay missed heartbeats.
	CauseHeartbeatMissed DegradedCause = "heartbeat_missed"
)

// causeOrder is the vocabulary in its one fixed order.
var causeOrder = []DegradedCause{CauseRefused, CauseRateLimited, CauseDropped, CauseReplayed, CauseHooksDrifted, CauseHeartbeatMissed}

// Valid reports whether c is in the closed vocabulary.
func (c DegradedCause) Valid() bool { return slices.Contains(causeOrder, c) }

// Health is a run's capture health at one moment.
type Health struct {
	// Causes are the recorded causes in vocabulary order, each once.
	Causes []DegradedCause
	// MissedHeartbeats counts the heartbeats a side of the relay missed.
	MissedHeartbeats int
}

// Degraded reports whether anything lowered the run.
func (h Health) Degraded() bool { return len(h.Causes) > 0 || h.MissedHeartbeats > 0 }

// Has reports whether c is recorded.
func (h Health) Has(c DegradedCause) bool { return slices.Contains(h.Causes, c) }

// CauseList renders the causes as the stored comma list.
func (h Health) CauseList() string {
	parts := make([]string, len(h.Causes))
	for i, c := range h.Causes {
		parts[i] = string(c)
	}
	return strings.Join(parts, ",")
}

// ParseCauses reads a stored comma list, keeping only known causes, in
// vocabulary order.
func ParseCauses(s string) []DegradedCause {
	var out []DegradedCause
	for _, p := range strings.Split(s, ",") {
		if c := DegradedCause(strings.TrimSpace(p)); c.Valid() && !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	sortCauses(out)
	return out
}

func sortCauses(cs []DegradedCause) {
	sort.Slice(cs, func(i, j int) bool { return slices.Index(causeOrder, cs[i]) < slices.Index(causeOrder, cs[j]) })
}

// runHealth is the daemon's per-run health (one per RunState), and the
// delivery of its changes to the daemon's OnHealth.
//
// A delivery is a database write of up to five seconds, so it never runs
// on the answer path (plans decision log P-040): a change marks the health
// dirty and at most one delivery goroutine per run hands the latest health
// to OnHealth, again and again while new changes arrive. The health only
// grows, so the latest health carries every earlier one and coalescing
// loses nothing; one goroutine per run keeps the writes in order.
type runHealth struct {
	mu sync.Mutex
	h  Health
	// rec is the run record the latest change was seen with (it carries
	// the terminal run binding, which can arrive after the run started).
	rec        RunRecord
	dirty      bool
	delivering bool
	// ended is set when the daemon ended the run (EndRun): every delivery
	// that finishes after it calls onEnd, so a late write cannot leave
	// state behind for a run that is gone.
	ended bool
	onEnd func(RunRecord)
}

// lower adds causes and missed heartbeats, and reports the new health and
// whether it changed (only a change is persisted).
func (r *runHealth) lower(missed int, causes ...DegradedCause) (Health, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	changed := false
	for _, c := range causes {
		if c.Valid() && !r.h.Has(c) {
			r.h.Causes = append(r.h.Causes, c)
			changed = true
		}
	}
	if missed > 0 {
		r.h.MissedHeartbeats += missed
		if !r.h.Has(CauseHeartbeatMissed) {
			r.h.Causes = append(r.h.Causes, CauseHeartbeatMissed)
		}
		changed = true
	}
	sortCauses(r.h.Causes)
	return Health{Causes: slices.Clone(r.h.Causes), MissedHeartbeats: r.h.MissedHeartbeats}, changed
}

// markDirty records that the health changed under rec and reports whether
// the caller must start the run's delivery goroutine (none is running).
func (r *runHealth) markDirty(rec RunRecord) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dirty, r.rec = true, rec
	if r.delivering {
		return false
	}
	r.delivering = true
	return true
}

// takeDirty hands the delivery goroutine the latest health to deliver;
// ok=false ends the goroutine (nothing new), with the end hook to call
// when the run has ended.
func (r *runHealth) takeDirty() (RunRecord, Health, func(RunRecord), bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.dirty {
		r.delivering = false
		if r.ended {
			return r.rec, Health{}, r.onEnd, false
		}
		return RunRecord{}, Health{}, nil, false
	}
	r.dirty = false
	return r.rec, Health{Causes: slices.Clone(r.h.Causes), MissedHeartbeats: r.h.MissedHeartbeats}, nil, true
}

// end marks the run ended and reports whether the caller runs onEnd now
// (no delivery in flight); otherwise the delivery goroutine runs it when it
// finishes.
func (r *runHealth) end(rec RunRecord, onEnd func(RunRecord)) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ended, r.onEnd = true, onEnd
	if r.rec.RunID == "" {
		r.rec = rec
	}
	return !r.delivering
}

// snapshot returns the current health.
func (r *runHealth) snapshot() Health {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Health{Causes: slices.Clone(r.h.Causes), MissedHeartbeats: r.h.MissedHeartbeats}
}

// HookRegistration is what a host-side read of a tool's hook configuration
// found: the events Observer's command is registered for, whether another
// surface carries Observer's wiring (a plugin), and whether the file could
// not be read as a hook configuration at all (a conflict or a parse error).
// Disabled names each hooks-off switch found set for the tool in any scope
// the vendor reads, the project files under the run's roots included (a box
// can write those), as "<switch id>@<path>", sorted.
type HookRegistration struct {
	Events   []string
	Covered  bool
	Conflict bool
	Disabled []string
}

// hookDriftRules is the drift table, walked top down: the first row that
// matches says the registration drifted from the launch's. Only a LOSS
// against the launch counts (an event Observer registered later is not a
// capture problem).
var hookDriftRules = []struct {
	name    string
	drifted func(launch, now HookRegistration) bool
}{
	{"the file stopped reading as a hook configuration", func(l, n HookRegistration) bool { return n.Conflict && !l.Conflict }},
	{"the surface that carried the wiring is gone", func(l, n HookRegistration) bool { return l.Covered && !n.Covered }},
	{"an event the launch registered is gone", func(l, n HookRegistration) bool {
		for _, ev := range l.Events {
			if !slices.Contains(n.Events, ev) {
				return true
			}
		}
		return false
	}},
	{"a switch turned the hooks off", func(l, n HookRegistration) bool {
		for _, sw := range n.Disabled {
			if !slices.Contains(l.Disabled, sw) {
				return true
			}
		}
		return false
	}},
}

// HookDrift reports whether now drifted from the launch's registration, and
// the rule that said so.
func HookDrift(launch, now HookRegistration) (bool, string) {
	for _, r := range hookDriftRules {
		if r.drifted(launch, now) {
			return true, r.name
		}
	}
	return false, ""
}

// HealthReport is the host helper's run_health request body: what it saw
// lower the run since its last report that the daemon answered (deltas, so
// a report that failed is carried into the next one and nothing is counted
// twice).
type HealthReport struct {
	V                int  `json:"v"`
	HooksDrifted     bool `json:"hooks_drifted,omitempty"`
	MissedHeartbeats int  `json:"missed_heartbeats,omitempty"`
	Dropped          int  `json:"dropped,omitempty"`
}

// healthReportVersion is HealthReport's version.
const healthReportVersion = 1

// maxHealthCount bounds a reported count (a report is a lowering, never a
// way to grow a counter without bound).
const maxHealthCount = 1 << 20

// ErrHealthReport reports a health report that fails validation.
var ErrHealthReport = errors.New("sandboxrelayd: health report refused")

// EncodeHealthReport renders r.
func EncodeHealthReport(r HealthReport) ([]byte, error) {
	r.V = healthReportVersion
	return json.Marshal(r)
}

// DecodeHealthReport parses and validates a report (strict: no unknown
// field, counts in range).
func DecodeHealthReport(b []byte) (HealthReport, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var r HealthReport
	if err := d.Decode(&r); err != nil {
		return HealthReport{}, fmt.Errorf("%w: %w", ErrHealthReport, err)
	}
	if d.More() || r.V != healthReportVersion || r.MissedHeartbeats < 0 || r.Dropped < 0 ||
		r.MissedHeartbeats > maxHealthCount || r.Dropped > maxHealthCount {
		return HealthReport{}, fmt.Errorf("%w: fields", ErrHealthReport)
	}
	return r, nil
}

// pendingHealth is what the helper has seen and not yet reported.
type pendingHealth struct {
	mu       sync.Mutex
	rep      HealthReport
	reported bool // hooks_drifted already reached the daemon
	sending  bool
}

// add records more of what lowered the run; it reports whether anything
// new is waiting.
func (p *pendingHealth) add(drifted bool, missed, dropped int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if drifted && !p.reported {
		p.rep.HooksDrifted = true
	}
	p.rep.MissedHeartbeats = min(p.rep.MissedHeartbeats+max(missed, 0), maxHealthCount)
	p.rep.Dropped = min(p.rep.Dropped+max(dropped, 0), maxHealthCount)
	return p.rep.HooksDrifted || p.rep.MissedHeartbeats > 0 || p.rep.Dropped > 0
}

// take hands the waiting report to one sender at a time (ok=false: nothing
// to send, or a send is in flight).
func (p *pendingHealth) take() (HealthReport, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sending || !(p.rep.HooksDrifted || p.rep.MissedHeartbeats > 0 || p.rep.Dropped > 0) {
		return HealthReport{}, false
	}
	p.sending = true
	r := p.rep
	p.rep = HealthReport{}
	return r, true
}

// done ends a send: a failed one puts its report back.
func (p *pendingHealth) done(r HealthReport, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sending = false
	if err == nil {
		if r.HooksDrifted {
			p.reported = true
		}
		return
	}
	p.rep.HooksDrifted = p.rep.HooksDrifted || r.HooksDrifted
	p.rep.MissedHeartbeats = min(p.rep.MissedHeartbeats+r.MissedHeartbeats, maxHealthCount)
	p.rep.Dropped = min(p.rep.Dropped+r.Dropped, maxHealthCount)
}
