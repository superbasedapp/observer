package applane

import (
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/reserve"
)

// Cap is one app cap a lane call reserves against, in one unit, as the
// caller resolved it: who it counts (EndUser and Service, "" meaning any),
// the start of its window, and the spend already RECORDED in that window
// (read by the caller from its store; the ledger adds what it holds).
type Cap struct {
	// Group names the cap; the USD and token limits of one cap share it
	// (reserve.Limit.Group).
	Group string
	// Name says which cap this is, for the refusal and the log ("org_app",
	// "machine_user_5h", ...).
	Name string
	// EndUser and Service filter the spend the cap counts; "" means any.
	EndUser, Service string
	// Since is the start of the cap's window.
	Since time.Time
	// Unit is reserve.UnitUSD or reserve.UnitTokens.
	Unit reserve.Unit
	// Limit is the cap.
	Limit float64
	// Recorded is the spend the caller's store recorded in the window.
	Recorded float64
	// Soft makes a breach warn instead of refuse.
	Soft bool
}

// Request is one lane call to reserve.
type Request struct {
	// Caps are the caps in scope, in the caller's canonical order.
	Caps []Cap
	// EndUser and Service are the call's app identity, recorded on the hold
	// so later calls' caps count it.
	EndUser, Service string
	// WorstUSD and WorstTokens are the call's worst case.
	WorstUSD    float64
	WorstTokens int64
	// UnpricedUSD is true when the model has no price: a USD cap cannot
	// bound the call, so a USD cap in scope refuses it (reserve's unknown
	// estimate rule; the gateway's unpriced-model posture).
	UnpricedUSD bool
	// Force writes the hold even when the decision refuses (observe mode:
	// the books stay true while nothing is refused).
	Force bool
	// Now is the reservation instant.
	Now time.Time
}

// Close says how a hold ends.
type Close struct {
	// Outcome is reserve.OutcomeSettle (the actual is known),
	// reserve.OutcomeRelease (the call cost nothing: refused upstream,
	// never sent) or reserve.OutcomeReconcile (the call ran but its cost is
	// unknown: it stays at its worst case, never $0).
	Outcome reserve.Outcome
	// USD and Tokens are the actual, read for OutcomeSettle.
	USD    float64
	Tokens int64
	// RecordedElsewhere is true when the caller's store will also record
	// this call's spend (the gateway rail's synthesized span): the settled
	// hold then counts only for the ledger's grace, until the store's read
	// includes it. False keeps it counted for the hold's retention.
	RecordedElsewhere bool
}

// DefaultGrace is how long a settled hold the store also records keeps
// counting, so a reservation made before the store's read catches up still
// sees it. Over-counting for this window is the conservative side.
const DefaultGrace = 30 * time.Second

// DefaultRetention is how long a settled hold the store does NOT record
// keeps counting: longer than the longest cap window (a calendar month).
const DefaultRetention = 32 * 24 * time.Hour

// DefaultMaxEntries bounds the ledger; the oldest settled entries go first.
const DefaultMaxEntries = 100000

// Ledger is the in-memory reservation book of the machine's app lanes. The
// zero value is NOT ready; use NewLedger. Safe for concurrent use: Reserve
// decides and writes the hold under one lock, so N concurrent calls can
// never all pass a cap only one of them fits under.
type Ledger struct {
	mu         sync.Mutex
	entries    []*entry
	grace      time.Duration
	retention  time.Duration
	maxEntries int
}

type entry struct {
	endUser, service string
	at               time.Time
	usd              float64
	tokens           float64
	open             bool
	settledAt        time.Time
	recorded         bool
}

// NewLedger returns an empty ledger with the default grace, retention and
// bound.
func NewLedger() *Ledger {
	return &Ledger{grace: DefaultGrace, retention: DefaultRetention, maxEntries: DefaultMaxEntries}
}

// Hold is one reserved call. Close is idempotent: only the first call books.
type Hold struct {
	l *Ledger
	e *entry
}

// Decision is the verdict on a Request, with the hold when one was written.
type Decision struct {
	reserve.Decision
	// Hold is the written hold (nil when nothing was held: no cap in scope,
	// or a refusal without Force).
	Hold *Hold
}

// Reserve decides r against its caps plus everything the ledger holds, and
// writes the hold when the call is admitted (or Force is set). A request
// with no caps is admitted with no hold: nothing to count against.
func (l *Ledger) Reserve(r Request) Decision {
	if len(r.Caps) == 0 {
		return Decision{Decision: reserve.Decision{Admitted: true, Rule: reserve.RuleWithinCaps}}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(r.Now)
	limits := make([]reserve.Limit, 0, len(r.Caps))
	for _, c := range r.Caps {
		est := r.WorstUSD
		if c.Unit == reserve.UnitTokens {
			est = float64(r.WorstTokens)
		}
		limits = append(limits, reserve.Limit{
			Group:     c.Group,
			Name:      c.Name,
			Unit:      c.Unit,
			Cap:       c.Limit,
			Committed: c.Recorded + l.heldLocked(c, r.Now),
			Estimate:  est,
			Soft:      c.Soft,
		})
	}
	req := reserve.Request{Limits: limits}
	if r.UnpricedUSD {
		req.Unknown = []reserve.Unit{reserve.UnitUSD}
	}
	d := Decision{Decision: reserve.Admit(req)}
	if !d.Admitted && !r.Force {
		return d
	}
	e := &entry{
		endUser: r.EndUser,
		service: strings.ToLower(strings.TrimSpace(r.Service)),
		at:      r.Now,
		usd:     r.WorstUSD,
		tokens:  float64(r.WorstTokens),
		open:    true,
	}
	l.entries = append(l.entries, e)
	l.boundLocked()
	d.Hold = &Hold{l: l, e: e}
	return d
}

// Close ends the hold: settle books the actual (an overrun is recorded, never
// clamped), release refunds it, reconcile keeps the worst case. A nil hold or
// a second Close is a no-op.
func (h *Hold) Close(c Close, now time.Time) {
	if h == nil || h.l == nil || h.e == nil {
		return
	}
	h.l.mu.Lock()
	defer h.l.mu.Unlock()
	e := h.e
	if !e.open {
		return
	}
	usd, uerr := reserve.Settle(reserve.Hold{State: reserve.HoldOpen, Estimate: e.usd}, reserve.Close{Outcome: c.Outcome, Actual: c.USD})
	tok, terr := reserve.Settle(reserve.Hold{State: reserve.HoldOpen, Estimate: e.tokens}, reserve.Close{Outcome: c.Outcome, Actual: float64(c.Tokens)})
	if uerr != nil || terr != nil {
		// An outcome reserve does not know: keep the worst case (never
		// under-count).
		usd.Booked, tok.Booked = e.usd, e.tokens
	}
	e.open = false
	e.settledAt = now
	e.usd, e.tokens = usd.Booked, tok.Booked
	// A call whose cost the store never learns (reconcile: unknown usage)
	// stays counted for the retention whatever the caller says.
	e.recorded = c.RecordedElsewhere && c.Outcome == reserve.OutcomeSettle
}

// Held returns the spend the ledger counts for a cap at now (open holds at
// their worst case, settled holds while they still count). For status
// surfaces and tests.
func (l *Ledger) Held(c Cap, now time.Time) float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.heldLocked(c, now)
}

// Open returns how many holds are open (calls in flight).
func (l *Ledger) Open() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, e := range l.entries {
		if e.open {
			n++
		}
	}
	return n
}

func (l *Ledger) heldLocked(c Cap, now time.Time) float64 {
	svc := strings.ToLower(strings.TrimSpace(c.Service))
	var sum float64
	for _, e := range l.entries {
		if e.at.Before(c.Since) || !l.countsLocked(e, now) {
			continue
		}
		if c.EndUser != "" && e.endUser != c.EndUser {
			continue
		}
		if svc != "" && e.service != svc {
			continue
		}
		if c.Unit == reserve.UnitTokens {
			sum += e.tokens
		} else {
			sum += e.usd
		}
	}
	return sum
}

// countsLocked is the counting rule table: an open hold counts; a settled
// hold the store does not record counts for the retention; a settled hold
// the store records counts for the grace only.
func (l *Ledger) countsLocked(e *entry, now time.Time) bool {
	switch {
	case e.open:
		return true
	case !e.recorded:
		return now.Sub(e.settledAt) < l.retention
	default:
		return now.Sub(e.settledAt) < l.grace
	}
}

// pruneLocked drops settled entries that no longer count.
func (l *Ledger) pruneLocked(now time.Time) {
	kept := l.entries[:0]
	for _, e := range l.entries {
		if l.countsLocked(e, now) {
			kept = append(kept, e)
		}
	}
	for i := len(kept); i < len(l.entries); i++ {
		l.entries[i] = nil
	}
	l.entries = kept
}

// boundLocked drops the oldest SETTLED entries past maxEntries. Open holds
// are never dropped: a call in flight always counts.
func (l *Ledger) boundLocked() {
	over := len(l.entries) - l.maxEntries
	if over <= 0 {
		return
	}
	kept := l.entries[:0]
	for _, e := range l.entries {
		if over > 0 && !e.open {
			over--
			continue
		}
		kept = append(kept, e)
	}
	for i := len(kept); i < len(l.entries); i++ {
		l.entries[i] = nil
	}
	l.entries = kept
}
