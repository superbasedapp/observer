package proccapture

import "time"

// BudgetState is how many exemplar rows have already been kept for the
// run's tool call, session, session-minute and service. A small value type:
// the caller reads it from its Ledger for each run and passes it to
// Classify, which never mutates anything.
type BudgetState struct {
	ToolCall int
	Session  int
	Minute   int
	Service  int
}

type minuteKey struct {
	session string
	minute  int64
}

// Ledger is the caller-owned budget counter set (one per Observer, one per
// replay). Not safe for concurrent use: the live Observer drives it from its
// single drain goroutine. Findings, failures and tool-linked runs (R1-R3)
// never take a slot, so they can never be turned away by a full budget.
type Ledger struct {
	toolCall map[string]int
	session  map[string]int
	minute   map[minuteKey]int
	service  map[string]int
}

// NewLedger returns an empty Ledger.
func NewLedger() *Ledger {
	return &Ledger{
		toolCall: make(map[string]int),
		session:  make(map[string]int),
		minute:   make(map[minuteKey]int),
		service:  make(map[string]int),
	}
}

func minuteOf(f RunFacts) minuteKey {
	return minuteKey{session: f.SessionID, minute: f.Time.Unix() / 60}
}

// State returns the run's current BudgetState.
func (l *Ledger) State(f RunFacts) BudgetState {
	s := BudgetState{Session: l.session[f.SessionID], Minute: l.minute[minuteOf(f)]}
	if f.ToolCallKey != "" {
		s.ToolCall = l.toolCall[f.ToolCallKey]
	}
	if f.ServiceRootKey != "" {
		s.Service = l.service[f.ServiceRootKey]
	}
	return s
}

// Record takes the slots a FINAL decision consumes. Call it once per run,
// when the decision stops being provisional.
func (l *Ledger) Record(f RunFacts, d Decision) {
	if d.ConsumesBudget {
		l.session[f.SessionID]++
		l.minute[minuteOf(f)]++
		if f.ToolCallKey != "" {
			l.toolCall[f.ToolCallKey]++
		}
	}
	if d.ConsumesService && f.ServiceRootKey != "" {
		l.service[f.ServiceRootKey]++
	}
}

// PruneMinutes forgets per-minute counters older than before. The live
// Observer calls it on its flush tick so the burst guard's map stays small.
func (l *Ledger) PruneMinutes(before time.Time) {
	cut := before.Unix() / 60
	for k := range l.minute {
		if k.minute < cut {
			delete(l.minute, k)
		}
	}
}

// ForgetToolCall drops one tool call's counter (its root ended long ago).
func (l *Ledger) ForgetToolCall(key string) { delete(l.toolCall, key) }

// ForgetService drops one service root's counter.
func (l *Ledger) ForgetService(key string) { delete(l.service, key) }
