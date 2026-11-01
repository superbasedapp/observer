package termfeed

import (
	"sync"
	"sync/atomic"
	"time"
)

// Trust classifies whether an event came from a trusted source (a hook event
// or the OOB launcher channel — authoritative) or is an untrusted hint (parsed
// from the attacker-controlled PTY stream — §2.1b). F4 weights trusted signals
// as anchors and PTY hints as early-warning only, so the discriminator travels
// with every event.
type Trust string

const (
	// TrustTrusted — a hook / OOB / transcript-of-record signal.
	TrustTrusted Trust = "trusted"
	// TrustHint — an untrusted hint from the PTY byte stream (never authorizes).
	TrustHint Trust = "hint"
)

// Event is one normalized signal on the feed. It is intentionally minimal —
// ids + a Kind string + trust + timestamp — so producers at different
// ingestion boundaries (hooks, transcript tail, OOB lifecycle, PTY hints)
// converge on one shape without threading their own types through the feed.
// The Kind vocabulary is owned by the producers, not this package.
type Event struct {
	// Kind is the producer-defined event kind (e.g. "hook:PreToolUse",
	// "transcript:turn", "oob:tool_exec_end", "pty:bell").
	Kind string
	// SessionID is the agent session the event concerns, when known ("" when the
	// event predates correlation).
	SessionID string
	// RunID is the terminal_run this event is attributed to, when known.
	RunID string
	// Tool is the source tool, when known.
	Tool string
	// Trust marks the event trusted or a hint.
	Trust Trust
	// At is the event time (UTC); the producer sets it.
	At time.Time
	// Count is a lifecycle frame's count, when it carries one (the sandbox
	// gateway's refusals held off the tool's screen); 0 otherwise.
	Count int
}

// Options configures a Feed. Both bounds default when non-positive.
type Options struct {
	// ReplayCap is how many recent events a late subscriber replays on join.
	ReplayCap int
	// QueueCap is each subscriber's outbound queue depth. A full queue drops the
	// oldest event (Lost++) rather than blocking the publisher.
	QueueCap int
}

const (
	defaultReplayCap = 256
	defaultQueueCap  = 256
)

// Feed is a bounded, in-process fan-out event feed. One Feed is shared by the
// producers (via Publish) and the consumers (via Subscribe). Safe for
// concurrent use.
type Feed struct {
	replayCap int
	queueCap  int

	mu     sync.Mutex
	replay []Event // bounded ring, oldest-first
	subs   map[*Sub]struct{}
}

// New builds a Feed with the given bounds.
func New(opts Options) *Feed {
	rc := opts.ReplayCap
	if rc <= 0 {
		rc = defaultReplayCap
	}
	qc := opts.QueueCap
	if qc <= 0 {
		qc = defaultQueueCap
	}
	return &Feed{
		replayCap: rc,
		queueCap:  qc,
		subs:      make(map[*Sub]struct{}),
	}
}

// Publish delivers an event to the replay ring and every live subscriber. It
// NEVER blocks: a subscriber whose queue is full loses its oldest event (that
// subscriber's Lost counter increments) so the producer hot path is never
// stalled. Safe to call concurrently, though the ordered replay ring is
// strongest with a single producer.
func (f *Feed) Publish(ev Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Append to the bounded replay ring.
	if len(f.replay) == f.replayCap {
		copy(f.replay, f.replay[1:])
		f.replay[len(f.replay)-1] = ev
	} else {
		f.replay = append(f.replay, ev)
	}
	// Fan out (non-blocking, drop-oldest on a full subscriber queue).
	for s := range f.subs {
		s.offer(ev)
	}
}

// Subscribe registers a new consumer. The returned Sub replays up to ReplayCap
// recent events (newest of them, if the ring is larger than the queue) and then
// receives live events on C(). The caller MUST Close the Sub when done.
func (f *Feed) Subscribe() *Sub {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := &Sub{ch: make(chan Event, f.queueCap)}
	// Seed with replay history, keeping the NEWEST when history exceeds the
	// queue depth (an overflowed seed increments Lost so the consumer sees it).
	start := 0
	if len(f.replay) > f.queueCap {
		start = len(f.replay) - f.queueCap
		s.lost.Add(uint64(start))
	}
	for _, ev := range f.replay[start:] {
		s.ch <- ev // guaranteed to fit: at most queueCap events
	}
	f.subs[s] = struct{}{}
	return s
}

// SubscriberCount returns the number of live subscribers (test/introspection).
func (f *Feed) SubscriberCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.subs)
}

// Unsubscribe removes and closes a subscriber. Publish never touches a removed
// subscriber (both take the feed lock), so the channel close is race-free.
func (f *Feed) Unsubscribe(s *Sub) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.subs[s]; ok {
		delete(f.subs, s)
		close(s.ch)
	}
}

// Sub is one consumer's view of the feed: a bounded queue plus a lost-event
// counter. Read from C(); check Lost() to detect gaps.
type Sub struct {
	ch   chan Event
	lost atomic.Uint64
}

// C is the receive channel. It is closed when the Sub is unsubscribed.
func (s *Sub) C() <-chan Event { return s.ch }

// Lost is the number of events this subscriber missed due to queue overflow
// (including any dropped during a large replay seed). A non-zero, growing value
// means the consumer is not keeping up and should re-sync from the store.
func (s *Sub) Lost() uint64 { return s.lost.Load() }

// offer enqueues ev without blocking. On a full queue it drops the OLDEST
// queued event and records the loss, then enqueues the newest — so a slow
// consumer always sees the most recent state with a visible gap, never a stall.
// Called only under the Feed lock (single offerer at a time).
func (s *Sub) offer(ev Event) {
	select {
	case s.ch <- ev:
		return
	default:
	}
	// Queue full: make room by discarding the oldest, then enqueue.
	select {
	case <-s.ch:
		s.lost.Add(1)
	default:
		// Consumer drained it between the two selects; fall through to enqueue.
	}
	select {
	case s.ch <- ev:
	default:
		// Still full (consumer racing): count the newest as lost rather than block.
		s.lost.Add(1)
	}
}
