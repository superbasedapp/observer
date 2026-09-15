package memlog

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/telemetrylog"
)

// Engine is the adapter name memlog reports from Probe.
const Engine = "memory"

// Default tuning applied when the corresponding Options / spec field is zero.
const (
	defaultDuplicateWindow = 2 * time.Hour
	defaultMaxDeliver      = 5
	defaultAckWait         = 30 * time.Second
	defaultNakDelay        = 1 * time.Second
	pollInterval           = 10 * time.Millisecond
)

// Options configure a memlog Log.
type Options struct {
	// MaxMessages caps the number of stored records; 0 means unbounded. A
	// NET-NEW record that would exceed the cap is rejected with
	// telemetrylog.ErrFull (Discard: New); a duplicate inside the window is
	// still accepted (it stores nothing new).
	MaxMessages int
	// MaxMsgBytes caps a single record's Payload size in bytes; 0 means
	// unbounded. A larger payload is rejected with telemetrylog.ErrTooLarge.
	MaxMsgBytes int
	// DuplicateWindow is how long a DedupID is remembered for de-duplication;
	// 0 means the 2h default. A record whose DedupID was last stored within
	// this window is dropped as a duplicate (PubResult.Duplicate = true);
	// outside it the record is stored again under a new sequence, mirroring
	// JetStream.
	DuplicateWindow time.Duration
	// Now is the clock the log reads for the duplicate window and delivery
	// deadlines; nil means time.Now. Injecting it lets a test prove window
	// expiry without sleeping.
	Now func() time.Time
}

// Log is the in-memory telemetrylog.Log. It is safe for concurrent use.
type Log struct {
	mu         sync.Mutex
	opts       Options
	now        func() time.Time
	closed     bool
	failNext   error
	generation string

	seq       uint64
	records   []*storedMsg
	lastByDup map[string]*storedMsg // DedupID -> most recently stored record
	bytes     uint64
	consumers map[string]*consumerState
}

// storedMsg is one durably-held record with its assigned sequence and store time.
type storedMsg struct {
	rec         telemetrylog.Record
	seq         uint64
	storedAt    time.Time
	payloadSize int
}

// New returns an empty in-memory Log configured by opts.
func New(opts Options) *Log {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	// This adapter owns an immutable log lifetime, independent of the
	// injectable delivery clock and of payload attributes.
	var identity [32]byte
	generation := ""
	if _, err := rand.Read(identity[:]); err == nil {
		generation = "memlog:" + hex.EncodeToString(identity[:])
	}
	return &Log{
		opts:       opts,
		now:        now,
		lastByDup:  make(map[string]*storedMsg),
		consumers:  make(map[string]*consumerState),
		generation: generation,
	}
}

// duplicateWindow resolves the configured window with its default.
func (l *Log) duplicateWindow() time.Duration {
	if l.opts.DuplicateWindow > 0 {
		return l.opts.DuplicateWindow
	}
	return defaultDuplicateWindow
}

// Publish appends rec to the log. See telemetrylog.Log.Publish for the contract.
func (l *Log) Publish(ctx context.Context, rec telemetrylog.Record) (telemetrylog.PubResult, error) {
	if err := ctx.Err(); err != nil {
		return telemetrylog.PubResult{}, fmt.Errorf("memlog.Publish: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return telemetrylog.PubResult{}, fmt.Errorf("memlog.Publish: %w", telemetrylog.ErrClosed)
	}
	if l.failNext != nil {
		err := l.failNext
		l.failNext = nil
		return telemetrylog.PubResult{}, fmt.Errorf("memlog.Publish: %w", err)
	}
	if err := telemetrylog.ValidateRecord(rec); err != nil {
		return telemetrylog.PubResult{}, fmt.Errorf("memlog.Publish: %w", err)
	}
	if l.opts.MaxMsgBytes > 0 && len(rec.Payload) > l.opts.MaxMsgBytes {
		return telemetrylog.PubResult{}, fmt.Errorf("memlog.Publish: %w", telemetrylog.ErrTooLarge)
	}

	now := l.now()

	// Duplicate inside the window: a SUCCESS that stores nothing new.
	if prev, ok := l.lastByDup[rec.DedupID]; ok && now.Sub(prev.storedAt) < l.duplicateWindow() {
		return telemetrylog.PubResult{Sequence: prev.seq, Duplicate: true}, nil
	}

	// A NET-NEW record over the capacity cap is shed.
	if l.opts.MaxMessages > 0 && len(l.records) >= l.opts.MaxMessages {
		return telemetrylog.PubResult{}, fmt.Errorf("memlog.Publish: %w", telemetrylog.ErrFull)
	}

	l.seq++
	msg := &storedMsg{
		rec:         cloneRecord(rec),
		seq:         l.seq,
		storedAt:    now,
		payloadSize: len(rec.Payload),
	}
	l.records = append(l.records, msg)
	l.lastByDup[rec.DedupID] = msg
	l.bytes += uint64(msg.payloadSize)
	return telemetrylog.PubResult{Sequence: msg.seq}, nil
}

// Subscribe attaches (creating it when absent) the durable consumer named by
// spec and returns its pull handle. Reattaching by the same Name reuses the same
// durable cursor and per-record delivery state.
func (l *Log) Subscribe(ctx context.Context, spec telemetrylog.ConsumerSpec) (telemetrylog.Consumer, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("memlog.Subscribe: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil, fmt.Errorf("memlog.Subscribe: %w", telemetrylog.ErrClosed)
	}
	if spec.Name == "" {
		return nil, fmt.Errorf("memlog.Subscribe: %w: empty consumer Name", telemetrylog.ErrInvalidRecord)
	}
	if spec.MaxAckPending < 0 {
		return nil, fmt.Errorf("memlog.Subscribe: %w: MaxAckPending must be non-negative", telemetrylog.ErrInvalidRecord)
	}
	cs, ok := l.consumers[spec.Name]
	if !ok {
		cs = &consumerState{
			name:          spec.Name,
			filters:       append([]string(nil), spec.FilterSubjects...),
			maxDeliver:    resolveMaxDeliver(spec.MaxDeliver),
			ackWait:       resolveAckWait(spec.AckWait),
			states:        make(map[uint64]*deliveryState),
			maxAckPending: spec.MaxAckPending,
		}
		l.consumers[spec.Name] = cs
	} else {
		// Credit belongs to the durable, not an individual handle. Updating
		// it also constrains any already-attached replicas.
		cs.maxAckPending = spec.MaxAckPending
	}
	return &consumer{log: l, state: cs}, nil
}

// Stats returns the engine-reported depth read.
func (l *Log) Stats(ctx context.Context) (telemetrylog.StreamStats, error) {
	if err := ctx.Err(); err != nil {
		return telemetrylog.StreamStats{}, fmt.Errorf("memlog.Stats: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return telemetrylog.StreamStats{}, fmt.Errorf("memlog.Stats: %w", telemetrylog.ErrClosed)
	}
	return l.statsLocked(), nil
}

// statsLocked builds the depth read; the caller holds l.mu.
func (l *Log) statsLocked() telemetrylog.StreamStats {
	st := telemetrylog.StreamStats{
		Messages: uint64(len(l.records)),
		Bytes:    l.bytes,
	}
	if len(l.records) > 0 {
		st.FirstSequence = l.records[0].seq
		st.LastSequence = l.records[len(l.records)-1].seq
	}
	now := l.now()
	for _, cs := range l.consumers {
		st.Consumers = append(st.Consumers, cs.statsLocked(l.records, now))
	}
	return st
}

// Probe reports memlog's health. It never returns an error, it reports one.
func (l *Log) Probe(ctx context.Context) telemetrylog.Report {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return telemetrylog.Report{Engine: Engine, Configured: true, Healthy: false, Detail: "closed"}
	}
	return telemetrylog.Report{
		Engine:     Engine,
		Configured: true,
		Healthy:    true,
		Replicas:   1,
		Stats:      l.statsLocked(),
	}
}

// Close makes every later call return telemetrylog.ErrClosed. It is idempotent.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	return nil
}

// FailNextPublish arms the next Publish call to return err (wrapped), then clears
// the arming. It is a test hook used to pin the collector's 503 / WAL-before-ack
// path (plan §6 criterion 2); pass telemetrylog.ErrUnavailable to simulate an
// unreachable backend.
func (l *Log) FailNextPublish(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failNext = err
}

// SetNow replaces the clock the log reads. It is a convenience for tests that
// did not inject Now via Options; Options.Now is the preferred path.
func (l *Log) SetNow(now func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now == nil {
		now = time.Now
	}
	l.now = now
}

func resolveMaxDeliver(n int) int {
	if n <= 0 {
		return defaultMaxDeliver
	}
	return n
}

func resolveAckWait(d time.Duration) time.Duration {
	if d <= 0 {
		return defaultAckWait
	}
	return d
}

// cloneRecord deep-copies the caller's record so later caller mutations of the
// payload or attrs map cannot reach the stored copy (and vice versa on delivery).
func cloneRecord(r telemetrylog.Record) telemetrylog.Record {
	out := r
	if r.Payload != nil {
		out.Payload = append([]byte(nil), r.Payload...)
	}
	if r.Attrs != nil {
		out.Attrs = make(map[string]string, len(r.Attrs))
		for k, v := range r.Attrs {
			out.Attrs[k] = v
		}
	}
	return out
}
