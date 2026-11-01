package natslog

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Connection recovery (T-883).
//
// The incident: an external broker was unreachable for about four hours. The
// nats.go client's default reconnect budget is 60 attempts per server
// (nats.DefaultMaxReconnect) at a 2 s wait plus jitter plus the dial timeout,
// a few minutes in all. When it ran out the library dropped the server from its
// pool and CLOSED the connection for good, and every later call on this Log
// returned nats.ErrConnectionClosed, mapped to telemetrylog.ErrUnavailable:
// readyz said log-unavailable and every consumer backed off forever after the
// broker was healthy again. Only a process restart recovered.
//
// Two layers now make the outage self-healing:
//
//  1. The client reconnects INDEFINITELY (MaxReconnects(-1)), and an auth error
//     seen while the broker restarts does not abort the loop
//     (IgnoreAuthErrorAbort). nats.go keeps the same *nats.Conn across a
//     reconnect, so the JetStream context, the stream handle and every consumer
//     handle keep working once it is back: nothing is cached that needs a
//     rebuild.
//  2. If the library closes the connection anyway (an unrecognised server
//     -ERR still closes it), the Log REBUILDS it: a fresh connection, a fresh
//     JetStream context and a fresh stream handle, with a bounded backoff. The
//     immutable stream identity Subscribe fences against is NOT replaced by a
//     rebuild, so a stream that changed under the outage is still refused with
//     ErrReconnectRequired and still takes the Runner's Reconnect path. Consumer
//     handles bound to the closed connection report ErrReattachRequired, so the
//     Runner re-subscribes them by durable name on the new connection.
//
// Logging is summarised, never per attempt: one WARN when the connection drops,
// one WARN per outageSummaryEvery while it stays down, one INFO when it returns.

// DefaultReconnectWait is the wait between reconnect passes (the nats.go default).
const DefaultReconnectWait = 2 * time.Second

// outageSummaryEvery is how often a still-down connection is summarised in the
// log. A four-hour outage writes about fifty lines, not one per attempt.
const outageSummaryEvery = 5 * time.Minute

// maxRebuildBackoff caps the wait between attempts to rebuild a CLOSED
// connection (layer 2). Reconnects of a live connection (layer 1) use the
// fixed ReconnectWait the library applies.
const maxRebuildBackoff = 30 * time.Second

// ConnectionState is a point-in-time view of the Log's broker connection. It is
// what Probe folds into its Detail while the broker is unreachable, and what a
// test asserts recovery against.
type ConnectionState struct {
	// Connected reports whether the current connection is up.
	Connected bool
	// DownSince is when the current outage began (zero while connected).
	DownSince time.Time
	// FailedReconnects counts failed reconnect attempts in the current outage.
	FailedReconnects uint64
	// Rebuilds counts connections rebuilt after the library closed one.
	Rebuilds uint64
}

// connWatch tracks one Log's connection lifecycle from the nats.go callbacks.
// It has its own lock, never the Log's, so a callback can never wait on a Log
// operation.
type connWatch struct {
	logger *slog.Logger
	now    func() time.Time

	mu          sync.Mutex
	stopping    bool // Close is under way: the drop that follows is ours
	downSince   time.Time
	failed      uint64
	lastSummary time.Time
	lastErr     string
	rebuilds    uint64
	onClosed    func(*nats.Conn)
	closedEarly *nats.Conn // closed before onClosed was bound
}

func newConnWatch(logger *slog.Logger) *connWatch {
	if logger == nil {
		logger = slog.Default()
	}
	return &connWatch{logger: logger, now: time.Now}
}

// options returns the nats.go connection options that make the client recover
// on its own and report through this watch.
func (w *connWatch) options(o Options) []nats.Option {
	jitter := min(o.ReconnectWait/2, nats.DefaultReconnectJitter)
	jitterTLS := min(o.ReconnectWait/2, nats.DefaultReconnectJitterTLS)
	return []nats.Option{
		nats.MaxReconnects(-1),
		nats.ReconnectWait(o.ReconnectWait),
		nats.ReconnectJitter(jitter, jitterTLS),
		nats.IgnoreAuthErrorAbort(),
		// No outbound buffering while disconnected: a publish that fails
		// during an outage fails NOW (ErrUnavailable, a 503 the node retries)
		// instead of sitting in an 8 MiB buffer and being sent hours later,
		// after the caller was already told it failed. Probe, Fetch and trim
		// requests fail fast the same way rather than waiting out a timeout.
		nats.ReconnectBufSize(-1),
		nats.DisconnectErrHandler(w.disconnected),
		nats.ReconnectErrHandler(w.reconnectFailed),
		nats.ReconnectHandler(w.reconnected),
		nats.ClosedHandler(w.closed),
	}
}

// bind installs the Log's closed-connection callback, replaying a close that
// happened before the Log existed.
func (w *connWatch) bind(fn func(*nats.Conn)) {
	w.mu.Lock()
	w.onClosed = fn
	early := w.closedEarly
	w.closedEarly = nil
	w.mu.Unlock()
	if early != nil {
		fn(early)
	}
}

// stop marks the coming disconnect as intentional (Log.Close).
func (w *connWatch) stop() {
	w.mu.Lock()
	w.stopping = true
	w.mu.Unlock()
}

func (w *connWatch) disconnected(nc *nats.Conn, err error) {
	if nc != nil && nc.IsClosed() {
		// A close, not a drop: closed() and the Log decide whether it matters
		// (a failed rebuild attempt closing its own candidate does not).
		return
	}
	w.mu.Lock()
	if w.stopping {
		w.mu.Unlock()
		return
	}
	now := w.now()
	if w.downSince.IsZero() {
		w.downSince = now
	}
	w.lastSummary = now
	w.lastErr = errText(err)
	w.mu.Unlock()
	w.logger.Warn("durable log connection lost; reconnecting indefinitely, the log is unavailable until the broker answers",
		"engine", engineName, "err", errText(err))
}

func (w *connWatch) reconnectFailed(_ *nats.Conn, err error) {
	w.mu.Lock()
	if w.stopping {
		w.mu.Unlock()
		return
	}
	now := w.now()
	if w.downSince.IsZero() {
		w.downSince, w.lastSummary = now, now
	}
	w.failed++
	w.lastErr = errText(err)
	due := now.Sub(w.lastSummary) >= outageSummaryEvery
	if due {
		w.lastSummary = now
	}
	attempts, downFor, last := w.failed, now.Sub(w.downSince), w.lastErr
	w.mu.Unlock()
	if due {
		w.logger.Warn("durable log still unreachable; reconnecting indefinitely",
			"engine", engineName, "attempts", attempts, "down_for", downFor.Round(time.Second).String(), "last_err", last)
	}
}

func (w *connWatch) reconnected(*nats.Conn) {
	w.restored("durable log connection restored")
}

// restored ends the current outage and logs it once.
func (w *connWatch) restored(msg string) {
	w.mu.Lock()
	var downFor time.Duration
	if !w.downSince.IsZero() {
		downFor = w.now().Sub(w.downSince)
	}
	attempts := w.failed
	w.downSince, w.failed, w.lastErr = time.Time{}, 0, ""
	w.mu.Unlock()
	w.logger.Info(msg, "engine", engineName, "down_for", downFor.Round(time.Second).String(), "failed_attempts", attempts)
}

func (w *connWatch) closed(nc *nats.Conn) {
	w.mu.Lock()
	if w.stopping {
		w.mu.Unlock()
		return
	}
	fn := w.onClosed
	if fn == nil {
		w.closedEarly = nc
	}
	w.mu.Unlock()
	if fn != nil {
		fn(nc)
	}
}

// lostForGood records and logs that the Log's CURRENT connection was closed
// by the library (the Log has already ruled out its own Close and a stale
// connection), which starts a rebuild.
func (w *connWatch) lostForGood(nc *nats.Conn) {
	w.mu.Lock()
	if w.downSince.IsZero() {
		w.downSince = w.now()
	}
	w.mu.Unlock()
	w.logger.Error("durable log connection closed by the client library; rebuilding it",
		"engine", engineName, "err", errText(nc.LastError()))
}

// rebuildFailed records one failed rebuild attempt, summarised like a reconnect.
func (w *connWatch) rebuildFailed(err error) {
	w.reconnectFailed(nil, err)
}

// rebuilt records a completed rebuild.
func (w *connWatch) rebuilt() {
	w.mu.Lock()
	w.rebuilds++
	w.mu.Unlock()
	w.restored("durable log connection rebuilt")
}

func (w *connWatch) snapshot() ConnectionState {
	w.mu.Lock()
	defer w.mu.Unlock()
	return ConnectionState{DownSince: w.downSince, FailedReconnects: w.failed, Rebuilds: w.rebuilds}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// ConnectionState reports the broker connection's current state.
func (l *Log) ConnectionState() ConnectionState {
	st := l.watch.snapshot()
	nc, _ := l.client()
	st.Connected = nc != nil && nc.IsConnected()
	if st.Connected {
		st.DownSince = time.Time{}
	}
	return st
}

// client returns the live connection and JetStream context, read under the lock
// because a rebuild replaces them.
func (l *Log) client() (*nats.Conn, jetstream.JetStream) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.nc, l.js
}

// onConnClosed starts the rebuild loop for a connection the library closed.
// A close of a connection that is no longer current, or after Close, is
// ignored, and at most one loop runs at a time.
func (l *Log) onConnClosed(nc *nats.Conn) {
	l.mu.Lock()
	if l.closed || l.rebuilding || nc != l.nc {
		l.mu.Unlock()
		return
	}
	l.rebuilding = true
	l.rebuildWG.Add(1)
	l.mu.Unlock()
	l.watch.lostForGood(nc)
	go l.rebuildLoop()
}

// rebuildLoop retries rebuildOnce with a bounded exponential backoff until it
// succeeds or the Log is closed.
func (l *Log) rebuildLoop() {
	defer l.rebuildWG.Done()
	delay := l.opts.ReconnectWait
	for {
		t := time.NewTimer(delay)
		select {
		case <-l.stopCh:
			t.Stop()
			l.endRebuild()
			return
		case <-t.C:
		}
		err := l.rebuildOnce()
		if err == nil {
			return
		}
		l.watch.rebuildFailed(err)
		delay = min(delay*2, maxRebuildBackoff)
	}
}

func (l *Log) endRebuild() {
	l.mu.Lock()
	l.rebuilding = false
	l.mu.Unlock()
}

// rebuildOnce dials a fresh connection and re-binds the JetStream context and
// the stream handle, exactly as a boot would. It deliberately does NOT adopt the
// stream's identity: Subscribe keeps fencing against the identity this Log was
// built (or last Reconnected) with, so a stream that changed under the outage is
// still refused with ErrReconnectRequired.
func (l *Log) rebuildOnce() error {
	nc, err := connectNATS(l.opts, l.watch)
	if err != nil {
		return fmt.Errorf("natslog: rebuild connection: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return fmt.Errorf("natslog: rebuild jetstream context: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), l.opts.PublishTimeout)
	defer cancel()
	stream, _, err := ensureStream(ctx, js, l.opts)
	if err != nil {
		nc.Close()
		return fmt.Errorf("natslog: rebuild stream handle: %w", streamProvisionErr(err, l.opts.MaxBytes))
	}
	l.mu.Lock()
	if l.closed {
		l.rebuilding = false
		l.mu.Unlock()
		nc.Close()
		return nil
	}
	l.nc, l.js, l.stream, l.rebuilding = nc, js, stream, false
	l.mu.Unlock()
	l.watch.rebuilt()
	return nil
}

// closeConn drains nc and waits, bounded, for it to close, then closes it
// outright. With indefinite reconnects a drain that never completes (the
// broker vanished mid-drain) must not leave a reconnect loop running after the
// Log is closed.
func closeConn(nc *nats.Conn, wait time.Duration) {
	if nc == nil {
		return
	}
	if nc.IsClosed() {
		return
	}
	done := nc.StatusChanged(nats.CLOSED)
	if err := nc.Drain(); err == nil {
		t := time.NewTimer(wait)
		select {
		case <-done:
		case <-t.C:
		}
		t.Stop()
	}
	nc.Close()
}
