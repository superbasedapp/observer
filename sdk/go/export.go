package superbased

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

const failureLogInterval = time.Minute

// exportStats are the process-wide export counters, read by Diagnostics.
type exportStats struct {
	mu            sync.Mutex
	handed        int64 // spans handed to a destination (once per destination)
	exported      int64
	abandoned     int64 // written off by a timed-out flush; may still arrive
	failedExports int64
	dropped       int64
	lastError     string
	lastErrorAt   time.Time
	lastLoggedAt  time.Time
	unlogged      int64
}

var stats = &exportStats{}

func (s *exportStats) reset() {
	s.mu.Lock()
	s.handed, s.exported, s.abandoned, s.failedExports, s.dropped, s.unlogged = 0, 0, 0, 0, 0, 0
	s.lastError, s.lastErrorAt, s.lastLoggedAt = "", time.Time{}, time.Time{}
	s.mu.Unlock()
}

func (s *exportStats) pendingLocked() int64 {
	p := s.handed - s.exported - s.dropped - s.abandoned
	if p < 0 {
		return 0
	}
	return p
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// countingExporter wraps a SpanExporter: it never panics into the processor,
// counts exported and dropped spans and failed exports, and (when quiet)
// keeps the error away from the OpenTelemetry error handler.
type countingExporter struct {
	inner sdktrace.SpanExporter
	quiet bool
}

func (c *countingExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) (err error) {
	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("exporter panic: %v", r)
			}
		}()
		err = c.inner.ExportSpans(ctx, spans)
	}()
	n := int64(len(spans))
	stats.mu.Lock()
	late := min(stats.abandoned, n)
	stats.abandoned -= late
	if err == nil {
		stats.dropped -= late
		stats.exported += n
	} else {
		if late == 0 {
			stats.failedExports++
			stats.unlogged++
		}
		stats.dropped += n - late
		stats.lastError = clip(err.Error(), 500)
		stats.lastErrorAt = time.Now()
	}
	stats.mu.Unlock()
	if err != nil {
		maybeLogFailures(time.Now())
		if c.quiet {
			return nil
		}
	}
	return err
}

func (c *countingExporter) Shutdown(ctx context.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = nil
		}
	}()
	if e := c.inner.Shutdown(ctx); e != nil && !c.quiet {
		return e
	}
	return nil
}

// maybeLogFailures writes at most one summary line per minute.
func maybeLogFailures(now time.Time) bool {
	stats.mu.Lock()
	if stats.unlogged == 0 || now.Sub(stats.lastLoggedAt) < failureLogInterval {
		stats.mu.Unlock()
		return false
	}
	n, errText, total := stats.unlogged, stats.lastError, stats.dropped
	stats.unlogged = 0
	stats.lastLoggedAt = now
	stats.mu.Unlock()
	if errText == "" {
		errText = "unknown"
	}
	logf(slog.LevelWarn, "%d trace export(s) failed since the last report (%d spans dropped in total); last error: %s", n, total, errText)
	return true
}

// legsOf is how many counted destinations a delegate hands each span to.
func legsOf(p sdktrace.SpanProcessor) int64 {
	if l, ok := p.(interface{ legs() int64 }); ok {
		return l.legs()
	}
	return 1
}

// discard is the delegate of a plan with nowhere to export: every span is
// counted as dropped (never silently lost; Diagnostics says why).
type discard struct{}

func (discard) OnStart(context.Context, sdktrace.ReadWriteSpan) {}
func (discard) OnEnd(sdktrace.ReadOnlySpan) {
	stats.mu.Lock()
	stats.dropped++
	stats.mu.Unlock()
}
func (discard) Shutdown(context.Context) error   { return nil }
func (discard) ForceFlush(context.Context) error { return nil }

// fanout is several processors as one delegate: one per destination of both,
// plus the console option. ForceFlush and Shutdown run them concurrently, so a
// destination that is down never spends the other's share of the deadline.
type fanout struct {
	procs []sdktrace.SpanProcessor
	n     int64 // counted destinations
}

func (f *fanout) legs() int64 { return f.n }

func (f *fanout) OnStart(ctx context.Context, s sdktrace.ReadWriteSpan) {
	for _, p := range f.procs {
		p.OnStart(ctx, s)
	}
}

func (f *fanout) OnEnd(s sdktrace.ReadOnlySpan) {
	for _, p := range f.procs {
		p.OnEnd(s)
	}
}

func (f *fanout) each(ctx context.Context, fn func(sdktrace.SpanProcessor) error) error {
	errs := make([]error, len(f.procs))
	var wg sync.WaitGroup
	for i, p := range f.procs {
		wg.Add(1)
		go func(i int, p sdktrace.SpanProcessor) {
			defer wg.Done()
			errs[i] = fn(p)
		}(i, p)
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

func (f *fanout) Shutdown(ctx context.Context) error {
	return f.each(ctx, func(p sdktrace.SpanProcessor) error { return p.Shutdown(ctx) })
}

func (f *fanout) ForceFlush(ctx context.Context) error {
	return f.each(ctx, func(p sdktrace.SpanProcessor) error { return p.ForceFlush(ctx) })
}

// consoleExporter prints each span as one JSON line (Options.Console).
type consoleExporter struct {
	mu sync.Mutex
	w  io.Writer
}

func (c *consoleExporter) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range spans {
		attrs := map[string]any{}
		for _, kv := range s.Attributes() {
			attrs[string(kv.Key)] = kv.Value.AsInterface()
		}
		line, _ := json.Marshal(map[string]any{
			"name": s.Name(), "trace_id": s.SpanContext().TraceID().String(), "span_id": s.SpanContext().SpanID().String(),
			"parent_span_id": s.Parent().SpanID().String(), "scope": s.InstrumentationScope().Name,
			"start": s.StartTime(), "end": s.EndTime(), "status": s.Status().Code.String(), "attributes": attrs,
		})
		fmt.Fprintln(c.w, string(line))
	}
	return nil
}
func (c *consoleExporter) Shutdown(context.Context) error { return nil }

// switchableProcessor is the one span processor the SDK adds to the provider
// holding the app's spans. It forwards to a replaceable delegate, stamps
// identity and per-request attributes the span does not carry, and applies
// the export pipeline before the delegate sees a finished span.
type switchableProcessor struct {
	mu              sync.RWMutex
	delegate        sdktrace.SpanProcessor
	stamp           []attribute.KeyValue
	pipe            *pipeline
	shutdownTimeout time.Duration
}

func (p *switchableProcessor) swap(d sdktrace.SpanProcessor, stamp []attribute.KeyValue) sdktrace.SpanProcessor {
	p.mu.Lock()
	defer p.mu.Unlock()
	old := p.delegate
	p.delegate, p.stamp = d, stamp
	return old
}

func (p *switchableProcessor) detach() sdktrace.SpanProcessor { return p.swap(nil, nil) }

func (p *switchableProcessor) current() sdktrace.SpanProcessor {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.delegate
}

func (p *switchableProcessor) setPipeline(pp *pipeline) {
	p.mu.Lock()
	p.pipe = pp
	p.mu.Unlock()
}

func sameValue(a, b attribute.Value) bool {
	return a.Type() == b.Type() && a.Emit() == b.Emit()
}

func (p *switchableProcessor) OnStart(ctx context.Context, s sdktrace.ReadWriteSpan) {
	p.mu.RLock()
	d, stamp := p.delegate, p.stamp
	p.mu.RUnlock()
	if d == nil {
		return
	}
	func() {
		defer func() { _ = recover() }()
		noteServiceName(s)
		existing := map[attribute.Key]attribute.Value{}
		for _, kv := range s.Attributes() {
			existing[kv.Key] = kv.Value
		}
		scope := currentScope(ctx).attributes()
		scopeTags := false
		for _, kv := range scope {
			if kv.Key == keyTags {
				scopeTags = true
			}
			if _, ok := existing[kv.Key]; !ok {
				s.SetAttributes(kv)
				existing[kv.Key] = kv.Value
			}
		}
		res := map[attribute.Key]attribute.Value{}
		if r := s.Resource(); r != nil {
			for _, kv := range r.Attributes() {
				res[kv.Key] = kv.Value
			}
		}
		for _, kv := range stamp {
			if rv, ok := res[kv.Key]; ok && sameValue(rv, kv.Value) {
				continue // the resource already says so
			}
			if cur, ok := existing[kv.Key]; !ok {
				s.SetAttributes(kv)
			} else if kv.Key == keyTags && scopeTags {
				s.SetAttributes(attribute.StringSlice(keyTags, normalizeTags(cur.AsStringSlice(), kv.Value.AsStringSlice())))
			}
		}
	}()
	func() {
		defer func() { _ = recover() }()
		d.OnStart(ctx, s)
	}()
}

func (p *switchableProcessor) OnEnd(s sdktrace.ReadOnlySpan) {
	p.mu.RLock()
	d, pipe := p.delegate, p.pipe
	p.mu.RUnlock()
	if d == nil {
		return
	}
	if pipe != nil {
		s = pipe.decide(s)
		if s == nil {
			return
		}
	}
	stats.mu.Lock()
	stats.handed += legsOf(d)
	stats.mu.Unlock()
	func() {
		defer func() { _ = recover() }()
		d.OnEnd(s)
	}()
}

// Shutdown is called when the HOLDING provider shuts down.
func (p *switchableProcessor) Shutdown(ctx context.Context) error {
	if old := p.detach(); old != nil {
		shutdownBounded(old, p.shutdownTimeout)
	}
	return nil
}

func (p *switchableProcessor) ForceFlush(ctx context.Context) error {
	d := p.current()
	if d == nil {
		return nil
	}
	return d.ForceFlush(ctx)
}

// noteTimeout: a flush or shutdown ran out of time; the spans still
// unresolved count as dropped (they may still arrive: abandoned).
func noteTimeout(op string, timeout time.Duration) {
	stats.mu.Lock()
	pending := stats.pendingLocked()
	stats.failedExports++
	stats.abandoned += pending
	stats.dropped += pending
	stats.unlogged++
	msg := fmt.Sprintf("%s timed out after %s with %d span(s) not exported", op, timeout, pending)
	if stats.lastError != "" {
		msg += "; exporter: " + stats.lastError
	}
	stats.lastError = clip(msg, 500)
	stats.lastErrorAt = time.Now()
	stats.mu.Unlock()
}

// runBounded runs fn with a context that ends after timeout and waits at most
// that long: a stuck exporter cannot block the host.
func runBounded(timeout time.Duration, fn func(context.Context) error) (finished bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("panic: %v", r)
			}
		}()
		done <- fn(ctx)
	}()
	select {
	case e := <-done:
		if e != nil && ctx.Err() != nil {
			return false, e
		}
		return true, e
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func flushBounded(p sdktrace.SpanProcessor, timeout time.Duration) bool {
	stats.mu.Lock()
	droppedBefore := stats.dropped
	stats.mu.Unlock()
	finished, err := runBounded(timeout, p.ForceFlush)
	if !finished {
		noteTimeout("flush", timeout)
	}
	// True only when nothing failed, was dropped or is still pending, in
	// every quiet mode (review FR-S07).
	stats.mu.Lock()
	clean := stats.pendingLocked() == 0 && stats.dropped <= droppedBefore
	stats.mu.Unlock()
	return finished && err == nil && clean
}

func shutdownBounded(p sdktrace.SpanProcessor, timeout time.Duration) bool {
	finished, _ := runBounded(timeout, p.Shutdown)
	if !finished {
		noteTimeout("shutdown", timeout)
	}
	return finished
}

var stderr io.Writer = os.Stderr
