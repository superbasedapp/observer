package api

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// auditlimit.go rate-limits IDENTICAL audit rows per source (FR-4 follow-up,
// docs/security.md AUDITRL-1). The ops VM's blackbox probe posts an unsigned
// body to /portal/webhooks/paddle every 2 minutes so that a route that stops
// verifying signatures pages; each probe was one
// paddle_webhook_signature_invalid row in security_audit_events (720 a day),
// which buried that very signal.
//
// The rule, per event in auditRowLimits: at most ONE row per (event, source)
// per window. The first event of a window is written; the rest of that
// window's events are not written but are still counted in
// sbci_audit_events_total and sbci_audit_rows_suppressed_total, and the
// next written row for that (event, source) carries the count in its detail
// ({"suppressed_rows":N,"window_seconds":W}). Nothing is trusted from the
// request: the source is the client IP the trusted-edge middleware
// authenticated (or the TCP peer when the edge is off; edgeClientIP), never
// a header the caller sets, and there is no "this is the probe" marker an
// attacker could copy. An attacker can therefore only thin out rows for
// their OWN source (or, when every request shares one peer, rows of the same
// already-invalid event), while the count of every attempt reaches the
// metrics and the next row, and a source's first attempt in any window is
// always written.

// auditRowLimits is the table of rate-limited audit events and their window.
// An event not listed here is always written. One row per event.
var auditRowLimits = map[string]time.Duration{
	"paddle_webhook_signature_invalid": 10 * time.Minute,
}

// auditLimiterMaxSources bounds the limiter's memory: past it, expired
// windows are dropped, and if every window is live a new source shares one
// overflow window (still limited, still counted; never unbounded growth).
const auditLimiterMaxSources = 4096

// auditOverflowSource is the shared source of the overflow window.
const auditOverflowSource = "overflow"

// auditSourceKey carries the request's audit source (a client IP) in the
// context; only the webhook wrapper sets it (observePaddleWebhook).
type auditSourceKey struct{}

func withAuditSource(ctx context.Context, source string) context.Context {
	return context.WithValue(ctx, auditSourceKey{}, source)
}

func auditSourceFrom(ctx context.Context) (string, bool) {
	src, ok := ctx.Value(auditSourceKey{}).(string)
	return src, ok && src != ""
}

// auditWindow is one (event, source)'s current window.
type auditWindow struct {
	start      time.Time
	window     time.Duration
	suppressed int
}

// auditLimiter is the in-process window table. Its zero value is ready to
// use. Per process: two serve replicas each write at most one row per window.
type auditLimiter struct {
	mu      sync.Mutex
	windows map[string]*auditWindow
}

// admit decides one event: write=true means write the row, carrying the
// previous window's suppressed count; write=false means the row is
// suppressed (and counted in the current window).
func (l *auditLimiter) admit(event, source string, window time.Duration, now time.Time) (write bool, carried int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.windows == nil {
		l.windows = map[string]*auditWindow{}
	}
	key := event + "\x00" + source
	w, ok := l.windows[key]
	if !ok && len(l.windows) >= auditLimiterMaxSources {
		for k, v := range l.windows {
			if !now.Before(v.start.Add(v.window)) {
				// An expired window's count is not lost from the metrics,
				// only from the next row; dropping it bounds memory.
				delete(l.windows, k)
			}
		}
		if len(l.windows) >= auditLimiterMaxSources {
			key = event + "\x00" + auditOverflowSource
			w, ok = l.windows[key]
		}
	}
	if ok && now.Before(w.start.Add(w.window)) && !now.Before(w.start) {
		w.suppressed++
		return false, 0
	}
	if ok {
		carried = w.suppressed
	}
	l.windows[key] = &auditWindow{start: now, window: window}
	return true, carried
}

// auditRowDetail is the detail JSON of a row that carries suppressed rows
// ("" when there are none, which RecordAudit stores as {}).
func auditRowDetail(carried int, window time.Duration) string {
	if carried <= 0 {
		return ""
	}
	return fmt.Sprintf(`{"suppressed_rows":%d,"window_seconds":%d}`, carried, int64(window/time.Second))
}
