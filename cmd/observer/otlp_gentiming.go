//go:build !sbo_omit_ingest_otlp

package main

import (
	"context"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/otlpvendor"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// otlp_gentiming.go puts a native OTLP export's per-call generation timing
// onto the tool's OWN transcript token row (AP-131 follow-up). The mapping
// (which export field is the duration, which is the join key, which
// token_usage column it equals) is the vendor table's (otlpvendor
// Vendor.TranscriptTiming + a KindGenTiming rule); the write is the store's
// one seam (store.StampTranscriptGenTiming, gen_basis "otel", native timing
// always wins). This file owns only the ordering problem: an export may
// arrive BEFORE the watcher has ingested the transcript row it describes.
//
// Late arrival: a stamp whose row is missing (or whose write failed
// transiently) is parked in an in-memory set owned by the otlpIngest and
// retried on every later export and on a ticker, until its row appears or
// genTimingPendingTTL passes. The set is bounded and is NOT durable: a stamp
// still parked when the daemon stops, or whose row never lands within the
// TTL, is dropped and that call keeps no otel timing (the transcript row and
// every other part of the export are unaffected). The export batch itself is
// never NACKed for a missing row: a retryable status would make the
// exporter resend everything else and, at shutdown, would not be honoured.
const (
	// genTimingPendingTTL bounds how long a parked stamp waits for its
	// transcript row. The watcher ingests a live transcript within seconds;
	// the margin covers a backlog after the daemon catches up.
	genTimingPendingTTL = 10 * time.Minute
	// genTimingPendingMax bounds the parked set; a stamp beyond it is
	// dropped (logged once).
	genTimingPendingMax = 4096
	// genTimingRetryEvery is the ticker period of the background retry, so
	// the last calls of a session (whose export is flushed at exit, often
	// before the watcher reads the final transcript line) still land when no
	// further export arrives.
	genTimingRetryEvery = 15 * time.Second
)

// genTimingPending is the parked-stamp set: stamp -> when it was first seen.
type genTimingPending struct {
	mu    sync.Mutex
	items map[store.TranscriptGenStamp]time.Time
}

// park adds a stamp, keeping its first-seen time; false when the set is full.
func (p *genTimingPending) park(st store.TranscriptGenStamp, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.items[st]; ok {
		return true
	}
	if p.items == nil {
		p.items = map[store.TranscriptGenStamp]time.Time{}
	}
	if len(p.items) >= genTimingPendingMax {
		return false
	}
	p.items[st] = now
	return true
}

// take removes and returns every parked stamp still inside the TTL, with its
// first-seen time; expired ones are dropped and counted.
func (p *genTimingPending) take(now time.Time) (live map[store.TranscriptGenStamp]time.Time, expired int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.items) == 0 {
		return nil, 0
	}
	live = make(map[store.TranscriptGenStamp]time.Time, len(p.items))
	for st, seen := range p.items {
		if now.Sub(seen) > genTimingPendingTTL {
			expired++
			continue
		}
		live[st] = seen
	}
	p.items = nil
	return live, expired
}

// restore re-parks a stamp with its ORIGINAL first-seen time.
func (p *genTimingPending) restore(st store.TranscriptGenStamp, seen time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.items == nil {
		p.items = map[store.TranscriptGenStamp]time.Time{}
	}
	if _, ok := p.items[st]; !ok && len(p.items) < genTimingPendingMax {
		p.items[st] = seen
	}
}

// size reports how many stamps are parked.
func (p *genTimingPending) size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.items)
}

// genStampFromOTLP converts a mapped export timing to the store's stamp.
func genStampFromOTLP(gt otlpvendor.GenTiming) store.TranscriptGenStamp {
	return store.TranscriptGenStamp{
		Tool: gt.Tool, SessionID: gt.SessionID, Key: string(gt.Key), KeyValue: gt.KeyValue, GenMs: gt.DurationMS,
	}
}

// stampGenTiming writes one stamp, reporting whether it must be retried
// (its row is not there yet, or the write failed transiently). A permanent
// failure is logged and not retried.
func (o *otlpIngest) stampGenTiming(ctx context.Context, st store.TranscriptGenStamp) (retry bool) {
	outcome, err := o.st.StampTranscriptGenTiming(ctx, st)
	switch {
	case err != nil && otlpTransientWrite(err):
		return true
	case err != nil:
		o.logger.Warn("otlp ingest: generation timing not stamped", "tool", st.Tool, "session", st.SessionID, "err", err)
		return false
	}
	return outcome == store.GenStampNoRow
}

// stampGenTimings writes an export's admitted timings, parking each one
// whose transcript row is not there yet.
func (o *otlpIngest) stampGenTimings(ctx context.Context, stamps []store.TranscriptGenStamp) {
	now := o.clock()
	for _, st := range stamps {
		if o.stampGenTiming(ctx, st) && !o.genPending.park(st, now) {
			o.warnOnce("gentiming-full", "otlp ingest: too many generation timings waiting for their transcript rows; dropping new ones", "max", genTimingPendingMax)
		}
	}
}

// retryPendingGenTimings re-tries every parked stamp once. Called at the
// start of each export and by runGenTimingRetry.
func (o *otlpIngest) retryPendingGenTimings(ctx context.Context) {
	live, expired := o.genPending.take(o.clock())
	if expired > 0 {
		o.logger.Debug("otlp ingest: generation timings expired before their transcript rows landed", "count", expired)
	}
	for st, seen := range live {
		if ctx.Err() != nil || o.stampGenTiming(ctx, st) {
			o.genPending.restore(st, seen)
		}
	}
}

// runGenTimingRetry retries the parked stamps on a ticker until ctx ends.
func (o *otlpIngest) runGenTimingRetry(ctx context.Context) {
	t := time.NewTicker(genTimingRetryEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if o.genPending.size() > 0 {
				o.retryPendingGenTimings(ctx)
			}
		}
	}
}
