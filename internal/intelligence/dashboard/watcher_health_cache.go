package dashboard

import (
	"context"
	"sync"
	"time"
)

// watcherHealthFreshTTL is how long a computed /api/health/watcher payload is
// served as-is (optimization review 2026-09-27, finding N5,
// docs/audits/optimization-review-2026-09-27.md).
//
// The payload is one cheap query plus an os.Stat of EVERY file the watcher
// has a cursor for — 7,427 files on the reference node, 2,159 of them on a
// /mnt/c DrvFs mount where a stat is a 9P round trip. That fan-out measured
// 2.7 s warm and 21-37 s cold, and the always-mounted Sidebar requests it on
// every page load (then every 60 s), so it was routinely the LAST response of
// a page load — the Overview page's wall time was the watcher stat, not its
// data. The answer only ever feeds a "the watcher has fallen behind" banner
// and the VS Code lag notifier, both of which are read on a minutes scale.
const watcherHealthFreshTTL = 20 * time.Second

// watcherHealthStaleServeMax bounds stale-while-revalidate: an entry older
// than watcherHealthFreshTTL but younger than this is served immediately
// while ONE background recompute refreshes it. The payload's own checked_at
// is the time the stat pass actually ran, so a stale answer is labelled as
// such on the wire rather than passed off as current.
const watcherHealthStaleServeMax = 10 * time.Minute

// watcherHealthCache is the one owner of the memoized payload. Only the
// production handler chain uses it (Options.ReadCaches); with it off every
// request recomputes, exactly as before.
type watcherHealthCache struct {
	// gate serializes computations (a blocking miss and a background
	// refresh never stat the file set concurrently).
	gate sync.Mutex

	mu         sync.Mutex
	payload    map[string]any
	at         time.Time
	valid      bool
	refreshing bool
	bg         sync.WaitGroup
}

func (c *watcherHealthCache) get(now time.Time) (payload map[string]any, fresh, stale bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.valid {
		return nil, false, false
	}
	age := now.Sub(c.at)
	switch {
	case age < 0:
		return nil, false, false
	case age < watcherHealthFreshTTL:
		return c.payload, true, false
	case age < watcherHealthStaleServeMax:
		return c.payload, false, true
	}
	return nil, false, false
}

func (c *watcherHealthCache) put(now time.Time, payload map[string]any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.payload, c.at, c.valid = payload, now, true
}

func (c *watcherHealthCache) beginRefresh() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.refreshing {
		return false
	}
	c.refreshing = true
	c.bg.Add(1)
	return true
}

func (c *watcherHealthCache) endRefresh() {
	c.mu.Lock()
	c.refreshing = false
	c.mu.Unlock()
	c.bg.Done()
}

// watcherHealthScanTimeout bounds one detached recompute (the stat fan-out
// cannot be cancelled mid-stat, but the query and the next file can).
const watcherHealthScanTimeout = 2 * time.Minute

// watcherHealthCached serves /api/health/watcher from the memoized payload:
// fresh entries directly, stale ones immediately plus one background
// recompute, and computes synchronously (singleflight through gate) only when
// there is nothing servable. Like the status snapshot, the computation runs
// detached from the requesting client (the SPA aborts polls on navigation),
// so the work it paid for is kept.
func (s *Server) watcherHealthCached(ctx context.Context) (map[string]any, error) {
	c := &s.watcherHealth
	if p, fresh, stale := c.get(s.now()); fresh {
		return p, nil
	} else if stale {
		if c.beginRefresh() {
			scanCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), watcherHealthScanTimeout)
			go func() {
				defer c.endRefresh()
				defer cancel()
				c.gate.Lock()
				defer c.gate.Unlock()
				if _, fresh, _ := c.get(s.now()); fresh {
					return
				}
				if out, err := s.computeWatcherHealth(scanCtx); err == nil {
					c.put(s.now(), out)
				}
			}()
		}
		return p, nil
	}
	c.gate.Lock()
	defer c.gate.Unlock()
	if p, fresh, _ := c.get(s.now()); fresh {
		return p, nil
	}
	scanCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), watcherHealthScanTimeout)
	defer cancel()
	out, err := s.computeWatcherHealth(scanCtx)
	if err != nil {
		return nil, err
	}
	c.put(s.now(), out)
	return out, nil
}
