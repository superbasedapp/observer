package secreachsvc

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultCacheTTL is how long a Cache keeps one import list.
const DefaultCacheTTL = 2 * time.Minute

// Cache keeps the import lists Tiers builds per project root (the Go
// list, each codeintel language list, each directory's installed Python
// metadata) for a TTL, so a surface that asks often (a findings list, its
// sort order, the finding drawer) pays the parse once: a cold parse of a
// large repository can take seconds where a warm one takes a few hundred
// milliseconds. Concurrent callers for one key wait for the one build. The
// lists are not watched: an edit shows after the TTL. A list a bound
// stopped (a cold parse that ran out of time) is kept for an eighth of the
// TTL only, so the next ask retries soon; a build the caller canceled is
// not kept.
//
// A background cache (NewBackgroundCache) also never makes a caller wait
// for a refresh: past its TTL an entry is served as it is, for up to its
// stale window, while one rebuild runs in the background (at most `workers`
// at a time across the cache), and a caller whose context carries
// WithoutColdWait does not wait for a list nobody has built yet either: the
// build starts in the background and the caller decides those findings
// without it (Pending reports that). The Code security findings list uses
// one, so a page of findings from twenty projects is not twenty cold
// parses (2026-11-06: 10 to 20 s per page on a live node).
//
// The zero Cache is not usable; NewCache builds one. A nil *Cache caches
// nothing.
type Cache struct {
	ttl time.Duration
	// stale is how long past its TTL a background cache serves an entry
	// while it rebuilds; 0 for a plain cache.
	stale time.Duration
	// workers bounds the background builds running at once; nil for a
	// plain cache (no background builds).
	workers chan struct{}
	now     func() time.Time
	mu      sync.Mutex
	entries map[string]*cacheEntry
}

type cacheEntry struct {
	mu      sync.Mutex
	built   time.Time
	expires time.Time
	val     any
	valid   bool
	// inflight is closed when the running build of this entry ends; nil
	// while none runs. A caller that must wait for a list waits on it
	// rather than starting a second build.
	inflight chan struct{}
}

// maxCacheEntries bounds the keys a Cache keeps (the oldest is dropped).
const maxCacheEntries = 64

// backgroundBuildLimit bounds one background build (the parse's own
// limits normally stop it far sooner).
const backgroundBuildLimit = 2 * time.Minute

// NewCache returns a cache keeping each list for ttl (DefaultCacheTTL when
// ttl <= 0).
func NewCache(ttl time.Duration) *Cache {
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	return &Cache{ttl: ttl, now: time.Now, entries: map[string]*cacheEntry{}}
}

// NewBackgroundCache returns a cache that keeps each list for ttl
// (DefaultCacheTTL when ttl <= 0), then serves it for up to stale more
// while it rebuilds in the background, running at most workers (at least
// 1) background builds at once.
func NewBackgroundCache(ttl, stale time.Duration, workers int) *Cache {
	c := NewCache(ttl)
	if stale < 0 {
		stale = 0
	}
	if workers < 1 {
		workers = 1
	}
	c.stale, c.workers = stale, make(chan struct{}, workers)
	return c
}

// WithCache makes Tiers reuse import lists through c.
func WithCache(c *Cache) Option { return func(o *options) { o.cache = c } }

// coldWaitKey is the context key of WithoutColdWait.
type coldWaitKey struct{}

// WithoutColdWait returns a context under which a background cache never
// makes Tiers wait for an import list nobody has built yet: the build
// starts in the background and the findings that needed it are decided
// without it. pending reports whether that happened for any list since
// this call. A plain cache, or no cache, ignores it (the build runs inline
// as before).
func WithoutColdWait(ctx context.Context) (out context.Context, pending func() bool) {
	flag := &atomic.Bool{}
	return context.WithValue(ctx, coldWaitKey{}, flag), flag.Load
}

// coldWait returns the flag of a WithoutColdWait context, nil otherwise.
func coldWait(ctx context.Context) *atomic.Bool {
	f, _ := ctx.Value(coldWaitKey{}).(*atomic.Bool)
	return f
}

// built is one build's result: the value, whether it is complete (an
// incomplete one is kept for an eighth of the TTL) and whether the build
// was canceled (not kept).
type built struct {
	val      any
	complete bool
	canceled bool
}

// entry returns key's entry, making it (and dropping the oldest when the
// cache is full) when there is none.
func (c *Cache) entry(key string) *cacheEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		if len(c.entries) >= maxCacheEntries {
			c.dropOldestLocked()
		}
		e = &cacheEntry{}
		c.entries[key] = e
	}
	return e
}

// load returns key's value, building it when the cache holds no fresh
// one. build is given the context to build under: the caller's for an
// inline build, a detached one bounded by backgroundBuildLimit for a
// background build.
func (c *Cache) load(ctx context.Context, key string, build func(context.Context) built) any {
	if c == nil {
		return build(ctx).val
	}
	e := c.entry(key)
	for {
		e.mu.Lock()
		now := c.now()
		if e.valid && now.Before(e.expires) {
			v := e.val
			e.mu.Unlock()
			return v
		}
		background := c.workers != nil
		if background && e.valid && now.Before(e.expires.Add(c.stale)) {
			// Stale while revalidating: serve it, refresh it once.
			if e.inflight == nil {
				c.startLocked(e, build)
			}
			v := e.val
			e.mu.Unlock()
			return v
		}
		if flag := coldWait(ctx); background && flag != nil {
			// Nobody built it (or it is too old to serve): build it in the
			// background and decide without it.
			if e.inflight == nil {
				c.startLocked(e, build)
			}
			e.mu.Unlock()
			flag.Store(true)
			return nil
		}
		if ch := e.inflight; ch != nil {
			// One build runs already: wait for it, then look again.
			e.mu.Unlock()
			select {
			case <-ch:
				continue
			case <-ctx.Done():
				return nil
			}
		}
		ch := make(chan struct{})
		e.inflight = ch
		e.mu.Unlock()

		b := build(ctx)

		e.mu.Lock()
		e.inflight = nil
		close(ch)
		e.valid = false
		if ctx.Err() == nil && !b.canceled {
			c.storeLocked(e, b)
		}
		e.mu.Unlock()
		return b.val
	}
}

// startLocked starts e's background build (e.mu held). The build waits for
// a worker slot, runs under a detached, bounded context and stores its
// result unless it was canceled; a refresh that fails keeps the entry it
// was refreshing.
func (c *Cache) startLocked(e *cacheEntry, build func(context.Context) built) {
	ch := make(chan struct{})
	e.inflight = ch
	go func() {
		c.workers <- struct{}{}
		ctx, cancel := context.WithTimeout(context.Background(), backgroundBuildLimit)
		b := build(ctx)
		failed := ctx.Err() != nil || b.canceled
		cancel()
		<-c.workers
		e.mu.Lock()
		e.inflight = nil
		close(ch)
		if !failed {
			c.storeLocked(e, b)
		}
		e.mu.Unlock()
	}()
}

// storeLocked keeps b in e (e.mu held): for the TTL, or an eighth of it
// when the build was incomplete.
func (c *Cache) storeLocked(e *cacheEntry, b built) {
	ttl := c.ttl
	if !b.complete {
		ttl /= 8
	}
	now := c.now()
	e.val, e.built, e.expires, e.valid = b.val, now, now.Add(ttl), true
}

// optionKey is the part of a cache key the options change.
func optionKey(o options) string {
	return strconv.FormatBool(o.codeIntel != nil) + strconv.FormatBool(o.preferCodeIntel)
}

// get returns root's Go import list, building it through the source
// ladder when the cache holds no fresh one.
func (c *Cache) get(ctx context.Context, o options, root string) *GoImports {
	v := c.load(ctx, root+"\x00"+optionKey(o), func(ctx context.Context) built {
		list := goImportsFor(ctx, o, root)
		return built{val: list, complete: list == nil || list.complete(), canceled: list != nil && list.Stats.Stopped == StoppedCanceled}
	})
	g, _ := v.(*GoImports)
	return g
}

// dropOldestLocked drops the entry built longest ago (c.mu held). An entry
// a build is running for, or that another caller holds, is kept.
func (c *Cache) dropOldestLocked() {
	oldestKey, oldest := "", time.Time{}
	for k, e := range c.entries {
		if e.mu.TryLock() {
			b, busy := e.built, e.inflight != nil
			e.mu.Unlock()
			if busy {
				continue
			}
			if oldestKey == "" || b.Before(oldest) {
				oldestKey, oldest = k, b
			}
		}
	}
	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}
