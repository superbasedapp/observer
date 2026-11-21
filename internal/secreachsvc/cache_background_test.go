package secreachsvc

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// waitIdle waits until key's entry has no build running.
func waitIdle(t *testing.T, c *Cache, key string) {
	t.Helper()
	e := c.entry(key)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		e.mu.Lock()
		ch := e.inflight
		e.mu.Unlock()
		if ch == nil {
			return
		}
		select {
		case <-ch:
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatalf("build of %q still running", key)
}

// constBuild returns a build that counts its calls and returns v.
func constBuild(v string, calls *atomic.Int32) func(context.Context) built {
	return func(context.Context) built {
		calls.Add(1)
		return built{val: v, complete: true}
	}
}

func testClock(c *Cache) *time.Time {
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	return &now
}

// TestBackgroundCacheServesStaleWhileRefreshing: past the TTL the old list
// is served at once while one refresh runs; the refresh's list is served
// after it ends.
func TestBackgroundCacheServesStaleWhileRefreshing(t *testing.T) {
	c := NewBackgroundCache(time.Minute, time.Hour, 1)
	now := testClock(c)
	var calls atomic.Int32
	if got := c.load(context.Background(), "k", constBuild("v1", &calls)); got != "v1" {
		t.Fatalf("first load = %v", got)
	}
	*now = now.Add(2 * time.Minute)
	release := make(chan struct{})
	slow := func(context.Context) built {
		<-release
		calls.Add(1)
		return built{val: "v2", complete: true}
	}
	if got := c.load(context.Background(), "k", slow); got != "v1" {
		t.Fatalf("stale load = %v, want the old list served at once", got)
	}
	// A second caller while the refresh runs: still the old list, and no
	// second refresh.
	if got := c.load(context.Background(), "k", slow); got != "v1" {
		t.Fatalf("second stale load = %v", got)
	}
	close(release)
	waitIdle(t, c, "k")
	if got := c.load(context.Background(), "k", constBuild("v3", &calls)); got != "v2" {
		t.Fatalf("after refresh = %v, want v2", got)
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("builds = %d, want 2 (one inline, one refresh)", n)
	}
}

// TestBackgroundCacheColdNoWait: under WithoutColdWait a list nobody has
// built is built in the background, the caller gets nil and pending; a
// caller that waits joins that build instead of starting another.
func TestBackgroundCacheColdNoWait(t *testing.T) {
	c := NewBackgroundCache(time.Minute, time.Hour, 1)
	testClock(c)
	var calls atomic.Int32
	release := make(chan struct{})
	slow := func(context.Context) built {
		<-release
		calls.Add(1)
		return built{val: "v1", complete: true}
	}
	ctx, pending := WithoutColdWait(context.Background())
	if pending() {
		t.Fatal("pending before any load")
	}
	if got := c.load(ctx, "k", slow); got != nil {
		t.Fatalf("cold no-wait load = %v, want nil", got)
	}
	if !pending() {
		t.Fatal("pending not reported")
	}
	done := make(chan any)
	go func() { done <- c.load(context.Background(), "k", slow) }()
	close(release)
	select {
	case got := <-done:
		if got != "v1" {
			t.Fatalf("waiting load = %v, want v1", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiting load never returned")
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("builds = %d, want the one background build", n)
	}
	ctx2, pending2 := WithoutColdWait(context.Background())
	if got := c.load(ctx2, "k", slow); got != "v1" || pending2() {
		t.Fatalf("warm no-wait load = %v pending %v, want v1 and not pending", got, pending2())
	}
}

// TestBackgroundCacheTable: the remaining rows of the load rule, one case
// each.
func TestBackgroundCacheTable(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"a plain cache ignores WithoutColdWait", func(t *testing.T) {
			c := NewCache(time.Minute)
			testClock(c)
			var calls atomic.Int32
			ctx, pending := WithoutColdWait(context.Background())
			if got := c.load(ctx, "k", constBuild("v", &calls)); got != "v" || pending() {
				t.Fatalf("got %v pending %v, want an inline build", got, pending())
			}
		}},
		{"past the stale window an entry is cold again", func(t *testing.T) {
			c := NewBackgroundCache(time.Minute, time.Hour, 1)
			now := testClock(c)
			var calls atomic.Int32
			c.load(context.Background(), "k", constBuild("v1", &calls))
			*now = now.Add(2 * time.Hour)
			if got := c.load(context.Background(), "k", constBuild("v2", &calls)); got != "v2" {
				t.Fatalf("got %v, want an inline rebuild", got)
			}
		}},
		{"a failed refresh keeps the stale list", func(t *testing.T) {
			c := NewBackgroundCache(time.Minute, time.Hour, 1)
			now := testClock(c)
			var calls atomic.Int32
			c.load(context.Background(), "k", constBuild("v1", &calls))
			*now = now.Add(2 * time.Minute)
			canceled := func(context.Context) built { return built{val: "partial", canceled: true} }
			if got := c.load(context.Background(), "k", canceled); got != "v1" {
				t.Fatalf("got %v", got)
			}
			waitIdle(t, c, "k")
			if got := c.load(context.Background(), "k", canceled); got != "v1" {
				t.Fatalf("after a failed refresh got %v, want the stale v1", got)
			}
		}},
		{"an incomplete background build is kept for an eighth of the TTL", func(t *testing.T) {
			c := NewBackgroundCache(8*time.Minute, time.Hour, 1)
			now := testClock(c)
			ctx, _ := WithoutColdWait(context.Background())
			c.load(ctx, "k", func(context.Context) built { return built{val: "inc", complete: false} })
			waitIdle(t, c, "k")
			var calls atomic.Int32
			if got := c.load(context.Background(), "k", constBuild("full", &calls)); got != "inc" || calls.Load() != 0 {
				t.Fatalf("got %v (builds %d), want the fresh incomplete list", got, calls.Load())
			}
			*now = now.Add(2 * time.Minute)
			if got := c.load(context.Background(), "k", constBuild("full", &calls)); got != "inc" {
				t.Fatalf("got %v, want the stale incomplete list while it refreshes", got)
			}
			waitIdle(t, c, "k")
			if got := c.load(context.Background(), "k", constBuild("again", &calls)); got != "full" {
				t.Fatalf("got %v, want the refreshed list", got)
			}
		}},
		{"a background build runs under a detached context", func(t *testing.T) {
			c := NewBackgroundCache(time.Minute, time.Hour, 1)
			testClock(c)
			parent, cancel := context.WithCancel(context.Background())
			ctx, _ := WithoutColdWait(parent)
			release := make(chan struct{})
			var sawCanceled atomic.Bool
			c.load(ctx, "k", func(bctx context.Context) built {
				<-release
				sawCanceled.Store(bctx.Err() != nil)
				return built{val: "v", complete: true}
			})
			cancel()
			close(release)
			waitIdle(t, c, "k")
			if sawCanceled.Load() {
				t.Fatal("the caller's cancel reached the background build")
			}
			if got := c.load(context.Background(), "k", func(context.Context) built { return built{val: "x", complete: true} }); got != "v" {
				t.Fatalf("got %v, want the background list kept", got)
			}
		}},
		{"a full cache never drops an entry whose build runs", func(t *testing.T) {
			c := NewBackgroundCache(time.Minute, time.Hour, 1)
			testClock(c)
			release := make(chan struct{})
			ctx, _ := WithoutColdWait(context.Background())
			c.load(ctx, "busy", func(context.Context) built { <-release; return built{val: "b", complete: true} })
			var calls atomic.Int32
			for i := 0; i < maxCacheEntries+4; i++ {
				c.load(context.Background(), "k"+string(rune('a'+i%26))+string(rune('a'+i/26)), constBuild("v", &calls))
			}
			c.mu.Lock()
			_, kept := c.entries["busy"]
			c.mu.Unlock()
			close(release)
			if !kept {
				t.Fatal("the running entry was dropped")
			}
			waitIdle(t, c, "busy")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, tc.run)
	}
}
