package oteldirect

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)

func TestLimiterRequests(t *testing.T) {
	type step struct {
		at        time.Duration
		n         int // requests sent at this instant
		allowed   int
		retryWant time.Duration // retry-after of the last refused one (0: none refused)
	}
	cases := []struct {
		name  string
		cfg   QuotaConfig
		steps []step
	}{
		{"burst then refuse", QuotaConfig{RequestsPerMinute: 60, Burst: 120, RowsPerMinute: 2000}, []step{
			{0, 121, 120, time.Second},
		}},
		{"refill at the sustained rate", QuotaConfig{RequestsPerMinute: 60, Burst: 120, RowsPerMinute: 2000}, []step{
			{0, 120, 120, 0},
			{10 * time.Second, 11, 10, time.Second},
		}},
		{"refill caps at the burst", QuotaConfig{RequestsPerMinute: 60, Burst: 5, RowsPerMinute: 2000}, []step{
			{0, 5, 5, 0},
			{time.Hour, 6, 5, time.Second},
		}},
		{"slow rate retry-after", QuotaConfig{RequestsPerMinute: 1, Burst: 1, RowsPerMinute: 2000}, []step{
			{0, 2, 1, time.Minute},
		}},
		{"zero config takes the defaults", QuotaConfig{}, []step{
			{0, 121, 120, time.Second},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := NewLimiter(c.cfg)
			for si, s := range c.steps {
				allowed := 0
				var retry time.Duration
				for i := 0; i < s.n; i++ {
					ok, ra := l.AllowRequest("tok", t0.Add(s.at))
					if ok {
						allowed++
					} else {
						retry = ra
					}
				}
				if allowed != s.allowed || retry != s.retryWant {
					t.Fatalf("step %d: allowed %d retry %v, want %d %v", si, allowed, retry, s.allowed, s.retryWant)
				}
			}
		})
	}
}

func TestLimiterRows(t *testing.T) {
	cfg := QuotaConfig{RequestsPerMinute: 60, Burst: 120, RowsPerMinute: 600} // 10 rows/s
	cases := []struct {
		name    string
		batches []struct {
			at   time.Duration
			rows int
			ok   bool
		}
		lastRetry time.Duration
	}{
		{"within the minute's allowance", []struct {
			at   time.Duration
			rows int
			ok   bool
		}{{0, 300, true}, {0, 300, true}, {0, 1, false}}, time.Second},
		{"one oversized batch passes, then repays", []struct {
			at   time.Duration
			rows int
			ok   bool
		}{{0, 1200, true}, {30 * time.Second, 10, false}, {61 * time.Second, 10, true}}, 0},
		{"zero rows always pass", []struct {
			at   time.Duration
			rows int
			ok   bool
		}{{0, 600, true}, {0, 0, true}}, 0},
		{"refill", []struct {
			at   time.Duration
			rows int
			ok   bool
		}{{0, 600, true}, {time.Second, 10, true}, {time.Second, 1, false}}, time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := NewLimiter(cfg)
			var retry time.Duration
			for i, b := range c.batches {
				ok, ra := l.AllowRows("tok", b.rows, t0.Add(b.at))
				if ok != b.ok {
					t.Fatalf("batch %d: ok=%v want %v", i, ok, b.ok)
				}
				if !ok {
					retry = ra
				}
			}
			if c.lastRetry != 0 && retry != c.lastRetry {
				t.Fatalf("retry-after = %v, want %v", retry, c.lastRetry)
			}
		})
	}
	// The oversized batch's refusal names the repayment time.
	l := NewLimiter(cfg)
	l.AllowRows("tok", 1200, t0)
	if _, ra := l.AllowRows("tok", 1, t0); ra != 60*time.Second {
		t.Fatalf("overdraft retry-after = %v, want 60s", ra)
	}
}

func TestLimiterKeysAreIndependent(t *testing.T) {
	l := NewLimiter(QuotaConfig{RequestsPerMinute: 60, Burst: 1, RowsPerMinute: 2000})
	if ok, _ := l.AllowRequest("a", t0); !ok {
		t.Fatal("a refused")
	}
	if ok, _ := l.AllowRequest("a", t0); ok {
		t.Fatal("a allowed twice")
	}
	if ok, _ := l.AllowRequest("b", t0); !ok {
		t.Fatal("b refused by a's bucket")
	}
}

func TestLimiterEviction(t *testing.T) {
	cases := []struct {
		name    string
		maxKeys int
		after   time.Duration
		wantLen int
	}{
		// Full buckets after the refill window are evicted losslessly at
		// the next sweep (at most once a minute).
		{"idle keys swept after refill", 1000, 3 * time.Minute, 1},
		{"recent keys kept before a sweep is due", 1000, 30 * time.Second, 11},
		// Past MaxKeys the least recently seen go, even when not full.
		{"bounded by MaxKeys", 5, 0, 5},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := NewLimiter(QuotaConfig{RequestsPerMinute: 60, Burst: 120, RowsPerMinute: 2000, MaxKeys: c.maxKeys})
			for i := 0; i < 10; i++ {
				l.AllowRequest(fmt.Sprintf("k%d", i), t0)
			}
			l.AllowRequest("late", t0.Add(c.after))
			if got := l.Len(); got != c.wantLen {
				t.Fatalf("keys = %d, want %d", got, c.wantLen)
			}
		})
	}
	// LRU: the most recently seen key survives a MaxKeys eviction.
	l := NewLimiter(QuotaConfig{RequestsPerMinute: 1, Burst: 2, RowsPerMinute: 2000, MaxKeys: 3})
	l.AllowRequest("old", t0)
	l.AllowRequest("mid", t0.Add(time.Second))
	l.AllowRequest("new", t0.Add(2*time.Second))
	l.AllowRequest("new", t0.Add(2*time.Second))
	l.AllowRequest("next", t0.Add(3*time.Second))
	if ok, _ := l.AllowRequest("new", t0.Add(3*time.Second)); ok {
		t.Fatal("the recently used key was evicted (its empty bucket reset)")
	}
}

func TestLimiterConcurrent(t *testing.T) {
	l := NewLimiter(QuotaConfig{RequestsPerMinute: 60, Burst: 100, RowsPerMinute: 2000})
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if ok, _ := l.AllowRequest("tok", t0); ok {
					mu.Lock()
					allowed++
					mu.Unlock()
				}
				l.AllowRows("tok", 1, t0)
			}
		}()
	}
	wg.Wait()
	if allowed != 100 {
		t.Fatalf("allowed = %d, want exactly the burst 100", allowed)
	}
}
