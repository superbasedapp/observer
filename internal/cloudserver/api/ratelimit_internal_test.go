package api

import (
	"testing"
	"time"
)

// TestFixedWindowLimiter is a pure, DB-free table walk of the limiter core:
// burst-then-exhaust, window refill after the reset, per-key isolation, and the
// disabled (limit<=0) mode. It uses an injected clock so refill is deterministic.
func TestFixedWindowLimiter(t *testing.T) {
	t.Run("burst exhausts then denies", func(t *testing.T) {
		clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
		l := newFixedWindowLimiter(3, time.Minute, clk.now)
		for i := 0; i < 3; i++ {
			if ok, _ := l.allow("k"); !ok {
				t.Fatalf("hit %d: want allowed", i+1)
			}
		}
		ok, retry := l.allow("k")
		if ok {
			t.Fatal("4th hit: want denied")
		}
		if retry <= 0 || retry > time.Minute {
			t.Fatalf("retry-after=%v, want (0, 1m]", retry)
		}
	})

	t.Run("window refills after reset", func(t *testing.T) {
		clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
		l := newFixedWindowLimiter(2, time.Minute, clk.now)
		l.allow("k")
		l.allow("k")
		if ok, _ := l.allow("k"); ok {
			t.Fatal("3rd hit in window: want denied")
		}
		// Advance past the window ⇒ counter refills.
		clk.advance(time.Minute + time.Second)
		if ok, _ := l.allow("k"); !ok {
			t.Fatal("post-window hit: want allowed (refilled)")
		}
	})

	t.Run("per-key isolation", func(t *testing.T) {
		clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
		l := newFixedWindowLimiter(1, time.Minute, clk.now)
		if ok, _ := l.allow("a"); !ok {
			t.Fatal("a first hit: want allowed")
		}
		if ok, _ := l.allow("a"); ok {
			t.Fatal("a second hit: want denied")
		}
		// A different key has its own independent budget.
		if ok, _ := l.allow("b"); !ok {
			t.Fatal("b first hit: want allowed (isolated from a)")
		}
	})

	t.Run("disabled mode (limit<=0) always allows", func(t *testing.T) {
		clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
		for _, lim := range []int{0, -1} {
			l := newFixedWindowLimiter(lim, time.Minute, clk.now)
			for i := 0; i < 1000; i++ {
				if ok, retry := l.allow("k"); !ok || retry != 0 {
					t.Fatalf("limit=%d hit %d: want allowed with 0 retry", lim, i)
				}
			}
		}
	})

	t.Run("nil limiter allows", func(t *testing.T) {
		var l *fixedWindowLimiter
		if ok, _ := l.allow("k"); !ok {
			t.Fatal("nil limiter: want allowed")
		}
	})
}

// TestRateLimitConfigFromEnv covers the default-vs-override-vs-disable ladder.
func TestRateLimitConfigFromEnv(t *testing.T) {
	t.Run("defaults when unset", func(t *testing.T) {
		for _, k := range []string{"SBCI_RATELIMIT_WINDOW", "SBCI_RATELIMIT_IP", "SBCI_RATELIMIT_DEVICE", "SBCI_RATELIMIT_ACCOUNT"} {
			t.Setenv(k, "")
		}
		cfg := RateLimitConfigFromEnv()
		if cfg.Window != defaultRateWindow || cfg.IPPerWindow != defaultRateIP ||
			cfg.DevicePerWindow != defaultRateDevice || cfg.AccountPerWindow != defaultRateAccount {
			t.Fatalf("defaults not applied: %+v", cfg)
		}
	})

	t.Run("overrides and explicit-zero disable", func(t *testing.T) {
		t.Setenv("SBCI_RATELIMIT_WINDOW", "30s")
		t.Setenv("SBCI_RATELIMIT_IP", "0") // explicit disable
		t.Setenv("SBCI_RATELIMIT_DEVICE", "7")
		t.Setenv("SBCI_RATELIMIT_ACCOUNT", "9")
		cfg := RateLimitConfigFromEnv()
		if cfg.Window != 30*time.Second {
			t.Fatalf("window=%v, want 30s", cfg.Window)
		}
		if cfg.IPPerWindow != 0 || cfg.DevicePerWindow != 7 || cfg.AccountPerWindow != 9 {
			t.Fatalf("overrides not applied: %+v", cfg)
		}
	})

	t.Run("garbage falls back to default", func(t *testing.T) {
		t.Setenv("SBCI_RATELIMIT_IP", "not-a-number")
		t.Setenv("SBCI_RATELIMIT_WINDOW", "not-a-duration")
		cfg := RateLimitConfigFromEnv()
		if cfg.IPPerWindow != defaultRateIP {
			t.Fatalf("IP=%d, want default %d on garbage", cfg.IPPerWindow, defaultRateIP)
		}
		if cfg.Window != defaultRateWindow {
			t.Fatalf("window=%v, want default on garbage", cfg.Window)
		}
	})
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }
