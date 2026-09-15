package crossmount

import (
	"testing"
	"time"
)

// swapExtrasScan installs a counting stub for the cache's refill seam
// and restores the original (plus a clean cache) on cleanup.
func swapExtrasScan(t *testing.T, homes []HomeRoot) *int {
	t.Helper()
	calls := 0
	orig := extrasScan
	extrasScan = func() []HomeRoot {
		calls++
		out := make([]HomeRoot, len(homes))
		copy(out, homes)
		return out
	}
	resetExtrasCacheForTest()
	t.Cleanup(func() {
		extrasScan = orig
		resetExtrasCacheForTest()
	})
	return &calls
}

// TestExtraHomesCachedWithinTTL pins the hot-path property the
// 2026-08-29 goroutine dump demanded: repeated ExtraHomes/AllHomes
// calls inside the TTL run exactly ONE underlying mount scan. Without
// the cache, watcher-health resolved ~5k cursor rows at one 9P scan
// each and the endpoint never returned.
func TestExtraHomesCachedWithinTTL(t *testing.T) {
	calls := swapExtrasScan(t, []HomeRoot{{Path: "/mnt/c/Users/u1", OS: OSWindows, Origin: "wsl-mnt:u1"}})

	for i := 0; i < 50; i++ {
		if got := ExtraHomes(); len(got) != 1 || got[0].Path != "/mnt/c/Users/u1" {
			t.Fatalf("call %d: got %+v, want the one stubbed home", i, got)
		}
		_ = AllHomes()
	}
	if *calls != 1 {
		t.Fatalf("underlying scans = %d, want 1 (100 lookups inside the TTL must share one scan)", *calls)
	}
}

// TestExtraHomesRescansAfterTTL proves the cache is a TTL, not a
// process-lifetime freeze: expiring it triggers exactly one fresh scan.
func TestExtraHomesRescansAfterTTL(t *testing.T) {
	calls := swapExtrasScan(t, nil)

	_ = ExtraHomes()
	if *calls != 1 {
		t.Fatalf("scans after first call = %d, want 1", *calls)
	}

	// Force expiry without sleeping.
	extrasCache.mu.Lock()
	extrasCache.expires = time.Now().Add(-time.Second)
	extrasCache.mu.Unlock()

	_ = ExtraHomes()
	if *calls != 2 {
		t.Fatalf("scans after expiry = %d, want 2", *calls)
	}
}

// TestExtraHomesReturnsACopy pins the aliasing rule: a caller mutating
// its result slice must not corrupt what later callers receive.
func TestExtraHomesReturnsACopy(t *testing.T) {
	swapExtrasScan(t, []HomeRoot{{Path: "/mnt/c/Users/u1", OS: OSWindows, Origin: "wsl-mnt:u1"}})

	first := ExtraHomes()
	first[0].Path = "/mangled"

	if got := ExtraHomes(); got[0].Path != "/mnt/c/Users/u1" {
		t.Fatalf("second caller saw %q — cache aliased the returned slice", got[0].Path)
	}
}
