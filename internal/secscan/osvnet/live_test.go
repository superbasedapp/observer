package osvnet

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
)

// TestLiveRefresh is a live check, skipped unless SBO_LIVE_OSV_NET=1: it
// refreshes two small ecosystems from the real bucket through the lane
// (HEAD, x-goog-hash, streamed CRC32C, zip check), then refreshes again and
// expects no second download.
func TestLiveRefresh(t *testing.T) {
	if os.Getenv("SBO_LIVE_OSV_NET") != "1" {
		t.Skip("SBO_LIVE_OSV_NET not set: live check")
	}
	s := osvdb.Open(t.TempDir())
	c := New(Options{})
	ecos := []string{"crates.io", "NuGet"}
	rep, err := s.Refresh(context.Background(), c, ecos, time.Now())
	if err != nil || len(rep.Changed) != len(ecos) {
		t.Fatalf("first refresh %+v %v", rep, err)
	}
	rep, err = s.Refresh(context.Background(), c, ecos, time.Now())
	if err != nil || len(rep.Unchanged) != len(ecos) {
		t.Fatalf("second refresh must find both current %+v %v", rep, err)
	}
	eps, _ := s.Epochs()
	for _, e := range ecos {
		t.Logf("%s epoch %s (%d bytes)", e, eps[e].String(), eps[e].Size)
	}
}
