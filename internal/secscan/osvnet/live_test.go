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
// expects no second download: each ecosystem is current or updated record
// by record (the watermark margin re-fetches the newest records).
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
	if err != nil || len(rep.Failed) != 0 || len(rep.Changed) != len(rep.Incremental) {
		t.Fatalf("second refresh must not download an export again %+v %v", rep, err)
	}
	eps, _ := s.Epochs()
	for _, e := range ecos {
		t.Logf("%s epoch %s (%d bytes)", e, eps[e].String(), eps[e].Size)
	}
}

// TestLiveModifiedSince is a live check, skipped unless SBO_LIVE_OSV_NET=1:
// it lists npm's records changed in the last day through Range reads of
// the real modified_id.csv and fetches the newest one.
func TestLiveModifiedSince(t *testing.T) {
	if os.Getenv("SBO_LIVE_OSV_NET") != "1" {
		t.Skip("SBO_LIVE_OSV_NET not set: live check")
	}
	c := New(Options{})
	mods, overflow, err := c.ModifiedSince(context.Background(), "npm", time.Now().Add(-24*time.Hour), osvdb.MaxDeltaRecords)
	if err != nil || len(mods) == 0 {
		t.Fatalf("listing %d %v %v", len(mods), overflow, err)
	}
	b, err := c.Record(context.Background(), "npm", mods[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("npm: %d records changed in 24 h (overflow %v); newest %s at %s, %d bytes", len(mods), overflow, mods[0].ID, mods[0].At, len(b))
}
