//go:build !sbo_omit_security_scan_scalibr

package scalibrchild

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/scalibrfacade"
)

// TestLiveCanaries is a live check, skipped unless SBO_LIVE_OSV_DB names a
// directory laid out as osv-scalibr/<Ecosystem>/all.zip with the real OSV
// exports (docs/dependency-scanning.md "Live checks"): every ecosystem's
// canary must match at least one advisory, or the self-test would mark a
// healthy database "not scanned". SBO_LIVE_OSV_ECOSYSTEMS, comma-separated,
// limits the check to the ecosystems it names (a directory holding only
// some exports).
func TestLiveCanaries(t *testing.T) {
	dir := os.Getenv("SBO_LIVE_OSV_DB")
	if dir == "" {
		t.Skip("SBO_LIVE_OSV_DB not set: live check")
	}
	inv, err := scalibrfacade.Extract(context.Background(), t.TempDir(), scalibrfacade.ExtractOptions{})
	if err != nil {
		t.Fatal(err)
	}
	only := map[string]bool{}
	for _, e := range strings.Split(os.Getenv("SBO_LIVE_OSV_ECOSYSTEMS"), ",") {
		if e = strings.TrimSpace(e); e != "" {
			only[e] = true
		}
	}
	for _, eco := range depscan.Ecosystems() {
		if len(only) > 0 && !only[eco] {
			continue
		}
		c, _ := depscan.CanaryFor(eco)
		start := time.Now()
		res, err := scalibrfacade.Match(context.Background(), inv, scalibrfacade.MatchRequest{Ecosystem: eco, Canary: &scalibrfacade.Canary{Name: c.Name, Version: c.Version}}, scalibrfacade.MatchOptions{DBDir: dir})
		if err != nil {
			t.Errorf("%s: %v", eco, err)
			continue
		}
		if !res.CanaryHit {
			t.Errorf("%s: canary %s %s (%s) matched nothing", eco, c.Name, c.Version, c.Advisory)
		}
		t.Logf("%s canary ok in %s", eco, time.Since(start).Round(time.Millisecond))
	}
}
