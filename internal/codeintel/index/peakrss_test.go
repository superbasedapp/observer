//go:build !sbo_omit_codeintel

package index_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/codeintel/index"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// peakRSSKiB reads the process's peak resident set size (VmHWM) on Linux.
// It returns 0 where /proc is not available.
func peakRSSKiB() int64 {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == "VmHWM:" {
			n, _ := strconv.ParseInt(f[1], 10, 64)
			return n
		}
	}
	return 0
}

// TestIndexRepositoryPeakRSS indexes a real checkout with the product
// defaults (default registry, force=true) and reports peak RSS. It is the
// measurement behind ADR-0010 and docs/codeintel/benchmarks.md, opt-in
// because it needs a checkout on disk:
//
//	SBO_CODEINTEL_RSS_REPO=/path/to/litemall go test ./internal/codeintel/index \
//	  -run TestIndexRepositoryPeakRSS -count=1 -v
//
// SBO_CODEINTEL_RSS_MAX_MIB (default 1024) is the failing bound.
func TestIndexRepositoryPeakRSS(t *testing.T) {
	repo := os.Getenv("SBO_CODEINTEL_RSS_REPO")
	if repo == "" {
		t.Skip("set SBO_CODEINTEL_RSS_REPO to a checkout to measure")
	}
	limitMiB := int64(1024)
	if v := os.Getenv("SBO_CODEINTEL_RSS_MAX_MIB"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			t.Fatalf("SBO_CODEINTEL_RSS_MAX_MIB: %v", err)
		}
		limitMiB = n
	}
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "obs.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()

	ix := index.New(index.Options{Store: store.New(database), Registry: index.DefaultRegistry()})
	start := time.Now()
	rep, err := ix.IndexProject(ctx, repo, true)
	if err != nil {
		t.Fatalf("IndexProject: %v", err)
	}
	peak := peakRSSKiB() / 1024
	t.Logf("indexed %s: scanned=%d indexed=%d skipped=%d failed=%d in %s, peak RSS %d MiB",
		repo, rep.Scanned, rep.Indexed, rep.Skipped, rep.Failed, time.Since(start).Round(time.Second), peak)
	if peak > limitMiB {
		t.Fatalf("peak RSS %d MiB exceeds %d MiB", peak, limitMiB)
	}
}
