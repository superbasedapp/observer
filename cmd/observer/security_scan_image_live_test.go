//go:build !sbo_omit_security && !sbo_omit_security_deps && !sbo_omit_security_scan_scalibr && !sbo_omit_security_scan_os

package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
)

// TestLiveImageScan is a live check of route A over real image tars and
// real stripped per-release exports, skipped unless SBO_LIVE_OS_IMAGES
// names a directory of `docker save` tars and SBO_LIVE_OS_DB a directory
// of stripped exports (the JSP-OS spike's ~/sbo-scratch/jsp-os/images and
// osv/filtered). With SBO_LIVE_OBSERVER_BIN set to a built observer, the
// child is that binary under the runner's caps; otherwise it runs in
// process.
//
// MEMORY: it matches REAL exports, so run it in WSL under a cap, e.g.
// `systemd-run --user --scope -p MemoryMax=2G -- ./observer.test
// -test.run TestLiveImageScan -test.v` (an uncapped Ubuntu match reached
// 7 GB in the spike). Never run it uncapped.
func TestLiveImageScan(t *testing.T) {
	images, dbs := os.Getenv("SBO_LIVE_OS_IMAGES"), os.Getenv("SBO_LIVE_OS_DB")
	if images == "" || dbs == "" {
		t.Skip("SBO_LIVE_OS_IMAGES / SBO_LIVE_OS_DB not set: live check")
	}
	e := imageTestEnv(t)
	if bin := os.Getenv("SBO_LIVE_OBSERVER_BIN"); bin != "" {
		imageChildRun = func(ctx context.Context, runner *extrun.Runner, req extrun.Request) extrun.Result {
			req.Program.Path = bin
			return runner.Run(ctx, req)
		}
	}
	cases := []struct{ tar, distro, version, db string }{
		{"debian-bookworm-slim.tar", "debian", "12", "Debian_12.strip.zip"},
		{"distroless-static-debian12.tar", "debian", "12", "Debian_12.strip.zip"},
		{"ubuntu-2404.tar", "ubuntu", "24.04", "Ubuntu_24.04_LTS.strip.zip"},
		{"buildpack-deps-noble.tar", "ubuntu", "24.04", "Ubuntu_24.04_LTS.strip.zip"},
		{"alpine-320.tar", "alpine", "3.20", "Alpine_v3.20.strip.zip"},
		{"ubi9-minimal-93.tar", "rhel", "9", "RedHat_el9.strip.zip"},
		{"rocky9-minimal.tar", "rocky", "9", "Rocky_9.strip.zip"},
	}
	installed := map[string]bool{}
	for _, c := range cases {
		img := filepath.Join(images, c.tar)
		if _, err := os.Stat(img); err != nil {
			t.Logf("%s: not present, skipped", c.tar)
			continue
		}
		r, ok := osvdb.ReleaseFor(c.distro, c.version)
		if !ok {
			t.Fatalf("%s %s: no release row", c.distro, c.version)
		}
		if !installed[r.Artifact] {
			tmp := filepath.Join(e.db.OSFeedDir(), r.Artifact+".zip")
			if err := copyLiveFile(filepath.Join(dbs, c.db), tmp); err != nil {
				t.Fatal(err)
			}
			if _, err := e.db.InstallOS(r, tmp, osvdb.OSInstall{IssuedAt: "live", Source: osvdb.SourceFeed}, time.Now()); err != nil {
				t.Fatal(err)
			}
			installed[r.Artifact] = true
		}
		start := time.Now()
		rep, err := e.scanImage(context.Background(), img, "", nil)
		if err != nil {
			t.Fatalf("%s: %v", c.tar, err)
		}
		cov := rep.Result.Coverage
		t.Logf("%s: release %s, %s (%s), %d findings, scanned %v, skipped %v, labels %v, %s",
			c.tar, rep.Release, cov.Outcome, cov.Reason, len(rep.Result.Findings), cov.Scanned, cov.Skipped, depscan.RunLabels(cov.Notes), time.Since(start).Round(time.Millisecond))
		for _, n := range cov.Notes {
			t.Logf("  note: %s", n)
		}
		if len(cov.Scanned) != 1 {
			t.Errorf("%s: the release's canary must pass on its real stripped file (%+v)", c.tar, cov)
		}
	}
}

func copyLiveFile(from, to string) error {
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		return err
	}
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(to)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
