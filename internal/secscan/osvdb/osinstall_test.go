package osvdb

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeTemp writes b to a new file in dir and returns its path.
func writeTemp(t *testing.T, dir string, b []byte) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.CreateTemp(dir, "in-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(b); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	return f.Name()
}

// TestInstallOS: a verified export installs under the release's own path
// and epoch key (source in the epoch string), a later one replaces it, a
// file that is not a zip is refused and the last-known-good stays, and the
// language epochs and Installed() are untouched.
func TestInstallOS(t *testing.T) {
	t.Parallel()
	s := Open(filepath.Join(t.TempDir(), "osv"))
	r, ok := ReleaseFor("debian", "12")
	if !ok {
		t.Fatal("no Debian 12 row")
	}
	if _, ok := s.OSInstalled(r); ok {
		t.Fatal("installed before an install")
	}
	now := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	ep, err := s.InstallOS(r, writeTemp(t, s.OSFeedDir(), zipOf(t, "DSA-1.json", `{"id":"DSA-1"}`)), OSInstall{IssuedAt: "2026-11-04T09:00:00Z", Source: SourceFeed}, now)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s.OSInstalled(r)
	if !ok || got != ep.String() || !strings.Contains(got, "source=feed") || !strings.HasPrefix(got, "2026-11-04T09:00:00Z crc32c=") {
		t.Fatalf("OSInstalled %q %v (epoch %q)", got, ok, ep.String())
	}
	if lang, err := s.Installed(); err != nil || len(lang) != 0 {
		t.Fatalf("an OS release read as a language export: %v %v", lang, err)
	}
	list := s.OSReleasesInstalled()
	if len(list) != 1 || list[0].Release.Artifact != "Debian-12" || list[0].Bytes != ep.Size {
		t.Fatalf("OSReleasesInstalled %+v", list)
	}
	// A file that is not a zip is refused; the installed export stays.
	if _, err := s.InstallOS(r, writeTemp(t, s.OSFeedDir(), []byte("not a zip")), OSInstall{IssuedAt: "x", Source: SourceFeed}, now); err == nil {
		t.Fatal("a non-zip installed")
	}
	if again, ok := s.OSInstalled(r); !ok || again != got {
		t.Fatalf("the last-known-good changed: %q", again)
	}
	// A failed check moves CheckedAt and records the reason, nothing else.
	later := now.Add(6 * time.Hour)
	if err := s.RecordOSCheck(r, later, "feed_unavailable"); err != nil {
		t.Fatal(err)
	}
	eps, _ := s.Epochs()
	if e := eps[OSEpochKey(r)]; e.LastError != "feed_unavailable" || !e.CheckedAt.Equal(later) || e.String() != got {
		t.Fatalf("after a failed check %+v", e)
	}
	// A check of a release with no epoch records nothing.
	u, _ := ReleaseFor("ubuntu", "24.04")
	if err := s.RecordOSCheck(u, later, "feed_unavailable"); err != nil {
		t.Fatal(err)
	}
	if eps, _ := s.Epochs(); len(eps) != 1 {
		t.Fatalf("a check of an uninstalled release wrote an epoch: %v", eps)
	}
	// A newer export from the org mirror replaces it.
	ep2, err := s.InstallOS(r, writeTemp(t, s.OSFeedDir(), zipOf(t, "DSA-2.json", `{"id":"DSA-2"}`)), OSInstall{IssuedAt: "2026-11-05T09:00:00Z", Source: SourceOrgMirror}, later)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := s.OSInstalled(r); got != ep2.String() || !strings.Contains(got, "source=org_mirror") {
		t.Fatalf("after the replace %q", got)
	}
	if s.OSDiskBytes() < ep2.Size {
		t.Fatalf("disk %d < installed %d", s.OSDiskBytes(), ep2.Size)
	}
	if _, err := s.InstallOS(OSRelease{}, writeTemp(t, s.OSFeedDir(), zipOf(t, "x.json", "{}")), OSInstall{}, now); err == nil {
		t.Fatal("an install with no release")
	}
}

// TestOSDiskBytesCountsLinksOnce: a cached base hard-linked as the
// installed export is counted once.
func TestOSDiskBytesCountsLinksOnce(t *testing.T) {
	t.Parallel()
	s := Open(filepath.Join(t.TempDir(), "osv"))
	r, _ := ReleaseFor("alpine", "3.20")
	body := zipOf(t, "ALPINE-1.json", `{"id":"ALPINE-1"}`)
	cached := filepath.Join(s.OSFeedDir(), r.ExportArtifact())
	if err := os.MkdirAll(s.OSFeedDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cached, body, 0o600); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(s.OSFeedDir(), ".install-x")
	if err := os.Link(cached, tmp); err != nil {
		t.Skipf("no hard links here: %v", err)
	}
	if _, err := s.InstallOS(r, tmp, OSInstall{IssuedAt: "2026-11-04T09:00:00Z", Source: SourceFeed}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := s.OSDiskBytes(); got != int64(len(body))+s.feedStateBytes(t) {
		t.Fatalf("disk %d, want %d", got, int64(len(body)))
	}
}

// feedStateBytes is the size of the feed directory's other files (none in
// this test).
func (s Store) feedStateBytes(t *testing.T) int64 {
	t.Helper()
	var n int64
	ents, _ := os.ReadDir(s.OSFeedDir())
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".zip") {
			continue
		}
		if fi, err := e.Info(); err == nil && fi.Mode().IsRegular() {
			n += fi.Size()
		}
	}
	return n
}
