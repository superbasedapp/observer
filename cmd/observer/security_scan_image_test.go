//go:build !sbo_omit_security && !sbo_omit_security_deps && !sbo_omit_security_scan_scalibr && !sbo_omit_security_scan_os

package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/secscan/scalibrchild"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// The images here are built in Go (no real image in testdata), and the
// child runs in process (a test binary is not observer); the release
// databases are tiny synthetic exports.

func imageTar(t *testing.T, files map[string]string) []byte {
	t.Helper()
	tarOf := func(entries [][2]string) []byte {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for _, e := range entries {
			if err := tw.WriteHeader(&tar.Header{Name: e[0], Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(e[1]))}); err != nil {
				t.Fatal(err)
			}
			_, _ = tw.Write([]byte(e[1]))
		}
		_ = tw.Close()
		return buf.Bytes()
	}
	var layer [][2]string
	for _, k := range slices.Sorted(func(yield func(string) bool) {
		for k := range files {
			if !yield(k) {
				return
			}
		}
	}) {
		layer = append(layer, [2]string{k, files[k]})
	}
	m, _ := json.Marshal([]map[string]any{{"Config": "c.json", "Layers": []string{"0/layer.tar"}}})
	return tarOf([][2]string{{"0/layer.tar", string(tarOf(layer))}, {"c.json", "{}"}, {"manifest.json", string(m)}})
}

func writeImageFile(t *testing.T, p string, b []byte) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func osvZip(t *testing.T, records ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i, r := range records {
		w, _ := zw.Create(strconv.Itoa(i) + ".json")
		_, _ = w.Write([]byte(r))
	}
	_ = zw.Close()
	return buf.Bytes()
}

const (
	imgDebian12 = "ID=debian\nVERSION_ID=\"12\"\nVERSION=\"12 (bookworm)\"\nVERSION_CODENAME=bookworm\n"
	imgStatus   = "Package: libc6\nStatus: install ok installed\nSource: glibc\nVersion: 2.36-9+deb12u3\n\n" +
		"Package: zlib1g\nStatus: install ok installed\nSource: zlib\nVersion: 1:1.2.13.dfsg-1\n\n" +
		"Package: linux-libc-dev\nStatus: install ok installed\nSource: linux\nVersion: 6.1.112-1\n\n"
	imgDSA5514 = `{"id":"DSA-5514-1","modified":"2024-01-01T00:00:00Z",
"affected":[{"package":{"ecosystem":"Debian:12","name":"glibc"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.36-9+deb12u3"}]}]}]}`
	imgZlib = `{"id":"DSA-9999-1","modified":"2024-01-01T00:00:00Z","aliases":["CVE-2099-0001"],
"affected":[{"package":{"ecosystem":"Debian:12","name":"zlib"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:1.2.13.dfsg-2"}]}]}]}`
)

// imageTestEnv opens an env with security.scan.os selected, the child in
// process, no isolation and the run directories under a temp cache.
func imageTestEnv(t *testing.T) *depsScanEnv {
	t.Helper()
	dir := t.TempDir()
	cache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	t.Setenv("LocalAppData", cache)
	setTestHome(t, t.TempDir())
	cfgPath := filepath.Join(dir, "config.toml")
	body := "[observer]\ndb_path = " + strconv.Quote(filepath.Join(dir, "observer.db")) +
		"\n[components]\nadd = [\"security.deps\", \"security.scan.scalibr\", \"security.scan.os\"]\n[security.deps]\nonline = false\n"
	writeImageFile(t, cfgPath, []byte(body))
	e, err := openDepsScanEnv(context.Background(), cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.cleanup)
	forceScanIsolation(t, false)
	prevRun := imageChildRun
	imageChildRun = func(ctx context.Context, _ *extrun.Runner, req extrun.Request) extrun.Result {
		var cr depscan.ChildRequest
		if err := json.Unmarshal(req.Stdin, &cr); err != nil {
			t.Fatal(err)
		}
		if req.Limits.MemoryBytes != 1536<<20 {
			t.Errorf("the image child runs without the scan child's memory cap: %d", req.Limits.MemoryBytes)
		}
		out, _ := json.Marshal(scalibrchild.Run(ctx, cr, nil))
		return extrun.Result{Outcome: extrun.OutcomeOK, Stdout: out}
	}
	t.Cleanup(func() { imageChildRun = prevRun })
	return e
}

// installRelease places a release export where LinkOSInto reads it and
// makes the ensure seam answer an epoch.
func installRelease(t *testing.T, e *depsScanEnv, r osvdb.OSRelease, zip []byte) {
	t.Helper()
	writeImageFile(t, e.db.OSZipPath(r), zip)
	prev := osReleaseEnsure
	osReleaseEnsure = func(context.Context, *depsScanEnv, osvdb.OSRelease) (string, string) {
		return "2026-11-04T00:00:00Z", ""
	}
	t.Cleanup(func() { osReleaseEnsure = prev })
}

func TestScanImageFindsRecordsAndCloses(t *testing.T) {
	e := imageTestEnv(t)
	ctx := context.Background()
	debian, _ := osvdb.ReleaseFor("debian", "12")
	installRelease(t, e, debian, osvZip(t, imgDSA5514, imgZlib))
	work := t.TempDir()
	img := writeImageFile(t, filepath.Join(work, "app.tar"), imageTar(t, map[string]string{
		"etc/os-release": imgDebian12, "var/lib/dpkg/status": imgStatus, "usr/bin/app": "binary",
	}))
	dockerfile := writeImageFile(t, filepath.Join(work, "Dockerfile"), []byte("ARG BASE=debian:12\nFROM golang:1.27 AS build\nRUN go build \\\n  FROM ./x\nFROM debian:12-slim\nCOPY --from=build /app /app\n"))
	rep, err := e.scanImage(ctx, img, dockerfile, nil)
	if err != nil {
		t.Fatal(err)
	}
	res := rep.Result
	if res.Coverage.Outcome != secscan.OutcomeFindings || rep.Release != "Debian:12" || !strings.HasPrefix(rep.Digest, "sha256:") {
		t.Fatalf("report %+v", rep)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings %+v, want the zlib one (glibc is at the fixed version, the kernel is left out)", res.Findings)
	}
	f := res.Findings[0]
	if f.Rule.ID != "CVE-2099-0001" || f.EvidenceRedacted != "Debian:12 zlib@1:1.2.13.dfsg-1" || f.Location.RelPath != "Dockerfile" || f.Location.StartLine != 5 || f.Category != policy.FindingVulnerableDependency {
		t.Fatalf("finding %+v", f)
	}
	if !slices.Equal(res.Coverage.Scanned, []string{"Debian:12"}) {
		t.Fatalf("scanned %v", res.Coverage.Scanned)
	}
	labels := depscan.RunLabels(res.Coverage.Notes)
	for _, want := range []string{"known gap", "kernel packages left out", "not isolated"} {
		if !slices.Contains(labels, want) {
			t.Errorf("labels %v lack %q", labels, want)
		}
	}
	hash := secposture.ProjectRootHash("image:" + rep.Digest)
	open, err := e.st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: hash, Status: policy.FindingStatusOpen, Limit: 10})
	if err != nil || len(open) != 1 {
		t.Fatalf("open findings under the image's key: %v %v", open, err)
	}
	inv := e.loadImageInventories()[rep.Digest]
	if inv.Release != "Debian:12" || inv.Artifact != "Debian-12" || len(inv.Packages) != 3 {
		t.Fatalf("inventory %+v: every OS package of the image, kernel included, by digest", inv)
	}
	// The release's data no longer lists the zlib advisory: a full scan of
	// the same image closes it.
	installRelease(t, e, debian, osvZip(t, imgDSA5514))
	again, err := e.scanImage(ctx, img, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if again.Result.Coverage.Outcome != secscan.OutcomeClean || again.Digest != rep.Digest {
		t.Fatalf("rescan %+v", again.Result.Coverage)
	}
	open, _ = e.st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: hash, Status: policy.FindingStatusOpen, Limit: 10})
	if len(open) != 0 {
		t.Fatalf("a full scan of the same image must close what it no longer reports: %v", open)
	}
}

func TestScanImageNotScanned(t *testing.T) {
	e := imageTestEnv(t)
	ctx := context.Background()
	work := t.TempDir()
	debianImg := writeImageFile(t, filepath.Join(work, "d.tar"), imageTar(t, map[string]string{"etc/os-release": imgDebian12, "var/lib/dpkg/status": imgStatus}))
	cases := []struct {
		name   string
		img    string
		reason string
	}{
		{"no OS-database accept, nothing installed", debianImg, depscan.ReasonDBNotAccepted},
		{"no os-release", writeImageFile(t, filepath.Join(work, "n.tar"), imageTar(t, map[string]string{"var/lib/dpkg/status": imgStatus})), depscan.ReasonNoOSRelease},
		{"distribution outside the table", writeImageFile(t, filepath.Join(work, "a.tar"), imageTar(t, map[string]string{"etc/os-release": "ID=arch\n"})), depscan.ReasonDistroNotSupported},
		{"interim Ubuntu", writeImageFile(t, filepath.Join(work, "u.tar"), imageTar(t, map[string]string{"etc/os-release": "ID=ubuntu\nVERSION_ID=\"23.10\"\n"})), depscan.ReasonReleaseNotSupported},
		{"not an image", writeImageFile(t, filepath.Join(work, "x.tar"), imageTar(t, nil)[:512]), "image_corrupt"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rep, err := e.scanImage(ctx, c.img, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			cov := rep.Result.Coverage
			if cov.Outcome != secscan.OutcomeNotScanned && cov.Outcome != secscan.OutcomeFailed {
				t.Fatalf("outcome %s: never clean", cov.Outcome)
			}
			if cov.Reason != c.reason {
				t.Fatalf("reason %q, want %q", cov.Reason, c.reason)
			}
		})
	}
	if runtime.GOOS == "windows" {
		rocky, _ := osvdb.ReleaseFor("rocky", "9.3")
		installRelease(t, e, rocky, osvZip(t))
		img := writeImageFile(t, filepath.Join(work, "r.tar"), imageTar(t, map[string]string{"etc/os-release": "ID=rocky\nVERSION_ID=\"9.3\"\n", "var/lib/rpm/rpmdb.sqlite": "db"}))
		rep, err := e.scanImage(ctx, img, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := rep.Result.Coverage.Skipped; len(got) != 1 || got[0].Reason != depscan.ReasonRPMOnWindows {
			t.Fatalf("rocky on windows: %+v", rep.Result.Coverage)
		}
	}
}

func TestScanImageRefusedDatabaseIsPartial(t *testing.T) {
	e := imageTestEnv(t)
	debian, _ := osvdb.ReleaseFor("debian", "12")
	installRelease(t, e, debian, osvZip(t, imgDSA5514))
	var layer bytes.Buffer
	tw := tar.NewWriter(&layer)
	for _, h := range []*tar.Header{
		{Name: "etc/os-release", Typeflag: tar.TypeReg, Size: int64(len(imgDebian12)), Mode: 0o644},
		{Name: "var/lib/dpkg/status", Typeflag: tar.TypeSymlink, Linkname: "/elsewhere/status", Mode: 0o777},
	} {
		_ = tw.WriteHeader(h)
		if h.Typeflag == tar.TypeReg {
			_, _ = tw.Write([]byte(imgDebian12))
		}
	}
	_ = tw.Close()
	m, _ := json.Marshal([]map[string]any{{"Layers": []string{"l.tar"}}})
	var outer bytes.Buffer
	ow := tar.NewWriter(&outer)
	for _, e := range [][2]string{{"l.tar", layer.String()}, {"manifest.json", string(m)}} {
		_ = ow.WriteHeader(&tar.Header{Name: e[0], Typeflag: tar.TypeReg, Size: int64(len(e[1])), Mode: 0o644})
		_, _ = ow.Write([]byte(e[1]))
	}
	_ = ow.Close()
	img := writeImageFile(t, filepath.Join(t.TempDir(), "i.tar"), outer.Bytes())
	rep, err := e.scanImage(context.Background(), img, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	cov := rep.Result.Coverage
	if cov.Outcome == secscan.OutcomeClean || len(cov.Scanned) != 0 {
		t.Fatalf("coverage %+v: a package database that is a link is never clean", cov)
	}
	found := false
	for _, s := range cov.Skipped {
		found = found || (s.Path == "var/lib/dpkg/status" && s.Reason == depscan.ReasonImageEntryRefused)
	}
	if !found {
		t.Fatalf("skipped %+v lacks the refused database", cov.Skipped)
	}
}

func TestImageHelpers(t *testing.T) {
	for _, c := range []struct {
		in   string
		want int
	}{
		{"FROM a\n", 1},
		{"# FROM x\nFROM a AS b\nRUN x \\\nFROM y\nfrom c\n", 5},
		{"RUN echo\n", 0},
	} {
		if got := lastFromLine([]byte(c.in)); got != c.want {
			t.Errorf("lastFromLine(%q) = %d, want %d", c.in, got, c.want)
		}
	}
	for _, c := range []struct {
		osr    map[string]string
		reason string
		label  string
	}{
		{map[string]string{"ID": "debian", "VERSION_ID": "12"}, "", "Debian:12"},
		{map[string]string{"ID": "ubuntu", "VERSION_ID": "24.04"}, "", "Ubuntu:24.04:LTS"},
		{map[string]string{"ID": "rhel", "VERSION_ID": "9.3"}, "", "Red Hat:enterprise_linux:9"},
		{map[string]string{"ID": "rocky", "VERSION_ID": "9.3"}, "", "Rocky Linux:9"},
		{map[string]string{"ID": "alpine", "VERSION_ID": "3.20.3"}, "", "Alpine:v3.20"},
		{map[string]string{"ID": "debian", "VERSION_ID": "10"}, depscan.ReasonReleaseNotSupported, ""},
		{map[string]string{"ID": "wolfi"}, depscan.ReasonDistroNotSupported, ""},
		{nil, depscan.ReasonNoOSRelease, ""},
	} {
		r, why := releaseForImage(c.osr)
		if why != c.reason || (why == "" && releaseLabel(r) != c.label) {
			t.Errorf("releaseForImage(%v) = %q %q, want %q %q", c.osr, releaseLabel(r), why, c.label, c.reason)
		}
		if why == "" {
			if _, ok := depscan.OSCanaryFor(releaseLabel(r)); !ok {
				t.Errorf("%s has no canary row: it would read no_canary", releaseLabel(r))
			}
		}
	}
	cmd := newSecurityScanImageCmd()
	if cmd.Flags().Lookup("dockerfile") == nil || cmd.Flags().Lookup("json") == nil {
		t.Fatal("flags")
	}
}
