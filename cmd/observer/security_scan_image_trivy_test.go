//go:build !sbo_omit_security && !sbo_omit_security_deps && !sbo_omit_security_scan_trivy && !sbo_omit_security_scan_image_trivy

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/seciac"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/secscan/trivydb"
	"github.com/marmutapp/superbased-observer/internal/secscan/trivyimage"
)

// The Trivy image driver's cmd seam, hermetic: the registry is a fake
// Fetcher, the binary decision and the driver's run are swapped (a test
// binary is not Trivy), and every directory is a temp one. Nothing here
// runs a real Trivy or reads a real database.

const allTrivyComponents = `"security.deps", "security.code", "security.scan.trivy", "security.scan.image.trivy"`

func trivyTestEnv(t *testing.T, components string) (*depsScanEnv, string) {
	t.Helper()
	dir := t.TempDir()
	cache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	t.Setenv("LocalAppData", cache)
	setTestHome(t, t.TempDir())
	cfgPath := filepath.Join(dir, "config.toml")
	body := "[observer]\ndb_path = " + strconv.Quote(filepath.Join(dir, "observer.db")) +
		"\n[components]\nadd = [" + components + "]\n[security.deps]\nonline = false\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := openDepsScanEnv(context.Background(), cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.cleanup)
	forceScanIsolation(t, false)
	return e, cfgPath
}

// fakeTrivyDB serves one database layer and counts manifest requests.
type fakeTrivyDB struct {
	layer []byte
	calls int
	fail  bool
}

func (f *fakeTrivyDB) Manifest(context.Context) (trivydb.Manifest, error) {
	f.calls++
	if f.fail {
		return trivydb.Manifest{}, errors.New("registry down")
	}
	sum := sha256.Sum256(f.layer)
	return trivydb.Manifest{
		Digest: "sha256:" + strings.Repeat("a", 64),
		Layer:  trivydb.Descriptor{MediaType: trivydb.LayerMediaType, Digest: "sha256:" + hex.EncodeToString(sum[:]), Size: int64(len(f.layer))},
	}, nil
}

func (f *fakeTrivyDB) Layer(_ context.Context, _ trivydb.Manifest, w io.Writer) error {
	_, err := w.Write(f.layer)
	return err
}

func trivyLayer(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range []struct{ name, body string }{
		{trivydb.DBFile, "BOLT"},
		{trivydb.MetadataFile, `{"Version":2,"NextUpdate":"2099-01-01T00:00:00Z","UpdatedAt":"2026-11-04T01:28:23Z"}`},
	} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func swapTrivyDB(t *testing.T, f trivydb.Fetcher) {
	t.Helper()
	prev := trivyDBFetcher
	trivyDBFetcher = func() trivydb.Fetcher { return f }
	t.Cleanup(func() { trivyDBFetcher = prev })
}

const fakeTrivyDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func swapTrivyBinary(t *testing.T, installed bool) {
	t.Helper()
	prev := trivyImageBinary
	bin := filepath.Join(t.TempDir(), "trivy")
	trivyImageBinary = func(*depsScanEnv) (seciac.Inspection, []string, bool) {
		if !installed {
			return seciac.Inspection{Reason: seciac.ReasonNotInstalled}, nil, false
		}
		return seciac.Inspection{Binary: bin, Digest: fakeTrivyDigest, Decision: seciac.Decision{Status: seciac.StatusVerified}}, nil, true
	}
	t.Cleanup(func() { trivyImageBinary = prev })
}

// trivyCall is what the swapped driver saw.
type trivyCall struct {
	in    trivyimage.ScanInput
	env   trivyimage.Env
	runs  int
	dbHit bool
}

// swapTrivyScan replaces the driver's run: it maps the Debian testdata
// report through the real mapping with the input the seam built.
func swapTrivyScan(t *testing.T, call *trivyCall) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "internal", "secscan", "trivyimage", "testdata", "debian-image-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := trivyimage.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	prev := trivyImageScan
	trivyImageScan = func(_ context.Context, env trivyimage.Env, in trivyimage.ScanInput) trivyimage.ScanOutput {
		call.in, call.env = in, env
		call.runs++
		_, err := os.Stat(filepath.Join(env.CacheDir, "db", trivydb.DBFile))
		call.dbHit = err == nil
		mi := in.Map
		mi.Report = rep
		out := trivyimage.Map(mi)
		return trivyimage.ScanOutput{
			FlagsOK: true, Version: trivyimage.TestedVersion,
			Result: trivyimage.RunResult(out.Label, depscan.EcoScanned, "", false, out.Matched, mi.Epoch, out, mi.Engine, in.Notes),
		}
	}
	t.Cleanup(func() { trivyImageScan = prev })
}

func acceptTrivy(t *testing.T, e *depsScanEnv) {
	t.Helper()
	key, err := depsRecordSigningKey(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := osvdb.RecordTrivyConsent(e.dir, "cli", "dev", time.Now(), key); err != nil {
		t.Fatal(err)
	}
}

func trivyRootfs(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "rootfs")
	if err := os.MkdirAll(filepath.Join(d, "etc"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "etc", "os-release"), []byte("ID=debian\nVERSION_ID=\"12\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return d
}

func notesHave(res secscan.Result, want string) bool {
	return strings.Contains(strings.Join(res.Coverage.Notes, "\n"), want)
}

// TestResolveImageDriver: the one-off flag, else the key, else the default;
// an unknown name is refused.
func TestResolveImageDriver(t *testing.T) {
	var cfg config.Config
	if got, err := resolveImageDriver(cfg, ""); err != nil || got != defaultImageDriver() {
		t.Fatalf("default %q %v", got, err)
	}
	cfg.Security.Scan.Image.Driver = imageDriverTrivy
	if got, _ := resolveImageDriver(cfg, ""); got != imageDriverTrivy {
		t.Errorf("key: %q", got)
	}
	if got, _ := resolveImageDriver(cfg, imageDriverScalibr); got != imageDriverScalibr {
		t.Errorf("flag: %q", got)
	}
	if _, err := resolveImageDriver(cfg, "grype"); err == nil {
		t.Error("an unknown driver was accepted")
	}
}

// TestTrivyImageGates: the verb refuses unless all three rows are selected;
// without the accept, and on a managed node, the run is not scanned, is
// recorded, and nothing is requested.
func TestTrivyImageGates(t *testing.T) {
	e, _ := trivyTestEnv(t, `"security.deps", "security.scan.image.trivy"`)
	if err := requireTrivyImageSelected(e); err == nil || !strings.Contains(err.Error(), trivyEngineComponent) {
		t.Fatalf("without the Trivy binary's row: %v", err)
	}
	e, _ = trivyTestEnv(t, allTrivyComponents)
	if err := requireTrivyImageSelected(e); err != nil {
		t.Fatal(err)
	}
	f := &fakeTrivyDB{layer: trivyLayer(t)}
	swapTrivyDB(t, f)
	swapTrivyBinary(t, true)
	call := &trivyCall{}
	swapTrivyScan(t, call)
	in := trivyRootfs(t)
	rep, err := runImageTrivyScan(context.Background(), e, in, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Result.Coverage.Outcome != secscan.OutcomeNotScanned || rep.Result.Coverage.Reason != depscan.ReasonDBNotAccepted || f.calls != 0 || call.runs != 0 {
		t.Fatalf("not accepted: %+v (%d requests, %d runs)", rep.Result.Coverage, f.calls, call.runs)
	}
	if rep.Digest != trivyDirDigest(in) || rep.Component != trivyimage.ComponentID || rep.Driver != trivyimage.DriverID {
		t.Errorf("report %+v", rep)
	}
	// A managed node: not scanned with its note, no request, even accepted.
	acceptTrivy(t, e)
	e.managed = true
	rep, err = runImageTrivyScan(context.Background(), e, in, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Result.Coverage.Reason != depscan.ReasonNoDatabase || f.calls != 0 || call.runs != 0 || !notesHave(rep.Result, "does not serve Trivy's database") {
		t.Fatalf("managed: %+v (%d requests)", rep.Result.Coverage, f.calls)
	}
}

// TestTrivyImageRun: after the accept the database downloads once and is
// linked into the run's cache; the driver gets the rootfs input and the
// epoch; its findings are recorded under this driver; the flag check is
// remembered; a second run within 6 hours asks the registry nothing; a
// missing binary is not scanned.
func TestTrivyImageRun(t *testing.T) {
	e, _ := trivyTestEnv(t, allTrivyComponents)
	acceptTrivy(t, e)
	f := &fakeTrivyDB{layer: trivyLayer(t)}
	swapTrivyDB(t, f)
	swapTrivyBinary(t, true)
	call := &trivyCall{}
	swapTrivyScan(t, call)
	in := trivyRootfs(t)
	rep, err := runImageTrivyScan(context.Background(), e, in, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	cov := rep.Result.Coverage
	if cov.Outcome != secscan.OutcomeFindings || len(rep.Result.Findings) == 0 || rep.Release != "Debian:12" || f.calls != 1 {
		t.Fatalf("%+v release %q, %d requests", cov, rep.Release, f.calls)
	}
	if call.in.Mode != trivyimage.ModeRootfs || call.in.Target != in || call.in.Project != in {
		t.Errorf("input %+v", call.in)
	}
	if !strings.HasPrefix(call.in.Map.Epoch, "trivy-db@sha256:aaaaaaaaaaaa/") || !call.dbHit {
		t.Errorf("epoch %q, database linked %v", call.in.Map.Epoch, call.dbHit)
	}
	if call.env.FlagsChecked || call.env.Digest != fakeTrivyDigest {
		t.Errorf("first run env %+v", call.env)
	}
	if _, err := os.Stat(call.env.CacheDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the run directory stayed: %v", err)
	}
	if e.loadTrivyImageState().FlagsOK != fakeTrivyDigest {
		t.Error("the flag check was not remembered")
	}
	root := secposture.ProjectRootHash("image:" + trivyDirDigest(in))
	open, err := e.openDepFindings(context.Background(), root)
	if err != nil || len(open) != len(rep.Result.Findings) {
		t.Fatalf("recorded findings %d of %d: %v", len(open), len(rep.Result.Findings), err)
	}
	for _, o := range open {
		if o.Engine.Driver != trivyimage.DriverID {
			t.Errorf("recorded driver %q", o.Engine.Driver)
		}
	}
	// Again: no registry request (not due); the flag check reads as done.
	if _, err := runImageTrivyScan(context.Background(), e, in, "", nil); err != nil || f.calls != 1 || !call.env.FlagsChecked {
		t.Fatalf("second run: %v, %d requests, flags %v", err, f.calls, call.env.FlagsChecked)
	}
	// Not installed: not scanned with the install hint, no driver run.
	swapTrivyBinary(t, false)
	runs := call.runs
	rep, _ = runImageTrivyScan(context.Background(), e, in, "", nil)
	if rep.Result.Coverage.Reason != depscan.ReasonNotInstalled || call.runs != runs || !notesHave(rep.Result, "iac install --engine trivy") {
		t.Errorf("not installed: %+v", rep.Result.Coverage)
	}
}

// TestTrivyImagePreviousDriver: after a switch another driver's open
// finding on the image stays open through a Trivy run, and the run says
// so.
func TestTrivyImagePreviousDriver(t *testing.T) {
	e, _ := trivyTestEnv(t, allTrivyComponents)
	acceptTrivy(t, e)
	swapTrivyDB(t, &fakeTrivyDB{layer: trivyLayer(t)})
	swapTrivyBinary(t, true)
	call := &trivyCall{}
	swapTrivyScan(t, call)
	in := trivyRootfs(t)
	root := secposture.ProjectRootHash("image:" + trivyDirDigest(in))
	// A first run gives a finding the shape to copy; the copy is made
	// another driver's.
	rep, err := runImageTrivyScan(context.Background(), e, in, "", nil)
	if err != nil || len(rep.Result.Findings) == 0 {
		t.Fatalf("%v %+v", err, rep.Result.Coverage)
	}
	other := rep.Result.Findings[0]
	other.ID = ""
	other.LocalKey = "scalibr-route-a-key"
	other.Engine.Driver = depscan.ScalibrID
	other.Project.RootHash = root
	if _, _, err := e.st.UpsertSecFinding(context.Background(), other, time.Now()); err != nil {
		t.Fatal(err)
	}
	rep, err = runImageTrivyScan(context.Background(), e, in, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !notesHave(rep.Result, trivyimage.PreviousDriverPrefix+" stay open until it scans again") {
		t.Fatalf("no previous-driver note: %q", rep.Result.Coverage.Notes)
	}
	open, _ := e.openDepFindings(context.Background(), root)
	n := 0
	for _, o := range open {
		if o.Engine.Driver == depscan.ScalibrID {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the other driver's finding was closed: %d open", n)
	}
}

// TestTrivyImageRefreshFailure: a failed first download is not scanned
// (feed_unavailable), no driver runs.
func TestTrivyImageRefreshFailure(t *testing.T) {
	e, _ := trivyTestEnv(t, allTrivyComponents)
	acceptTrivy(t, e)
	swapTrivyDB(t, &fakeTrivyDB{fail: true})
	swapTrivyBinary(t, true)
	call := &trivyCall{}
	swapTrivyScan(t, call)
	rep, err := runImageTrivyScan(context.Background(), e, trivyRootfs(t), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Result.Coverage.Reason != depscan.ReasonFeedUnavailable || call.runs != 0 {
		t.Fatalf("%+v", rep.Result.Coverage)
	}
}

// TestTrivyDBAcceptCLI: shown always; recorded only with --yes or a yes on
// a terminal; never without a terminal and without --yes; a managed node
// has nothing to accept; refresh refuses before the accept.
func TestTrivyDBAcceptCLI(t *testing.T) {
	e, _ := trivyTestEnv(t, allTrivyComponents)
	var w bytes.Buffer
	if err := runTrivyDBAccept(&w, strings.NewReader("y\n"), e, false, false, time.Now()); err != nil || e.trivyConsent().Accepted() {
		t.Fatalf("no terminal, no --yes: %v", err)
	}
	if !strings.Contains(w.String(), osvdb.TrivyRegistryHost) || !strings.Contains(w.String(), "Nothing recorded") {
		t.Errorf("text %q", w.String())
	}
	if err := runTrivyDBRefresh(context.Background(), &w, e); err == nil || !strings.Contains(err.Error(), "not accepted") {
		t.Errorf("refresh before the accept: %v", err)
	}
	if err := runTrivyDBAccept(&w, strings.NewReader("n\n"), e, false, true, time.Now()); err != nil || e.trivyConsent().Accepted() {
		t.Fatal("a no on the terminal recorded")
	}
	if err := runTrivyDBAccept(&w, strings.NewReader("y\n"), e, false, true, time.Now()); err != nil || !e.trivyConsent().Accepted() {
		t.Fatal("a yes on the terminal did not record")
	}
	e2, _ := trivyTestEnv(t, allTrivyComponents)
	if err := runTrivyDBAccept(&w, nil, e2, true, false, time.Now()); err != nil || !e2.trivyConsent().Accepted() {
		t.Fatal("--yes did not record")
	}
	e3, _ := trivyTestEnv(t, allTrivyComponents)
	e3.managed = true
	w.Reset()
	if err := runTrivyDBAccept(&w, nil, e3, true, false, time.Now()); err != nil || e3.trivyConsent().Accepted() || !strings.Contains(w.String(), "managed node") {
		t.Fatalf("managed: %v %q", err, w.String())
	}
	if err := acceptTrivyDBDash(e3); err == nil || e3.trivyConsent().Accepted() {
		t.Error("the dashboard accept recorded on a managed node")
	}
	e4, _ := trivyTestEnv(t, `"security.deps", "security.scan.image.trivy"`)
	if err := acceptTrivyDBDash(e4); err == nil {
		t.Error("the dashboard accept recorded without the Trivy binary's row")
	}
}

// TestImageDriverVerbAndStatus: the driver verb writes the key; status
// carries the driver and Trivy lines; the dashboard state the same.
func TestImageDriverVerbAndStatus(t *testing.T) {
	_, cfgPath := trivyTestEnv(t, allTrivyComponents)
	var w bytes.Buffer
	if err := setImageDriver(context.Background(), &w, cfgPath, imageDriverTrivy); err != nil {
		t.Fatal(err)
	}
	if err := setImageDriver(context.Background(), &w, cfgPath, "grype"); err == nil {
		t.Error("an unknown driver was written")
	}
	e, err := openDepsScanEnv(context.Background(), cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.cleanup)
	if e.cfg.Security.Scan.Image.Driver != imageDriverTrivy {
		t.Fatalf("key %q", e.cfg.Security.Scan.Image.Driver)
	}
	w.Reset()
	writeImageDriverState(context.Background(), &w, e)
	for _, want := range []string{"image OS packages: driver trivy", trivyImageComponent + "): in this build", "database: not accepted"} {
		if !strings.Contains(w.String(), want) {
			t.Errorf("status lacks %q:\n%s", want, w.String())
		}
	}
	st := imageDriverStatus(e)
	if st.Driver != imageDriverTrivy || !st.TrivyCompiled || st.Trivy == nil || !st.Trivy.Selected {
		t.Fatalf("dashboard state %+v", st)
	}
	if db := st.Trivy.DB; db.Accepted || db.Blocked != depscan.ReasonDBNotAccepted || db.ApproxDownloadMB != osvdb.TrivyApproxDownloadMB || db.Text != osvdb.TrivyConsentText {
		t.Fatalf("database state %+v", db)
	}
	// The verb is wired under `scan image` with its one-off flag.
	c := withImageDriver(&cobra.Command{Use: "image", RunE: func(*cobra.Command, []string) error { return nil }})
	if c.Flags().Lookup("driver") == nil {
		t.Error("the image verb lacks --driver")
	}
	found := false
	for _, sub := range c.Commands() {
		found = found || sub.Name() == "driver"
	}
	if !found {
		t.Error("no driver subcommand")
	}
}
