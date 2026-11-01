//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dblease"
	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
)

// TestScannersOfferedWithNoComponentsBlock is the offer (lane sec-deps4,
// decision log P-036): an install with no [components] block runs both
// dependency drivers wherever they are compiled, with their parent
// security.deps; their loops are allowed and `observer security scan`
// picks both. What such an install sees before the database accept is
// TestScannersOfferedWaitForTheAccept.
func TestScannersOfferedWithNoComponentsBlock(t *testing.T) {
	requireUnstampedBuild(t)
	snap := componentstate.Resolve(config.ComponentsConfig{}, fullNodeIDs())
	if snap.Configured {
		t.Fatal("the zero block must be unconfigured")
	}
	for _, id := range []string{securityDepsComponent, depscan.ScalibrComponent, depscan.OSVComponent} {
		if !securitySelected(snap, id) {
			t.Fatalf("%s does not run with no [components] block although it is offered", id)
		}
	}
	for _, loop := range []string{"security.scan.scalibr", "security.scan.osv"} {
		if !loopAllowed(snap, loop) {
			t.Fatalf("the %s loop is not allowed with no [components] block", loop)
		}
	}
	ids, err := depsScanComponents(snap, "")
	if err != nil || len(ids) != 2 {
		t.Fatalf("`observer security scan` drivers %v err %v", ids, err)
	}
	if !depsScanSelected(snap) {
		t.Fatal("the scan verbs refuse with no [components] block")
	}
}

// TestScannersOfferedWaitForTheAccept: on an existing install (a config
// with no [components] block) the scan status runs and says the database
// accept is owed with its size; `observer security scan db refresh` and
// both daemon loops download nothing until the developer accepts, and a
// scan claims nothing; after the accept the loops download.
func TestScannersOfferedWaitForTheAccept(t *testing.T) {
	requireUnstampedBuild(t)
	remote := useRemote(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	body := "# an existing install: no [components] block\n[observer]\ndb_path = \"" + filepath.ToSlash(filepath.Join(dir, "observer.db")) + "\"\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var status bytes.Buffer
	st := newSecurityScanStatusCmd()
	st.Flags().String("config", cfgPath, "")
	st.SetContext(context.Background())
	st.SetOut(&status)
	if err := st.RunE(st, nil); err != nil {
		t.Fatalf("status with no [components] block: %v", err)
	}
	if !strings.Contains(status.String(), "databases not downloaded: accept to download about 300 MB") {
		t.Fatalf("status does not say the accept is owed:\n%s", status.String())
	}
	var refresh *cobra.Command
	for _, c := range newSecurityScanDBCmd().Commands() {
		if c.Name() == "refresh" {
			refresh = c
		}
	}
	var out bytes.Buffer
	refresh.Flags().String("config", cfgPath, "")
	refresh.SetContext(context.Background())
	refresh.SetOut(&out)
	if err := refresh.RunE(refresh, nil); err != nil || !strings.Contains(out.String(), "accept to download") {
		t.Fatalf("db refresh before the accept: %v %q", err, out.String())
	}
	for _, component := range []string{depscan.ScalibrComponent, depscan.OSVComponent} {
		var lastDB time.Time
		if err := depsScanPass(context.Background(), cfgPath, component, &lastDB); err != nil {
			t.Fatalf("%s pass: %v", component, err)
		}
	}
	if remote.calls.Load() != 0 {
		t.Fatalf("an existing install downloaded the OSV databases before the accept (%d requests)", remote.calls.Load())
	}
	if _, err := osvdb.RecordConsent(secposture.LayoutFor(cfgPath).Dir, "dashboard", "dev", time.Now(), testDepsSigningKey(t, secposture.LayoutFor(cfgPath).Dir)); err != nil {
		t.Fatal(err)
	}
	var lastDB time.Time
	if err := depsScanPass(context.Background(), cfgPath, depscan.OSVComponent, &lastDB); err != nil {
		t.Fatal(err)
	}
	if remote.calls.Load() == 0 {
		t.Fatal("the accept did not start the download")
	}
}

// TestSecurityScanSelectedUnderABlock: selecting a driver and its parent
// under a [components] block starts its loop.
func TestSecurityScanSelectedUnderABlock(t *testing.T) {
	requireUnstampedBuild(t)
	snap := componentstate.Resolve(config.ComponentsConfig{Add: []string{"security", "security.deps", depscan.ScalibrComponent}}, fullNodeIDs())
	if !securitySelected(snap, depscan.ScalibrComponent) || !loopAllowed(snap, depscan.ScalibrComponent) {
		t.Fatal("a selected driver's loop must be allowed")
	}
	ids, err := depsScanComponents(snap, "scalibr")
	if err != nil || len(ids) != 1 {
		t.Fatalf("ids %v err %v", ids, err)
	}
	if _, err := depsScanComponents(snap, "nope"); err == nil {
		t.Fatal("an unknown driver name must be refused")
	}
}

// TestDepsDownloadGate: the database download waits only for the node to
// be individual and the developer's one-time accept (operator ruling PT-19
// (2)), whatever the online setting; online matching, which sends names,
// keeps the online setting and its disclosure.
func TestDepsDownloadGate(t *testing.T) {
	// Verified stands for a record whose MAC checked out (the read path's
	// job, pinned in internal/secscan/osvdb and internal/secfeed).
	shown := secfeed.Disclosure{Version: secfeed.DisclosureVersion, ShownAt: time.Now(), Surface: "cli", Verified: true}
	accepted := osvdb.Consent{Version: osvdb.ConsentVersion, AcceptedAt: time.Now(), Surface: "dashboard", Verified: true}
	cases := []struct {
		name             string
		e                depsScanEnv
		download, online string
	}{
		// Lane SEC-H2: a managed node's online matching passes the gate and
		// goes to the org relay only (relayOnlineMatcher); its database
		// download stays refused without the org mirror.
		{"managed node never downloads publicly", depsScanEnv{managed: true, disclose: shown, consent: accepted, cfg: onlineCfg(true)}, "managed_node_uses_org_mirror", ""},
		{"managed node with the org mirror named needs no accept", depsScanEnv{managed: true, mirror: true, cfg: onlineCfg(true)}, "", "disclosure_not_shown"},
		{"nothing accepted", depsScanEnv{disclose: shown, cfg: onlineCfg(true)}, depscan.ReasonDBNotAccepted, ""},
		{"accepted, online off", depsScanEnv{consent: accepted, cfg: onlineCfg(false)}, "", "online_checks_off"},
		{"accepted, disclosure pending", depsScanEnv{consent: accepted, cfg: onlineCfg(true)}, "", "disclosure_not_shown"},
		{"a terminal record is not an accept", depsScanEnv{consent: osvdb.Consent{Version: osvdb.ConsentVersion, AcceptedAt: time.Now(), Surface: "terminal", Verified: true}, disclose: shown, cfg: onlineCfg(true)}, depscan.ReasonDBNotAccepted, ""},
		{"open", depsScanEnv{consent: accepted, disclose: shown, cfg: onlineCfg(true)}, "", ""},
		{"an unverified accept is no accept", depsScanEnv{consent: osvdb.Consent{Version: osvdb.ConsentVersion, AcceptedAt: time.Now(), Surface: "cli"}, disclose: shown, cfg: onlineCfg(true)}, depscan.ReasonDBNotAccepted, ""},
		{"an unverified disclosure is not shown", depsScanEnv{consent: accepted, disclose: secfeed.Disclosure{Version: secfeed.DisclosureVersion, ShownAt: time.Now(), Surface: "cli"}, cfg: onlineCfg(true)}, "", "disclosure_not_shown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.e.downloadBlocked(); got != c.download {
				t.Fatalf("download %q, want %q", got, c.download)
			}
			if got := c.e.onlineBlocked(); got != c.online {
				t.Fatalf("online %q, want %q", got, c.online)
			}
		})
	}
}

func onlineCfg(on bool) config.Config {
	c := config.Default()
	c.Security.Deps.Online = on
	return c
}

func TestDepsScanDueOnDatabaseUpdate(t *testing.T) {
	now := time.Now()
	prev := depsLastScan{At: now.Add(-time.Hour), Epoch: "npm=a"}
	switch {
	case depsScanDue(prev, true, "npm=a", now):
		t.Fatal("a fresh scan against the same database is not due")
	case !depsScanDue(prev, true, "npm=b", now):
		t.Fatal("a database update must trigger a rescan")
	case !depsScanDue(depsLastScan{}, false, "npm=a", now):
		t.Fatal("a never-scanned project is due")
	case !depsScanDue(depsLastScan{At: now.Add(-25 * time.Hour), Epoch: "npm=a"}, true, "npm=a", now):
		t.Fatal("a day-old scan is due")
	}
}

// scanVerbRefuses runs one scan verb against the config at cfg and reports
// its error.
func scanVerbRefuses(t *testing.T, c *cobra.Command, cfg string) error {
	t.Helper()
	c.Flags().String("config", cfg, "")
	c.SetContext(context.Background())
	c.SetOut(io.Discard)
	c.SetErr(io.Discard)
	return c.RunE(c, nil)
}

// TestSecurityScanVerbsRefuseWhenSkipped: a [components] block that removes
// both drivers (or security.deps) makes `observer security scan
// status` and `db refresh` refuse before they open anything, so they write
// no osv-scanner canary project and start no download.
func TestSecurityScanVerbsRefuseWhenSkipped(t *testing.T) {
	requireUnstampedBuild(t)
	for _, block := range []string{
		"[components]\nremove = [\"security.deps\"]\n",
		"[components]\nremove = [\"security.scan.scalibr\", \"security.scan.osv\"]\n",
	} {
		dir := t.TempDir()
		cfg := filepath.Join(dir, "config.toml")
		if err := os.WriteFile(cfg, []byte(block), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := scanVerbRefuses(t, newSecurityScanStatusCmd(), cfg); err == nil {
			t.Fatalf("%q: `observer security scan status` ran", block)
		}
		var refresh *cobra.Command
		for _, c := range newSecurityScanDBCmd().Commands() {
			if c.Name() == "refresh" {
				refresh = c
			}
		}
		if err := scanVerbRefuses(t, refresh, cfg); err == nil {
			t.Fatalf("%q: `observer security scan db refresh` ran", block)
		}
		if _, err := os.Stat(filepath.Join(dir, secposture.DirName)); err == nil {
			t.Fatalf("%q: a refused verb wrote under the security directory", block)
		}
	}
}

// TestDepsScanSelected pins the predicate both verbs use: a legacy
// snapshot selects the offered drivers; a block removing them does not; a
// block naming one selects it.
func TestDepsScanSelected(t *testing.T) {
	requireUnstampedBuild(t)
	if !depsScanSelected(componentstate.Resolve(config.ComponentsConfig{}, fullNodeIDs())) {
		t.Fatal("a config with no [components] block selects no dependency driver although they are offered")
	}
	if depsScanSelected(componentstate.Resolve(config.ComponentsConfig{Remove: []string{depscan.ScalibrComponent, depscan.OSVComponent}}, fullNodeIDs())) {
		t.Fatal("a block removing both drivers selects a driver")
	}
	if !depsScanSelected(componentstate.Resolve(config.ComponentsConfig{Add: []string{"security", "security.deps", depscan.OSVComponent}}, fullNodeIDs())) {
		t.Fatal("a block naming security.scan.osv and security.deps must select it")
	}
}

// TestSecurityScanReportNamesGaps: a manifest with no lockfile and an
// unpinned requirements file print as "not scanned" in plain words, and the
// run reads "scanned in part, not clean" (lane SEC-D2B milestone 1b).
func TestSecurityScanReportNamesGaps(t *testing.T) {
	var buf bytes.Buffer
	writeScanReport(&buf, depsScanReport{Driver: depscan.ScalibrID, Result: secscan.Result{Coverage: secscan.Coverage{
		Outcome: secscan.OutcomeUnknown, Reason: "partial_coverage",
		Notes: []string{depscan.NotIsolatedPrefix + ": the scan child ran with network access (ledger SECP-8): no isolation provider."},
		Skipped: []secscan.Skip{
			{Path: depscan.EcosystemSkipPrefix + "crates.io", Reason: depscan.ReasonNoLockfile},
			{Path: "tool/Cargo.toml", Reason: depscan.ReasonNoLockfile},
			{Path: "requirements.txt", Reason: depscan.ReasonUnpinned},
		},
	}}})
	out := buf.String()
	for _, want := range []string{
		"scanned in part, not clean",
		"not scanned: crates.io: no lockfile",
		"not scanned: tool/Cargo.toml: no lockfile",
		"not scanned: requirements.txt: no exact version pinned",
		"scalibr (not isolated): scanned in part",
		"note: Not isolated: the scan child ran with network access",
	} {
		if !bytes.Contains([]byte(out), []byte(want)) {
			t.Errorf("report %q lacks %q", out, want)
		}
	}
}

// TestScalibrIsolateStagesOutsideObserver: the isolated scan child's run
// directory lives under the user cache, never ~/.observer, holds a link to
// each installed database, is handed to the provider read-only, and is
// removed afterwards (lane SEC-D2B milestone 2d).
func TestScalibrIsolateStagesOutsideObserver(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the isolation engine and XDG_CACHE_HOME are Linux-only")
	}
	forceScanIsolation(t, true)
	cache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	setTestHome(t, t.TempDir())
	obs := t.TempDir()
	db := osvdb.Open(filepath.Join(obs, "security", "osv"))
	zip := filepath.Join(db.Dir(), "osv-scalibr", "npm", "all.zip")
	if err := os.MkdirAll(filepath.Dir(zip), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zip, []byte("zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := &depsScanEnv{dir: filepath.Join(obs, "security"), db: db}
	var got extrun.OneShotDirs
	factory := func(d extrun.OneShotDirs) (extrun.IsolationProvider, error) {
		got = d
		return nil, errors.New("stop here")
	}
	project := t.TempDir()
	iso, err := e.scalibrIsolate(factory, map[string]string{"npm": "e1"})(project)
	if err == nil || iso.Cleanup == nil || iso.Provider != nil {
		t.Fatalf("the factory's error must come back with a cleanup and no provider: %v", err)
	}
	if got.Project != project || len(got.ProgramDirs) != 1 {
		t.Fatalf("dirs %+v", got)
	}
	for _, d := range append([]string{got.Output, got.Cache}, got.ProgramDirs...) {
		if !strings.HasPrefix(d, cache) || strings.HasPrefix(d, obs) {
			t.Fatalf("run directory %s is not under the user cache %s", d, cache)
		}
	}
	if _, err := os.Stat(filepath.Join(got.ProgramDirs[0], "osv-scalibr", "npm", "all.zip")); err != nil {
		t.Fatalf("the installed database is not linked into the run: %v", err)
	}
	iso.Cleanup()
	if _, err := os.Stat(filepath.Dir(got.Output)); !os.IsNotExist(err) {
		t.Fatalf("the run directory must be removed: %v", err)
	}
}

// forceScanIsolation sets the host probe scalibrIsolate asks first.
func forceScanIsolation(t *testing.T, available bool) {
	t.Helper()
	prev := scanIsolationAvailable
	scanIsolationAvailable = func() bool { return available }
	t.Cleanup(func() { scanIsolationAvailable = prev })
}

// TestDepsScanOneAtATime pins milestone 2e of lane SEC-D2B: a scan in
// another process (the lease held elsewhere) defers a daemon pass and
// makes a CLI scan wait for it.
func TestDepsScanOneAtATime(t *testing.T) {
	if !dblease.Available() {
		t.Skip("no cross-process lease on this platform")
	}
	dir := t.TempDir()
	e := &depsScanEnv{dir: dir, logger: slog.Default()}
	other, ok, err := dblease.TryAcquire(dir, depsScanLeaseName)
	if err != nil || !ok {
		t.Fatalf("take the lease as another process would: %v %v", ok, err)
	}
	if _, err := e.acquireDepsScan(context.Background(), false, nil); !errors.Is(err, errDepsScanBusy) {
		t.Fatalf("a daemon pass must defer while another scan runs: %v", err)
	}
	saved := depsLeasePoll
	depsLeasePoll = 10 * time.Millisecond
	t.Cleanup(func() { depsLeasePoll = saved })
	waited := 0
	go func() {
		time.Sleep(60 * time.Millisecond)
		other()
	}()
	release, err := e.acquireDepsScan(context.Background(), true, func() { waited++ })
	if err != nil || waited != 1 {
		t.Fatalf("a CLI scan waits, then runs: err %v, told %d times", err, waited)
	}
	release()
	ctx, cancel := context.WithCancel(context.Background())
	again, _, _ := dblease.TryAcquire(dir, depsScanLeaseName)
	defer again()
	cancel()
	if _, err := e.acquireDepsScan(ctx, true, nil); err == nil {
		t.Fatal("a canceled wait must give up")
	}
	select {
	case depsScanHeavy <- struct{}{}:
		<-depsScanHeavy
	default:
		t.Fatal("the in-process slot must be free after a refused scan")
	}
}

// TestDepsLastScanSurvivesRestart: the last scan is read back by a new
// daemon (a new env over the same directory), keyed by driver and the
// project root's hash, so the project is not due again at once.
func TestDepsLastScanSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	first := &depsScanEnv{dir: dir}
	if err := first.rememberScan(depscan.ScalibrID, "/home/u/src/p", "npm=a", now); err != nil {
		t.Fatal(err)
	}
	if err := first.rememberScan(depscan.OSVID, "/home/u/src/old", "npm=a", now.Add(-3*depsScanActive)); err != nil {
		t.Fatal(err)
	}
	if err := first.rememberScan(depscan.OSVID, "/home/u/src/q", "npm=a", now); err != nil {
		t.Fatal(err)
	}
	restarted := &depsScanEnv{dir: dir}
	last := restarted.loadLastScans()
	prev, ok := last[depsLastKey(depscan.ScalibrID, "/home/u/src/p")]
	if !ok || depsScanDue(prev, ok, "npm=a", now.Add(time.Minute)) {
		t.Fatalf("last %v: a project scanned before the restart is not due", last)
	}
	if _, ok := last[depsLastKey(depscan.OSVID, "/home/u/src/p")]; ok {
		t.Fatal("the memory is per driver")
	}
	if _, ok := last[depsLastKey(depscan.OSVID, "/home/u/src/old")]; ok {
		t.Fatal("entries older than twice the active window are dropped")
	}
	b, _ := os.ReadFile(restarted.depsLastFile())
	if strings.Contains(string(b), "/home/u/src") {
		t.Fatalf("the file stores hashes, never paths: %s", b)
	}
}
