//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dblease"
	"github.com/marmutapp/superbased-observer/internal/extrun"
	extrunhost "github.com/marmutapp/superbased-observer/internal/extrun/host"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depdriver"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvnet"
	"github.com/marmutapp/superbased-observer/internal/secscan/scalibrchild"
	"github.com/marmutapp/superbased-observer/internal/secscan/scalibrfacade"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// security_scan.go is the daemon and CLI side of the project dependency
// scanners (security pillar plan sections 4.4, 8.2 and 8.4, Phase D2):
//
//   - the security.scan.scalibr and security.scan.osv loops (moduleGates
//     rows), each started only while its component is selected (offered
//     with the install gate by lane sec-deps4, P-036): refresh the local
//     OSV databases once the developer accepted the download (PT-19), then
//     scan each recently active project's
//     dependencies through its driver, one heavy scan at a time per
//     daemon, and record the run through secsvc.RecordRun;
//   - `observer security scan` (run now, status, database refresh, the
//     osv-scanner install offer) and the hidden `observer security
//     scan-child`, the SCALIBR child the linked driver starts through the
//     shared runner.
//
// What decides whether a database download may run (depsDownloadGate): an
// individual node, and the developer's one-time accept of the download
// (operator ruling PT-19 (2), osvdb.Consent), given in the dashboard or
// with `observer security scan db accept`, never by an agent (R-165);
// after the accept the refreshes are automatic. Online matching
// (depsOnlineGate) sends package names, so it keeps the install gate's
// online setting and disclosure. A managed node never downloads from the
// public bucket: its databases come from the org mirror (security plan
// section 8.3), which is not built yet, so a managed node reports its
// dependencies "not scanned" (database_missing) and says why.

// Cadence and bounds.
const (
	depsScanTick    = 15 * time.Minute
	depsScanEvery   = 24 * time.Hour
	depsDBEvery     = 6 * time.Hour
	depsScanActive  = 30 * 24 * time.Hour
	depsScanPerTick = 20
	depsChildStdin  = 1 << 20
)

// depsScanHeavy holds one heavy dependency scan at a time in this process;
// the cross-process lease (depsScanLeaseName) holds it per machine
// (security plan section 4.4: one heavy scan at a time per machine).
var depsScanHeavy = make(chan struct{}, 1)

// startSecurityScan starts the two driver loops on ng.
func startSecurityScan(ctx context.Context, ng *gatedGroup, configPath string, snap componentstate.Snapshot) {
	if !securitySelected(snap, securityDepsComponent) {
		return
	}
	// Loop names are literals so TestEveryDaemonLoopIsClassified can match
	// them against the moduleGates rows.
	if securitySelected(snap, depscan.ScalibrComponent) {
		ng.Go("security.scan.scalibr", func() error {
			depsScanLoop(ctx, configPath, depscan.ScalibrComponent)
			return nil
		})
	}
	if securitySelected(snap, depscan.OSVComponent) {
		ng.Go("security.scan.osv", func() error {
			depsScanLoop(ctx, configPath, depscan.OSVComponent)
			return nil
		})
	}
}

// depsScanEnv is what one pass opens.
type depsScanEnv struct {
	cfg      config.Config
	st       *store.Store
	dir      string
	db       osvdb.Store
	managed  bool
	disclose secfeed.Disclosure
	// consent is the one-time accept of the database download.
	consent osvdb.Consent
	// mirror: the managed pull in force names the org mirror (lane SEC-E4).
	mirror bool
	// configPath is the --config the env was opened with.
	configPath string
	logger     *slog.Logger
	cleanup    func()
	// root is the project a gate is walked for (onlineBlockedAt); "" reads
	// the org-wide floor only.
	root string
}

func openDepsScanEnv(ctx context.Context, configPath string) (*depsScanEnv, error) {
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return nil, err
	}
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		cleanup()
		return nil, err
	}
	st := store.New(database)
	dir := secposture.LayoutFor(resolved).Dir
	e := &depsScanEnv{cfg: cfg, st: st, dir: dir, db: osvdb.Open(filepath.Join(dir, "osv")), cleanup: cleanup, logger: newLogger(cfg.Observer.LogLevel)}
	if lk := managedTenancyLookup(st); lk != nil {
		e.managed = lk()
	}
	e.configPath = configPath
	if e.managed {
		e.mirror = depsMirrorNamedFor(ctx, cfg, st)
	}
	e.disclose = readDepsDisclosure(dir)
	e.consent = osvdb.ReadConsent(dir, depsRecordKey(dir))
	return e, nil
}

// depsGate is one ordered gate, walked top-down (CLAUDE.md module rule 5).
type depsGate []struct {
	reason string
	closed func(*depsScanEnv) bool
}

// first returns the first closed row's reason, "" when every row is open.
func (g depsGate) first(e *depsScanEnv) string {
	for _, r := range g {
		if r.closed(e) {
			return r.reason
		}
	}
	return ""
}

// depsDownloadGate is the gate in front of the database download (PT-19
// (2): ask once, then automatic).
//
// A managed node never downloads from the public bucket: its databases
// come from the org mirror (lane SEC-E4) only while its managed pull in
// force names the mirror, and it never waits for an accept it cannot give
// (the download is from its own org server, not a public host).
var depsDownloadGate = depsGate{
	{"managed_node_uses_org_mirror", func(e *depsScanEnv) bool { return e.managed && !e.mirror }},
	{"scanner_source_not_allowed", func(e *depsScanEnv) bool {
		return !depsScannerSourceAllowed(e.cfg.Security, e.dbSource())
	}},
	{depscan.ReasonDBNotAccepted, func(e *depsScanEnv) bool { return !e.managed && !e.consent.Accepted() }},
}

// dbSource is where this node's databases come from (the
// allow.scanner_sources vocabulary).
func (e *depsScanEnv) dbSource() string {
	if e.managed {
		return depsScannerSourceOrgMirror
	}
	return "vendor_release"
}

// depsOnlineGate is the gate in front of online matching, which sends
// ecosystem, public name and version: the install gate's online setting
// and its disclosure. A managed node passes it like an individual one and
// matches through the org relay only, never a public host (lane SEC-H2,
// relayOnlineMatcher); before that lane it was refused here
// (managed_node_uses_org_mirror).
var depsOnlineGate = depsGate{
	// Read through the org floors' seam (security_scanning_wire.go): a
	// managed floor may require the online checks, any floor may forbid them.
	// Per project (lane sec-p3): a project section may forbid them there.
	{"online_checks_off", func(e *depsScanEnv) bool { return !securityFloorsAppliedAt(e.cfg.Security, e.root).Deps.Online }},
	{"disclosure_not_shown", func(e *depsScanEnv) bool { return !e.disclose.Shown() }},
}

// downloadBlocked returns the download gate's first closed reason, ""
// when the download may run.
func (e *depsScanEnv) downloadBlocked() string { return depsDownloadGate.first(e) }

// onlineBlocked returns the online gate's first closed reason, "" when
// online matching may run, under the org-wide floor only.
func (e *depsScanEnv) onlineBlocked() string { return e.onlineBlockedAt("") }

// onlineBlockedAt is onlineBlocked in one project (lane sec-p3): the gate is
// walked with that directory's project sections merged over the org-wide
// floor.
func (e *depsScanEnv) onlineBlockedAt(root string) string {
	scoped := *e
	scoped.root = root
	return depsOnlineGate.first(&scoped)
}

// awaitingAccept reports whether a scan cannot run at all yet: no database
// is installed and the download waits for the one-time accept. Such a run
// starts no driver and claims nothing, least of all clean. A managed node
// never waits for an accept it cannot give (its databases come from the
// organization's mirror), so its scans keep reporting database_missing
// (lane sec-deps4 audit finding 3).
func (e *depsScanEnv) awaitingAccept() bool {
	if e.managed || e.consent.Accepted() {
		return false
	}
	eps, err := e.db.Installed()
	return err != nil || len(eps) == 0
}

// depsAcceptHint is the one sentence every surface shows before the
// accept: the size, the source and the two ways to accept.
var depsAcceptHint = fmt.Sprintf("databases not downloaded: accept to download about %d MB from %s (`observer security scan db accept`, or the Scanners card on the dashboard's Code security page)", osvdb.ApproxDownloadMB, osvdb.Source)

// refreshDB refreshes every ecosystem's export when the gate is open.
func (e *depsScanEnv) refreshDB(ctx context.Context) (osvdb.Report, string, error) {
	if r := e.downloadBlocked(); r != "" {
		return osvdb.Report{}, r, nil
	}
	remote := depsOSVRemote()
	if e.managed {
		r, err := e.orgMirrorOSV(ctx)
		if err != nil {
			return osvdb.Report{}, "", err
		}
		remote = r
	}
	rep, err := e.db.Refresh(ctx, remote, depscan.Ecosystems(), time.Now())
	return rep, "", err
}

// orgMirrorOSV fetches the security.osv_export kind from the org mirror
// into the content channel (a failure keeps the last-known-good) and
// returns a remote over what is installed; nothing installed is an error,
// and the dependencies stay "not scanned".
func (e *depsScanEnv) orgMirrorOSV(ctx context.Context) (osvdb.Remote, error) {
	st := depsContentStore(depsConfigPath(e.configPath))
	ferr := fetchFromOrgMirror(ctx, e.configPath, st, []content.Kind{content.OSVExport}, depsTrust())
	l, err := st.Load(content.OSVExport, depsTrust(), depsAdvisoryFloor(e.cfg.Security))
	if err != nil {
		return nil, errors.Join(ferr, fmt.Errorf("no OSV exports from the org mirror: %w", err))
	}
	if ferr != nil {
		e.logger.Warn("security: org mirror fetch failed; the installed OSV exports stay in use", "err", ferr, "freshness", l.Freshness)
	}
	return mirrorOSVRemote{l: l}, nil
}

// depsOSVRemote is the database download's network side (the declared
// egress lane, internal/secscan/osvnet); a test swaps it.
var depsOSVRemote = func() osvdb.Remote { return osvnet.New(osvnet.Options{}) }

// depsSelfExecutable is the daemon's own binary, the scan child.
func depsSelfExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	return exe, nil
}

// facadeExtractorNames lists the linked extractors ("" in a build without
// SCALIBR).
func facadeExtractorNames() []string {
	infos, err := scalibrfacade.Extractors()
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(infos))
	for _, i := range infos {
		out = append(out, i.Name)
	}
	return out
}

// depsDriver returns the driver for a component id, built over the current
// database epochs; nil when the driver is not in this build.
func (e *depsScanEnv) depsDriver(component string, runner *extrun.Runner) (secscan.Driver, error) {
	return e.depsDriverFor(component, runner, nil)
}

// depsOnlineAttached reports whether depsDriverFor attaches the online
// matcher m to component's driver: only the linked driver matches online.
func depsOnlineAttached(component string, m depdriver.OnlineMatcher) bool {
	return m != nil && component == depscan.ScalibrComponent
}

// depsDriverFor is depsDriver with an online matcher for the linked driver
// (nil keeps matching local).
func (e *depsScanEnv) depsDriverFor(component string, runner *extrun.Runner, online depdriver.OnlineMatcher) (secscan.Driver, error) {
	epochs, err := e.db.Installed()
	if err != nil {
		return nil, err
	}
	switch component {
	case depscan.ScalibrComponent:
		exe, err := depsSelfExecutable()
		if err != nil {
			return nil, err
		}
		env := depdriver.Env{
			Runner: runner, Executable: exe, Compiled: scalibrfacade.Compiled, Extractors: facadeExtractorNames(),
			DBDir: e.db.Dir(), Epochs: epochs, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Online: online,
		}
		if factory := isolationFactoryFor(componentSnapshotForConfig(e.cfg), filepath.Dir(e.dir), nil); factory != nil {
			env.Isolate = e.scalibrIsolate(factory, epochs)
			env.IsolatedRunner = func(p extrun.IsolationProvider) *extrun.Runner {
				return extrunhost.NewRunner(extrunhost.Options{Isolation: p})
			}
		}
		return depdriver.NewScalibr(env), nil
	case depscan.OSVComponent:
		d := depsOSVDriver(runner, e.db.Dir(), epochs, filepath.Join(e.dir, "osv-canary"))
		if d == nil {
			return nil, nil
		}
		return d, nil
	}
	return nil, fmt.Errorf("security scan: unknown driver component %q", component)
}

// depsScanCacheRoot is the per-user directory the isolated scan child's
// run directories live in: outside ~/.observer, which the isolation engine
// never binds.
func depsScanCacheRoot() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("no user cache directory: %w", err)
	}
	return filepath.Join(base, "superbased-observer", "scanners", "deps"), nil
}

// scanIsolationAvailable is the host probe scalibrIsolate asks first
// (isolationAvailable; a test swaps it).
var scanIsolationAvailable = isolationAvailable

// scalibrIsolate prepares one isolated run of the scan child (lane SEC-D2B
// milestone 2d): a run directory under depsScanCacheRoot holding hard links
// to the installed databases (bound read-only), an output and a cache
// directory, and the one-shot provider over the project. The provider binds
// resolved paths only, so the child is handed the project root and the
// database directory resolved through symlinks (lane SEC-DEPS3 item 3). A
// host with no isolation provider yields no provider and no error (the
// child runs unisolated, labelled), and that is decided before anything is
// prepared, so a preparation failure on such a host never refuses the
// scan; on a host with a provider, anything that fails refuses the scan
// (item 5, audit finding 2 of lane sec-deps3b).
func (e *depsScanEnv) scalibrIsolate(factory extrun.IsolationFactory, epochs map[string]string) func(string) (depdriver.Isolated, error) {
	return func(root string) (depdriver.Isolated, error) {
		if !scanIsolationAvailable() {
			return depdriver.Isolated{}, nil
		}
		realRoot, err := filepath.EvalSymlinks(root)
		if err != nil {
			return depdriver.Isolated{}, fmt.Errorf("the project root could not be resolved: %w", err)
		}
		base, err := depsScanCacheRoot()
		if err != nil {
			return depdriver.Isolated{}, err
		}
		runs := filepath.Join(base, "runs")
		if err := os.MkdirAll(runs, 0o700); err != nil {
			return depdriver.Isolated{}, err
		}
		runRoot, err := os.MkdirTemp(runs, "scalibr-")
		if err != nil {
			return depdriver.Isolated{}, err
		}
		iso := depdriver.Isolated{Cleanup: func() { _ = os.RemoveAll(runRoot) }}
		dbDir := filepath.Join(runRoot, "db")
		if err := e.db.LinkInto(dbDir, depscan.SortedEcosystems(epochs)); err != nil {
			return iso, fmt.Errorf("the OSV database could not be linked outside ~/.observer: %w", err)
		}
		out, cache := filepath.Join(runRoot, "out"), filepath.Join(runRoot, "cache")
		for _, d := range []string{dbDir, out, cache} {
			if err := os.MkdirAll(d, 0o700); err != nil {
				return iso, err
			}
		}
		realDB, err := filepath.EvalSymlinks(dbDir)
		if err != nil {
			return iso, fmt.Errorf("the run's database directory could not be resolved: %w", err)
		}
		prov, err := factory(extrun.OneShotDirs{Project: root, Output: out, Cache: cache, ProgramDirs: []string{dbDir}})
		switch {
		case err != nil && isolationMissingOnHost(err):
			return iso, nil
		case err != nil:
			return iso, err
		}
		iso.Provider, iso.Root, iso.DBDir = prov, realRoot, realDB
		return iso, nil
	}
}

// depsScanLeaseName is the cross-process lease one dependency scan holds
// (internal/dblease, a flock on unix and a LockFileEx lock on windows,
// under ~/.observer/security): the daemon's two driver loops and every
// `observer security scan` take it, so one heavy scan runs at a time per
// machine (security plan section 4.4). Elsewhere the lease is a no-op and
// only the in-process slot holds (ledger SECP-8).
const depsScanLeaseName = "deps-scan"

// depsLeasePoll is how often a waiting CLI scan retries the lease.
var depsLeasePoll = 2 * time.Second

// errDepsScanBusy is a scan that did not start because another process
// holds the lease and the caller does not wait (a daemon pass: the project
// stays due for the next tick).
var errDepsScanBusy = errors.New("another dependency scan is running")

// acquireDepsScan takes the in-process slot and the cross-process lease.
// wait false returns errDepsScanBusy when another process holds the lease;
// wait true retries until ctx ends, calling onWait once. A lease error is
// fail-open (dblease's contract): the scan goes ahead under the in-process
// slot only.
func (e *depsScanEnv) acquireDepsScan(ctx context.Context, wait bool, onWait func()) (func(), error) {
	select {
	case depsScanHeavy <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	slot := func() { <-depsScanHeavy }
	told := false
	for {
		release, ok, err := dblease.TryAcquire(e.dir, depsScanLeaseName)
		if err != nil {
			e.logger.Warn("security: dependency scan lease unavailable; running under the in-process slot only", "err", err)
			return slot, nil
		}
		if ok {
			return func() { release(); slot() }, nil
		}
		if !wait {
			slot()
			return nil, errDepsScanBusy
		}
		if !told && onWait != nil {
			onWait()
			told = true
		}
		select {
		case <-ctx.Done():
			slot()
			return nil, ctx.Err()
		case <-time.After(depsLeasePoll):
		}
	}
}

// scanOne scans one project with one driver, holding the scan lease, and
// records the run: findings through secsvc.RecordRun (the one writer), and
// every open finding of this driver the run no longer reports, in an
// ecosystem it scanned in full, becomes not_reproduced. The run is also
// remembered in the last-scan file, so a restarted daemon does not scan
// the project again before it is due. online reports that the driver
// carries an online matcher (`scan --online`, depsOnlineAttached): with
// the online gate open it can match without a local database, so the
// accept does not hold it back (lane sec-deps4 audit finding 2).
func (e *depsScanEnv) scanOne(ctx context.Context, d secscan.Driver, root string, scope secscan.Target, wait bool, onWait func(), online bool) (secscan.Result, error) {
	if !(online && e.onlineBlockedAt(root) == "") && e.awaitingAccept() {
		// Before the accept: no driver starts, nothing is recorded, and
		// the result says why (PT-19 (2)).
		return secscan.Result{
			Coverage: secscan.Coverage{Outcome: secscan.OutcomeNotScanned, Reason: depscan.ReasonDBNotAccepted},
			Engine:   secscan.EngineIdentity{Name: d.Row().ID},
		}, nil
	}
	t := scope
	t.ProjectRoot = root
	if why := depsProjectDatabaseRefusal(e.cfg.Security, root, e.dbSource()); why != "" {
		// The project's own floor asks for a database the node's one cannot
		// be (lane SEC-P4 decision 10): unknown, never clean, and nothing
		// closes.
		res := secscan.Result{Coverage: secscan.Coverage{Outcome: secscan.OutcomeUnknown, Reason: why}, Engine: secscan.EngineIdentity{Name: d.Row().ID}}
		_, err := secsvc.RecordRun(ctx, e.st, t, res, time.Now(), 0, secsvc.Gone{}, securityRT.notify)
		return res, err
	}
	release, err := e.acquireDepsScan(ctx, wait, onWait)
	if err != nil {
		return secscan.Result{}, err
	}
	defer release()
	started := time.Now()
	res, err := d.Scan(ctx, t)
	if err != nil {
		return res, err
	}
	if res.Engine.Name == "" {
		res.Engine.Name = d.Row().ID
	}
	if _, err := secsvc.RecordRun(ctx, e.st, t, res, started, time.Since(started), secsvc.Gone{}, securityRT.notify); err != nil {
		return res, err
	}
	if res.Coverage.Outcome == secscan.OutcomeFindings || res.Coverage.Outcome == secscan.OutcomeClean || res.Coverage.Outcome == secscan.OutcomeUnknown {
		hash := secposture.ProjectRootHash(root)
		open, err := e.st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: hash, Status: policy.FindingStatusOpen, Limit: 1000})
		if err == nil {
			for _, id := range depscan.StaleFindings(open, d.Row().ID, res.Findings, depscan.ScannedEcosystems(res.Coverage)) {
				// Hold-aware (lane sec-gate4 milestone 1c): a finding an
				// unpushed commit holds, or one that reached a remote, stays open.
				_, _ = e.st.CloseSecFindingNotReproduced(ctx, id, time.Now())
			}
		}
	}
	epochs, _ := e.db.Installed()
	if err := e.rememberScan(d.Row().ID, root, depdriver.EpochSummary(epochs), time.Now()); err != nil {
		e.logger.Debug("security: could not record the last dependency scan", "err", err)
	}
	return res, nil
}

// depsScanLoop is one driver's loop: refresh the databases, then scan each
// active project that is due (never scanned, older than depsScanEvery, or
// scanned against an older database epoch, as the last-scan file says).
func depsScanLoop(ctx context.Context, configPath, component string) {
	var lastDB time.Time
	for {
		if err := depsScanPass(ctx, configPath, component, &lastDB); err != nil && ctx.Err() == nil {
			slog.Default().Warn("security: dependency scan pass failed", "driver", component, "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(depsScanTick):
		}
	}
}

// depsLastScan is one project's last scan by one driver.
type depsLastScan struct {
	At    time.Time `json:"at"`
	Epoch string    `json:"epoch"`
}

// depsScanDue reports whether a project is due: a database update triggers
// a rescan (security plan section 11.1 D2).
func depsScanDue(prev depsLastScan, ok bool, epoch string, now time.Time) bool {
	return !ok || prev.Epoch != epoch || now.Sub(prev.At) >= depsScanEvery
}

// depsLastFile is the last-scan file: driver id and project root hash to
// the last scan (no path is stored). Its one writer is rememberScan, under
// the scan lease.
func (e *depsScanEnv) depsLastFile() string { return filepath.Join(e.dir, "deps-scan-last.json") }

func depsLastKey(driverID, root string) string {
	return driverID + "|" + secposture.ProjectRootHash(root)
}

// loadLastScans reads the last-scan file; a missing or unreadable file is
// no memory (every project is due).
func (e *depsScanEnv) loadLastScans() map[string]depsLastScan {
	out := map[string]depsLastScan{}
	b, err := os.ReadFile(e.depsLastFile())
	if err != nil {
		return out
	}
	if json.Unmarshal(b, &out) != nil {
		return map[string]depsLastScan{}
	}
	return out
}

// rememberScan records one scan, dropping entries older than twice the
// active-project window, and writes the file atomically.
func (e *depsScanEnv) rememberScan(driverID, root, epoch string, now time.Time) error {
	m := e.loadLastScans()
	for k, v := range m {
		if now.Sub(v.At) > 2*depsScanActive {
			delete(m, k)
		}
	}
	m[depsLastKey(driverID, root)] = depsLastScan{At: now, Epoch: epoch}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(e.dir, 0o700); err != nil {
		return err
	}
	tmp := e.depsLastFile() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, e.depsLastFile())
}

func depsScanPass(ctx context.Context, configPath, component string, lastDB *time.Time) error {
	e, err := openDepsScanEnv(ctx, configPath)
	if err != nil {
		return err
	}
	defer e.cleanup()
	if time.Since(*lastDB) >= depsDBEvery {
		rep, blocked, err := e.refreshDB(ctx)
		switch {
		case blocked != "":
			// Not marked as done: an accept given meanwhile starts the
			// download at the next tick, not 6 hours later.
			e.logger.Debug("security: OSV database download not allowed", "reason", blocked)
		case err != nil:
			e.logger.Warn("security: OSV database refresh failed", "err", err)
		case len(rep.Failed) > 0:
			e.logger.Warn("security: OSV database refresh failed for some ecosystems", "failed", len(rep.Failed))
		}
		if blocked == "" {
			*lastDB = time.Now()
		}
	}
	if e.awaitingAccept() {
		e.logger.Debug("security: dependency scans wait for the OSV database accept", "driver", component)
		return nil
	}
	d, err := e.depsDriver(component, extrunhost.NewRunner(extrunhost.Options{}))
	if err != nil || d == nil {
		return err
	}
	epochs, _ := e.db.Installed()
	epoch := depdriver.EpochSummary(epochs)
	roots, err := e.st.SecActiveProjectRoots(ctx, time.Now().Add(-depsScanActive))
	if err != nil {
		return err
	}
	e.scheduledScans(ctx, component, d.Row().ID, epoch, roots, os.Stat, func(root string) (secscan.Result, error) {
		return e.scanOne(ctx, d, root, secscan.Target{Scope: policy.FindingScopeScheduled}, false, nil, false)
	})
	return nil
}

// scheduledScans is one tick of the dependency schedule over the active
// roots: at most depsScanPerTick due scans, each of a folder on this host.
// A root that is not rooted on this host (FU-193's "Xcode (project
// unknown)") is never statted or scanned relative to the daemon's working
// directory (audit finding 1 on the w14 hand-back). stat and scan are the
// seams a test swaps.
func (e *depsScanEnv) scheduledScans(ctx context.Context, component, driverID, epoch string, roots []string, stat func(string) (os.FileInfo, error), scan func(root string) (secscan.Result, error)) {
	last := e.loadLastScans()
	n := 0
	for _, root := range roots {
		if ctx.Err() != nil || n >= depsScanPerTick {
			break
		}
		if !git.HostRooted(root) {
			continue
		}
		if fi, err := stat(root); err != nil || !fi.IsDir() {
			continue
		}
		prev, ok := last[depsLastKey(driverID, root)]
		if !depsScanDue(prev, ok, epoch, time.Now()) {
			continue
		}
		n++
		res, err := scan(root)
		if errors.Is(err, errDepsScanBusy) {
			// Another process (a CLI scan) holds the lease: try the rest
			// on the next tick rather than queue behind it.
			e.logger.Debug("security: dependency scan deferred, another scan is running", "driver", component)
			break
		}
		if err != nil {
			e.logger.Warn("security: dependency scan failed", "driver", component, "err", err)
			continue
		}
		e.logger.Debug("security: dependency scan", "driver", component, "outcome", res.Coverage.Outcome, "findings", len(res.Findings))
	}
}

// runScanChild is `observer security scan-child`: one request on stdin, one
// answer on stdout. It loads no config and opens no database.
func runScanChild(ctx context.Context, in io.Reader, out, errw io.Writer) error {
	b, err := io.ReadAll(io.LimitReader(in, depsChildStdin+1))
	if err != nil {
		return err
	}
	if len(b) > depsChildStdin {
		return errors.New("scan-child: request too large")
	}
	var req depscan.ChildRequest
	if err := json.Unmarshal(b, &req); err != nil {
		return fmt.Errorf("scan-child: %w", err)
	}
	resp := scalibrchild.Run(ctx, req, errw)
	return json.NewEncoder(out).Encode(resp)
}
