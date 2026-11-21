//go:build !sbo_omit_security && !sbo_omit_security_deps && !sbo_omit_security_scan_trivy && !sbo_omit_security_scan_image_trivy

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/extrun"
	extrunhost "github.com/marmutapp/superbased-observer/internal/extrun/host"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/seciac"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/secscan/trivydb"
	"github.com/marmutapp/superbased-observer/internal/secscan/trivyimage"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
)

// security_scan_image_trivy.go is the cmd seam of the Trivy image driver,
// component security.scan.image.trivy (OS and CI vulnerability scanning
// plan section 6.7, operator ruling Q6, lane OS-2 T). A build with
// sbo_omit_security_scan_image_trivy (or without the Trivy binary's row,
// sbo_omit_security_scan_trivy) drops this file, the pure driver
// (internal/secscan/trivyimage) and the download lane
// (internal/secscan/trivydb); security_scan_image_trivy_omit.go answers
// instead.
//
// One run, in order: hold the dependency scan lease; take the image's
// identity (security_scan_image_trivy_id*.go: route A's digest where
// internal/secimage is compiled, so both drivers share the project key
// "image:<digest>"); walk the database gate (an individual node and the
// developer's one-time accept, osvdb.TrivyConsent; a managed node reads
// not scanned and makes no request, its organization's mirror does not
// serve Trivy's database yet); download or refresh the database when due
// (trivydb.Due: at most every 6 hours, not before its own NextUpdate),
// keeping the last good one on a failure; resolve and decide the Trivy
// binary through the config driver's resolution (the pinned guided install
// first, else PATH, shims excluded; internal/seciac); link the database
// into the run's cache directory; scan the canary and then the image
// through the shared runner, isolated (trivyimage.Env.Scan); record the
// run through secsvc.RecordRun; close the Trivy findings of the same image
// a full scan no longer reports (never another driver's).
//
// The database download is the security.scan.trivy.db lane
// (tests/invariant/egress_lanes_test.go): it runs on this verb, on
// `observer security scan trivy-db refresh`, and on the daemon's dependency
// scan pass (maybeRefreshTrivyDB, when trivydb.Due says so), only after the
// accept and never on a managed node.

// trivyImageCompiled reports the driver in this build.
func trivyImageCompiled() bool { return true }

// The node-local files.
const (
	trivyImageStateFile = "trivy-image.json"
	trivyDBTimeout      = 30 * time.Minute
)

// trivyImageRoot is the driver's per-user directory: the database and the
// per-run directories, outside ~/.observer (the isolated run binds them).
func trivyImageRoot() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("no user cache directory: %w", err)
	}
	return filepath.Join(base, "superbased-observer", "scanners", "trivy-image"), nil
}

// trivyDBStore is the installed database.
func trivyDBStore() (trivydb.Store, error) {
	root, err := trivyImageRoot()
	if err != nil {
		return trivydb.Store{}, err
	}
	return trivydb.Store{Root: filepath.Join(root, "db")}, nil
}

// trivyDBFetcher is the download lane (tests swap it).
var trivyDBFetcher = func() trivydb.Fetcher { return trivydb.New(trivydb.Options{}) }

// trivyImageScan runs the driver (tests swap it: a test binary is not
// Trivy).
var trivyImageScan = func(ctx context.Context, env trivyimage.Env, in trivyimage.ScanInput) trivyimage.ScanOutput {
	return env.Scan(ctx, in)
}

// trivyImageBinary resolves and decides the Trivy binary (tests swap it:
// no Trivy is installed where they run).
var trivyImageBinary = func(e *depsScanEnv) (seciac.Inspection, []string, bool) { return e.trivyBinary() }

// trivyDBGate is the gate in front of the database download, walked
// top-down (depsGate).
var trivyDBGate = depsGate{
	{"managed_node_uses_org_mirror", func(e *depsScanEnv) bool { return e.managed }},
	{depscan.ReasonDBNotAccepted, func(e *depsScanEnv) bool { return !e.trivyConsent().Accepted() }},
}

// trivyManagedNote is a managed node's note on every Trivy image scan.
const trivyManagedNote = "Managed node: your organization's mirror does not serve Trivy's database yet, so Trivy image scans are not run and nothing is downloaded."

func (e *depsScanEnv) trivyConsent() osvdb.TrivyConsent {
	return osvdb.ReadTrivyConsent(e.dir, depsRecordKey(e.dir))
}

// trivyImageState is the driver's node-local state: the binary digest
// whose --help listed every flag of both modes.
type trivyImageState struct {
	FlagsOK string `json:"flags_ok,omitempty"`
}

func (e *depsScanEnv) trivyStatePath() string { return filepath.Join(e.dir, trivyImageStateFile) }

func (e *depsScanEnv) loadTrivyImageState() trivyImageState {
	var s trivyImageState
	b, err := iacReadCapped(e.trivyStatePath(), 4096)
	if err != nil || json.Unmarshal(b, &s) != nil {
		return trivyImageState{}
	}
	return s
}

func (e *depsScanEnv) saveTrivyImageState(s trivyImageState) {
	if b, err := json.Marshal(s); err == nil {
		_ = iacWriteFile(e.trivyStatePath(), b)
	}
}

// ensureTrivyDB makes the database available: the gate, then a refresh
// when due. It returns the installed state, or a fixed reason, and a note
// when a refresh failed but an older database stays in use.
func ensureTrivyDB(ctx context.Context, e *depsScanEnv, now time.Time) (trivydb.State, string, string) {
	if why := trivyDBGate.first(e); why != "" {
		if why == "managed_node_uses_org_mirror" {
			return trivydb.State{}, depscan.ReasonNoDatabase, trivyManagedNote
		}
		return trivydb.State{}, why, ""
	}
	s, err := trivyDBStore()
	if err != nil {
		return trivydb.State{}, depscan.ReasonNoDatabase, ""
	}
	st := s.State()
	if !trivydb.Due(st, now) {
		if st.Installed() {
			return st, "", ""
		}
		return st, depscan.ReasonFeedUnavailable, ""
	}
	rctx, cancel := context.WithTimeout(ctx, trivyDBTimeout)
	defer cancel()
	next, _, err := s.Refresh(rctx, trivyDBFetcher(), now)
	if err == nil {
		return next, "", ""
	}
	if next.Installed() {
		return next, "", "Database refresh failed (" + trivyRefreshReason(err) + "); the database built " + next.UpdatedAt.UTC().Format(time.RFC3339) + " was used."
	}
	return next, depscan.ReasonFeedUnavailable, ""
}

// trivyDaemonGate is the gate in front of the daemon's refresh, walked top
// down: the driver's components selected (security.deps,
// security.scan.trivy and security.scan.image.trivy, as the Scanners card
// reads them), then the download's own gate (trivyDBGate: an individual
// node, the developer's accept).
var trivyDaemonGate = append(depsGate{
	{"not_selected", func(e *depsScanEnv) bool {
		snap := componentSnapshotForConfig(e.cfg)
		return !securitySelected(snap, trivyImageComponent) || !securitySelected(snap, trivyEngineComponent) || !securitySelected(snap, securityDepsComponent)
	}},
}, trivyDBGate...)

// maybeRefreshTrivyDB is the daemon's refresh of Trivy's database, on the
// dependency scan pass (depsScanPass): behind trivyDaemonGate, only when
// trivydb.Due says so (at most every 6 hours after the last check and not
// before the database's own NextUpdate; the store's state file carries
// both, so the two driver loops and a restarted daemon share the cadence),
// under the dependency scan lease without waiting (a CLI scan that holds it
// is not raced; the next tick tries again). A failed refresh is fail-soft:
// the store keeps the last good database and records the failure, which
// the Scanners card shows. It reports whether a refresh ran.
func maybeRefreshTrivyDB(ctx context.Context, e *depsScanEnv, now time.Time) bool {
	if why := trivyDaemonGate.first(e); why != "" {
		return false
	}
	s, err := trivyDBStore()
	if err != nil || !trivydb.Due(s.State(), now) {
		return false
	}
	release, err := e.acquireDepsScan(ctx, false, nil)
	if err != nil {
		return false
	}
	defer release()
	// Another process may have refreshed while the lease was taken.
	if !trivydb.Due(s.State(), now) {
		return false
	}
	rctx, cancel := context.WithTimeout(ctx, trivyDBTimeout)
	defer cancel()
	st, changed, err := s.Refresh(rctx, trivyDBFetcher(), now)
	switch {
	case err != nil:
		e.logger.Warn("security: Trivy database refresh failed; the installed database stays in use", "reason", trivyRefreshReason(err), "installed", st.Installed())
	case changed:
		e.logger.Info("security: Trivy database refreshed", "epoch", st.Epoch())
	default:
		e.logger.Debug("security: Trivy database is current", "epoch", st.Epoch())
	}
	return true
}

func trivyRefreshReason(err error) string {
	var re *trivydb.RefreshError
	if errors.As(err, &re) {
		return re.Reason
	}
	return "refresh_failed"
}

// trivyBinary resolves and decides the Trivy binary through the config
// driver's resolution (one trust rule for both Trivy drivers).
func (e *depsScanEnv) trivyBinary() (seciac.Inspection, []string, bool) {
	resolved, err := config.ResolveGlobalPath(e.configPath)
	if err != nil {
		return seciac.Inspection{Reason: seciac.ReasonNotInstalled}, nil, false
	}
	ie := &iacEnv{
		id: seciac.Trivy, cfg: e.cfg, resolved: resolved, st: e.st, secDir: e.dir, managed: e.managed,
		snap: componentSnapshotForConfig(e.cfg), configPath: e.configPath,
	}
	ie.manifest = loadIaCManifest(iacContentStore(resolved), iacTrust(), seciac.Trivy)
	d := ie.inspector()
	if d == nil {
		return seciac.Inspection{Reason: seciac.ReasonNotInstalled}, nil, false
	}
	in := d.Inspect()
	var notes []string
	if in.Decision.Status == seciac.StatusUnverifiedLabelled {
		notes = append(notes, seciac.UnverifiedPrefix+": this Trivy binary is not covered by a verified pin ("+in.Decision.Detail+", driver_unverified); it ran on this individual node, labelled. A managed node refuses it.")
	}
	return in, notes, in.Reason == "" && in.Decision.Run()
}

// trivyImageRun is one run's directories.
type trivyImageRun struct {
	dir, cache, out, canary, input string
}

func newTrivyImageRun() (trivyImageRun, error) {
	root, err := trivyImageRoot()
	if err != nil {
		return trivyImageRun{}, err
	}
	runs := filepath.Join(root, "runs")
	if err := os.MkdirAll(runs, 0o700); err != nil {
		return trivyImageRun{}, err
	}
	dir, err := os.MkdirTemp(runs, "run-")
	if err != nil {
		return trivyImageRun{}, err
	}
	r := trivyImageRun{dir: dir, cache: filepath.Join(dir, "cache"), out: filepath.Join(dir, "out"), canary: filepath.Join(dir, "canary"), input: filepath.Join(dir, "input")}
	for _, d := range []string{r.cache, r.out, r.canary, r.input, filepath.Join(r.cache, "modules")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			_ = os.RemoveAll(dir)
			return trivyImageRun{}, err
		}
	}
	for rel, body := range trivyimage.CanaryFiles() {
		p := filepath.Join(r.canary, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			_ = os.RemoveAll(dir)
			return trivyImageRun{}, err
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			_ = os.RemoveAll(dir)
			return trivyImageRun{}, err
		}
	}
	return r, nil
}

// trivyDirDigest is a directory input's identity, the formula of
// secimage.DirDigest ("dir:" and the sha256 of its absolute path), so both
// drivers key a directory the same way.
func trivyDirDigest(abs string) string {
	s := sha256.Sum256([]byte(abs))
	return "dir:" + hex.EncodeToString(s[:])
}

// trivyReleaseLabel maps Trivy's detected OS onto the release table's label
// ("" for a release the table does not hold).
func trivyReleaseLabel(o *trivyimage.OSInfo) string {
	if !o.Detected() {
		return ""
	}
	id := strings.ToLower(o.Family)
	if id == "redhat" {
		id = "rhel"
	}
	if r, ok := osvdb.ReleaseFor(id, o.Name); ok {
		return releaseLabel(r)
	}
	return ""
}

// trivyRunnerFor builds the isolated runner of one run (the config
// driver's rule: Trivy runs only isolated).
func (e *depsScanEnv) trivyRunnerFor(run trivyImageRun, dbDir string) func(string) (*extrun.Runner, string) {
	return func(project string) (*extrun.Runner, string) {
		factory := isolationFactoryFor(componentSnapshotForConfig(e.cfg), filepath.Dir(e.dir), nil)
		if factory == nil || !scanIsolationAvailable() {
			return nil, trivyimage.ReasonIsolationRequired
		}
		prov, err := factory(extrun.OneShotDirs{Project: project, Output: run.out, Cache: run.cache, ProgramDirs: []string{dbDir}})
		switch {
		case err != nil && isolationMissingOnHost(err):
			return nil, trivyimage.ReasonIsolationRequired
		case err != nil || prov == nil:
			return nil, depscan.ReasonIsolationRefused
		}
		return extrunhost.NewRunner(extrunhost.Options{Isolation: prov}), ""
	}
}

// trivyInput is the run's read-only input: a tar is hard-linked into the
// run's input directory (so the isolated run binds only it); where the link
// cannot be made the tar's own directory is the input.
func trivyInput(in string, isDir bool, run trivyImageRun) (trivyimage.Mode, string, string) {
	if isDir {
		return trivyimage.ModeRootfs, in, in
	}
	link := filepath.Join(run.input, "image.tar")
	if err := os.Link(in, link); err == nil {
		return trivyimage.ModeImage, link, run.input
	}
	return trivyimage.ModeImage, in, filepath.Dir(in)
}

// previousDriverNote names the other driver's open findings on the image,
// which stay open after a switch.
func (e *depsScanEnv) previousDriverNote(ctx context.Context, t secscan.Target) string {
	open, err := e.openDepFindings(ctx, secposture.ProjectRootHash(t.ProjectRoot))
	if err != nil {
		return ""
	}
	n := 0
	for _, f := range open {
		if f.Engine.Driver != trivyimage.DriverID && f.Status == policy.FindingStatusOpen {
			n++
		}
	}
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("%s stay open until it scans again: %d open finding(s) of this image come from another driver.", trivyimage.PreviousDriverPrefix, n)
}

// runImageTrivyScan runs one Trivy image scan and records it (file
// comment).
func runImageTrivyScan(ctx context.Context, e *depsScanEnv, in, dockerfile string, onWait func()) (imageScanReport, error) {
	rep := imageScanReport{Image: in, Component: trivyimage.ComponentID, Driver: trivyimage.DriverID}
	loc, err := imageLocationFor(in, dockerfile)
	if err != nil {
		return rep, err
	}
	fi, err := os.Stat(in)
	if err != nil {
		return rep, err
	}
	release, err := e.acquireDepsScan(ctx, true, onWait)
	if err != nil {
		return rep, err
	}
	defer release()
	started := time.Now()
	run, err := newTrivyImageRun()
	if err != nil {
		return rep, fmt.Errorf("security scan image: run directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(run.dir) }()
	digest, idReason := trivyImageDigest(in, fi.IsDir(), filepath.Join(run.dir, "id"))
	if digest == "" {
		digest = trivyDirDigest(in)
	}
	rep.Digest = digest
	key := digest
	if !strings.HasPrefix(key, "dir:") && !strings.HasPrefix(key, "sha256:") {
		key = trivyDirDigest(in)
	}
	t := secscan.Target{Scope: policy.FindingScopeManual, ProjectRoot: "image:" + key}
	engine := secscan.EngineIdentity{Name: trivyimage.DriverID}
	var notes []string
	if n := e.previousDriverNote(ctx, t); n != "" {
		notes = append(notes, n)
	}
	stop := func(reason string, failed bool, extra ...string) secscan.Result {
		return trivyimage.RunResult("", depscan.EcoNotScanned, reason, failed, 0, "", trivyimage.MapOutput{}, engine, append(notes, extra...))
	}
	var res secscan.Result
	switch {
	case idReason != "":
		res = stop(idReason, false)
	default:
		res = e.trivyScanImage(ctx, run, in, fi.IsDir(), loc, t, engine, notes, stop)
	}
	if rel := scannedRelease(res); rel != "" {
		rep.Release = rel
	}
	if _, err := secsvc.RecordRun(ctx, e.st, t, res, started, time.Since(started), secsvc.Gone{}, securityRT.notify); err != nil {
		return rep, err
	}
	e.closeStaleTrivyFindings(ctx, t, res)
	rep.Result = res
	return rep, nil
}

// scannedRelease is the release a run named (scanned or not).
func scannedRelease(res secscan.Result) string {
	if len(res.Coverage.Scanned) > 0 {
		return res.Coverage.Scanned[0]
	}
	for _, s := range res.Coverage.Skipped {
		if strings.HasPrefix(s.Path, depscan.EcosystemSkipPrefix) {
			return strings.TrimPrefix(s.Path, depscan.EcosystemSkipPrefix)
		}
	}
	return ""
}

func (e *depsScanEnv) trivyScanImage(ctx context.Context, run trivyImageRun, in string, isDir bool, loc imageLocation, t secscan.Target, engine secscan.EngineIdentity, notes []string, stop func(string, bool, ...string) secscan.Result) secscan.Result {
	st, why, note := ensureTrivyDB(ctx, e, time.Now())
	if note != "" {
		notes = append(notes, note)
	}
	if why != "" {
		var extra []string
		if note != "" {
			extra = []string{note}
		}
		return stop(why, false, extra...)
	}
	bin, binNotes, ok := trivyImageBinary(e)
	notes = append(notes, binNotes...)
	switch {
	case bin.Reason == seciac.ReasonNotInstalled:
		return stop(depscan.ReasonNotInstalled, false, "Trivy is not installed: install the pinned, signature-checked release from the IaC scanners card on the Code security Scanners tab or with `observer security iac install --engine trivy` (it needs security.scan.trivy and security.code selected).")
	case !ok:
		return stop(trivyimage.ReasonUnverified, true)
	}
	store, err := trivyDBStore()
	if err != nil {
		return stop(depscan.ReasonDatabaseLinkFailed, true)
	}
	dbDir, err := store.LinkInto(st, run.cache)
	if err != nil {
		return stop(depscan.ReasonDatabaseLinkFailed, true)
	}
	mode, target, project := trivyInput(in, isDir, run)
	state := e.loadTrivyImageState()
	env := trivyimage.Env{
		RunnerFor: e.trivyRunnerFor(run, dbDir), Binary: bin.Binary, Digest: bin.Digest,
		CacheDir: run.cache, OutDir: run.out, CanaryDir: run.canary, FlagsChecked: state.FlagsOK != "" && state.FlagsOK == bin.Digest,
		ReadFile: iacReadCapped, GOOS: runtime.GOOS,
	}
	out := trivyImageScan(ctx, env, trivyimage.ScanInput{
		Mode: mode, Target: target, Project: project, Notes: notes,
		Map: trivyimage.MapInput{
			LabelFor: trivyReleaseLabel, RootHash: secposture.ProjectRootHash(t.ProjectRoot), Scope: t.Scope, Engine: engine,
			Epoch: st.Epoch(), Location: trivyimage.Location{RelPath: loc.RelPath, Line: loc.Line},
		},
	})
	if out.FlagsOK {
		state.FlagsOK = bin.Digest
		e.saveTrivyImageState(state)
	}
	return out.Result
}

// closeStaleTrivyFindings closes the open Trivy findings of the same image
// that a full scan no longer reports; another driver's findings stay open.
func (e *depsScanEnv) closeStaleTrivyFindings(ctx context.Context, t secscan.Target, res secscan.Result) {
	switch res.Coverage.Outcome {
	case secscan.OutcomeFindings, secscan.OutcomeClean, secscan.OutcomeUnknown:
	default:
		return
	}
	open, err := e.openDepFindings(ctx, secposture.ProjectRootHash(t.ProjectRoot))
	if err != nil {
		return
	}
	for _, id := range depscan.StaleFindings(open, trivyimage.DriverID, res.Findings, depscan.ScannedEcosystems(res.Coverage)) {
		_, _ = e.st.CloseSecFindingNotReproduced(ctx, id, time.Now())
	}
}

// --- trivy-db accept and refresh ---------------------------------------

// newSecurityScanTrivyDBCmd is `observer security scan trivy-db`: the
// one-time accept of Trivy's database download (R-165 denies it to an
// agent) and a refresh now.
func newSecurityScanTrivyDBCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "trivy-db",
		Short: fmt.Sprintf("Trivy's vulnerability database for the Trivy image driver (about %d MB from %s)", osvdb.TrivyApproxDownloadMB, osvdb.TrivyRegistryHost),
	}
	var yes bool
	accept := &cobra.Command{
		Use:   "accept",
		Short: fmt.Sprintf("Accept, once, the download of Trivy's database (about %d MB, %d MB on disk, from %s; checked every %d hours)", osvdb.TrivyApproxDownloadMB, osvdb.TrivyApproxDiskMB, osvdb.TrivySource, osvdb.TrivyRefreshHours),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			e, err := openTrivyDBEnv(cmd)
			if err != nil {
				return err
			}
			defer e.cleanup()
			return runTrivyDBAccept(cmd.OutOrStdout(), cmd.InOrStdin(), e, yes, term.IsTerminal(int(os.Stdin.Fd())), time.Now())
		},
	}
	accept.Flags().BoolVar(&yes, "yes", false, "record the accept without asking (you read the text above)")
	refresh := &cobra.Command{
		Use:   "refresh",
		Short: "Download or refresh Trivy's database now (an individual node, after the accept)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			e, err := openTrivyDBEnv(cmd)
			if err != nil {
				return err
			}
			defer e.cleanup()
			return runTrivyDBRefresh(cmd.Context(), cmd.OutOrStdout(), e)
		},
	}
	c.AddCommand(accept, refresh)
	return c
}

func openTrivyDBEnv(cmd *cobra.Command) (*depsScanEnv, error) {
	configPath, _ := cmd.Flags().GetString("config")
	e, err := openDepsScanEnv(cmd.Context(), configPath)
	if err != nil {
		return nil, err
	}
	if err := requireTrivyImageSelected(e); err != nil {
		e.cleanup()
		return nil, err
	}
	return e, nil
}

// runTrivyDBAccept shows the accept text and records the accept on a yes:
// asked on a terminal, recorded with --yes, never otherwise.
func runTrivyDBAccept(w io.Writer, in io.Reader, e *depsScanEnv, yes, isTerminal bool, now time.Time) error {
	if e.managed {
		fmt.Fprintln(w, "This is a managed node: "+strings.TrimPrefix(trivyManagedNote, "Managed node: ")+" There is nothing to accept here.")
		return nil
	}
	fmt.Fprintln(w, osvdb.TrivyConsentText)
	if c := e.trivyConsent(); c.Accepted() {
		fmt.Fprintf(w, "\nAlready accepted %s (%s).\n", c.AcceptedAt.Local().Format(time.RFC3339), c.Surface)
		return nil
	}
	if !yes && isTerminal {
		fmt.Fprintf(w, "\nDownload about %d MB from %s and keep it up to date? [y/N] ", osvdb.TrivyApproxDownloadMB, osvdb.TrivyRegistryHost)
		yes = depsReadYes(in)
	}
	if !yes {
		fmt.Fprintln(w, "\nNothing recorded. Accept on the dashboard's Code security page (Scanners), or re-run with --yes.")
		return nil
	}
	key, err := depsRecordSigningKey(e.dir)
	if err != nil {
		return err
	}
	if _, err := osvdb.RecordTrivyConsent(e.dir, "cli", depsLocalAccount(), now, key); err != nil {
		return err
	}
	fmt.Fprintln(w, "\nRecorded. The next Trivy image scan downloads the database; `observer security scan trivy-db refresh` downloads it now.")
	return nil
}

// runTrivyDBRefresh downloads or refreshes the database now, under the
// dependency scan lease and the gate.
func runTrivyDBRefresh(ctx context.Context, w io.Writer, e *depsScanEnv) error {
	if why := trivyDBGate.first(e); why != "" {
		if why == depscan.ReasonDBNotAccepted {
			return errors.New("Trivy's database download is not accepted: run `observer security scan trivy-db accept` (or accept on the dashboard's Scanners card)")
		}
		return errors.New(strings.TrimPrefix(trivyManagedNote, "Managed node: "))
	}
	release, err := e.acquireDepsScan(ctx, true, func() { fmt.Fprintln(w, "waiting for another dependency scan to finish...") })
	if err != nil {
		return err
	}
	defer release()
	s, err := trivyDBStore()
	if err != nil {
		return err
	}
	rctx, cancel := context.WithTimeout(ctx, trivyDBTimeout)
	defer cancel()
	st, changed, err := s.Refresh(rctx, trivyDBFetcher(), time.Now())
	if err != nil {
		return fmt.Errorf("Trivy's database: %w", err)
	}
	if changed {
		fmt.Fprintf(w, "Trivy's database installed: %s, %d MB on disk.\n", st.Epoch(), st.DBBytes>>20)
	} else {
		fmt.Fprintf(w, "Trivy's database is current: %s.\n", st.Epoch())
	}
	return nil
}

// --- status ------------------------------------------------------------

// fillTrivyImageStatus adds the Trivy driver's state.
func fillTrivyImageStatus(e *depsScanEnv, st *dashapi.ScannerImageStatus) {
	snap := componentSnapshotForConfig(e.cfg)
	tr := &dashapi.ScannerTrivyImageStatus{Tested: trivyimage.TestedVersion}
	tr.Selected = securitySelected(snap, trivyImageComponent) && securitySelected(snap, trivyEngineComponent) && securitySelected(snap, securityDepsComponent)
	if tr.Selected && e.st != nil {
		bin, _, ok := e.trivyBinary()
		tr.Installed = bin.Reason != seciac.ReasonNotInstalled
		tr.Pinned = ok && bin.Decision.Status == seciac.StatusVerified
		if tr.Installed {
			tr.Decision = bin.Decision.String()
		}
	}
	db := dashapi.ScannerTrivyDBStatus{
		Text: osvdb.TrivyConsentText, Source: osvdb.TrivySource, ApproxDownloadMB: osvdb.TrivyApproxDownloadMB, ApproxDiskMB: osvdb.TrivyApproxDiskMB,
		Managed: e.managed, Blocked: trivyDBGate.first(e),
	}
	if c := e.trivyConsent(); c.Accepted() {
		db.Accepted, db.AcceptedAt, db.AcceptedOn, db.By = true, c.AcceptedAt.UTC().Format(time.RFC3339), c.Surface, c.By
	}
	if s, err := trivyDBStore(); err == nil {
		ds := s.State()
		db.Installed, db.LastError = ds.Installed(), ds.LastError
		if ds.Installed() {
			db.Epoch, db.Bytes = ds.Epoch(), ds.DBBytes
			db.UpdatedAt, db.NextUpdate = ds.UpdatedAt.UTC().Format(time.RFC3339), ds.NextUpdate.UTC().Format(time.RFC3339)
			db.AgeHours = float64(int(ds.Age(time.Now()).Hours()*10)) / 10
		}
		if !ds.CheckedAt.IsZero() {
			db.CheckedAt = ds.CheckedAt.UTC().Format(time.RFC3339)
		}
	}
	tr.DB = db
	st.Trivy = tr
}

// writeTrivyImageState prints the Trivy driver's lines.
func writeTrivyImageState(_ context.Context, w io.Writer, st *dashapi.ScannerImageStatus) {
	tr := st.Trivy
	if tr == nil {
		return
	}
	sel := "not selected"
	if tr.Selected {
		sel = "selected"
	}
	bin := "not checked"
	switch {
	case !tr.Selected:
	case !tr.Installed:
		bin = "not installed"
	case tr.Pinned:
		bin = "installed, pinned (" + tr.Decision + ")"
	default:
		bin = "installed, not covered by a verified pin (" + tr.Decision + ")"
	}
	fmt.Fprintf(w, "    %s; binary %s; tested version %s\n", sel, bin, tr.Tested)
	db := tr.DB
	switch {
	case db.Managed:
		fmt.Fprintln(w, "    database: "+trivyManagedNote)
	case !db.Accepted:
		fmt.Fprintf(w, "    database: not accepted (about %d MB from %s): `observer security scan trivy-db accept`\n", db.ApproxDownloadMB, db.Source)
	case !db.Installed:
		fmt.Fprintf(w, "    database: accepted %s, not downloaded yet\n", db.AcceptedAt)
	default:
		fmt.Fprintf(w, "    database: %s, %.1f h old, %d MB on disk, checked %s\n", db.Epoch, db.AgeHours, db.Bytes>>20, db.CheckedAt)
	}
	if db.LastError != "" {
		fmt.Fprintf(w, "    last refresh failed: %s (the installed database stays in use)\n", db.LastError)
	}
}

// acceptTrivyDBDash records the dashboard's accept (the Scanners card's
// confirm dialog).
func acceptTrivyDBDash(e *depsScanEnv) error {
	snap := componentSnapshotForConfig(e.cfg)
	for _, id := range []string{trivyImageComponent, trivyEngineComponent, securityDepsComponent} {
		if !securitySelected(snap, id) {
			return fmt.Errorf("%s is not selected on this node", id)
		}
	}
	if e.managed {
		return errors.New(trivyManagedNote)
	}
	key, err := depsRecordSigningKey(e.dir)
	if err != nil {
		return err
	}
	_, err = osvdb.RecordTrivyConsent(e.dir, "dashboard", depsLocalAccount(), time.Now(), key)
	return err
}
