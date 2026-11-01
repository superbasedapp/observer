//go:build !sbo_omit_security

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/dblease"
	"github.com/marmutapp/superbased-observer/internal/extrun"
	extrunhost "github.com/marmutapp/superbased-observer/internal/extrun/host"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/secengine"
	"github.com/marmutapp/superbased-observer/internal/seciac"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// security_iac.go is the cmd seam of the two IaC drivers,
// security.scan.trivy and security.scan.kics (security pillar plan sections
// 4.4, 5.6 P2 and 8.1, gap G4, lane GATES-SEC): the engine bindings each
// driver's own build-tagged file registers (security_iac_trivy.go,
// security_iac_kics.go), the selection rule, the env a verb or the loop
// opens, the node-local state files (one owner: this file), and the run
// seam that records a run. Both components are opt-in (securityOptIn): with
// no [components] block nothing here runs, downloads or probes, and every
// verb answers "not selected" before it opens anything.

// iacBinding is one compiled engine.
type iacBinding struct {
	id seciac.EngineID
	// newDriver builds the engine's driver over an env.
	newDriver func(seciac.Env) *seciac.Driver
	// downloader is the guided install's egress lane; nil when the engine
	// publishes no release binaries (KICS).
	downloader func() iacDownloader
}

// iacDownloader is a release download of an engine's egress lane.
type iacDownloader interface {
	Download(ctx context.Context, url string, limit int64, w io.Writer) (int64, string, error)
}

// iacBindings are the engines compiled into this build, registered from
// each engine's own file (its omit tag removes its row).
var iacBindings = map[seciac.EngineID]iacBinding{}

// registerIaCEngine adds a compiled engine (called from init only).
func registerIaCEngine(b iacBinding) { iacBindings[b.id] = b }

// iacComponent is the catalog id of an engine.
func iacComponent(id seciac.EngineID) string { return "security.scan." + string(id) }

// iacSelected is the optional-module predicate with the opt-in rule: the
// engine compiled in, its component and security.code selected.
func iacSelected(snap componentstate.Snapshot, id seciac.EngineID) bool {
	_, compiled := iacBindings[id]
	return compiled && securitySelected(snap, iacComponent(id)) && securitySelected(snap, "security.code")
}

// errIaCNotSelected is every verb's answer while a component is off.
func errIaCNotSelected(id seciac.EngineID) error {
	if _, ok := iacBindings[id]; !ok {
		return fmt.Errorf("%s is not in this build", iacComponent(id))
	}
	return fmt.Errorf("the %s component is not selected: add it (and security.code) under [components] (observer components status)", iacComponent(id))
}

// The node-local files, in the security directory.
const (
	iacScanLeaseName    = "iac-scan"
	iacInstallLease     = "iac-install"
	iacInstallDomain    = "sbo-iac-install-v1"
	iacConsentDomain    = "sbo-iac-install-consent-v1"
	iacStateFileFmt     = "iac-%s.json"
	iacInstallFileFmt   = "iac-%s-install.json"
	iacConsentFileFmt   = "iac-%s-install-consent.json"
	iacMaxStateBytes    = 16 << 20
	iacMaxRecordBytes   = 4096
	iacOpenSightingsCap = 256
)

// iacEnv is what a verb or the loop opens for one engine.
type iacEnv struct {
	id         seciac.EngineID
	cfg        config.Config
	resolved   string
	st         *store.Store
	secDir     string
	managed    bool
	manifest   *seciac.ManifestPins
	snap       componentstate.Snapshot
	configPath string
	cleanup    func()
}

// openIaCEnv refuses when the component is not selected, before it opens
// anything.
func openIaCEnv(ctx context.Context, configPath string, id seciac.EngineID) (*iacEnv, error) {
	if !iacSelected(componentSnapshotFor(configPath), id) {
		return nil, errIaCNotSelected(id)
	}
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return nil, err
	}
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		cleanup()
		return nil, err
	}
	e := &iacEnv{id: id, cfg: cfg, resolved: resolved, st: store.New(database), secDir: secposture.LayoutFor(resolved).Dir, snap: componentSnapshotForConfig(cfg), configPath: configPath, cleanup: cleanup}
	if lk := managedTenancyLookup(e.st); lk != nil {
		e.managed = lk()
	}
	e.manifest = loadIaCManifest(iacContentStore(resolved), iacTrust(), id)
	return e, nil
}

// iacContentStore is the content store the security.engine manifest lives
// in: the same one the code rules read, so one manifest pins every engine.
func iacContentStore(resolvedConfig string) contentchan.Store {
	return contentchan.Store{Root: filepath.Join(secposture.LayoutFor(resolvedConfig).Dir, "code-content")}
}

// iacTrust is the key material the engine manifest verifies with (a
// variable so tests can stand in a key).
var iacTrust = func() contentchan.Trust { return contentchan.Trust{VendorKeys: iacVendorKeys()} }

// iacVendorKeysFn is set by security_iac_vendorkey.go (the compiled vendor
// keys); nil in a build without the org update module.
var iacVendorKeysFn func() []ed25519.PublicKey

func iacVendorKeys() []ed25519.PublicKey {
	if iacVendorKeysFn == nil {
		return nil
	}
	return iacVendorKeysFn()
}

// loadIaCManifest returns the verified engine manifest's pins for id, nil
// when none verifies; a stale or refused manifest still revokes.
func loadIaCManifest(cs contentchan.Store, tr contentchan.Trust, id seciac.EngineID) *seciac.ManifestPins {
	l, err := cs.Load(content.Engine, tr, 0)
	if err != nil {
		return nil
	}
	mp, ferr := seciac.FromManifest(l.Manifest, id)
	if ferr != nil || l.Freshness == content.Unknown {
		var rev []string
		for _, r := range l.Manifest.Revoked {
			if r.SHA256 != "" {
				rev = append(rev, r.SHA256)
			}
		}
		if len(rev) == 0 {
			return nil
		}
		return &seciac.ManifestPins{Revoked: rev, Version: l.Manifest.ManifestVersion}
	}
	return &mp
}

// iacScanRoot is the per-user directory of the engine's guided install,
// its own HOME and cache, the canary and the per-run output directories:
// outside ~/.observer, which the isolation engine never binds.
func iacScanRoot(id seciac.EngineID) (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("no user cache directory: %w", err)
	}
	return filepath.Join(base, "superbased-observer", "scanners", string(id)), nil
}

// iacInstalledPath is where the guided install puts the engine.
func iacInstalledPath(id seciac.EngineID) string {
	root, err := iacScanRoot(id)
	if err != nil {
		return ""
	}
	e, _ := seciac.Lookup(id)
	name := e.Binary
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(root, "bin", name)
}

// iacReadCapped reads a regular file (never through a symlink) of at most
// limit bytes.
func iacReadCapped(path string, limit int64) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > limit {
		return nil, fmt.Errorf("%s is not a regular file within %d bytes", path, limit)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err == nil && int64(len(b)) > limit {
		err = fmt.Errorf("%s is over %d bytes", path, limit)
	}
	return b, err
}

// iacWriteFile writes a node-local file atomically, 0600.
func iacWriteFile(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-iac-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(b)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(name, 0o600)
	}
	if werr == nil {
		werr = os.Rename(name, path)
	}
	if werr != nil {
		_ = os.Remove(name)
	}
	return werr
}

// iacStateStore is a driver's state file (one owner: this file).
type iacStateStore struct{ path string }

func (f iacStateStore) Load() (seciac.State, error) {
	var s seciac.State
	b, err := iacReadCapped(f.path, iacMaxStateBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return seciac.State{}, err
	}
	return s, nil
}

func (f iacStateStore) Save(s seciac.State) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return iacWriteFile(f.path, b)
}

func (e *iacEnv) statePath() string {
	return filepath.Join(e.secDir, fmt.Sprintf(iacStateFileFmt, e.id))
}

// iacRecordKeyPath is the posture key beside the global config (the key the
// scanners' accept records use).
func iacRecordKeyPath(secDir string) string {
	return filepath.Join(filepath.Dir(secDir), guardposture.KeyFilename)
}

// iacInstallFile is the guided install's record: the binary digest bound
// to the verified archive digest it came from, MAC'd under the posture key.
type iacInstallFile struct {
	Engine        string    `json:"engine"`
	Version       string    `json:"version"`
	ArchiveSHA256 string    `json:"archive_sha256"`
	BinarySHA256  string    `json:"binary_sha256"`
	Source        string    `json:"source"`
	At            time.Time `json:"at"`
	MAC           string    `json:"mac"`
}

func (r iacInstallFile) canonical() []byte {
	return []byte(r.Engine + "\n" + r.Version + "\n" + r.ArchiveSHA256 + "\n" + r.BinarySHA256 + "\n" + r.Source + "\n" + r.At.UTC().Format(time.RFC3339Nano) + "\n")
}

// readIaCInstallRecord returns the verified install record, nil when there
// is none or it does not verify (it then vouches for nothing).
func readIaCInstallRecord(secDir string, id seciac.EngineID) *seciac.InstallRecord {
	b, err := iacReadCapped(filepath.Join(secDir, fmt.Sprintf(iacInstallFileFmt, id)), iacMaxRecordBytes)
	if err != nil {
		return nil
	}
	var r iacInstallFile
	if json.Unmarshal(b, &r) != nil || r.Engine != string(id) {
		return nil
	}
	key, err := guardposture.ReadKey(iacRecordKeyPath(secDir))
	if err != nil || !guardposture.VerifyRecordMAC(iacInstallDomain, r.canonical(), key, r.MAC) {
		return nil
	}
	return &seciac.InstallRecord{ArchiveSHA256: r.ArchiveSHA256, BinarySHA256: r.BinarySHA256, Version: r.Version, Verified: true}
}

// writeIaCInstallRecord signs and writes the install record.
func writeIaCInstallRecord(secDir string, r iacInstallFile) error {
	key, err := guardposture.LoadOrCreateKey(iacRecordKeyPath(secDir))
	if err != nil {
		return fmt.Errorf("the install record cannot be signed: %w", err)
	}
	r.MAC = guardposture.RecordMAC(iacInstallDomain, r.canonical(), key)
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return iacWriteFile(filepath.Join(secDir, fmt.Sprintf(iacInstallFileFmt, r.Engine)), b)
}

// listIaCTree lists a directory tree's regular files (never following a
// symlink), at most seciac.MaxQueriesFiles.
func listIaCTree(dir string) secengine.TreeListing {
	var l secengine.TreeListing
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		l.Missing = true
		return l
	}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			return nil
		case !d.Type().IsRegular():
			l.Irregular = true
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		if len(l.Files) >= seciac.MaxQueriesFiles {
			return errors.New("too many files")
		}
		l.Files = append(l.Files, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return secengine.TreeListing{Err: err.Error()}
	}
	return l
}

// iacTopNames lists a project's top-level names (for the ignored-config
// note).
func iacTopNames(dir string) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// iacIsolation returns the isolation seam of a driver env (nil, nil: none
// on this host or in this build).
func (e *iacEnv) iacIsolation() (func(extrun.OneShotDirs) (extrun.IsolationProvider, error), func(extrun.IsolationProvider) *extrun.Runner) {
	factory := isolationFactoryFor(e.snap, filepath.Dir(e.resolved), nil)
	if factory == nil {
		return nil, nil
	}
	return func(d extrun.OneShotDirs) (extrun.IsolationProvider, error) {
			if !isolationAvailable() {
				return nil, nil
			}
			p, err := factory(d)
			if err != nil && isolationMissingOnHost(err) {
				return nil, nil
			}
			return p, err
		}, func(p extrun.IsolationProvider) *extrun.Runner {
			return extrunhost.NewRunner(extrunhost.Options{Isolation: p})
		}
}

// iacAllowRepoConfig reads the engine's allow_repo_config key.
// allowUnpinned is the engine's allow_unpinned key, never on a managed node
// (ruling P-143).
func (e *iacEnv) allowUnpinned() bool {
	if e.managed {
		return false
	}
	if e.id == seciac.KICS {
		return e.cfg.Security.Scan.Kics.AllowUnpinned
	}
	return e.cfg.Security.Scan.Trivy.AllowUnpinned
}

func (e *iacEnv) allowRepoConfig() bool {
	if e.id == seciac.KICS {
		return e.cfg.Security.Scan.Kics.AllowRepoConfig
	}
	return e.cfg.Security.Scan.Trivy.AllowRepoConfig
}

// driver builds the driver for one run; cleanup removes the run's output
// directory.
func (e *iacEnv) driver() (*seciac.Driver, func(), error) {
	b, ok := iacBindings[e.id]
	if !ok {
		return nil, nil, errIaCNotSelected(e.id)
	}
	root, err := iacScanRoot(e.id)
	if err != nil {
		return nil, nil, err
	}
	cache, runs, canary := filepath.Join(root, "engine"), filepath.Join(root, "runs"), filepath.Join(root, "canary")
	for _, d := range []string{cache, runs, canary} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, nil, err
		}
	}
	for name, body := range seciac.CanaryFiles {
		if err := os.WriteFile(filepath.Join(canary, name), []byte(body), 0o600); err != nil {
			return nil, nil, err
		}
	}
	out, err := os.MkdirTemp(runs, "run-")
	if err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(filepath.Join(out, "empty-config.json"), []byte("{}\n"), 0o600); err != nil {
		_ = os.RemoveAll(out)
		return nil, nil, err
	}
	env := e.baseEnv(extrunhost.NewRunner(extrunhost.Options{}), cache)
	env.OutDir, env.CanaryDir = out, canary
	env.Isolate, env.IsolatedRunner = e.iacIsolation()
	return b.newDriver(env), func() { _ = os.RemoveAll(out) }, nil
}

func (e *iacEnv) baseEnv(r *extrun.Runner, cache string) seciac.Env {
	return seciac.Env{
		Runner: r, CacheDir: cache, Installed: iacInstalledPath(e.id), InstallRecord: readIaCInstallRecord(e.secDir, e.id),
		Managed: e.managed, Manifest: e.manifest, State: iacStateStore{path: e.statePath()},
		AllowRepoConfig: e.allowRepoConfig(), AllowUnpinned: e.allowUnpinned(), TopNames: iacTopNames,
		ProbeHash: iacProbeHashes.hash(r.Hash, os.Stat), ListTree: listIaCTree, ReadFile: iacReadCapped,
		RootHash: secposture.ProjectRootHash, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
	}
}

// inspector is what status and doctor read through: it creates no
// directory, writes no canary and opens no run directory.
func (e *iacEnv) inspector() *seciac.Driver {
	b, ok := iacBindings[e.id]
	if !ok {
		return nil
	}
	root, _ := iacScanRoot(e.id)
	env := e.baseEnv(extrunhost.NewRunner(extrunhost.Options{}), filepath.Join(root, "engine"))
	env.Isolate, env.IsolatedRunner = e.iacIsolation()
	return b.newDriver(env)
}

// errIaCScanBusy is a run that did not start: another IaC scan holds the
// machine's lease.
var errIaCScanBusy = errors.New("another IaC scan is running")

// iacRunReport is what one run reports (`--json`).
type iacRunReport struct {
	Engine   string   `json:"engine"`
	Project  string   `json:"project_root_hash"`
	Outcome  string   `json:"outcome"`
	Reason   string   `json:"reason,omitempty"`
	Findings int      `json:"findings"`
	New      int      `json:"new"`
	Notes    []string `json:"notes,omitempty"`
	Recorded bool     `json:"recorded"`
}

// runIaCScan is THE run seam: one scan of root (or its linked worktree
// checkout) by one engine, recorded as one run. It takes the machine's IaC
// scan lease without waiting. A complete run of the main checkout closes
// the engine's open findings at the files it read but did not report
// again; a linked worktree closes nothing (P-041).
func runIaCScan(ctx context.Context, e *iacEnv, t secscan.Target) (iacRunReport, error) {
	rep := iacRunReport{Engine: string(e.id), Project: secposture.ProjectRootHash(t.ProjectRoot)}
	release, ok, err := dblease.TryAcquire(e.secDir, iacScanLeaseName)
	if err == nil && !ok {
		return rep, errIaCScanBusy
	}
	defer release()
	d, cleanup, err := e.driver()
	if err != nil {
		return rep, err
	}
	defer cleanup()
	started := time.Now()
	res, err := d.Scan(ctx, t)
	if err != nil {
		return rep, err
	}
	rep.Outcome, rep.Reason, rep.Findings, rep.Notes = string(res.Coverage.Outcome), res.Coverage.Reason, len(res.Findings), res.Coverage.Notes
	if res.Coverage.Outcome == secscan.OutcomeNotScanned {
		// Nothing ran (not installed, not isolated): nothing is recorded and
		// the project keeps reading not_scanned, never clean.
		return rep, nil
	}
	gone := secsvc.Gone{}
	if t.CheckoutRoot == "" || filepath.Clean(t.CheckoutRoot) == filepath.Clean(t.ProjectRoot) {
		gone = secsvc.Gone{Pack: string(e.id), Paths: iacGonePaths(ctx, e.st, e.id, rep.Project, res)}
	}
	rep.New, err = secsvc.RecordRun(ctx, e.st, t, res, started, time.Since(started), gone, nil)
	rep.Recorded = err == nil
	return rep, err
}

// iacGonePaths are the files a complete run speaks for: the engine's open
// sightings in the project and the files this run reported, capped.
func iacGonePaths(ctx context.Context, st *store.Store, id seciac.EngineID, rootHash string, res secscan.Result) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p != "" && !seen[p] && len(out) < iacOpenSightingsCap {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, f := range res.Findings {
		add(f.Location.RelPath)
	}
	rows, err := st.SecRescanSightings(ctx, store.SecRescanQuery{
		Driver: string(id), Classes: []store.SecRescanClass{{Pack: string(id)}}, RootHashes: []string{rootHash}, Limit: iacOpenSightingsCap,
	})
	if err == nil {
		for _, r := range rows {
			add(r.Path)
		}
	}
	sort.Strings(out)
	return out
}
