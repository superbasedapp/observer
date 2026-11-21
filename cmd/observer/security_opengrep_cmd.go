//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/dblease"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/extrun"
	extrunhost "github.com/marmutapp/superbased-observer/internal/extrun/host"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/remedy"
	"github.com/marmutapp/superbased-observer/internal/secengine"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secrulepack"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/opengrep"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// security_opengrep_cmd.go is `observer security code` (component
// security.scan.opengrep, Phase G lane G1): status, a scan of one known
// project (full, or diff-scoped against a base commit), the rule pack list
// and import, and the guided install text. The component is opt-in
// (securityOptIn): an install with no [components] block sees every verb
// refuse "not selected", and nothing starts, downloads or records.

// opengrepComponent is the catalog id.
const opengrepComponent = opengrep.ComponentID

// codeScanLeaseName is the cross-process lease of one Opengrep scan (one
// heavy scan at a time per machine, security plan section 4.4).
const codeScanLeaseName = "code-scan"

// codeStateFile is the driver's node-local state (the companion tree record
// and the self-test), under the security directory.
const codeStateFile = "opengrep-engine.json"

// errCodeNotSelected is every verb's answer while the component is off.
var errCodeNotSelected = fmt.Errorf("the %s component is not selected: add it under [components] (observer components status); it needs Opengrep, installed by you or by `observer security code install`", opengrepComponent)

// codeScanSelected is the optional-module predicate with the opt-in rule.
func codeScanSelected(snap componentstate.Snapshot) bool {
	return securitySelected(snap, opengrepComponent) && securitySelected(snap, "security.code")
}

// codeEnv is what a verb opens.
type codeEnv struct {
	cfg      config.Config
	resolved string
	st       *store.Store
	secDir   string
	managed  bool
	pack     codePack
	manifest *secengine.ManifestPins
	snap     componentstate.Snapshot
	// configPath is the --config the env was opened with.
	configPath string
	cleanup    func()
}

// openCodeEnv refuses when the component is not selected, before it opens
// anything.
func openCodeEnv(ctx context.Context, configPath string) (*codeEnv, error) {
	if !codeScanSelected(componentSnapshotFor(configPath)) {
		return nil, errCodeNotSelected
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
	e := &codeEnv{cfg: cfg, resolved: resolved, st: store.New(database), secDir: secposture.LayoutFor(resolved).Dir, cleanup: cleanup, snap: componentSnapshotForConfig(cfg), configPath: configPath}
	if lk := managedTenancyLookup(e.st); lk != nil {
		e.managed = lk()
	}
	cs := codeRulesStore(resolved)
	if e.pack, err = loadCodePack(cs, codeRulesTrust()); err != nil {
		cleanup()
		return nil, err
	}
	e.manifest = loadEngineManifest(cs, codeRulesTrust())
	return e, nil
}

// loadEngineManifest returns the verified security.engine manifest's
// Opengrep pins, nil when none is installed or it does not verify (the
// compiled pins then hold).
func loadEngineManifest(cs contentchan.Store, tr contentchan.Trust) *secengine.ManifestPins {
	l, err := cs.Load(content.Engine, tr, 0)
	return engineManifestPins(l, err)
}

// engineManifestPins reads a loaded engine manifest. Its pins count only
// while it is inside its age floor and its entries pass FromManifest; its
// revocations count whatever its freshness (lane SEC-G1 audit finding 5): a
// stale manifest still refuses what it revoked. A manifest that does not
// load at all yields nothing here; the revocations the driver remembered
// from it on an earlier scan (opengrep.State.Revoked) still hold.
func engineManifestPins(l contentchan.Loaded, err error) *secengine.ManifestPins {
	if err != nil {
		return nil
	}
	mp, ferr := secengine.FromManifest(l.Manifest)
	if ferr != nil || l.Freshness == content.Unknown {
		rev := secengine.RevocationsOf(l.Manifest)
		if len(rev) == 0 {
			return nil
		}
		return &secengine.ManifestPins{Revoked: rev, Version: l.Manifest.ManifestVersion}
	}
	return &mp
}

// codeScanRoot is the per-user directory of the pack copy, the engine's own
// HOME and cache, and the per-run output directories: outside ~/.observer,
// which the isolation engine never binds.
func codeScanRoot() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("no user cache directory: %w", err)
	}
	return filepath.Join(base, "superbased-observer", "scanners", "opengrep"), nil
}

// materializePack writes the pack under root/packs/<version>-<digest>/ and
// re-reads it: what Opengrep is handed is checked against the pack digest,
// so a copy changed on disk is rewritten before the run.
func materializePack(root string, p *secrulepack.Pack) (string, error) {
	dir := packCopyDir(root, p)
	files := p.Files()
	if got, err := readPackDir(dir); err == nil && secrulepack.CanonicalDigest(got) == p.Digest() {
		return dir, nil
	}
	_ = os.RemoveAll(dir)
	for name, b := range files {
		dst := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return "", err
		}
		if err := os.WriteFile(dst, b, 0o600); err != nil {
			return "", err
		}
	}
	got, err := readPackDir(dir)
	if err != nil || secrulepack.CanonicalDigest(got) != p.Digest() {
		return "", errors.New("the rule pack copy does not match its digest after writing")
	}
	return dir, nil
}

// packCopyDir is where materializePack writes a pack's copy.
func packCopyDir(root string, p *secrulepack.Pack) string {
	return filepath.Join(root, "packs", p.Version()+"-"+p.Digest()[:16])
}

// readPackDir reads every regular file under dir into pack paths.
func readPackDir(dir string) (map[string][]byte, error) {
	out := map[string][]byte{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", p)
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		b, err := readCappedFile(p, secrulepack.MaxRuleBytes)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = b
		return nil
	})
	return out, err
}

// listEngineTree lists the companion tree directory (never following a
// symlink).
func listEngineTree(dir string) secengine.TreeListing {
	var l secengine.TreeListing
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		return secengine.TreeListing{Missing: true}
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
		if len(l.Files) >= secengine.MaxTreeFiles {
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

// codeStateStore is the driver's state file (one owner: this file).
type codeStateStore struct{ path string }

func (f codeStateStore) Load() (opengrep.State, error) {
	var s opengrep.State
	b, err := readCappedFile(f.path, 1<<20)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return opengrep.State{}, err
	}
	return s, nil
}

func (f codeStateStore) Save(s opengrep.State) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		return err
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}

// driver builds the driver for one run; cleanup removes the run's output
// directory.
func (e *codeEnv) driver(jobs int) (*opengrep.Driver, func(), error) {
	root, err := codeScanRoot()
	if err != nil {
		return nil, nil, err
	}
	packDir, err := materializePack(root, e.pack.Pack)
	if err != nil {
		return nil, nil, err
	}
	cacheDir := filepath.Join(root, "engine")
	runs := filepath.Join(root, "runs")
	for _, d := range []string{cacheDir, runs} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, nil, err
		}
	}
	out, err := os.MkdirTemp(runs, "run-")
	if err != nil {
		return nil, nil, err
	}
	env := opengrep.Env{
		Runner: extrunhost.NewRunner(extrunhost.Options{}),
		Pack:   e.pack.Pack, PackDir: packDir, CacheDir: cacheDir, OutDir: out,
		Managed: e.managed, Manifest: e.manifest,
		State: codeStateStore{path: filepath.Join(e.secDir, codeStateFile)}, ListTree: listEngineTree,
		ReadFile: readCappedFile, Jobs: jobs, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Installed: codeInstalledPath(),
		LinkedCommonDir: codeLinkedCommonDir,
		Taint:           codeTaintConfig(e.cfg.Security.Scan.Opengrep), Stat: codeLstat,
		TaintCache: codeTaintCacheStore{path: filepath.Join(root, codeTaintCacheFile)},
	}
	if factory := isolationFactoryFor(e.snap, filepath.Dir(e.resolved), nil); factory != nil {
		env.Isolate = func(d extrun.OneShotDirs) (extrun.IsolationProvider, error) {
			if !isolationAvailable() {
				return nil, nil
			}
			p, err := factory(d)
			if err != nil && isolationMissingOnHost(err) {
				return nil, nil
			}
			return p, err
		}
		env.IsolatedRunner = func(p extrun.IsolationProvider) *extrun.Runner {
			return extrunhost.NewRunner(extrunhost.Options{Isolation: p})
		}
	}
	return opengrep.New(env), func() { _ = os.RemoveAll(out) }, nil
}

// codeLinkedCommonDir is the main repository's git directory of a linked
// worktree checkout, "" for any other directory.
func codeLinkedCommonDir(dir string) string {
	c, _ := git.LinkedCommonDir(dir)
	return c
}

// inspector is the driver status and doctor read through (lane SEC-G1
// audit finding 6): it names the directories a scan would use but creates
// none, writes no pack copy and opens no run directory. Probe and Inspect
// read the binary, the tree listing and the driver's record, nothing else.
func (e *codeEnv) inspector() (*opengrep.Driver, error) {
	root, err := codeScanRoot()
	if err != nil {
		return nil, err
	}
	return opengrep.New(opengrep.Env{
		// The binary's digest is cached (security_opengrep_digest.go): the
		// loop, the card and the Scanners card read through here often.
		Runner: codeInspectRunner(),
		Pack:   e.pack.Pack, PackDir: packCopyDir(root, e.pack.Pack), CacheDir: filepath.Join(root, "engine"),
		Managed: e.managed, Manifest: e.manifest,
		State: codeStateStore{path: filepath.Join(e.secDir, codeStateFile)}, ListTree: listEngineTree,
		ReadFile: readCappedFile, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Installed: codeInstalledPath(),
	}), nil
}

// treeWords is how status and doctor name the unpacked tree: the name
// check, and the recorded state with its age (its file digests are compared
// before each scan, never by status or doctor).
func treeWords(in opengrep.Inspection, now time.Time) string {
	s := string(in.Tree)
	if !in.TreeRecordedAt.IsZero() {
		s += fmt.Sprintf(" (recorded %s, %s ago; its file digests are checked before each scan, not here)",
			in.TreeRecordedAt.UTC().Format(time.RFC3339), now.Sub(in.TreeRecordedAt).Round(time.Minute))
	}
	return s
}

// securityCodeSubcommands is `observer security code`.
func securityCodeSubcommands() []*cobra.Command {
	cmd := &cobra.Command{
		Use:   "code",
		Short: "Code rules run by a separately installed Opengrep (component security.scan.opengrep; opt-in)",
		Long: "Runs Observer's own observer-code rule pack with a separately installed Opengrep\n" +
			"(LGPL-2.1, never bundled), pinned and verified (v1.30.1 on linux amd64). Findings are\n" +
			"flag only: no rule clears the precision bar (docs/code-rules-precision.md). Opt-in: add\n" +
			"security.scan.opengrep under [components].",
	}
	cmd.AddCommand(newCodeStatusCmd(), newCodeScanCmd(), newCodeRulesCmd(), newCodeInstallCmd(), newCodeGuidedInstallCmd(), newCodeRefreshCmd())
	return []*cobra.Command{cmd}
}

func newCodeStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the Opengrep engine, its verification, the rule pack and the last scans (starts nothing)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			configPath, _ := cmd.Flags().GetString("config")
			e, err := openCodeEnv(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer e.cleanup()
			return writeCodeStatus(cmd.Context(), cmd.OutOrStdout(), e)
		},
	}
}

// decisionWords is how status names a decision.
func decisionWords(d secengine.Decision) string {
	switch d.Status {
	case secengine.StatusVerified:
		return "verified (" + d.Detail + ")"
	case secengine.StatusUnverifiedLabelled:
		return "unverified, runs labelled on this individual node (" + d.Detail + ")"
	}
	return "refused: driver_unverified (" + d.Detail + ")"
}

func writeCodeStatus(ctx context.Context, w io.Writer, e *codeEnv) error {
	d, err := e.inspector()
	if err != nil {
		return err
	}
	pin, _ := secengine.CompiledPin(runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(w, "component: %s selected\n", opengrepComponent)
	tenancy := "individual node (an unverified engine runs labelled)"
	if e.managed {
		tenancy = "managed node (an unverified engine is refused)"
	}
	fmt.Fprintln(w, "node:", tenancy)
	fmt.Fprintf(w, "pin for %s/%s: %s %s %s\n", runtime.GOOS, runtime.GOARCH, pin.Version, pin.Status, pin.SHA256)
	if e.manifest != nil {
		fmt.Fprintf(w, "engine manifest: version %d, %d Opengrep pins, %d revoked\n", e.manifest.Version, len(e.manifest.Pins), len(e.manifest.Revoked))
	}
	p := d.Probe(ctx)
	switch {
	case !p.Installed:
		fmt.Fprintln(w, "opengrep: not installed (no process starts; see observer security code install)")
	default:
		info := d.Inspect()
		fmt.Fprintf(w, "opengrep: %s sha256 %s\n", info.Binary, info.Digest)
		fmt.Fprintln(w, "verification:", decisionWords(info.Decision))
		fmt.Fprintln(w, "unpacked tree:", treeWords(info, time.Now()))
		if !info.SelfTestAt.IsZero() {
			fmt.Fprintf(w, "canary self-test: passed %s, %s ago\n", info.SelfTestAt.UTC().Format(time.RFC3339), time.Since(info.SelfTestAt).Round(time.Minute))
		}
	}
	pk := e.pack
	fmt.Fprintf(w, "rule pack: %s %s (%s), %d rules, digest %s\n", pk.Pack.Manifest.ID, pk.Pack.Version(), pk.Source, len(pk.Pack.Manifest.Rules), pk.Pack.Digest())
	if pk.Note != "" {
		fmt.Fprintln(w, "rule pack note:", pk.Note)
	}
	iso := "no (runs are labelled \"not isolated\")"
	if isolationFactoryFor(e.snap, filepath.Dir(e.resolved), nil) != nil && isolationAvailable() {
		iso = "yes (bwrap one-shot, no network)"
	}
	fmt.Fprintln(w, "isolation:", iso)
	for _, l := range codeExtraLines(ctx, e) {
		fmt.Fprintln(w, l)
	}
	return nil
}

// codeExtraLines are the lane SEC-G2 status and doctor lines: the guided
// install, the pack's freshness and last fetch, the triggers and the last
// run. They read files and the store only; nothing starts.
func codeExtraLines(ctx context.Context, e *codeEnv) []string {
	var out []string
	p := secengine.PlanInstall(e.installInput(ctx))
	switch {
	case p.Blocked != "":
		out = append(out, "guided install: "+codeBlockedWords(p.Blocked))
	case p.Installed:
		out = append(out, "guided install: Opengrep "+p.Pin.Version+" installed at "+codeInstalledPath())
	case e.managed:
		out = append(out, "guided install: available from the org mirror (observer security code install)")
	case readCodeInstallConsent(e.secDir).Covers(p):
		out = append(out, "guided install: consent given for "+p.Pin.Version+", not installed yet (observer security code install)")
	default:
		out = append(out, fmt.Sprintf("guided install: Opengrep %s, %s download, %s unpacked; waits for your one-time consent (observer security code install, or the Code rules card)", p.Pin.Version, secengine.MB(p.DownloadBytes), secengine.MB(p.TreeBytes)))
	}
	fresh := string(e.pack.Freshness)
	if fresh == "" {
		fresh = "embedded"
	}
	out = append(out, "rule pack freshness: "+fresh)
	if f, ok := readCodeFetch(e.secDir)[string(content.RulePack)]; ok {
		line := fmt.Sprintf("last content fetch: %s at %s", f.Source, f.At.UTC().Format(time.RFC3339))
		if f.Error != "" {
			line += " FAILED (" + f.Error + "); the installed pack stays in use and reads stale, never current"
		}
		out = append(out, line)
	}
	oc := e.cfg.Security.Scan.Opengrep
	sched := "off"
	if oc.ScheduleHours > 0 {
		sched = fmt.Sprintf("every %d hours", oc.ScheduleHours)
	}
	out = append(out, fmt.Sprintf("triggers: post-write %s, commit diff %s, schedule %s (none runs in a hook or the commit gate's quick scan)", onOff(oc.PostWrite), onOff(oc.CommitDiff), sched))
	if e.st != nil {
		if r, ok, err := e.st.SecLatestRun(ctx, opengrep.DriverID); err == nil && ok {
			out = append(out, fmt.Sprintf("last run: %s %s at %s", r.Scope, r.Outcome, r.StartedAt.UTC().Format(time.RFC3339)))
		}
		if words, at, ok := codeLastTaintPass(ctx, e.st); ok {
			out = append(out, fmt.Sprintf("intrafile taint pass (full scan at %s): %s", at.UTC().Format(time.RFC3339), words))
		}
	}
	return out
}

func newCodeScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan [DIR]",
		Short: "Scan one known project with the observer-code rules (a full scan, or --diff BASE)",
		Long: "Scans a project Observer already knows (its git root must be a project in the local\n" +
			"store). --full (the default) reads every file but dependency and virtual-environment\n" +
			"directories; --diff BASE reads only what changed since BASE and reports only new results\n" +
			"(--baseline-commit), so it closes no older finding. Findings are flag only.",
		Args: cobra.MaximumNArgs(1),
		RunE: runCodeScanCmd,
	}
	cmd.Flags().String("diff", "", "scan only what changed since this commit (a ref is resolved to its commit)")
	cmd.Flags().Bool("full", false, "scan the whole project (the default)")
	cmd.Flags().Int("jobs", 0, "Opengrep -j (1 to 8; default 4); the children cap scales with it")
	cmd.Flags().Bool("json", false, "print the result as JSON")
	return cmd
}

// knownProjectRoot resolves dir to its project root (git.FindRoot: in a
// linked worktree, the main repository) and its checkout root
// (git.FindCheckoutRoot: the worktree's own top level), and requires the
// project to be one the store knows (lane SEC-G1 audit finding 2). The
// project keys the findings; the checkout is what a scan reads.
func knownProjectRoot(ctx context.Context, st *store.Store, dir string) (root, checkout string, err error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", "", err
	}
	root, ok := git.FindRoot(abs)
	if !ok {
		return "", "", fmt.Errorf("%s is not inside a git repository", abs)
	}
	checkout, ok = git.FindCheckoutRoot(abs)
	if !ok || checkout == "" {
		checkout = root
	}
	roots, err := st.ProjectRoots(ctx)
	if err != nil {
		return "", "", err
	}
	if !slices.Contains(roots, root) {
		return "", "", fmt.Errorf("%s is not a project Observer knows (open it with an AI tool Observer watches first)", root)
	}
	return root, checkout, nil
}

// codeScanReport is `scan --json`.
type codeScanReport struct {
	Project  string                 `json:"project_root_hash"`
	Mode     string                 `json:"mode"`
	Coverage secscan.Coverage       `json:"coverage"`
	Engine   secscan.EngineIdentity `json:"engine"`
	New      int                    `json:"new_findings"`
	Findings []codeScanFinding      `json:"findings"`
	Labels   []string               `json:"labels"`
	// LinkedWorktree: the run read a linked worktree of the project; its
	// findings are recorded on the project and it closed nothing.
	LinkedWorktree bool `json:"linked_worktree,omitempty"`
}

type codeScanFinding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Path     string `json:"path"`
	Line     int    `json:"line"`
}

func runCodeScanCmd(cmd *cobra.Command, args []string) error {
	configPath, _ := cmd.Flags().GetString("config")
	base, _ := cmd.Flags().GetString("diff")
	fullFlag, _ := cmd.Flags().GetBool("full")
	jobs, _ := cmd.Flags().GetInt("jobs")
	asJSON, _ := cmd.Flags().GetBool("json")
	if base != "" && fullFlag {
		return errors.New("pass --diff BASE or --full, not both")
	}
	ctx := cmd.Context()
	e, err := openCodeEnv(ctx, configPath)
	if err != nil {
		return err
	}
	defer e.cleanup()
	dir := "."
	if len(args) == 1 {
		dir = args[0]
	}
	root, checkout, err := knownProjectRoot(ctx, e.st, dir)
	if err != nil {
		return err
	}
	t := secscan.Target{ProjectRoot: root, CheckoutRoot: checkout, Scope: policy.FindingScopeManual}
	mode := "full"
	if base != "" {
		commit, err := resolveDiffBase(ctx, checkout, base)
		if err != nil {
			return err
		}
		t.Scope, t.BaseRev, mode = policy.FindingScopeDiff, commit, "diff"
	}
	release, err := acquireCodeScan(ctx, e.secDir, func() { fmt.Fprintln(cmd.ErrOrStderr(), "waiting for another Opengrep scan to finish...") })
	if err != nil {
		return err
	}
	defer release()
	d, cleanup, err := e.driver(jobs)
	if err != nil {
		return err
	}
	defer cleanup()
	started := time.Now()
	res, scanned, err := d.ScanFiles(ctx, t)
	if err != nil {
		return err
	}
	created, err := recordCodeScan(ctx, e.st, t, res, scanned, started, securityRT.notify)
	if err != nil {
		return err
	}
	rep := codeScanReport{Project: secposture.ProjectRootHash(root), Mode: mode, Coverage: res.Coverage, Engine: res.Engine, New: created, Findings: []codeScanFinding{}, Labels: codeRunLabels(res.Coverage.Notes), LinkedWorktree: checkout != root}
	for _, f := range res.Findings {
		rep.Findings = append(rep.Findings, codeScanFinding{Rule: f.Rule.ID, Severity: string(f.Severity), Path: f.Location.RelPath, Line: f.Location.StartLine})
	}
	w := cmd.OutOrStdout()
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	outcome := string(res.Coverage.Outcome)
	if res.Coverage.Reason != "" {
		outcome += " (" + res.Coverage.Reason + ")"
	}
	if len(rep.Labels) > 0 {
		outcome += ", " + strings.Join(rep.Labels, ", ")
	}
	fmt.Fprintf(w, "%s scan: %s; %d findings (%d new), %d files read\n", mode, outcome, len(res.Findings), created, res.Coverage.FilesScanned)
	for _, f := range rep.Findings {
		fmt.Fprintf(w, "  %-8s %s:%d %s\n", f.Severity, f.Path, f.Line, f.Rule)
	}
	if p, ok := opengrep.TaintPassOf(res.Coverage); ok {
		fmt.Fprintln(w, "intrafile taint pass:", opengrep.TaintStatusWords(p))
	}
	for _, n := range res.Coverage.Notes {
		fmt.Fprintln(w, "note:", n)
	}
	if rep.LinkedWorktree {
		fmt.Fprintln(w, "note: this is a linked worktree of the project: its findings are recorded on the project, and this run closes no finding")
	}
	return nil
}

// codeRunLabels returns the labels a run's notes carry, in table order.
func codeRunLabels(notes []string) []string {
	var out []string
	for _, l := range opengrep.NoteLabels {
		for _, n := range notes {
			if strings.HasPrefix(n, l.Prefix) {
				out = append(out, l.Words)
				break
			}
		}
	}
	return out
}

// acquireCodeScan takes the cross-process scan lease, waiting for another
// scan; a lease error is fail-open (dblease's contract).
func acquireCodeScan(ctx context.Context, dir string, onWait func()) (func(), error) {
	told := false
	for {
		release, ok, err := dblease.TryAcquire(dir, codeScanLeaseName)
		if err != nil {
			return func() {}, nil
		}
		if ok {
			return release, nil
		}
		if !told && onWait != nil {
			onWait()
			told = true
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// resolveDiffBase turns a ref into its commit id with git, through the
// shared runner under the driver's own component and the git hardening. A
// ref that starts with "-" or holds anything but a ref's characters is
// refused before git runs.
func resolveDiffBase(ctx context.Context, root, ref string) (string, error) {
	if opengrep.ValidBase(ref) {
		return ref, nil
	}
	if ref == "" || strings.HasPrefix(ref, "-") || len(ref) > 200 || strings.ContainsAny(ref, " \t\n\\:?*[") {
		return "", fmt.Errorf("--diff %q is not a commit or ref name", ref)
	}
	r := extrunhost.NewRunner(extrunhost.Options{})
	run := r.Run(ctx, extrun.Request{
		Component: opengrepComponent, Program: extrun.Program{Spec: &opengrep.GitSpec},
		Args: []string{"rev-parse", "--verify", "--end-of-options", ref + "^{commit}"},
		Env:  extrun.EnvSpec{Set: extrun.GitHardeningEnv(runtime.GOOS)}, Dir: root,
		Limits: extrun.Limits{Wall: 10 * time.Second, StdoutBytes: 4 << 10, StderrBytes: 4 << 10},
	})
	commit := strings.TrimSpace(string(run.Stdout))
	if run.Outcome != extrun.OutcomeOK || !opengrep.ValidBase(commit) {
		return "", fmt.Errorf("--diff %q does not name a commit in %s", ref, root)
	}
	return commit, nil
}

func newCodeRulesCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "rules", Short: "The observer-code rule pack: list the rules, import a signed newer pack"}
	list := &cobra.Command{
		Use:   "list",
		Short: "List the rules of the pack in use",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			configPath, _ := cmd.Flags().GetString("config")
			e, err := openCodeEnv(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer e.cleanup()
			w := cmd.OutOrStdout()
			p := e.pack.Pack
			fmt.Fprintf(w, "%s %s (%s), licence %s\n", p.Manifest.ID, p.Version(), e.pack.Source, p.Manifest.Licence)
			for _, r := range p.Manifest.Rules {
				prec := "no precision figure (flag only)"
				if r.Precision != nil {
					prec = fmt.Sprintf("precision %.2f, Wilson lower %.2f of %d (%s)", r.Precision.Figure, r.Precision.WilsonLower, r.Precision.Denominator, map[bool]string{true: "may block", false: "flag only"}[r.BlockingEligible()])
				}
				fmt.Fprintf(w, "  %-36s %-6s %-8s %s [%s] %s\n", r.ID, r.Severity, r.CWE, strings.Join(r.Languages, ","), r.Category, prec)
			}
			return nil
		},
	}
	imp := &cobra.Command{
		Use:   "import DIR",
		Short: "Install a signed rule pack from DIR (DIR/security.rule_pack/manifest.json and its bundle); a newer verified pack replaces the embedded one",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath, _ := cmd.Flags().GetString("config")
			e, err := openCodeEnv(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer e.cleanup()
			if e.managed {
				return errors.New("a managed node takes rule packs only from its org mirror (not built yet); nothing was imported")
			}
			p, err := importCodePack(args[0], codeRulesStore(e.resolved), codeRulesTrust())
			if err != nil {
				return err
			}
			chosen, err := loadCodePack(codeRulesStore(e.resolved), codeRulesTrust())
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "installed %s %s (digest %s); in use: %s %s (%s)\n", p.Manifest.ID, p.Version(), p.Digest(), chosen.Pack.Manifest.ID, chosen.Pack.Version(), chosen.Source)
			if chosen.Note != "" {
				fmt.Fprintln(cmd.OutOrStdout(), "note:", chosen.Note)
			}
			return nil
		},
	}
	cmd.AddCommand(list, imp)
	return cmd
}

// opengrepInstallOffer is the guided install text: the vendor's own
// release, for the user to fetch and check. Observer installs nothing.
func opengrepInstallOffer(w io.Writer) {
	fmt.Fprintln(w, "Opengrep is not bundled with Observer (LGPL-2.1, used only as a separate process). To use")
	fmt.Fprintln(w, "security.scan.opengrep, download the pinned release yourself, check its sha256, make it")
	fmt.Fprintln(w, "executable and put it on your PATH as `opengrep`:")
	fmt.Fprintln(w)
	for _, p := range secengine.CompiledPins() {
		mark := ""
		if p.OS == runtime.GOOS && p.Arch == runtime.GOARCH {
			mark = "  (this machine)"
		}
		switch p.Status {
		case secengine.PinPinned:
			fmt.Fprintf(w, "  %s/%s%s\n    %s\n    sha256 %s\n", p.OS, p.Arch, mark, p.URL(), p.SHA256)
		default:
			fmt.Fprintf(w, "  %s/%s%s\n    %s\n    sha256: pin owed (refused as driver_unverified until it is verified and pinned)\n", p.OS, p.Arch, mark, p.URL())
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "The signing identity is %s\n(issuer %s); the release is verified once, online, where Observer's pins are built.\n", secengine.Identity(secengine.TestedVersion), secengine.Issuer)
	fmt.Fprintln(w, "Or let Observer do it: `observer security code install` (or the Code rules card) states the")
	fmt.Fprintln(w, "sizes, asks once, downloads the pinned release and checks it before installing. Observer")
	fmt.Fprintln(w, "installs nothing unasked. Until Opengrep is on this machine, no process starts.")
}

func newCodeInstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install-opengrep",
		Short: "Show the pinned Opengrep release URL and sha256 for this machine (installs nothing)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			configPath, _ := cmd.Flags().GetString("config")
			if !codeScanSelected(componentSnapshotFor(configPath)) {
				return errCodeNotSelected
			}
			opengrepInstallOffer(cmd.OutOrStdout())
			return nil
		},
	}
}

// securityCodeDoctorCheck is the doctor row (security plan section 4.11):
// one line while the component is off; otherwise the engine, its
// verification and the pack, with nothing started.
func securityCodeDoctorCheck(ctx context.Context, configPath string) diag.Check {
	c := diag.Check{Name: opengrepComponent, Status: diag.StatusOK}
	if !codeScanSelected(componentSnapshotFor(configPath)) {
		c.Message = "Code rules (Opengrep): not selected (opt-in; turn it on in Code security > Scanners, or add security.scan.opengrep under [components])"
		c.Remediations = []remedy.Remediation{remedy.Of(remedy.OpenScanners, "")}
		return c
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		c.Status, c.Message = diag.StatusWarn, "Code rules (Opengrep): config not readable: "+err.Error()
		return c
	}
	if _, err := os.Stat(cfg.Observer.DBPath); err != nil {
		c.Message = "Code rules (Opengrep): no database yet; nothing checked"
		return c
	}
	e, err := openCodeEnv(ctx, configPath)
	if err != nil {
		c.Status, c.Message = diag.StatusWarn, "Code rules (Opengrep): "+err.Error()
		return c
	}
	defer e.cleanup()
	d, err := e.inspector()
	if err != nil {
		c.Status, c.Message = diag.StatusWarn, "Code rules (Opengrep): "+err.Error()
		return c
	}
	p := d.Probe(ctx)
	c.Details = append(c.Details, fmt.Sprintf("rule pack: %s %s (%s), %d rules, flag only", e.pack.Pack.Manifest.ID, e.pack.Pack.Version(), e.pack.Source, len(e.pack.Pack.Manifest.Rules)))
	switch {
	case !p.Installed:
		c.Message = "Code rules (Opengrep): not installed; no process starts (observer security code install)"
	default:
		info := d.Inspect()
		c.Message = "Code rules (Opengrep): " + decisionWords(info.Decision)
		if !info.Decision.Run() {
			c.Status = diag.StatusWarn
		}
		c.Details = append(c.Details, "binary: "+info.Binary, "unpacked tree: "+treeWords(info, time.Now()))
	}
	c.Details = append(c.Details, codeExtraLines(ctx, e)...)
	if st, err := codeRulesStore(e.resolved).State(content.Engine); err == nil {
		if note := engineCoverageNote(st, runtime.GOOS, runtime.GOARCH); note != "" {
			c.Details = append(c.Details, note)
		}
	}
	return c
}
