//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	extrunhost "github.com/marmutapp/superbased-observer/internal/extrun/host"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
)

// OSVAttribution is depscan's one attribution string (security plan
// section 8.7).
const OSVAttribution = depscan.Attribution

// securityScanSubcommands are `observer security scan` and the hidden
// scan child.
func securityScanSubcommands() []*cobra.Command {
	scan := &cobra.Command{
		Use:   "scan [DIR]",
		Short: "Scan a project's dependencies for known vulnerabilities (components security.scan.scalibr and security.scan.osv)",
		Long: "Scans the project's lockfiles and manifests with each selected dependency driver and matches the\n" +
			"packages against the local OSV database, one ecosystem at a time. An ecosystem whose database is\n" +
			"missing, or whose self-test fails, is reported \"not scanned\", never clean.\n\n" + OSVAttribution,
		Args: cobra.MaximumNArgs(1),
		RunE: runSecurityScanCmd,
	}
	scan.Flags().String("driver", "", "only this driver: scalibr or osv (default: every selected driver)")
	scan.Flags().Bool("refresh-db", false, "refresh the local OSV databases first (when the download is allowed)")
	scan.Flags().Bool("json", false, "print the results as JSON")
	scan.Flags().Bool("online", false, "match ecosystems with no local database against api.osv.dev (ecosystem, public package name and version only), and git submodules by their pinned commit ids only (never a submodule's url or path)")
	scan.Flags().String("reach", "", "run the Go source check instead of the dependency scan: `go-source` runs osv-scanner's Go call analysis once per go.mod, which runs this machine's Go toolchain on the project (opted in per project with `scan reach enable`; isolated, no network; component security.reach.go)")
	scan.Flags().Bool("allow-unisolated", false, "with --reach go-source: run even where the isolation component's no-network run is not available (labelled \"not isolated\")")
	scan.Flags().StringArray("artifacts", nil, "also read the executables, Java archives and wheels under this directory of the project for this run (Go build info, cargo auditable; repeatable); folders you turned on with `scan artifacts enable` are read as well, every other folder is not; SCALIBR driver only")
	// The image verb carries the driver switch (security_scan_image_driver.go,
	// lane OS-2 T); trivy-db is the Trivy image driver's database.
	sbomCmd := newSecuritySBOMCmd()
	scan.AddCommand(newSecurityScanArtifactsCmd(), newSecurityScanReachCmd(), newSecurityScanStatusCmd(), newSecurityScanDBCmd(), newSecurityScanInstallCmd(), withImageDriver(newSecurityScanImageCmd()), newSecurityScanTrivyDBCmd())
	child := &cobra.Command{
		Use:    "scan-child",
		Short:  "The dependency scan child process (started by the daemon through the runner)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScanChild(cmd.Context(), cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	// The package lookup posture (lane RM-2): `observer security lookup`.
	return []*cobra.Command{scan, child, newSecurityLookupCmd(), sbomCmd, newSecurityLicensesCmd()}
}

// depsScanComponents returns the selected driver components, filtered by
// the --driver flag.
func depsScanComponents(snap componentstate.Snapshot, only string) ([]string, error) {
	all := []string{depscan.ScalibrComponent, depscan.OSVComponent}
	if only != "" {
		id := "security.scan." + only
		if id != depscan.ScalibrComponent && id != depscan.OSVComponent {
			return nil, fmt.Errorf("unknown driver %q: use scalibr or osv", only)
		}
		all = []string{id}
	}
	var out []string
	for _, id := range all {
		if securitySelected(snap, id) && securitySelected(snap, securityDepsComponent) {
			out = append(out, id)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no dependency driver is selected: add %s or %s (and %s) under [components] in your config",
			depscan.ScalibrComponent, depscan.OSVComponent, securityDepsComponent)
	}
	return out, nil
}

// depsScanSelected reports whether either dependency driver is selected
// with its parent security.deps under the opt-in rule (securitySelected,
// security_optin.go).
func depsScanSelected(snap componentstate.Snapshot) bool {
	for _, id := range []string{depscan.ScalibrComponent, depscan.OSVComponent} {
		if securitySelected(snap, id) && securitySelected(snap, securityDepsComponent) {
			return true
		}
	}
	return false
}

// requireDepsScanSelected refuses a scan verb when no driver is selected, before
// it opens anything: `status` writes the osv-scanner canary project and `db
// refresh` downloads the OSV databases (about 300 MB), so an install with no
// [components] block must run neither.
func requireDepsScanSelected(configPath string) error {
	if depsScanSelected(componentSnapshotFor(configPath)) {
		return nil
	}
	return fmt.Errorf("no dependency driver is selected: add %s or %s (and %s) under [components] in your config",
		depscan.ScalibrComponent, depscan.OSVComponent, securityDepsComponent)
}

func runSecurityScanCmd(cmd *cobra.Command, args []string) error {
	configPath, _ := cmd.Flags().GetString("config")
	only, _ := cmd.Flags().GetString("driver")
	refresh, _ := cmd.Flags().GetBool("refresh-db")
	asJSON, _ := cmd.Flags().GetBool("json")
	online, _ := cmd.Flags().GetBool("online")
	dir := "."
	if len(args) == 1 {
		dir = args[0]
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", root)
	}
	named, _ := cmd.Flags().GetStringArray("artifacts")
	reach, _ := cmd.Flags().GetString("reach")
	allowUnisolated, _ := cmd.Flags().GetBool("allow-unisolated")
	switch {
	case reach != "" && reach != reachSourceValue:
		return fmt.Errorf("unknown --reach %q: use %s", reach, reachSourceValue)
	case reach == "" && allowUnisolated:
		return errors.New("--allow-unisolated goes with --reach go-source")
	case reach != "" && (only != "" || refresh || online || len(named) > 0):
		return errReachSourceFlags
	case reach != "":
		return runReachSourceCmd(cmd, configPath, root, allowUnisolated, asJSON)
	}
	artifactDirs, err := resolveArtifactDirs(root, named)
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	e, err := openDepsScanEnv(ctx, configPath)
	if err != nil {
		return err
	}
	defer e.cleanup()
	ids, err := depsScanComponents(componentSnapshotForConfig(e.cfg), only)
	if err != nil {
		return err
	}
	if len(artifactDirs) > 0 && !slices.Contains(ids, depscan.ScalibrComponent) {
		return fmt.Errorf("--artifacts needs the SCALIBR driver (%s): osv-scanner reads no build artifact", depscan.ScalibrComponent)
	}
	w := cmd.OutOrStdout()
	if refresh {
		if err := writeDBRefresh(ctx, w, e); err != nil {
			return err
		}
	}
	runner := extrunhost.NewRunner(extrunhost.Options{})
	// The SuperBased lookup (lane RM-2) answers first in lookup mode remote
	// or both; --online (api.osv.dev) takes what it does not answer. Ruling
	// Q9 (a) kept --online a CLI option; decision P-1 of
	// docs/plans/dashboard-cli-parity-plan-2026-11-06.md supersedes it: the
	// dashboard's Scan now runs the same check ("Also check online") through
	// the same depsRunMatchers and the same gate. Here a closed gate refuses
	// the run.
	e.remoteFetchAlways = true
	run := e.depsRunMatchers(root, online)
	if run.blocked != "" {
		return fmt.Errorf("online matching is not allowed here: %s", run.blocked)
	}
	matcher := run.matcher
	var all []depsScanReport
	for _, id := range ids {
		d, err := e.depsDriverAt(id, runner, matcher, root, artifactDirs)
		if err != nil {
			return err
		}
		res, err := e.scanOne(ctx, d, root, secscan.Target{Scope: policy.FindingScopeManual}, true, func() {
			fmt.Fprintln(cmd.ErrOrStderr(), "waiting for another dependency scan (the daemon's or another command's) to finish...")
		}, depsOnlineAttached(id, matcher))
		if err != nil {
			return fmt.Errorf("%s: %w", id, err)
		}
		all = append(all, depsScanReport{Driver: d.Row().ID, Component: id, Beta: depscan.Beta(d.Row(), runtime.GOOS, runtime.GOARCH), Result: res})
	}
	symbols := e.reachGoRunsAfterScan(root, ids)
	if asJSON {
		out := map[string]any{"results": all, "attribution": OSVAttribution}
		if symbols != nil {
			out["symbol_checks"] = symbols
		}
		return writeSecurityJSON(w, out)
	}
	for _, r := range all {
		writeScanReport(w, r)
	}
	writeReachGoSummary(w, symbols)
	fmt.Fprintf(w, "\n%s\n", OSVAttribution)
	return nil
}

// resolveArtifactDirs turns the --artifacts directories into the child's
// form: a relative one is read against the project root, each must be an
// existing directory inside the root (the scan's paths are all relative to
// it), and the result is relative, forward slashes, cleaned and sorted
// (depscan.CleanArtifactDirs).
func resolveArtifactDirs(root string, named []string) ([]string, error) {
	rels := make([]string, 0, len(named))
	for _, d := range named {
		abs := d
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(root, d)
		}
		abs = filepath.Clean(abs)
		if fi, err := os.Stat(abs); err != nil || !fi.IsDir() {
			return nil, fmt.Errorf("--artifacts %s: not a directory", d)
		}
		rel, err := filepath.Rel(root, abs)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("--artifacts %s: must be a directory inside the project %s", d, root)
		}
		rels = append(rels, filepath.ToSlash(rel))
	}
	out, err := depscan.CleanArtifactDirs(rels)
	if err != nil {
		return nil, fmt.Errorf("--artifacts: %w", err)
	}
	return out, nil
}

// depsScanReport is one driver's result as the CLI prints it.
type depsScanReport struct {
	Driver    string         `json:"driver"`
	Component string         `json:"component"`
	Beta      bool           `json:"beta"`
	Result    secscan.Result `json:"result"`
}

func writeScanReport(w io.Writer, r depsScanReport) {
	label := r.Driver
	if r.Beta {
		label += " (beta on this platform)"
	}
	cov := r.Result.Coverage
	for _, l := range depscan.RunLabels(cov.Notes) {
		label += " (" + l + ")"
	}
	fmt.Fprintf(w, "%s: %s", label, depsOutcomeWords(cov.Outcome))
	if cov.Reason != "" {
		fmt.Fprintf(w, " (%s)", cov.Reason)
	}
	fmt.Fprintf(w, ", %d finding(s), %d dependency file(s)\n", len(r.Result.Findings), cov.FilesScanned)
	switch cov.Reason {
	case depscan.ReasonDBNotAccepted:
		fmt.Fprintln(w, "  "+depsAcceptHint)
	case depscan.ReasonLookupNotChosen, depscan.ReasonRemoteNotAccepted:
		fmt.Fprintln(w, "  "+lookupChooseHint)
	}
	for _, s := range cov.Skipped {
		what := strings.TrimPrefix(s.Path, depscan.EcosystemSkipPrefix)
		if what == "" {
			what = "a dependency file"
		}
		fmt.Fprintf(w, "  not scanned: %s: %s\n", what, depscan.ReasonWords(s.Reason))
	}
	for _, f := range r.Result.Findings {
		fmt.Fprintf(w, "  %-8s %s  %s  %s\n", f.Severity, f.Rule.ID, f.EvidenceRedacted, f.Location.RelPath)
	}
	if r.Result.Engine.DatabaseEpoch != "" {
		fmt.Fprintf(w, "  database: %s\n", r.Result.Engine.DatabaseEpoch)
	}
	for _, n := range cov.Notes {
		fmt.Fprintf(w, "  note: %s\n", n)
	}
}

// depsOutcomeWords is the plain wording of each outcome (scanned is not
// clean: only OutcomeClean says "no known vulnerabilities").
var depsOutcomeWords = func(o secscan.Outcome) string {
	switch o {
	case secscan.OutcomeClean:
		return "scanned, no known vulnerabilities"
	case secscan.OutcomeFindings:
		return "scanned, known vulnerabilities found"
	case secscan.OutcomeUnknown:
		return "scanned in part, not clean"
	case secscan.OutcomeNotScanned:
		return "not scanned"
	case secscan.OutcomeFailed:
		return "failed, not scanned"
	}
	return string(o)
}

func newSecurityScanStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the dependency drivers, their platform labels, the local OSV databases and the download gate",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			configPath, _ := cmd.Flags().GetString("config")
			if err := requireDepsScanSelected(configPath); err != nil {
				return err
			}
			e, err := openDepsScanEnv(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer e.cleanup()
			writeScanStatus(cmd.Context(), cmd.OutOrStdout(), e)
			return nil
		},
	}
}

func writeScanStatus(ctx context.Context, w io.Writer, e *depsScanEnv) {
	snap := componentSnapshotForConfig(e.cfg)
	runner := extrunhost.NewRunner(extrunhost.Options{})
	for _, id := range []string{depscan.ScalibrComponent, depscan.OSVComponent} {
		state := "not selected"
		if securitySelected(snap, id) && securitySelected(snap, securityDepsComponent) {
			state = "selected"
		}
		d, err := e.depsDriver(id, runner)
		if err != nil || d == nil {
			fmt.Fprintf(w, "%s: %s, not in this build\n", id, state)
			continue
		}
		p := d.Probe(ctx)
		fmt.Fprintf(w, "%s: %s, platform %s", id, state, p.Platform)
		if p.Beta {
			fmt.Fprint(w, " (beta)")
		}
		if p.Version != "" {
			fmt.Fprintf(w, ", version %s", p.Version)
		}
		if p.Reason != "" {
			fmt.Fprintf(w, ", %s", p.Reason)
		}
		fmt.Fprintln(w)
		if p.Reason == depscan.ReasonNotInstalled {
			fmt.Fprintln(w, "  not installed: dependencies show as not scanned; `observer security scan install-osv-scanner` shows how to install it")
		}
	}
	writeLookupState(ctx, w, e) // lane RM-2
	writeDBDownloadState(w, e)
	writeDBSourceState(w, e)
	writeOSDBState(w, e)
	writeImageDriverState(ctx, w, e) // lane OS-2 T
	eps, _ := e.db.Epochs()
	for _, eco := range depscan.Ecosystems() {
		ep, ok := eps[eco]
		switch {
		case !ok:
			fmt.Fprintf(w, "  %-14s no database\n", eco)
		case !ep.Installed():
			fmt.Fprintf(w, "  %-14s no database (last error: %s)\n", eco, ep.LastError)
		default:
			fmt.Fprintf(w, "  %-14s %s, %d bytes, fetched %s", eco, ep.LastModified, ep.Size, ep.FetchedAt.Format("2006-01-02 15:04"))
			if ep.Source != "" {
				fmt.Fprintf(w, " from %s", osvSourceName(ep.Source))
			}
			if ep.LastError != "" {
				fmt.Fprintf(w, " (last refresh failed: %s)", ep.LastError)
			}
			fmt.Fprintln(w)
		}
	}
	fmt.Fprintf(w, "\n%s\n", OSVAttribution)
}

// writeDBDownloadState prints the download gate in plain words: before the
// accept, the size, the source and how to accept.
func writeDBDownloadState(w io.Writer, e *depsScanEnv) {
	switch r := e.downloadBlocked(); r {
	case "":
		fmt.Fprintf(w, "database download: on (%s, checked every 6 h); accepted %s (%s", osvdb.Source, e.consent.AcceptedAt.Local().Format(time.RFC3339), e.consent.Surface)
		if e.consent.By != "" {
			fmt.Fprintf(w, ", by %s", e.consent.By)
		}
		fmt.Fprintln(w, ")")
	case depscan.ReasonDBNotAccepted:
		fmt.Fprintln(w, depsAcceptHint)
		fmt.Fprintln(w, "  until then no dependency scan runs and no project reads clean")
	default:
		fmt.Fprintf(w, "database download: not allowed (%s)\n", r)
	}
}

func newSecurityScanDBCmd() *cobra.Command {
	db := &cobra.Command{Use: "db", Short: "The local OSV databases"}
	db.AddCommand(newSecurityScanDBAcceptCmd(), newSecurityScanDBImportCmd())
	db.AddCommand(&cobra.Command{
		Use:   "refresh",
		Short: "Refresh the local OSV databases now (individual node, after the one-time accept)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			configPath, _ := cmd.Flags().GetString("config")
			if err := requireDepsScanSelected(configPath); err != nil {
				return err
			}
			e, err := openDepsScanEnv(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer e.cleanup()
			return writeDBRefresh(cmd.Context(), cmd.OutOrStdout(), e)
		},
	})
	return db
}

func writeDBRefresh(ctx context.Context, w io.Writer, e *depsScanEnv) error {
	rep, blocked, err := e.refreshDB(ctx)
	switch blocked {
	case "":
	case depscan.ReasonDBNotAccepted:
		fmt.Fprintln(w, depsAcceptHint)
		return nil
	default:
		fmt.Fprintf(w, "database download not allowed: %s\n", blocked)
		return nil
	}
	if err == nil {
		fmt.Fprintf(w, "databases: %d updated, %d current, %d failed\n", len(rep.Changed), len(rep.Unchanged), len(rep.Failed))
		for eco, why := range rep.Failed {
			fmt.Fprintf(w, "  %s: %s\n", eco, why)
		}
	}
	// The exploit kinds (security_exploit.go) ride the same accept and are
	// refreshed with the databases, here as on the daemon's tick, under the
	// OSV database feed's own gate. An import-only node fetches none: `scan
	// db import` installs them from the directory instead.
	if !e.osvImportOnly() {
		writeExploitRefresh(w, e.refreshExploitNow(ctx, time.Now()))
	}
	return err
}

// newSecurityScanDBImportCmd is `observer security scan db import <dir>`:
// an individual node installs a signed security.osv_export set a person
// copied in (the org mirror's import layout, <dir>/security.osv_export/
// manifest.json and its artifacts), verified exactly as the signed mirror's
// download, and, when present, the exploit kinds beside it
// (<dir>/security.kev/ and <dir>/security.epss/, importExploitSets). With [security.deps] db_source = "import" it is the node's only
// source and nothing is fetched. Guard rule R-165 denies it to an agent:
// what it installs is what every dependency scan matches against.
func newSecurityScanDBImportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "import DIR",
		Short: "Install a signed OSV database set from a directory (DIR/security.osv_export/manifest.json and its artifacts, plus DIR/security.kev and DIR/security.epss when present); individual node",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath, _ := cmd.Flags().GetString("config")
			if err := requireDepsScanSelected(configPath); err != nil {
				return err
			}
			e, err := openDepsScanEnv(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer e.cleanup()
			return runDBImport(cmd.Context(), cmd.OutOrStdout(), e, args[0])
		},
	}
}

// newSecurityScanDBAcceptCmd is `observer security scan db accept`: the
// developer's one-time accept of the OSV database download (operator
// ruling PT-19 (2)). It shows the size and the source, then asks on a
// terminal; without a terminal it records only with --yes. Guard rule
// R-165 denies it to an agent.
//
// With --os it is the OS release databases' one accept instead (OS-2,
// ruling Q1 (b), runDBAcceptOS): its own signed record, its own text,
// superbased.app only; the same terminal and --yes rules, and R-165 denies
// it in every spelling.
func newSecurityScanDBAcceptCmd() *cobra.Command {
	var yes, osDBs bool
	cmd := &cobra.Command{
		Use:   "accept",
		Short: fmt.Sprintf("Accept, once, the OSV database download (about %d MB from %s), or with --os the OS release databases (from %s only, on demand); refreshes are automatic after that", osvdb.ApproxDownloadMB, osvdb.Source, osvdb.OSSource),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			configPath, _ := cmd.Flags().GetString("config")
			if err := requireDepsScanSelected(configPath); err != nil {
				return err
			}
			e, err := openDepsScanEnv(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer e.cleanup()
			isTerminal := term.IsTerminal(int(os.Stdin.Fd()))
			if osDBs {
				return runDBAcceptOS(cmd.OutOrStdout(), cmd.InOrStdin(), e, yes, isTerminal, time.Now())
			}
			return runDBAccept(cmd.OutOrStdout(), cmd.InOrStdin(), e, yes, isTerminal, time.Now())
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "record the accept without asking (you read the text above)")
	cmd.Flags().BoolVar(&osDBs, "os", false, "accept the OS release databases instead: the per-release databases your scanned container images use, fetched on demand from "+osvdb.OSSource+" only")
	return cmd
}

// runDBAccept shows the accept text and records the accept on a yes.
func runDBAccept(w io.Writer, in io.Reader, e *depsScanEnv, yes, isTerminal bool, now time.Time) error {
	if e.managed {
		fmt.Fprintln(w, "This is a managed node: its OSV databases come from your organization's mirror, never from the public bucket, so there is nothing to accept here.")
		return nil
	}
	fmt.Fprintln(w, osvdb.ConsentText)
	if e.consent.Accepted() {
		fmt.Fprintf(w, "\nAlready accepted %s (%s); the databases refresh automatically.\n", e.consent.AcceptedAt.Local().Format(time.RFC3339), e.consent.Surface)
		return nil
	}
	if !yes && isTerminal {
		fmt.Fprintf(w, "\nDownload about %d MB from %s now and keep it up to date? [y/N] ", osvdb.ApproxDownloadMB, osvdb.Source)
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
	c, err := osvdb.RecordConsent(e.dir, "cli", depsLocalAccount(), now, key)
	if err != nil {
		return err
	}
	e.consent = c
	fmt.Fprintln(w, "\nRecorded. The daemon downloads the databases within 15 minutes; `observer security scan db refresh` downloads them now.")
	return nil
}

// depsLocalAccount names the local account an accept is recorded under,
// "" when it cannot be read.
func depsLocalAccount() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	for _, k := range []string{"USER", "USERNAME"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}
