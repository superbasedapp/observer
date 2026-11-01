//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	extrunhost "github.com/marmutapp/superbased-observer/internal/extrun/host"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depdriver"
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
	scan.Flags().Bool("online", false, "match ecosystems with no local database against api.osv.dev (ecosystem, public package name and version only)")
	scan.AddCommand(newSecurityScanStatusCmd(), newSecurityScanDBCmd(), newSecurityScanInstallCmd())
	child := &cobra.Command{
		Use:    "scan-child",
		Short:  "The dependency scan child process (started by the daemon through the runner)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScanChild(cmd.Context(), cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	return []*cobra.Command{scan, child}
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
	w := cmd.OutOrStdout()
	if refresh {
		if err := writeDBRefresh(ctx, w, e); err != nil {
			return err
		}
	}
	runner := extrunhost.NewRunner(extrunhost.Options{})
	var matcher depdriver.OnlineMatcher
	if online {
		if blocked := e.onlineBlockedAt(root); blocked != "" {
			return fmt.Errorf("online matching is not allowed here: %s", blocked)
		}
		matcher = e.onlineMatcher(root)
	}
	var all []depsScanReport
	for _, id := range ids {
		d, err := e.depsDriverFor(id, runner, matcher)
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
	if asJSON {
		return writeSecurityJSON(w, map[string]any{"results": all, "attribution": OSVAttribution})
	}
	for _, r := range all {
		writeScanReport(w, r)
	}
	fmt.Fprintf(w, "\n%s\n", OSVAttribution)
	return nil
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
	if cov.Reason == depscan.ReasonDBNotAccepted {
		fmt.Fprintln(w, "  "+depsAcceptHint)
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
	writeDBDownloadState(w, e)
	eps, _ := e.db.Epochs()
	for _, eco := range depscan.Ecosystems() {
		ep, ok := eps[eco]
		switch {
		case !ok:
			fmt.Fprintf(w, "  %-10s no database\n", eco)
		case !ep.Installed():
			fmt.Fprintf(w, "  %-10s no database (last error: %s)\n", eco, ep.LastError)
		default:
			fmt.Fprintf(w, "  %-10s %s, %d bytes, fetched %s", eco, ep.LastModified, ep.Size, ep.FetchedAt.Format("2006-01-02 15:04"))
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
	db.AddCommand(newSecurityScanDBAcceptCmd())
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
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "databases: %d updated, %d current, %d failed\n", len(rep.Changed), len(rep.Unchanged), len(rep.Failed))
	for eco, why := range rep.Failed {
		fmt.Fprintf(w, "  %s: %s\n", eco, why)
	}
	return nil
}

// newSecurityScanDBAcceptCmd is `observer security scan db accept`: the
// developer's one-time accept of the OSV database download (operator
// ruling PT-19 (2)). It shows the size and the source, then asks on a
// terminal; without a terminal it records only with --yes. Guard rule
// R-165 denies it to an agent.
func newSecurityScanDBAcceptCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "accept",
		Short: fmt.Sprintf("Accept, once, the OSV database download (about %d MB from %s); refreshes are automatic after that", osvdb.ApproxDownloadMB, osvdb.Source),
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
			return runDBAccept(cmd.OutOrStdout(), cmd.InOrStdin(), e, yes, term.IsTerminal(int(os.Stdin.Fd())), time.Now())
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "record the accept without asking (you read the text above)")
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
