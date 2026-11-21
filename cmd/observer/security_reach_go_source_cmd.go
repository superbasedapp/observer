//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secreach"
	"github.com/marmutapp/superbased-observer/internal/secreachsvc"
)

// security_reach_go_source_cmd.go is the CLI of the Go source check,
// 3b-src (OS and CI vulnerability scanning plan section 14.5 item 3b): the
// per-project opt-in (`observer security scan reach enable|disable`,
// R-165), its status, and the run (`observer security scan --reach
// go-source [DIR]`, security_reach_go_source.go). Every verb that writes
// the opt-in, and every run, is the developer's (guard rule R-165).

// reachSourceValue is the one --reach value.
const reachSourceValue = "go-source"

// reachSourceOptions is one source check.
type reachSourceOptions struct {
	// Root is the project, absolute.
	Root string
	// AllowUnisolated is the run flag's override.
	AllowUnisolated bool
	// OnWait is called once if another heavy scan holds the lease.
	OnWait func()
	// Progress is told each go.mod before it runs.
	Progress func(target string)
}

// reachSourceReport is what one check did.
type reachSourceReport struct {
	Project string `json:"project"`
	// Isolation is the provider's name, or "not isolated".
	Isolation string `json:"isolation"`
	// Toolchain is the local Go release that ran (GOROOT/VERSION); the
	// standard library is evaluated at each go.mod's own line instead.
	Toolchain string `json:"toolchain,omitempty"`
	// Engine is osv-scanner's reported version.
	Engine string `json:"engine_version,omitempty"`
	// MemoryCap is how the shared runner held the memory cap on the first
	// run ("enforced (cgroup)", or per process on a host without a usable
	// cgroup v2: "best_effort (rlimit_data)").
	MemoryCap string `json:"memory_cap,omitempty"`
	// Runs are the stored per-go.mod answers.
	Runs []secreach.SymbolRun `json:"runs"`
	// Truncated: the project has more go.mod files than were listed.
	Truncated bool     `json:"truncated,omitempty"`
	Notes     []string `json:"notes,omitempty"`
}

// newSecurityScanReachCmd is `observer security scan reach`.
func newSecurityScanReachCmd() *cobra.Command {
	reach := &cobra.Command{
		Use:   "reach",
		Short: "Show the Go source check's opt-in for a project (the check is off until you turn it on)",
		Long: "The Go source check (`observer security scan --reach go-source`) runs osv-scanner's Go call analysis once\n" +
			"per go.mod, which runs this machine's Go toolchain on the project's code. It needs your opt-in per project,\n" +
			"recorded here (an agent cannot give it). Without arguments this prints the project's state.\n\n" + secreachsvc.SourceOptInText,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return runReachStatus(cmd) },
	}
	reach.PersistentFlags().String("project", ".", "the project folder")
	var yes, allowUnisolated, asJSON bool
	status := &cobra.Command{
		Use: "status", Short: "Show the project's opt-in, the isolation and the caps", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return runReachStatus(cmd) },
	}
	status.Flags().BoolVar(&asJSON, "json", false, "print as JSON")
	enable := &cobra.Command{
		Use: "enable", Short: "Opt the project in to the Go source check", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return runReachEnable(cmd, yes, allowUnisolated) },
	}
	enable.Flags().BoolVar(&yes, "yes", false, "record the opt-in without asking (you read the text above)")
	enable.Flags().BoolVar(&allowUnisolated, "allow-unisolated", false, "also allow the check to run without the isolation component where it is not available (labelled \"not isolated\")")
	disable := &cobra.Command{
		Use: "disable", Short: "Withdraw the project's opt-in", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return runReachDisable(cmd) },
	}
	reach.AddCommand(status, enable, disable)
	return reach
}

// reachProject is the --project folder, absolute and existing, and the
// security directory.
func reachProject(cmd *cobra.Command) (*depsScanEnv, string, error) {
	p, _ := cmd.Flags().GetString("project")
	root, err := filepath.Abs(p)
	if err != nil {
		return nil, "", err
	}
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		return nil, "", fmt.Errorf("%s is not a directory", root)
	}
	configPath, _ := cmd.Flags().GetString("config")
	e, err := openDepsScanEnv(cmd.Context(), configPath)
	if err != nil {
		return nil, "", err
	}
	return e, root, nil
}

// reachStatusView is `scan reach status --json`.
type reachStatusView struct {
	Project            string               `json:"project"`
	Compiled           bool                 `json:"compiled"`
	Selected           bool                 `json:"selected"`
	OptedIn            bool                 `json:"opted_in"`
	AllowUnisolated    bool                 `json:"allow_unisolated"`
	OptedAt            string               `json:"opted_at,omitempty"`
	Surface            string               `json:"surface,omitempty"`
	IsolationAvailable bool                 `json:"isolation_available"`
	MemoryMiB          int64                `json:"memory_mib"`
	TimeoutSeconds     int64                `json:"timeout_seconds"`
	MaxModules         int                  `json:"max_modules"`
	Runs               []secreach.SymbolRun `json:"runs"`
}

func reachStatusOf(e *depsScanEnv, root string) reachStatusView {
	hash := secposture.ProjectRootHash(root)
	o := secreachsvc.ReadSourceOptIn(e.dir, hash, depsRecordKey(e.dir))
	c := e.cfg.Security.Reach.Go
	v := reachStatusView{
		Project: root, Compiled: reachSourceCompiled, Selected: securitySelected(componentSnapshotForConfig(e.cfg), reachGoComponent),
		OptedIn: o.OptedIn(), AllowUnisolated: o.UnisolatedAllowed(), IsolationAvailable: reachSourceIsolationAvailable(e),
		MemoryMiB: c.MemoryBytes() >> 20, TimeoutSeconds: int64(c.Timeout() / time.Second), MaxModules: c.MaxModules(),
		Runs: []secreach.SymbolRun{},
	}
	if v.OptedIn {
		v.OptedAt, v.Surface = o.OptedAt.Local().Format(time.RFC3339), o.Surface
	}
	for _, r := range secreachsvc.LoadSymbolRuns(e.dir, hash) {
		if r.Source == secreach.SourceGovulncheckSource {
			v.Runs = append(v.Runs, r)
		}
	}
	return v
}

func runReachStatus(cmd *cobra.Command) error {
	e, root, err := reachProject(cmd)
	if err != nil {
		return err
	}
	defer e.cleanup()
	v := reachStatusOf(e, root)
	if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "Go source check for %s\n", root)
	switch {
	case !v.Compiled:
		fmt.Fprintln(w, "  not in this build (security.reach.go or security.scan.osv is compiled out)")
	case !v.Selected:
		fmt.Fprintf(w, "  the %s component is not selected\n", reachGoComponent)
	}
	if v.OptedIn {
		fmt.Fprintf(w, "  opted in %s (%s)\n", v.OptedAt, v.Surface)
	} else {
		fmt.Fprintln(w, "  not opted in (`observer security scan reach enable`)")
	}
	iso := "available"
	if !v.IsolationAvailable {
		iso = "not available on this host"
		if v.AllowUnisolated {
			iso += "; you allowed the check to run without it"
		}
	}
	fmt.Fprintf(w, "  isolation: %s\n", iso)
	fmt.Fprintf(w, "  caps: %d MiB per go.mod (GOMEMLIMIT at 90 %%), %d s per go.mod, at most %d go.mod files\n", v.MemoryMiB, v.TimeoutSeconds, v.MaxModules)
	writeReachSourceRuns(w, v.Runs)
	return nil
}

func runReachEnable(cmd *cobra.Command, yes, allowUnisolated bool) error {
	e, root, err := reachProject(cmd)
	if err != nil {
		return err
	}
	defer e.cleanup()
	w := cmd.OutOrStdout()
	fmt.Fprintln(w, secreachsvc.SourceOptInText)
	if allowUnisolated {
		fmt.Fprintln(w, "\nWith --allow-unisolated the check also runs where the isolation component is not available: then it has this machine's network and sees your files as you do, labelled \"not isolated\".")
	}
	if !yes && term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintf(w, "\nOpt %s in to the Go source check? [y/N] ", root)
		yes = dastReadYesLine(cmd.InOrStdin())
	}
	if !yes {
		fmt.Fprintln(w, "\nNothing recorded. Re-run with --yes, or answer y on a terminal.")
		return nil
	}
	key, err := depsRecordSigningKey(e.dir)
	if err != nil {
		return err
	}
	if _, err := secreachsvc.RecordSourceOptIn(e.dir, secposture.ProjectRootHash(root), "cli", depsLocalAccount(), allowUnisolated, time.Now(), key); err != nil {
		return err
	}
	fmt.Fprintln(w, "\nRecorded. `observer security scan --reach go-source` now runs the check when you start it.")
	return nil
}

func runReachDisable(cmd *cobra.Command) error {
	e, root, err := reachProject(cmd)
	if err != nil {
		return err
	}
	defer e.cleanup()
	if err := secreachsvc.WithdrawSourceOptIn(e.dir, secposture.ProjectRootHash(root)); err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), "Withdrawn. The stored answers stay until the next check; `observer security scan --reach go-source` now refuses for this project.")
	return nil
}

// dastReadYesLine reads a y/yes answer (the DAST accept's reader lives in
// a file another omit tag can remove).
func dastReadYesLine(r io.Reader) bool {
	b := make([]byte, 64)
	n, _ := r.Read(b)
	line, _, _ := strings.Cut(string(b[:n]), "\n")
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

// runReachSourceCmd is `observer security scan --reach go-source [DIR]`.
func runReachSourceCmd(cmd *cobra.Command, configPath, root string, allowUnisolated, asJSON bool) error {
	e, err := openDepsScanEnv(cmd.Context(), configPath)
	if err != nil {
		return err
	}
	defer e.cleanup()
	errw := cmd.ErrOrStderr()
	rep, err := e.runReachSource(cmd.Context(), reachSourceOptions{
		Root: root, AllowUnisolated: allowUnisolated,
		OnWait: func() {
			fmt.Fprintln(errw, "waiting for another dependency scan (the daemon's or another command's) to finish...")
		},
		Progress: func(t string) { fmt.Fprintf(errw, "checking %s ...\n", t) },
	})
	if err != nil {
		return err
	}
	if asJSON {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	w := cmd.OutOrStdout()
	label := rep.Isolation
	if rep.Toolchain != "" {
		label += ", toolchain " + rep.Toolchain
	}
	if rep.Engine != "" {
		label += ", osv-scanner " + rep.Engine
	}
	if rep.MemoryCap != "" {
		label += ", memory cap " + rep.MemoryCap
	}
	fmt.Fprintf(w, "Go source check (govulncheck-source through osv-scanner; %s) for %s\n", label, rep.Project)
	for _, n := range rep.Notes {
		fmt.Fprintf(w, "  %s\n", n)
	}
	if rep.Truncated {
		fmt.Fprintln(w, "  the project has more go.mod files than were listed; the rest were not checked")
	}
	writeReachSourceRuns(w, rep.Runs)
	fmt.Fprintln(w, "Ranks and labels only: `not called` is for that go.mod's build on this platform; tests, other build tags and other platforms are outside it.")
	return nil
}

// writeReachSourceRuns prints one line per go.mod.
func writeReachSourceRuns(w io.Writer, runs []secreach.SymbolRun) {
	if len(runs) == 0 {
		fmt.Fprintln(w, "  no stored source check")
		return
	}
	for _, r := range runs {
		if r.Reason != "" {
			fmt.Fprintf(w, "  %s: not checked (%s)\n", r.Target, r.Reason.Text())
			continue
		}
		called, not := map[string]bool{}, map[string]bool{}
		assumed := ""
		for _, rec := range r.Records {
			key := rec.Module + "@" + rec.Version
			switch rec.Verdict {
			case secreach.VerdictCalled:
				called[key] = true
			case secreach.VerdictNotCalled:
				not[key] = true
			}
			if rec.AssumedGo != "" {
				assumed = rec.AssumedGo
			}
		}
		for k := range called {
			delete(not, k)
		}
		line := fmt.Sprintf("  %s: %d packages with a listed function called, %d with none called", r.Target, len(called), len(not))
		if assumed != "" {
			line += "; stdlib evaluated at go" + assumed + " from the go.mod"
		}
		fmt.Fprintln(w, line)
	}
}

// errReachSourceFlags refuses a --reach run mixed with the dependency
// scan's own flags.
var errReachSourceFlags = errors.New("--reach go-source runs the Go source check alone: drop --driver, --refresh-db, --online and --artifacts")

// reachSourceJobs is the dashboard's one owner of its runs' state: which
// projects have a run going, and each one's last refusal or failure. One
// run at a time per project; the dependency scan lease keeps heavy runs one
// at a time per machine.
var reachSourceJobs = struct {
	sync.Mutex
	running map[string]bool
	lastErr map[string]string
}{running: map[string]bool{}, lastErr: map[string]string{}}

// reachSourceStatusDash is the card's view of a project.
func reachSourceStatusDash(e *depsScanEnv, root string) dashapi.ReachSourceStatus {
	v := reachStatusOf(e, root)
	out := dashapi.ReachSourceStatus{
		Project: root, Compiled: v.Compiled, Selected: v.Selected, OptedIn: v.OptedIn, AllowUnisolated: v.AllowUnisolated,
		OptedAt: v.OptedAt, Surface: v.Surface, IsolationAvailable: v.IsolationAvailable, Text: secreachsvc.SourceOptInText,
		MemoryMiB: v.MemoryMiB, TimeoutSeconds: v.TimeoutSeconds, MaxModules: v.MaxModules, Runs: []dashapi.ReachSourceRun{},
	}
	reachSourceJobs.Lock()
	out.Running, out.LastError = reachSourceJobs.running[root], reachSourceJobs.lastErr[root]
	reachSourceJobs.Unlock()
	for _, r := range v.Runs {
		row := dashapi.ReachSourceRun{Target: r.Target, Reason: string(r.Reason), ReasonText: r.Reason.Text()}
		called, not := map[string]bool{}, map[string]bool{}
		for _, rec := range r.Records {
			key := rec.Module + "@" + rec.Version
			switch rec.Verdict {
			case secreach.VerdictCalled:
				called[key] = true
			case secreach.VerdictNotCalled:
				not[key] = true
			}
			if rec.AssumedGo != "" {
				row.AssumedGo = rec.AssumedGo
			}
		}
		for k := range called {
			delete(not, k)
		}
		row.Called, row.NotCalled = len(called), len(not)
		out.Runs = append(out.Runs, row)
	}
	return out
}

// wireReachSourceDash sets the card's three seam functions over open (the
// scanner seam's env opener).
func wireReachSourceDash(seam *dashapi.ScannerDB, open func() (*depsScanEnv, bool, error)) {
	seam.ReachSource = func(_ context.Context, root string) (dashapi.ReachSourceStatus, error) {
		e, _, err := open()
		if err != nil {
			return dashapi.ReachSourceStatus{}, err
		}
		return reachSourceStatusDash(e, root), nil
	}
	seam.SetReachSource = func(_ context.Context, root string, ch dashapi.ReachSourceChange) error {
		e, _, err := open()
		if err != nil {
			return err
		}
		hash := secposture.ProjectRootHash(root)
		if !ch.Enabled {
			return secreachsvc.WithdrawSourceOptIn(e.dir, hash)
		}
		if !securitySelected(componentSnapshotForConfig(e.cfg), reachGoComponent) {
			return errReachSourceNotSelectedDash
		}
		key, err := depsRecordSigningKey(e.dir)
		if err != nil {
			return err
		}
		_, err = secreachsvc.RecordSourceOptIn(e.dir, hash, "dashboard", depsLocalAccount(), ch.AllowUnisolated, time.Now(), key)
		return err
	}
	seam.RunReachSource = func(ctx context.Context, root string) error {
		e, _, err := open()
		if err != nil {
			return err
		}
		v := reachStatusOf(e, root)
		switch {
		case !v.Compiled:
			return errors.New("the Go source check is not in this build")
		case !v.Selected:
			return errReachSourceNotSelectedDash
		case !v.OptedIn:
			return errors.New("this project is not opted in to the Go source check")
		case !v.IsolationAvailable && !v.AllowUnisolated:
			return errors.New("isolation is not available on this host and running without it is not allowed for this project")
		}
		reachSourceJobs.Lock()
		if reachSourceJobs.running[root] {
			reachSourceJobs.Unlock()
			return errors.New("a Go source check of this project is already running")
		}
		reachSourceJobs.running[root] = true
		delete(reachSourceJobs.lastErr, root)
		reachSourceJobs.Unlock()
		// The run outlives the request that started it (the card polls);
		// its caps are per go.mod, so it is bounded without the request.
		runCtx := context.WithoutCancel(ctx)
		go func() {
			_, err := e.runReachSource(runCtx, reachSourceOptions{Root: root})
			reachSourceJobs.Lock()
			delete(reachSourceJobs.running, root)
			if err != nil {
				reachSourceJobs.lastErr[root] = err.Error()
			}
			reachSourceJobs.Unlock()
			if err != nil && e.logger != nil {
				e.logger.Warn("security: the Go source check did not run", "err", err)
			}
		}()
		return nil
	}
}

var errReachSourceNotSelectedDash = fmt.Errorf("the %s component is not selected on this node", reachGoComponent)
