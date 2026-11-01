//go:build !sbo_omit_security && !sbo_omit_security_scan_custom

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/extrun/host"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/seccustom"
	"github.com/marmutapp/superbased-observer/internal/seccustomsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
	trhost "github.com/marmutapp/superbased-observer/internal/toolresolve/host"
)

// security_custom_cmd.go is the cmd seam of the custom scanner driver
// (security pillar plan section 8.6, Phase D3; component
// security.scan.custom): it builds the one seccustomsvc.Service the CLI and
// the dashboard use, injecting the hardened runner and, when the isolation
// component is active, its one-shot factory (never an import of the
// isolation engine), and it adds `observer security scanners`.

// customScanComponent is the catalog id.
const customScanComponent = seccustom.ComponentID

// customScanExecutor is the one executor every custom run shares, so the
// survivor scan of one run never counts another live run's processes.
var customScanExecutor = sync.OnceValue(host.NewExecutor)

// customScanSelected reports whether the component is on: selected under
// securitySelected (security_optin.go), which keeps it opt-in. An install
// with no [components] block resolves every compiled module active, and
// this off-by-default component must not switch itself on there (plans
// decision log P-023).
func customScanSelected(snap componentstate.Snapshot) bool {
	return securitySelected(snap, customScanComponent)
}

// customScannerService builds the service for the config at configPath
// and the store, or nil when the component is not selected under snap.
func customScannerService(ctx context.Context, snap componentstate.Snapshot, configPath string, st *store.Store) (*seccustomsvc.Service, error) {
	if !customScanSelected(snap) {
		return nil, nil
	}
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return nil, err
	}
	observerDir := filepath.Dir(resolved)
	cacheRoot, err := customScanCacheRoot()
	if err != nil {
		return nil, err
	}
	env := sync.OnceValue(func() toolresolve.Env { return trhost.NewEnv(trhost.Options{}) })
	o := seccustomsvc.Options{
		Layout:    seccustomsvc.LayoutFor(observerDir),
		CacheRoot: cacheRoot,
		ConfigDir: observerDir,
		Resolve: func(spec integration.BinaryResolveSpec) toolresolve.Resolution {
			return toolresolve.Resolve(spec, env())
		},
		NewRunner: func(p extrun.IsolationProvider) *extrun.Runner {
			return host.NewRunner(host.Options{Isolation: p, Executor: customScanExecutor()})
		},
		Isolation: isolationFactoryFor(snap, observerDir, nil),
	}
	if st != nil {
		o.Store = st
		// The org's custom driver policy on a managed node (lane SEC-E4).
		// A config that does not load still gets the managed rules (the
		// grant and the pull live in the store, not in config.toml).
		cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
		if err != nil {
			cfg = config.Default()
		}
		// The floors in force (allow.custom_manifests) read in a process
		// that is not the daemon too: `observer security scanners run` and
		// the other CLI verbs apply the same floor the daemon applies
		// (SEC-E4 merge finding 1). Idempotent, and never over a daemon's
		// own binding.
		bindSecurityFloorsForCLI(ctx, configPath, cfg, st)
		o.Org = customOrgSource(cfg, st)
	}
	return seccustomsvc.New(o), nil
}

// customScanCacheRoot is the per-user cache directory for the drivers'
// caches and run directories: outside ~/.observer, which the isolation
// engine never binds.
func customScanCacheRoot() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("no user cache directory: %w", err)
	}
	return filepath.Join(base, "superbased-observer", "scanners"), nil
}

// openCustomScanners opens the service for a CLI verb, refusing when the
// component is not active.
func openCustomScanners(ctx context.Context, configPath string) (*seccustomsvc.Service, func(), error) {
	snap := componentSnapshotFor(configPath)
	if !customScanSelected(snap) {
		return nil, nil, fmt.Errorf("the %s component is not selected: add it under [components] (observer components status)", customScanComponent)
	}
	_, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return nil, nil, err
	}
	svc, err := customScannerService(ctx, snap, configPath, store.New(database))
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return svc, cleanup, nil
}

// securityCustomSubcommands are the custom scanner verbs under
// `observer security`.
func securityCustomSubcommands() []*cobra.Command {
	cmd := &cobra.Command{
		Use:   "scanners",
		Short: "Custom scanners: import, self-test and run a scanner you configured",
		Long: "A custom scanner is a program you configured through a structured,\n" +
			"digest-pinned manifest (component security.scan.custom). Import one from\n" +
			"a built-in template (gosec, bandit, semgrep) or a manifest file: preview\n" +
			"shows it in full with its digest, import accepts exactly that digest.\n" +
			"Every choice is a picker: an executable by its number in the preview,\n" +
			"limits by their fixed steps. Findings are flag-only.",
	}
	cmd.AddCommand(newCustomTemplatesCmd(), newCustomPreviewCmd(), newCustomImportCmd(), newCustomListCmd(),
		newCustomRemoveCmd(), newCustomSelfTestCmd(), newCustomRunCmd(), newCustomAuditCmd())
	return []*cobra.Command{cmd}
}

// customSourceFlags are the source and picker flags shared by preview and
// import.
type customSourceFlags struct {
	template, file string
	executable     int
	companions     []int
	input, output  string
	cache          string
	networkNone    bool
	category       string
	severity       []string
	limits         [6]int
}

func (f *customSourceFlags) bind(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.template, "template", "", "a built-in template: "+strings.Join(customTemplateIDs(), ", "))
	cmd.Flags().StringVar(&f.file, "file", "", "a manifest file to import")
	cmd.Flags().IntVar(&f.executable, "executable", 0, "pick the executable by its number in the preview")
	cmd.Flags().IntSliceVar(&f.companions, "companion", nil, "pick each companion by its number in the preview, in order")
	cmd.Flags().StringVar(&f.input, "input", "", "targets_file or stdin")
	cmd.Flags().StringVar(&f.output, "output-mode", "", "sarif_file or sarif_stdout")
	cmd.Flags().StringVar(&f.cache, "cache", "", "none or per_driver")
	cmd.Flags().BoolVar(&f.networkNone, "network-none", false, "turn the manifest's declared hosts off (declared hosts are not enforced: a run with them can reach any host)")
	cmd.Flags().StringVar(&f.category, "category", "", "the finding category")
	cmd.Flags().StringArrayVar(&f.severity, "severity", nil, "LEVEL=SEVERITY, re-map one level the manifest names")
	for i, lf := range seccustom.LimitFields() {
		cmd.Flags().IntVar(&f.limits[i], strings.ReplaceAll(string(lf), "_", "-"), 0, fmt.Sprintf("one of %v", seccustom.LimitSteps(lf)))
	}
}

func customTemplateIDs() []string {
	var out []string
	for _, t := range seccustom.Templates() {
		out = append(out, t.ID)
	}
	return out
}

// source reads the chosen source.
func (f *customSourceFlags) source() (seccustomsvc.Source, error) {
	switch {
	case (f.template == "") == (f.file == ""):
		return seccustomsvc.Source{}, errors.New("name one of --template and --file")
	case f.template != "":
		return seccustomsvc.Source{Template: f.template}, nil
	}
	b, err := os.ReadFile(f.file) //nolint:gosec // G304: the manifest the user names on purpose; read under the strict reader's 64 KiB cap
	if err != nil {
		return seccustomsvc.Source{}, err
	}
	if len(b) > seccustom.MaxManifestBytes {
		return seccustomsvc.Source{}, fmt.Errorf("the manifest is over %d KiB", seccustom.MaxManifestBytes>>10)
	}
	return seccustomsvc.Source{File: b}, nil
}

// choices turns the flags into pickers, resolving numbers against the
// candidates of a first prepare.
func (f *customSourceFlags) choices(cand seccustom.Candidates) (seccustom.Choices, error) {
	var c seccustom.Choices
	pick := func(list []string, n int, what string) (string, error) {
		if n == 0 {
			return "", nil
		}
		if n < 1 || n > len(list) {
			return "", fmt.Errorf("%s %d is not one of the %d discovered", what, n, len(list))
		}
		return list[n-1], nil
	}
	var err error
	if c.Executable, err = pick(cand.Executable, f.executable, "executable"); err != nil {
		return c, err
	}
	for i, n := range f.companions {
		var list []string
		if i < len(cand.Companions) {
			list = cand.Companions[i]
		}
		p, err := pick(list, n, "companion")
		if err != nil {
			return c, err
		}
		c.Companions = append(c.Companions, p)
	}
	c.Input, c.Output, c.Cache = seccustom.Input(f.input), seccustom.Output(f.output), seccustom.Cache(f.cache)
	c.NetworkNone, c.Category = f.networkNone, f.category
	for i, lf := range seccustom.LimitFields() {
		c.Limits = setCustomLimit(c.Limits, lf, f.limits[i])
	}
	for _, kv := range f.severity {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return c, fmt.Errorf("--severity %q is not LEVEL=SEVERITY", kv)
		}
		if c.Severity == nil {
			c.Severity = map[string]policy.FindingSeverity{}
		}
		c.Severity[k] = policy.FindingSeverity(v)
	}
	return c, nil
}

func setCustomLimit(l seccustom.Limits, f seccustom.LimitField, v int) seccustom.Limits {
	switch f {
	case seccustom.LimitWall:
		l.WallSeconds = v
	case seccustom.LimitMemory:
		l.MemoryMiB = v
	case seccustom.LimitCPU:
		l.CPUSeconds = v
	case seccustom.LimitOutput:
		l.OutputMiB = v
	case seccustom.LimitChildren:
		l.ChildProcesses = v
	case seccustom.LimitFile:
		l.FileMiB = v
	}
	return l
}

// prepareFromFlags runs a first prepare for the candidates, then the
// prepare with the pickers applied.
func prepareFromFlags(ctx context.Context, svc *seccustomsvc.Service, f *customSourceFlags) (seccustomsvc.Source, seccustom.Choices, seccustomsvc.Prepared, error) {
	src, err := f.source()
	if err != nil {
		return src, seccustom.Choices{}, seccustomsvc.Prepared{}, err
	}
	first, err := svc.Prepare(ctx, src, seccustom.Choices{})
	if err != nil {
		return src, seccustom.Choices{}, first, err
	}
	c, err := f.choices(first.Candidates)
	if err != nil {
		return src, c, first, err
	}
	p, err := svc.Prepare(ctx, src, c)
	return src, c, p, err
}

func printPrepared(w io.Writer, p seccustomsvc.Prepared) {
	b, _ := json.MarshalIndent(p.Manifest, "", "  ")
	fmt.Fprintf(w, "custom scanner %s (%s)\n", p.ID, map[bool]string{true: "replaces the accepted one", false: "new"}[p.Replaces])
	if p.Note != "" {
		fmt.Fprintf(w, "  note: %s\n", p.Note)
	}
	fmt.Fprintf(w, "  pin: %s\n", p.Pin)
	if nw := seccustom.NetworkWords(p.Manifest.Network); nw != "" {
		fmt.Fprintf(w, "  %s\n", nw)
	}
	if p.ExecNote != "" {
		fmt.Fprintf(w, "  check: %s\n", p.ExecNote)
	}
	fmt.Fprintf(w, "  child processes are counted in %s on this OS\n", seccustom.ChildrenUnit(runtime.GOOS))
	fmt.Fprintln(w, "  executables discovered:")
	for i, c := range p.Candidates.Executable {
		mark := " "
		if c == p.Manifest.Executable {
			mark = "*"
		}
		fmt.Fprintf(w, "   %s %d. %s\n", mark, i+1, c)
	}
	for i, list := range p.Candidates.Companions {
		fmt.Fprintf(w, "  companion %d discovered:\n", i+1)
		for j, c := range list {
			fmt.Fprintf(w, "     %d. %s\n", j+1, c)
		}
	}
	if p.FileSHA256 != "" {
		fmt.Fprintf(w, "  file sha256:     %s\n", p.FileSHA256)
	}
	fmt.Fprintf(w, "  manifest sha256: %s\n", p.ManifestSHA256)
	fmt.Fprintf(w, "the manifest, in full:\n%s\n", b)
	fmt.Fprintf(w, "accept exactly this with: observer security scanners import ... --confirm %s\n", p.ManifestSHA256)
}

func newCustomTemplatesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "templates",
		Short: "List the built-in templates",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			for _, t := range seccustom.Templates() {
				fmt.Fprintf(cmd.OutOrStdout(), "%-8s %s\n         %s\n", t.ID, t.Title, t.Note)
			}
			return nil
		},
	}
}

func newCustomPreviewCmd() *cobra.Command {
	var configPath string
	var asJSON bool
	f := &customSourceFlags{}
	cmd := &cobra.Command{
		Use:   "preview",
		Short: "Show a manifest in full, with what discovery found and its digest",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, cleanup, err := openCustomScanners(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			_, _, p, err := prepareFromFlags(cmd.Context(), svc, f)
			if err != nil {
				return err
			}
			if asJSON {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(p)
			}
			printPrepared(cmd.OutOrStdout(), p)
			return nil
		},
	}
	f.bind(cmd)
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

func newCustomImportCmd() *cobra.Command {
	var configPath, confirm string
	var noSelfTest bool
	f := &customSourceFlags{}
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Accept a custom scanner (the digest preview showed), then self-test it",
		Long: "Accept the manifest preview showed. --confirm must be the manifest\n" +
			"sha256 preview printed for the same flags; anything that changed since\n" +
			"(a different binary on disk, a different pick) refuses. An agent running\n" +
			"this is refused by guard rule R-165.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, cleanup, err := openCustomScanners(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			src, c, _, err := prepareFromFlags(cmd.Context(), svc, f)
			if err != nil {
				return err
			}
			rec, err := svc.Accept(cmd.Context(), src, c, confirm, "cli")
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "accepted %s (manifest %s, pin %s)\n", rec.ID, rec.ManifestSHA256, rec.Pin)
			if noSelfTest || rec.Manifest.SelfTest == nil {
				if rec.Manifest.SelfTest == nil {
					fmt.Fprintln(w, "this scanner has no self-test: a run with no findings is unknown, never clean")
				}
				return nil
			}
			st, err := svc.SelfTest(cmd.Context(), rec.ID)
			if err != nil {
				return err
			}
			printSelfTest(w, st)
			return nil
		},
	}
	f.bind(cmd)
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.Flags().StringVar(&confirm, "confirm", "", "the manifest sha256 preview printed")
	cmd.Flags().BoolVar(&noSelfTest, "no-self-test", false, "do not run the self-test now (runs stay unknown until it passes)")
	return cmd
}

func printSelfTest(w io.Writer, st seccustom.SelfTestState) {
	if st.Passed {
		fmt.Fprintln(w, "self-test passed: runs with no findings can be clean while the digests and versions stay the same")
		return
	}
	fmt.Fprintf(w, "self-test FAILED (%s); missing %v: runs stay unknown, never clean\n", st.Detail, st.Missing)
}

func newCustomListCmd() *cobra.Command {
	var configPath string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the accepted custom scanners",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, cleanup, err := openCustomScanners(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			recs, bad := svc.Records(cmd.Context())
			if asJSON {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"scanners": recs, "unreadable": bad})
			}
			w := cmd.OutOrStdout()
			for _, r := range recs {
				state := "self-test not run"
				if r.SelfTest.Ran {
					state = "self-test " + map[bool]string{true: "passed", false: "failed"}[r.SelfTest.Passed]
				}
				fmt.Fprintf(w, "%-20s %s %s  %s, pin %s, %s\n", r.ID, r.Manifest.Name, r.Manifest.Version, r.Manifest.Executable, r.Pin, state)
			}
			for id, why := range bad {
				fmt.Fprintf(w, "%-20s NOT LOADED: %s\n", id, why)
			}
			if len(recs)+len(bad) == 0 {
				fmt.Fprintln(w, "no custom scanners")
			}
			for _, d := range svc.RequiredMissing(cmd.Context()) {
				fmt.Fprintf(w, "REQUIRED BY THE ORG, not accepted here: manifest %s\n", d)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

func newCustomRemoveCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "remove ID",
		Short: "Remove a custom scanner",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, cleanup, err := openCustomScanners(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			return svc.Remove(cmd.Context(), args[0], "cli")
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	return cmd
}

func newCustomSelfTestCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "self-test ID",
		Short: "Run a custom scanner's self-test fixture now",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, cleanup, err := openCustomScanners(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st, err := svc.SelfTest(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			printSelfTest(cmd.OutOrStdout(), st)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	return cmd
}

func newCustomRunCmd() *cobra.Command {
	var configPath, dir string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "run ID",
		Short: "Scan a project with a custom scanner (background work, run by hand here)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, cleanup, err := openCustomScanners(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			root, err := customScanProjectRoot(dir)
			if err != nil {
				return err
			}
			rep, err := svc.Run(cmd.Context(), args[0], root, policy.FindingScopeManual)
			if err != nil {
				return err
			}
			if asJSON {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(rep)
			}
			printRunReport(cmd.OutOrStdout(), rep)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.Flags().StringVar(&dir, "dir", "", "the project directory (default: the working directory's repository)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

// customScanProjectRoot resolves dir (or the working directory) to its
// repository root: the checkout's own top level, so a run in a linked
// worktree scans the worktree's files (F0-14).
func customScanProjectRoot(dir string) (string, error) {
	if dir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		dir = wd
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		abs = r
	}
	if root, ok := git.FindCheckoutRoot(abs); ok {
		return root, nil
	}
	return abs, nil
}

func printRunReport(w io.Writer, rep seccustomsvc.RunReport) {
	v := string(rep.Verdict.Outcome)
	if rep.Verdict.Reason != "" {
		v += " (" + rep.Verdict.Reason + ")"
	}
	fmt.Fprintf(w, "%s: %s, %d findings, %d results refused, %d closed\n", rep.Driver, v, rep.Findings, rep.Refused, rep.Closed)
	iso := "not isolated: " + rep.NotIsolatedWhy
	if rep.Isolation != "" {
		iso = "isolated (" + rep.Isolation + ")"
	}
	fmt.Fprintf(w, "  %s; containment: %s\n", iso, rep.Containment.Label)
	if rep.Network != "" {
		fmt.Fprintf(w, "  %s\n", rep.Network)
	}
	if rep.ToolchainSkew != "" {
		fmt.Fprintf(w, "  toolchain: %s\n", rep.ToolchainSkew)
	}
	fmt.Fprintf(w, "  runner %s, exit %s %s, %s\n", rep.RunnerOut, strconv.Itoa(rep.ExitCode), rep.ExitMeaning, rep.Duration.Round(1e6))
	for _, t := range rep.Toolchain {
		fmt.Fprintf(w, "  companion %s version %q\n", t.Path, t.Version)
	}
	if rep.Detail != "" {
		fmt.Fprintf(w, "  %s\n", rep.Detail)
	}
}

func newCustomAuditCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Show the custom scanner audit log",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, cleanup, err := openCustomScanners(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			for _, e := range svc.Layout().Audit(200) {
				fmt.Fprintf(cmd.OutOrStdout(), "%s %-9s %s via %s manifest %s %s\n", e.At.Format("2006-01-02T15:04:05Z"), e.Action, e.ID, e.Via, e.ManifestSHA256, e.Detail)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	return cmd
}

// customScannersForDashboard is the service the dashboard's custom scanner
// routes use, or nil (the routes then answer 404 while the component is
// inactive, through the component guard).
func customScannersForDashboard(ctx context.Context, snap componentstate.Snapshot, configPath string, st *store.Store) any {
	svc, err := customScannerService(ctx, snap, configPath, st)
	if err != nil || svc == nil {
		return nil
	}
	return svc
}
