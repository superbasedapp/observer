//go:build !sbo_omit_security

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secfinding/sarif"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secrules"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_cli.go is `observer security` and the doctor's `security` check
// (security pillar plan sections 4.2, 4.3 and 4.11, Phase A). The verb is
// the catalog's (component `security`): gateComponentVerbs refuses it with
// exit 3 while the module is not active.

// securityProjectState is one project's derived posture.
type securityProjectState struct {
	ProjectRootHash string `json:"project_root_hash"`
	State           string `json:"state"`
	Reason          string `json:"reason"`
	Blocking        int    `json:"blocking"`
	// quickScanBudget is the project's effective quick-scan budget, the
	// one the hook uses (secposture.EffectiveQuickScanBudget); doctor's
	// clamp lines read it, the JSON does not carry it.
	quickScanBudget time.Duration
}

// securityStatusReport is `observer security status --json`.
type securityStatusReport struct {
	Module      string                 `json:"module"`
	RulePack    string                 `json:"rule_pack"`
	SecurityDir string                 `json:"security_dir"`
	Projects    []securityProjectState `json:"projects"`
}

// securityModuleName names a module signal.
func securityModuleName(m secposture.ModuleSignal) string {
	switch m {
	case secposture.ModuleActive:
		return "active"
	case secposture.ModuleInactive:
		return "inactive"
	case secposture.ModuleUnverified:
		return "unverified"
	default:
		return "no_daemon"
	}
}

// readSecurityStatus derives every active project's posture state exactly
// as the hook would read it now.
func readSecurityStatus(ctx context.Context, configPath string, st *store.Store) (securityStatusReport, error) {
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return securityStatusReport{}, err
	}
	layout := secposture.LayoutFor(resolved)
	ld := guardposture.Load(guardposture.PosturePath(resolved), guardposture.KeyPath(resolved))
	module := secposture.ModuleSignalFrom(ld.State, ld.Posture)
	rep := securityStatusReport{Module: securityModuleName(module), RulePack: secrules.PackVersion, SecurityDir: layout.Dir, Projects: []securityProjectState{}}
	now := time.Now()
	// The projects the posture writer signs (secsvc.WriteAll): an idle
	// project has no posture file and is not listed.
	roots, err := st.SecActiveProjectRoots(ctx, now.Add(-secsvc.DefaultActiveWithin))
	if err != nil {
		return rep, err
	}
	for _, root := range roots {
		r := secposture.Load(layout, root, module, now, secposture.Versions{})
		rep.Projects = append(rep.Projects, securityProjectState{
			ProjectRootHash: secposture.ProjectRootHash(root), State: string(r.State.Posture),
			Reason: string(r.State.Reason), Blocking: r.State.Blocking,
			quickScanBudget: secposture.EffectiveQuickScanBudget(r),
		})
	}
	return rep, nil
}

// securityDirtyDetail is doctor's dirty-marker line (section 4.11): how
// many projects the hook marked, how many in the last day, and whether the
// directory can take the next raise. warn reports a marker that is not a
// readable counter or a directory the hook cannot write.
func securityDirtyDetail(l secposture.Layout, now time.Time) (line string, warn bool) {
	h, err := secposture.ReadDirtyHealth(l, now.Add(-24*time.Hour))
	switch {
	case err != nil:
		return "dirty markers: not readable: " + err.Error(), true
	case !h.Exists:
		return "dirty markers: none yet (no write-capable agent call seen while the module is active)", false
	case !h.Writable:
		return fmt.Sprintf("dirty markers: %d, directory %s is not writable, so the hook cannot mark new activity", h.Markers, h.Dir), true
	case h.Unreadable > 0:
		return fmt.Sprintf("dirty markers: %d (%d raised in the last 24 h), %d not a readable counter (those projects read dirty)", h.Markers, h.Recent, h.Unreadable), true
	default:
		return fmt.Sprintf("dirty markers: %d (%d raised in the last 24 h)", h.Markers, h.Recent), false
	}
}

func newSecurityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "security",
		Short: "Code security: posture and findings (security pillar, preview)",
		Long: "Code security, the security pillar's module (component `security`).\n" +
			"`status` shows each project's commit-gate posture as the hook reads it;\n" +
			"`findings` lists the findings the local store holds. Both are read-only.\n" +
			"`trust` checks and records repository trust (component `security.trust`);\n" +
			"`deps` shows and feeds the package install checks (component `security.deps`);\n" +
			"`scan` scans a project's dependencies (components `security.scan.scalibr`, `security.scan.osv`);\n" +
			"`code` runs Observer's code rules with a separately installed Opengrep (component `security.scan.opengrep`);\n" +
			"`provenance` keeps signed AI change records per commit (component `security.provenance`);\n" +
			"`verify` checks a pull request's change in CI (headless).",
	}
	cmd.AddCommand(newSecurityStatusCmd(), newSecurityFindingsCmd(), newSecurityExportCmd(), newSecurityVerifyCmd())
	// Local finding exceptions and baselines (lane sec-c3).
	cmd.AddCommand(securityExceptionSubcommands()...)
	// Repository trust (component security.trust, Phase B); none when
	// that child is compiled out.
	cmd.AddCommand(securityTrustSubcommands()...)
	// Package checks (component security.deps, Phase D1); none when that
	// child is compiled out.
	cmd.AddCommand(securityDepsSubcommands()...)
	// Custom scanners (component security.scan.custom, Phase D3); none when
	// that child is compiled out.
	cmd.AddCommand(securityCustomSubcommands()...)
	// Dependency scanners (security.scan.scalibr and security.scan.osv,
	// Phase D2) and the hidden scan child; none without security.deps.
	cmd.AddCommand(securityScanSubcommands()...)
	// Code rules run by Opengrep (security.scan.opengrep, Phase G lane
	// G1); none when that driver is compiled out.
	cmd.AddCommand(securityCodeSubcommands()...)
	// SARIF import and actionlint (security.scan.sarif-import and
	// security.scan.actionlint, lane sec-g5); none when compiled out.
	cmd.AddCommand(securitySARIFImportSubcommands()...)
	cmd.AddCommand(securityActionlintSubcommands()...)
	// IaC checks (security.scan.trivy and security.scan.kics, lane
	// GATES-SEC): status, scan and install; refuses while not selected.
	cmd.AddCommand(securityIaCSubcommands()...)
	// Feedback and assistance (component security.feedback, Phase H, lane
	// sec-h): the judge's advisory explanation and the coverage report.
	cmd.AddCommand(securityFeedbackSubcommands()...)
	mergeSecurityScanCmds(cmd)
	// AI change records (component security.provenance, lane sec-f2a).
	cmd.AddCommand(securityProvenanceSubcommands()...)
	return cmd
}

// mergeSecurityScanCmds keeps ONE `observer security scan` (live check
// macOS 2026-10-22, D3). The history scan (security_exceptions.go, always
// built with the module) and the dependency scan (security_scan_cmd.go,
// built with security.deps) were both registered as `scan`; cobra ran the
// first one, so the documented `observer security scan --history` failed
// with "unknown flag" and `security --help` listed scan twice. When both
// are built, the dependency scan is the command and carries every flag of
// the history scan; --history runs the history scan (a [DIR] argument
// stands in for --project). With only one built, it stays as it is.
func mergeSecurityScanCmds(parent *cobra.Command) {
	var scans []*cobra.Command
	for _, c := range parent.Commands() {
		if c.Name() == "scan" {
			scans = append(scans, c)
		}
	}
	if len(scans) != 2 {
		return
	}
	primary, history := scans[0], scans[1]
	if primary.Flags().Lookup("history") != nil {
		primary, history = history, primary
	}
	if history.Flags().Lookup("history") == nil || primary.RunE == nil || history.RunE == nil {
		return
	}
	parent.RemoveCommand(history)
	// A flag both declare (--json) is the primary's; its value is copied to
	// the history scan's own before that runs.
	shared := map[string]*pflag.Flag{}
	history.Flags().VisitAll(func(f *pflag.Flag) {
		if primary.Flags().Lookup(f.Name) == nil {
			primary.Flags().AddFlag(f)
			return
		}
		shared[f.Name] = f
	})
	runDeps := primary.RunE
	runHistory := history.RunE
	primary.RunE = func(cmd *cobra.Command, args []string) error {
		if on, _ := cmd.Flags().GetBool("history"); !on {
			return runDeps(cmd, args)
		}
		for name, hf := range shared {
			if pf := cmd.Flags().Lookup(name); pf != nil && pf.Changed {
				if err := hf.Value.Set(pf.Value.String()); err != nil {
					return err
				}
			}
		}
		if len(args) == 1 {
			if pf := cmd.Flags().Lookup("project"); pf != nil && !pf.Changed {
				if err := pf.Value.Set(args[0]); err != nil {
					return err
				}
			}
		}
		return runHistory(cmd, nil)
	}
	primary.Use = "scan [DIR]"
	primary.Short = "Scan a project's dependencies for known vulnerabilities, or with --history its commit history for secrets"
	primary.Long += "\n\nWith --history it scans the commit history for secrets instead (--project or DIR, --max-commits, --json):\n" + history.Long
}

// newSecurityExportCmd is `observer security export --format sarif`
// (section 4.5.3 "Out"): the local findings as SARIF 2.1.0 that GitHub
// code scanning accepts, with Observer's lineage in each result's
// properties bag and never any evidence.
func newSecurityExportCmd() *cobra.Command {
	var configPath, format, project, status string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export findings as SARIF 2.1.0 (with Observer's lineage)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if format != "sarif" {
				return fmt.Errorf("unsupported --format %q (sarif)", format)
			}
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			got, err := store.New(database).ListSecFindings(cmd.Context(), store.SecFindingFilter{
				ProjectRootHash: project, Status: secfinding.Status(status), Limit: 1000,
			})
			if err != nil {
				return err
			}
			data, err := sarif.Encode(got, sarif.ToolInfo{Name: "SuperBased Observer", Version: version, InformationURI: "https://superbased.app"})
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(append(data, '\n'))
			return err
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.Flags().StringVar(&format, "format", "sarif", "export format (sarif)")
	cmd.Flags().StringVar(&project, "project", "", "project root hash")
	cmd.Flags().StringVar(&status, "status", "open", "finding status to export (empty for all)")
	return cmd
}

func newSecurityStatusCmd() *cobra.Command {
	var configPath string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show each project's commit-gate posture as the hook reads it",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			rep, err := readSecurityStatus(cmd.Context(), configPath, store.New(database))
			if err != nil {
				return err
			}
			if asJSON {
				return writeSecurityJSON(cmd.OutOrStdout(), rep)
			}
			w := cmd.OutOrStdout()
			printSecurityStatus(w, rep)
			// Lane SEC-E: the org floors and the managed pull, each key with
			// what it does on this node (applied or not_applicable: why).
			for _, l := range securityOrgStatusLines(cmd.Context(), configPath, cfg, store.New(database)) {
				fmt.Fprintln(w, l)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

// printSecurityStatus writes the status report as text.
func printSecurityStatus(w io.Writer, rep securityStatusReport) {
	fmt.Fprintf(w, "Code security: module %s, rule pack %s\n", rep.Module, rep.RulePack)
	for _, p := range rep.Projects {
		line := fmt.Sprintf("  %s  %s (%s)", securityHashPrefix(p.ProjectRootHash), p.State, p.Reason)
		if p.Blocking > 0 {
			line += fmt.Sprintf(", %d blocking", p.Blocking)
		}
		fmt.Fprintln(w, line)
	}
}

// securityHashPrefix is the first 12 characters of a project root hash, or the
// whole of a shorter one (the store may hold a hash it did not write).
func securityHashPrefix(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func newSecurityFindingsCmd() *cobra.Command {
	var configPath, project, status string
	var limit int
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "findings",
		Short: "List the findings the local store holds",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			got, err := store.New(database).ListSecFindings(cmd.Context(), store.SecFindingFilter{
				ProjectRootHash: project, Status: secfinding.Status(status), Limit: limit,
			})
			if err != nil {
				return err
			}
			if asJSON {
				return writeSecurityJSON(cmd.OutOrStdout(), got)
			}
			w := cmd.OutOrStdout()
			if len(got) == 0 {
				fmt.Fprintln(w, "No findings.")
				return nil
			}
			for _, f := range got {
				loc := f.Location.RelPath
				if f.Location.StartLine > 0 {
					loc += fmt.Sprintf(":%d", f.Location.StartLine)
				}
				fmt.Fprintf(w, "%-8s %-8s %-22s %-10s %s  %s\n", f.Severity, f.Status, f.Category, f.Rule.ID, loc, f.Message)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.Flags().StringVar(&project, "project", "", "project root hash")
	cmd.Flags().StringVar(&status, "status", "", "open, not_reproduced, fixed_verified, suppressed, accepted_risk or false_positive")
	cmd.Flags().IntVar(&limit, "limit", 200, "most findings to list (at most 1000)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

func writeSecurityJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// securityDoctorCheck is doctor's `security` check (section 4.11): the
// module state, the posture files' verification and freshness per state,
// the rule pack version and the quick-scan service. While the module is
// not active it is one line and probes nothing.
func securityDoctorCheck(ctx context.Context, configPath string, st *store.Store) diag.Check {
	c := diag.Check{Name: "security", Status: diag.StatusOK}
	if !componentSnapshotFor(configPath).ModuleActive("security") {
		c.Message = "Code security: not active; Settings > Components"
		return c
	}
	if st == nil {
		c.Status, c.Message = diag.StatusWarn, "Code security: active, but the database is not available"
		return c
	}
	rep, err := readSecurityStatus(ctx, configPath, st)
	if err != nil {
		c.Status, c.Message = diag.StatusWarn, "Code security: posture not readable: "+err.Error()
		return c
	}
	byState := map[string]int{}
	for _, p := range rep.Projects {
		byState[p.State+" ("+p.Reason+")"]++
	}
	var keys []string
	for k := range byState {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		c.Details = append(c.Details, fmt.Sprintf("%d project(s) %s", byState[k], k))
	}
	c.Details = append(c.Details, "rule pack "+rep.RulePack, "quick scan: not available in this release (security Phase C)")
	if line, warn := securityDirtyDetail(secposture.Layout{Dir: rep.SecurityDir}, time.Now()); line != "" {
		c.Details = append(c.Details, line)
		if warn {
			c.Status = diag.StatusWarn
		}
	}
	// The node settings lane LEFT-SEC built: each one not at its default,
	// or overridden by an org floor or the managed rule, is named.
	if cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath}); err == nil {
		for _, l := range securityNodeSettingStatus(ctx, configPath, cfg, st) {
			c.Details = append(c.Details, strings.TrimSpace(l))
		}
		c.Details = append(c.Details, quickScanClampDetailsForReport(rep, integration.Capabilities())...)
	}
	// AI change records (security.provenance, lane sec-f2a).
	if line, warn := provenanceDoctorDetail(ctx, configPath, st); line != "" {
		c.Details = append(c.Details, line)
		if warn {
			c.Status = diag.StatusWarn
		}
	}
	c.Message = fmt.Sprintf("Code security: active (guard posture says %s), %d project(s)", rep.Module, len(rep.Projects))
	if rep.Module != "active" {
		// The daemon has not signed the module's state yet (or the guard
		// posture does not verify): every commit gate reads unknown.
		c.Status = diag.StatusWarn
		c.Details = append(c.Details, "the guard posture does not say the module is active; start or restart the daemon")
	}
	if strings.Contains(strings.Join(keys, " "), "posture_unverified") {
		c.Status = diag.StatusWarn
	}
	return c
}

// quickScanClampDetailsForReport is doctor's clamp lines for the budgets the
// hook uses (LEFT2 audit E4): each active project's effective signed budget
// (secposture.EffectiveQuickScanBudget), or the default when no project is
// active, deduplicated.
func quickScanClampDetailsForReport(rep securityStatusReport, caps []integration.Capability) []string {
	budgets := map[time.Duration]bool{}
	for _, p := range rep.Projects {
		budgets[p.quickScanBudget] = true
	}
	if len(budgets) == 0 {
		budgets[secposture.IndividualQuickScan] = true
	}
	seen := map[string]bool{}
	var out []string
	for b := range budgets {
		for _, l := range quickScanClampDetails(b, caps) {
			if !seen[l] {
				seen[l] = true
				out = append(out, l)
			}
		}
	}
	sort.Strings(out)
	return out
}

// quickScanClampDetails names, for doctor, every registered gate hook whose
// vendor timeout is too short for the chosen quick-scan budget (lane
// LEFT2-SEC item R-039): there the scan is clamped below the timeout with a
// margin. One line per tool and event, sorted; nothing when every budget
// fits.
func quickScanClampDetails(budget time.Duration, caps []integration.Capability) []string {
	if budget <= 0 {
		budget = secposture.IndividualQuickScan
	}
	var out []string
	for _, c := range caps {
		for _, b := range c.Hook.Bindings {
			if !b.Registered || !b.Cap.IsGate() || b.HostTimeout <= 0 {
				continue
			}
			if got, clamped := secposture.ClampQuickScanBudget(budget, b.HostTimeout); clamped {
				out = append(out, fmt.Sprintf("quick scan: %s %s hook timeout %v is shorter than the %v budget; the scan is clamped to %v", c.Tool, b.NativeEvent, b.HostTimeout, budget, got))
			}
		}
	}
	sort.Strings(out)
	return out
}
