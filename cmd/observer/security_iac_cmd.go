//go:build !sbo_omit_security

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/seciac"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// security_iac_cmd.go is `observer security iac` (lane GATES-SEC): status,
// scan and install for the two IaC engines. Every verb refuses "not
// selected" before it opens anything while its component is off, so an
// install with no [components] block runs, downloads and probes nothing.
// Guard rule R-165 denies an agent's `security iac install` (it downloads
// a third-party engine on the developer's consent).

// iacEngineFlag parses --engine.
func iacEngineFlag(v string) (seciac.EngineID, error) {
	id := seciac.EngineID(strings.ToLower(strings.TrimSpace(v)))
	if _, ok := seciac.Lookup(id); !ok {
		return "", fmt.Errorf("--engine must be trivy or kics, not %q", v)
	}
	return id, nil
}

// securityIaCSubcommands is `observer security iac`.
func securityIaCSubcommands() []*cobra.Command {
	cmd := &cobra.Command{
		Use:   "iac",
		Short: "Infrastructure-as-code checks with Trivy or KICS (components security.scan.trivy, security.scan.kics; opt-in)",
		Long: "Checks a project's Dockerfiles, Kubernetes, Terraform, CloudFormation and Helm files with a\n" +
			"separately installed, pinned engine: Trivy (misconfiguration only, signature-checked, every\n" +
			"network path off) or KICS (run only inside the isolation component's no-network run).\n" +
			"Findings are flag only. Opt-in: add security.scan.trivy or security.scan.kics, and\n" +
			"security.code, under [components].",
	}
	cmd.AddCommand(newIaCStatusCmd(), newIaCScanCmd(), newIaCInstallCmd())
	return []*cobra.Command{cmd}
}

func newIaCStatusCmd() *cobra.Command {
	var configPath string
	var asJSON bool
	c := &cobra.Command{
		Use:   "status",
		Short: "Show each IaC engine's selection, install and verification (starts nothing)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rows := iacStatusRows(cmd.Context(), configPath)
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(rows)
			}
			for _, r := range rows {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", r.Component, r.Line)
			}
			return nil
		},
	}
	c.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	c.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return c
}

// iacStatusRow is one engine's status.
type iacStatusRow struct {
	Component string `json:"component"`
	Engine    string `json:"engine"`
	Compiled  bool   `json:"compiled"`
	Selected  bool   `json:"selected"`
	Installed bool   `json:"installed"`
	Binary    string `json:"binary,omitempty"`
	Digest    string `json:"digest,omitempty"`
	Decision  string `json:"decision,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Line      string `json:"line"`
}

// iacStatusRows reads each engine without starting or writing anything.
func iacStatusRows(ctx context.Context, configPath string) []iacStatusRow {
	snap := componentSnapshotFor(configPath)
	var rows []iacStatusRow
	for _, e := range seciac.Engines() {
		r := iacStatusRow{Component: iacComponent(e.ID), Engine: string(e.ID)}
		_, r.Compiled = iacBindings[e.ID]
		r.Selected = iacSelected(snap, e.ID)
		switch {
		case !r.Compiled:
			r.Line = e.Title + ": not in this build"
		case !r.Selected:
			r.Line = e.Title + ": not selected (opt-in; add " + r.Component + " and security.code under [components]); nothing is installed, downloaded or run"
		default:
			env, err := openIaCEnv(ctx, configPath, e.ID)
			if err != nil {
				r.Line = e.Title + ": " + err.Error()
				break
			}
			in := env.inspector().Inspect()
			env.cleanup()
			r.Binary, r.Digest, r.Reason = in.Binary, in.Digest, in.Reason
			r.Installed = in.Binary != "" && in.Reason != seciac.ReasonNotInstalled
			if r.Installed && in.Reason == "" {
				r.Decision = in.Decision.String()
			}
			r.Line = iacStatusLine(e, in)
		}
		rows = append(rows, r)
	}
	return rows
}

// iacStatusLine is one engine's status sentence.
func iacStatusLine(e seciac.Engine, in seciac.Inspection) string {
	switch {
	case in.Reason == seciac.ReasonNotInstalled:
		hint := "install it yourself"
		if e.GuidedInstall() {
			hint = "`observer security iac install --engine " + string(e.ID) + "` or install it yourself"
		}
		return e.Title + ": selected, not installed: no process starts and projects read not_scanned (" + hint + ")"
	case in.Reason != "":
		return e.Title + ": selected, found at " + in.Binary + " but not usable (" + in.Reason + ")"
	}
	s := e.Title + ": " + in.Binary + " sha256 " + in.Digest + ": " + in.Decision.String()
	if e.RequireIsolation {
		s += "; runs only inside the isolation component's no-network run"
	}
	if !in.SelfTestAt.IsZero() {
		s += "; canary passed " + in.SelfTestAt.UTC().Format("2006-01-02")
	}
	return s
}

func newIaCScanCmd() *cobra.Command {
	var configPath, project, engine string
	var asJSON bool
	c := &cobra.Command{
		Use:   "scan",
		Short: "Scan a project with one IaC engine and record the run (flag-only findings)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			id, err := iacEngineFlag(engine)
			if err != nil {
				return err
			}
			env, err := openIaCEnv(cmd.Context(), configPath, id)
			if err != nil {
				return err
			}
			defer env.cleanup()
			root, checkout, err := securityKnownProjectRoot(cmd.Context(), env.st, project)
			if err != nil {
				return err
			}
			t := secscan.Target{ProjectRoot: root, Scope: policy.FindingScopeManual}
			if checkout != root {
				t.CheckoutRoot = checkout
			}
			rep, err := runIaCScan(cmd.Context(), env, t)
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(rep)
			}
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "%s: %d finding(s) (%d new); outcome %s", id, rep.Findings, rep.New, rep.Outcome)
			if rep.Reason != "" {
				_, _ = fmt.Fprintf(out, " (%s)", rep.Reason)
			}
			_, _ = fmt.Fprintln(out)
			for _, n := range rep.Notes {
				_, _ = fmt.Fprintf(out, "  %s\n", n)
			}
			return nil
		},
	}
	c.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	c.Flags().StringVar(&project, "project", ".", "a directory inside the project")
	c.Flags().StringVar(&engine, "engine", "trivy", "trivy or kics")
	c.Flags().BoolVar(&asJSON, "json", false, "print the report as JSON")
	return c
}

func newIaCInstallCmd() *cobra.Command {
	var configPath, engine string
	var yes, plan bool
	c := &cobra.Command{
		Use:   "install",
		Short: "Install the pinned engine from the vendor's release after your one-time size consent (individual node), or from the org mirror (managed node)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			id, err := iacEngineFlag(engine)
			if err != nil {
				return err
			}
			env, err := openIaCEnv(cmd.Context(), configPath, id)
			if err != nil {
				return err
			}
			defer env.cleanup()
			p := seciac.PlanInstall(env.installInput(cmd.Context()))
			out := cmd.OutOrStdout()
			if plan {
				return writeIaCPlan(out, env, p)
			}
			consent := yes
			if !env.managed && !p.Installed && p.Blocked == "" && !readIaCConsent(env.secDir, id).Covers(p) && !yes {
				_, _ = fmt.Fprintln(out, seciac.ConsentText(p))
				_, _ = fmt.Fprint(out, "Download and install? [y/N] ")
				consent = iacAskYes(cmd.InOrStdin())
				if !consent {
					return errors.New("nothing was downloaded")
				}
			}
			got, err := env.installIaCEngine(cmd.Context(), codeSurfaceCLIName, consent)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(out, "%s %s installed at %s (archive sha256 %s)\n", id, got.Pin.Version, iacInstalledPath(id), got.Pin.AssetSHA256)
			return nil
		},
	}
	c.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	c.Flags().StringVar(&engine, "engine", "trivy", "trivy (KICS publishes no release binaries)")
	c.Flags().BoolVar(&yes, "yes", false, "give the one-time size consent without the question")
	c.Flags().BoolVar(&plan, "plan", false, "print what the install would do and change nothing")
	return c
}

// codeSurfaceCLIName is the consent surface of the CLI.
const codeSurfaceCLIName = "cli"

func writeIaCPlan(w io.Writer, env *iacEnv, p seciac.InstallPlan) error {
	switch {
	case p.Blocked != "":
		_, _ = fmt.Fprintf(w, "blocked: %s\n", seciac.BlockedWords(env.id, p.Blocked, runtime.GOOS, runtime.GOARCH))
	case p.Installed:
		_, _ = fmt.Fprintf(w, "installed: %s %s\n", env.id, p.Pin.Version)
	default:
		_, _ = fmt.Fprintf(w, "source %s, pin %s %s (%s), archive sha256 %s\n", p.Source, env.id, p.Pin.Version, p.Pin.Asset, p.Pin.AssetSHA256)
		if p.URL != "" {
			_, _ = fmt.Fprintln(w, seciac.ConsentText(p))
		}
	}
	return nil
}

func iacAskYes(r io.Reader) bool {
	line, _ := bufio.NewReader(r).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

// securityIaCDoctorCheck is the doctor's one line: it starts and writes
// nothing, and reads only the selection while nothing is selected.
func securityIaCDoctorCheck(ctx context.Context, configPath string) diag.Check {
	c := diag.Check{Name: "security.scan.iac", Status: diag.StatusOK}
	var parts []string
	for _, r := range iacStatusRows(ctx, configPath) {
		parts = append(parts, r.Line)
		if r.Selected && r.Reason != "" && r.Reason != seciac.ReasonNotInstalled {
			c.Status = diag.StatusWarn
		}
	}
	c.Message = strings.Join(parts, "; ")
	return c
}
