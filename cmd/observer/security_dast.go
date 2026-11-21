//go:build !sbo_omit_security && !sbo_omit_security_dast

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/secdast"
	"github.com/marmutapp/superbased-observer/internal/secdast/dastconsent"
	"github.com/marmutapp/superbased-observer/internal/secdastnet"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_dast.go is the cmd seam of the local passive DAST checker
// (component security.dast; OS and CI vulnerability scanning plan section
// 14.9, phase M3L-5): `observer security dast <url>` checks ONE dev server
// on this machine, `observer security dast accept` records the developer's
// one accept, and `observer security dast candidates` lists the URLs a
// project's .claude/launch.json names. The checks are internal/secdast's
// table; the requests go only through internal/secdastnet (the
// security.dast egress lane, loopback only). Opt-in (securityOptIn): a
// config with no [components] block selecting security.dast refuses every
// verb. R-165 denies an agent the run, the accept and the record: every run
// starts from the developer.

var errDASTNotSelected = fmt.Errorf("the %s component is not selected: add it under [components] (observer components status)", secdast.ComponentID)

// dastEnv is what one verb opens: the security directory the accept
// record lives in.
type dastEnv struct {
	dir string
}

func openDASTEnv(cmd *cobra.Command) (dastEnv, error) {
	configPath, _ := cmd.Flags().GetString("config")
	return openDASTEnvAt(configPath)
}

// openDASTEnvAt is openDASTEnv for a config path (the CLI's --config, or
// the dashboard seam's resolved path): errDASTNotSelected unless the
// config selects security.dast.
func openDASTEnvAt(configPath string) (dastEnv, error) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return dastEnv{}, err
	}
	if !securitySelected(componentSnapshotForConfig(cfg), secdast.ComponentID) {
		return dastEnv{}, errDASTNotSelected
	}
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return dastEnv{}, err
	}
	dir := secposture.LayoutFor(resolved).Dir
	if dir == "" {
		return dastEnv{}, errors.New("no security directory for the DAST accept record")
	}
	return dastEnv{dir: dir}, nil
}

// keyPath is the node's posture key beside the security directory (the
// key every consent record is signed with).
func (e dastEnv) keyPath() string {
	return filepath.Join(filepath.Dir(e.dir), guardposture.KeyFilename)
}

func (e dastEnv) consent() dastconsent.Consent {
	key, err := guardposture.ReadKey(e.keyPath())
	if err != nil {
		return dastconsent.Consent{}
	}
	return dastconsent.Read(e.dir, key)
}

func securityDASTSubcommands() []*cobra.Command { return []*cobra.Command{newSecurityDASTCmd()} }

func newSecurityDASTCmd() *cobra.Command {
	var asJSON, insecureTLS, noStore bool
	var storeProject string
	c := &cobra.Command{
		Use:   "dast <url>",
		Short: "Passive checks of a dev server on this machine (localhost only; component security.dast, opt-in)",
		Long: "Runs Observer's passive DAST checks against ONE development server on this machine:\n" +
			"a few plain GET requests (the page, /.git/HEAD, /.env, a missing page, and the source\n" +
			"maps of up to 3 scripts) and checks on what comes back: security headers, cookie flags,\n" +
			"CORS, exposed .git and .env, directory listings, source maps, framework debug pages and\n" +
			"version banners. The URL must be localhost, 127.0.0.1 or [::1] with a port; anything\n" +
			"else is refused, also after name resolution, and no redirect off it is followed.\n" +
			"Findings are flag only; they are stored against the project (--project, default the git\n" +
			"root of the working directory; --no-store prints only). The first run asks for the one\n" +
			"accept (or run `observer security dast accept`). An agent cannot run it (guard R-165).",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			e, err := openDASTEnv(cmd)
			if err != nil {
				return err
			}
			t, err := secdast.ParseTarget(args[0])
			if err != nil {
				return err
			}
			if !e.consent().Accepted() {
				isTTY := term.IsTerminal(int(os.Stdin.Fd()))
				if !isTTY || asJSON {
					return errors.New("the DAST checker is not accepted yet: run `observer security dast accept` first")
				}
				if err := runDASTAccept(cmd.OutOrStdout(), cmd.InOrStdin(), e, false, true, time.Now()); err != nil {
					return err
				}
				if !e.consent().Accepted() {
					return errors.New("nothing was checked: the DAST checker is not accepted")
				}
				fmt.Fprintln(cmd.OutOrStdout())
			}
			var rec dastRecorder
			if !noStore {
				root, perr := securityProjectRoot(storeProject)
				switch {
				case perr != nil && storeProject != "":
					return perr
				case perr == nil:
					configPath, _ := cmd.Flags().GetString("config")
					_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
					if err != nil {
						return err
					}
					defer cleanup()
					st := store.New(database)
					rec = dastRecorder{root: root, record: func(ctx context.Context, r dastRun) (int, error) {
						return recordDASTRun(ctx, st, e.dir, root, t, r.Report, r.Findings, r.Started, r.Took)
					}}
				}
			}
			return runDAST(cmd.Context(), cmd.OutOrStdout(), t, secdastnet.Options{InsecureTLS: insecureTLS}, asJSON, time.Now(), rec)
		},
	}
	c.Flags().BoolVar(&noStore, "no-store", false, "print the findings only; store nothing")
	c.Flags().StringVar(&storeProject, "project", "", "the project directory to store the findings against (default: the git root of the working directory; outside a repository they are printed only)")
	c.Flags().BoolVar(&asJSON, "json", false, "print the report as JSON")
	c.Flags().BoolVar(&insecureTLS, "insecure-tls", false, "accept an untrusted (self-signed) certificate on an https dev server; the address stays loopback-only")
	var yes bool
	accept := &cobra.Command{
		Use:   "accept",
		Short: "Accept, once, that the DAST checker may send its requests to dev servers you name on this machine",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			e, err := openDASTEnv(cmd)
			if err != nil {
				return err
			}
			return runDASTAccept(cmd.OutOrStdout(), cmd.InOrStdin(), e, yes, term.IsTerminal(int(os.Stdin.Fd())), time.Now())
		},
	}
	accept.Flags().BoolVar(&yes, "yes", false, "record the accept without asking (you read the text above)")
	var project string
	var candJSON bool
	candidates := &cobra.Command{
		Use:   "candidates",
		Short: "List the dev server URLs a project's .claude/launch.json names (read only; nothing is contacted)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := openDASTEnv(cmd); err != nil {
				return err
			}
			return runDASTCandidates(cmd.OutOrStdout(), project, candJSON)
		},
	}
	candidates.Flags().StringVar(&project, "project", "", "project directory (default: the current directory)")
	candidates.Flags().BoolVar(&candJSON, "json", false, "print as JSON")
	c.AddCommand(accept, candidates)
	return c
}

// runDASTAccept shows the accept text and records the accept on a yes:
// asked on a terminal, recorded with --yes, never otherwise.
func runDASTAccept(w io.Writer, in io.Reader, e dastEnv, yes, isTerminal bool, now time.Time) error {
	fmt.Fprintln(w, dastconsent.Text)
	if c := e.consent(); c.Accepted() {
		fmt.Fprintf(w, "\nAlready accepted %s (%s).\n", c.AcceptedAt.Local().Format(time.RFC3339), c.Surface)
		return nil
	}
	if !yes && isTerminal {
		fmt.Fprint(w, "\nLet the DAST checker send these requests to dev servers you name on this machine? [y/N] ")
		yes = dastReadYes(in)
	}
	if !yes {
		fmt.Fprintln(w, "\nNothing recorded. Re-run with --yes, or answer y on a terminal.")
		return nil
	}
	key, err := guardposture.LoadOrCreateKeyBeforePosture(e.keyPath())
	if err != nil {
		return err
	}
	if _, err := dastconsent.Record(e.dir, "cli", dastLocalAccount(), now, key); err != nil {
		return err
	}
	fmt.Fprintln(w, "\nRecorded. `observer security dast <url>` now runs the checks you start.")
	return nil
}

func dastReadYes(r io.Reader) bool {
	b := make([]byte, 64)
	n, _ := r.Read(b)
	line, _, _ := strings.Cut(string(b[:n]), "\n")
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

func dastLocalAccount() string {
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

// dastFindingView is one finding as the CLI prints it.
type dastFindingView struct {
	Rule       string   `json:"rule"`
	Title      string   `json:"title"`
	Severity   string   `json:"severity"`
	Confidence string   `json:"confidence"`
	CWE        []string `json:"cwe,omitempty"`
	Evidence   string   `json:"evidence"`
	Message    string   `json:"message"`
	FixHint    string   `json:"fix_hint"`
	LocalKey   string   `json:"local_key"`
}

// dastReportView is the --json shape.
type dastReportView struct {
	Target   string               `json:"target"`
	Outcome  string               `json:"outcome"`
	Requests int                  `json:"requests"`
	Checks   int                  `json:"checks"`
	Errors   []secdast.ProbeError `json:"errors,omitempty"`
	Findings []dastFindingView    `json:"findings"`
	// Stored: the run was recorded against StoredProject (its directory
	// name); New counts the findings it saw for the first time.
	Stored        bool   `json:"stored"`
	StoredProject string `json:"stored_project,omitempty"`
	New           int    `json:"new,omitempty"`
}

// dastRecorder stores a run against a project; the zero value prints only.
type dastRecorder struct {
	root   string
	record func(ctx context.Context, r dastRun) (int, error)
}

// runDAST is THE CLI run seam: the lane's run (runDASTLane), the record
// when there is a project, then the report.
func runDAST(ctx context.Context, w io.Writer, t secdast.Target, opts secdastnet.Options, asJSON bool, now time.Time, rec dastRecorder) error {
	run, err := runDASTLane(ctx, t, opts, now)
	if err != nil {
		return err
	}
	rep, findings := run.Report, run.Findings
	view := dastReportView{Target: rep.Target, Outcome: rep.Outcome, Requests: run.RoundTrips, Checks: rep.Checks, Errors: rep.Errors, Findings: dastViews(findings)}
	if rec.record != nil {
		created, err := rec.record(ctx, run)
		if err != nil {
			return err
		}
		view.StoredProject, view.Stored, view.New = filepath.Base(rec.root), true, created
	}
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(view); err != nil {
			return err
		}
	} else {
		printDASTReport(w, view)
	}
	if rep.Outcome == secdast.OutcomeUnreachable {
		reason := ""
		if len(rep.Errors) > 0 {
			reason = ": " + rep.Errors[0].Error
		}
		return fmt.Errorf("the dev server at %s did not answer%s; nothing was checked", t.String(), reason)
	}
	return nil
}

func dastViews(fs []secfinding.Finding) []dastFindingView {
	out := make([]dastFindingView, 0, len(fs))
	for _, f := range fs {
		title := f.Rule.ID
		if row, ok := secdast.CheckByID(f.Rule.ID); ok {
			title = row.Title
		}
		out = append(out, dastFindingView{
			Rule: f.Rule.ID, Title: title, Severity: string(f.Severity), Confidence: string(f.Confidence),
			CWE: f.References.CWE, Evidence: f.EvidenceRedacted, Message: f.Message, FixHint: f.FixHint, LocalKey: f.LocalKey,
		})
	}
	return out
}

func printDASTReport(w io.Writer, v dastReportView) {
	fmt.Fprintf(w, "DAST %s: %s, %d requests, %d checks\n", v.Target, v.Outcome, v.Requests, v.Checks)
	for _, e := range v.Errors {
		fmt.Fprintf(w, "  no answer for %s (%s): %s\n", e.Probe, e.Path, e.Error)
	}
	if v.Outcome == secdast.OutcomeUnreachable {
		return
	}
	if len(v.Findings) == 0 {
		fmt.Fprintln(w, "  no finding from the passive checks (they cover headers, cookies, CORS and exposed files, not your app's logic)")
		return
	}
	for _, f := range v.Findings {
		fmt.Fprintf(w, "\n  [%s] %s (%s)\n    %s\n    %s\n    fix: %s\n", f.Severity, f.Title, f.Rule, f.Evidence, f.Message, f.FixHint)
	}
	if v.Stored {
		fmt.Fprintf(w, "\n%d findings, flag only, stored against %s (%d new); see Code security > Findings.\n", len(v.Findings), v.StoredProject, v.New)
		return
	}
	fmt.Fprintf(w, "\n%d findings, flag only (printed, not stored).\n", len(v.Findings))
}

// dastToken is the 404 probe's random path part.
func dastToken() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// runDASTCandidates lists the dev-server URLs a project's own files name
// (secdast.ProjectCandidates: .claude/launch.json, package.json scripts,
// framework config files), each marked listening where the kernel's listen
// table says so (Linux). Nothing is contacted.
func runDASTCandidates(w io.Writer, project string, asJSON bool) error {
	if project == "" {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		project = wd
	}
	if root, ok := git.FindRoot(project); ok {
		project = root
	}
	cands := dastProjectCandidates(project)
	if cands == nil {
		cands = []secdast.Candidate{}
	}
	if asJSON {
		return json.NewEncoder(w).Encode(map[string]any{"project": project, "candidates": cands})
	}
	if len(cands) == 0 {
		fmt.Fprintf(w, "No dev server found in %s's files (.claude/launch.json, package.json scripts, framework configs).\n", project)
		return nil
	}
	for _, c := range cands {
		state := ""
		switch c.Listening {
		case "yes":
			state = "  [listening]"
		case "no":
			state = "  [not listening]"
		}
		fmt.Fprintf(w, "%s  %s (%s)%s\n", c.URL, c.Name, c.Source, state)
	}
	return nil
}
