package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/marmutapp/superbased-observer/internal/cloudagents"
	"github.com/marmutapp/superbased-observer/internal/cloudagentssvc"
)

// newCloudAgentsCmd is the CLI twin of Settings > Cloud agents
// (docs/cloud-agents.md): link the cloud-agent accounts whose sessions
// Observer pulls, see per-signal coverage, sync now, unlink. Every verb
// works on this machine's database; the first-wave connectors use the
// vendor CLI's own login (codex, gh), so Observer stores no credential.
func newCloudAgentsCmd() *cobra.Command {
	var configPath string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "cloud-agents",
		Short: cloudAgentsShort(),
		Long:  cloudAgentsLong(),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCloudAgentsStatus(cmd, configPath, jsonOut)
		},
	}
	cmd.PersistentFlags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print the page model as JSON")

	status := &cobra.Command{
		Use:   "status",
		Short: "Show linked accounts and what each one covers (the default)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCloudAgentsStatus(cmd, configPath, jsonOut)
		},
	}
	status.Flags().BoolVar(&jsonOut, "json", false, "print the page model as JSON")
	cmd.AddCommand(status, newCloudAgentsConnectCmd(&configPath), newCloudAgentsTestCmd(&configPath),
		newCloudAgentsSyncCmd(&configPath), newCloudAgentsDisconnectCmd(&configPath),
		newCloudAgentsUsersCmd(&configPath), newCloudAgentsChooseUserCmd(&configPath))
	return cmd
}

func withCloudAgents(cmd *cobra.Command, configPath string, fn func(*cloudagentssvc.Service) error) error {
	cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
	if err != nil {
		return err
	}
	defer cleanup()
	return fn(newCloudAgentsService(cfg, database, newLogger(cfg.Observer.LogLevel)))
}

func connectorIDs() string {
	ids := make([]string, 0, len(cloudagents.Connectors))
	for _, c := range cloudagents.Connectors {
		ids = append(ids, c.ID)
	}
	return strings.Join(ids, ", ")
}

// apiConnectorIDs lists the connectors that take a pasted API key, in table
// order.
func apiConnectorIDs() string {
	var ids []string
	for _, c := range cloudagents.Connectors {
		if c.Kind == cloudagents.SourceAPI {
			ids = append(ids, c.ID)
		}
	}
	return strings.Join(ids, ", ")
}

// cloudAgentsShort is the one-line help of `observer cloud-agents`. It
// names every connector from the connector table, so a connector added
// later is named without editing the help.
func cloudAgentsShort() string {
	labels := make([]string, 0, len(cloudagents.Connectors))
	for _, c := range cloudagents.Connectors {
		labels = append(labels, c.Label)
	}
	return "Pull your cloud agent sessions (" + strings.Join(labels, ", ") + ") into Observer"
}

// cloudAgentsCredentialNote says, per source kind, what a connector of that
// kind uses to reach the vendor (one row per kind; a kind with no row says
// nothing rather than guess).
var cloudAgentsCredentialNote = map[cloudagents.SourceKind]func(cloudagents.Connector) string{
	cloudagents.SourceCLI: func(c cloudagents.Connector) string {
		return "runs your own `" + c.Command + "` with its login; Observer stores no credential"
	},
	cloudagents.SourceAPI: func(cloudagents.Connector) string {
		return "an API key you paste at `connect`"
	},
}

// cloudAgentsLong is the long help of `observer cloud-agents`: one line per
// row of the connector table (id, label, how it reaches the vendor), so the
// help cannot fall behind the table.
func cloudAgentsLong() string {
	width := 0
	for _, c := range cloudagents.Connectors {
		width = max(width, len(c.ID))
	}
	var b strings.Builder
	b.WriteString("Lists the cloud-agent sessions of accounts you link, beside your local sessions.\n")
	b.WriteString("Nothing is pulled until you connect an account.\n\nConnectors:\n")
	for _, c := range cloudagents.Connectors {
		line := fmt.Sprintf("  %-*s  %s", width, c.ID, c.Label)
		if note, ok := cloudAgentsCredentialNote[c.Kind]; ok {
			line += ": " + note(c)
		}
		b.WriteString(line + "\n")
	}
	b.WriteString("\nAn API key is read without echo (or as one line from stdin) and kept in the\n")
	b.WriteString("OS keychain only; it is never a flag.")
	return b.String()
}

func runCloudAgentsStatus(cmd *cobra.Command, configPath string, jsonOut bool) error {
	return withCloudAgents(cmd, configPath, func(svc *cloudagentssvc.Service) error {
		v, err := svc.Status(cmd.Context())
		if err != nil {
			return err
		}
		out := cmd.OutOrStdout()
		if jsonOut {
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			return enc.Encode(v)
		}
		printCloudAgentsView(out, v)
		return nil
	})
}

func printCloudAgentsView(w io.Writer, v cloudagentssvc.View) {
	if len(v.Accounts) == 0 {
		_, _ = fmt.Fprintf(w, "No cloud-agent account linked. Nothing is pulled.\nConnect one with `observer cloud-agents connect <connector>` (%s).\n", connectorIDs())
		printConnectorLevels(w, v.Connectors)
		return
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	// OPEN counts sessions still running; WAITING live sessions waiting for
	// the user; OWED finished sessions the next pass still has to re-read (a
	// detail read or a run stream).
	_, _ = fmt.Fprintln(tw, "ID\tCONNECTOR\tACCOUNT\tCOVERAGE\tLAST ERROR\tLAST SUCCESS\tOPEN\tWAITING\tOWED\tGAPS")
	for _, a := range v.Accounts {
		acct := terminalSafe(a.AccountID)
		if a.Display != "" {
			acct = terminalSafe(a.Display) + " (" + acct + ")"
		}
		last := "never"
		if a.LastSuccess != nil {
			last = a.LastSuccess.Local().Format(time.DateTime)
		}
		errc := a.LastError
		if errc == "" {
			errc = "-"
		}
		_, _ = fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\n", a.ID, a.Connector, acct, a.Coverage.Label(), errc, last, a.OpenTasks, a.Waiting, a.Owed, len(a.Gaps))
	}
	_ = tw.Flush()
	for _, a := range v.Accounts {
		_, _ = fmt.Fprintf(w, "\n%s (account %d):\n", a.Label, a.ID)
		if c, ok := connectorInfo(v.Connectors, a.Connector); ok {
			printGrounding(w, c)
			printVendorUser(w, a, c.UserLabel)
		}
		for _, s := range a.Signals {
			_, _ = fmt.Fprintf(w, "  %-10s %s\n", s.Signal, s.Label)
		}
		for _, g := range a.Gaps {
			what := "discovery"
			if g.Scope != "" {
				what = g.Scope + " (stream expired; the run's final state stands)"
			}
			_, _ = fmt.Fprintf(w, "  gap: %s .. %s not covered: %s\n", g.From.Local().Format(time.DateTime), g.To.Local().Format(time.DateTime), what)
		}
	}
}

// connectorInfo finds a connector in the page model's catalog.
func connectorInfo(cs []cloudagentssvc.ConnectorInfo, id string) (cloudagentssvc.ConnectorInfo, bool) {
	for _, c := range cs {
		if c.ID == id {
			return c, true
		}
	}
	return cloudagentssvc.ConnectorInfo{}, false
}

// printGrounding prints a connector's coverage level (CA-D17) and, below
// the best level, what it means.
func printGrounding(w io.Writer, c cloudagentssvc.ConnectorInfo) {
	_, _ = fmt.Fprintf(w, "  %-10s %s\n", "level", c.GroundingLabel)
	if c.GroundingRank > 0 && c.GroundingMeaning != "" {
		_, _ = fmt.Fprintf(w, "  %-10s %s\n", "", c.GroundingMeaning)
	}
}

// printConnectorLevels lists every connector with its coverage level.
func printConnectorLevels(w io.Writer, cs []cloudagentssvc.ConnectorInfo) {
	if len(cs) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "\nConnectors and their coverage level:")
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	for _, c := range cs {
		_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\n", c.ID, c.Label, c.GroundingLabel)
	}
	_ = tw.Flush()
}

func printProbe(w io.Writer, r cloudagentssvc.ProbeResult) {
	if r.OK {
		// The account id and display come from a vendor response: never
		// let one write a control or bidi character to the terminal.
		who := terminalSafe(r.AccountID)
		if r.Display != "" {
			who = terminalSafe(r.Display) + " (" + who + ")"
		}
		_, _ = fmt.Fprintf(w, "%s: reachable as %s\n", r.Connector, who)
		return
	}
	_, _ = fmt.Fprintf(w, "%s: not usable (%s): coverage %s\n", r.Connector, r.ErrorClass, r.Coverage.Label())
	if hint := probeHint(r); hint != "" {
		_, _ = fmt.Fprintln(w, hint)
	}
}

// probeHints is the fix the CLI prints for each failure class.
var probeHints = map[cloudagents.ErrorClass]map[string]string{
	cloudagents.ErrNotInstalled: {
		cloudagents.ConnectorCodexCloud:   "Install the Codex CLI (npm i -g @openai/codex) and run `codex login`.",
		cloudagents.ConnectorCopilotAgent: "Install GitHub CLI 2.80 or newer (`gh agent-task` is required) and run `gh auth login`.",
	},
	cloudagents.ErrNotSignedIn: {
		cloudagents.ConnectorCodexCloud:     "Run `codex login` (sign in with ChatGPT), then try again.",
		cloudagents.ConnectorCopilotAgent:   "Run `gh auth login`, then try again.",
		cloudagents.ConnectorCursorCloud:    "Cursor refused the key. Create a user API key at cursor.com Dashboard > API Keys (User API Keys, Add), then connect again.",
		cloudagents.ConnectorDevin:          "Devin refused the token. Create a personal access token or service-user key, then connect again.",
		cloudagents.ConnectorOpenHandsCloud: "OpenHands refused the key. Use the Cloud API key (Settings > API Keys), not the LLM key.",
		cloudagents.ConnectorWarpCloud:      "Warp refused the key. Create a Personal API key in the Warp app (Settings > Platform > API Keys, or `oz api-key create`), then connect again.",
		cloudagents.ConnectorQoderCloud:     "Qoder refused the token. Create a personal access token in your Qoder account settings (access tokens; the token the Cloud Agents SDK reads as QODER_ACCESS_TOKEN), and check the region: an account in China uses --region cn.",
		cloudagents.ConnectorClineCloud:     "Cline refused the key. Create an API key at app.cline.bot (Account > API Keys), then connect again.",
	},
	cloudagents.ErrPermissionDenied: {
		cloudagents.ConnectorCodexCloud:     "Codex Cloud is not available to this account (plan or workspace setting).",
		cloudagents.ConnectorCopilotAgent:   "The Copilot cloud agent is not available to this account.",
		cloudagents.ConnectorCursorCloud:    "Cloud Agents are not available to this key (Free and Plus plans do not include them).",
		cloudagents.ConnectorDevin:          "The token cannot list this organization's sessions (ViewOrgSessions), or the organization id is wrong.",
		cloudagents.ConnectorOpenHandsCloud: "The key cannot read conversations.",
		cloudagents.ConnectorWarpCloud:      "The key cannot list agent runs (a team's Agent key sees only its team; use a Personal key for your own runs).",
		cloudagents.ConnectorQoderCloud:     "The token cannot list Cloud Agents sessions. Cloud Agents may not be on this plan (it is listed for Teams and Enterprise), or a new account has no environment yet.",
		cloudagents.ConnectorClineCloud:     "This Cline account cannot list cloud sessions (Cloud sessions are rolling out, and need a GitHub connection at app.cline.bot).",
	},
	// A vendor 5xx: the network and the key are fine (live 2026-11-01: one
	// Cursor 500 read as "unreachable" made the network look down).
	cloudagents.ErrServerError: {
		cloudagents.ConnectorCursorCloud:    "Cursor returned a server error (HTTP 5xx). Your network and key are fine; try again in a minute.",
		cloudagents.ConnectorDevin:          "Devin returned a server error (HTTP 5xx). Your network and token are fine; try again in a minute.",
		cloudagents.ConnectorOpenHandsCloud: "OpenHands returned a server error (HTTP 5xx). Your network and key are fine; try again in a minute.",
		cloudagents.ConnectorWarpCloud:      "Warp returned a server error (HTTP 5xx). Your network and key are fine; try again in a minute.",
		cloudagents.ConnectorQoderCloud:     "Qoder returned a server error (HTTP 5xx). Your network and token are fine; try again in a minute.",
		cloudagents.ConnectorClineCloud:     "Cline returned a server error (HTTP 5xx). Your network and key are fine; try again in a minute.",
	},
}

func probeHint(r cloudagentssvc.ProbeResult) string { return classHint(r.ErrorClass, r.Connector) }

// classHint is the fix the CLI prints for a failure class on a connector.
func classHint(class cloudagents.ErrorClass, connector string) string {
	return probeHints[class][connector]
}

// cloudAgentsParamFlags are the non-secret connection parameters a connect
// or test command takes as flags.
type cloudAgentsParamFlags struct {
	orgID  string
	region string
}

// paramFlagName maps a connector parameter to its flag.
var paramFlagName = map[string]string{cloudagents.ParamOrgID: "org-id", cloudagents.ParamRegion: "region"}

func addParamFlags(c *cobra.Command, f *cloudAgentsParamFlags) {
	c.Flags().StringVar(&f.orgID, "org-id", "", "Devin organization id, org-<32 hex> (devin only; not a secret)")
	c.Flags().StringVar(&f.region, "region", "", "API region, one of the connector's listed choices (qoder-cloud: global or cn); asked for when omitted on a terminal")
}

// cloudAgentsPick asks for a picker parameter on a terminal: the choices are
// numbered and the answer is a number, never free text. Off a terminal the
// flag is required.
var cloudAgentsPick = func(in io.Reader, prompt io.Writer, p cloudagents.ParamSpec) (string, error) {
	f, ok := in.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) { //nolint:gosec // G115: a descriptor number
		return "", errors.New("not a terminal, so pass the flag")
	}
	return pickChoice(bufio.NewReader(f), prompt, p)
}

// pickChoice prints a parameter's numbered choices and reads one number.
func pickChoice(r *bufio.Reader, prompt io.Writer, p cloudagents.ParamSpec) (string, error) {
	_, _ = fmt.Fprintf(prompt, "%s:\n", p.Label)
	for i, ch := range p.Choices {
		_, _ = fmt.Fprintf(prompt, "  %d) %s (%s)\n", i+1, ch.Label, ch.Value)
	}
	_, _ = fmt.Fprintf(prompt, "Pick 1-%d: ", len(p.Choices))
	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	n, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || n < 1 || n > len(p.Choices) {
		return "", errors.New("no listed choice was picked")
	}
	return p.Choices[n-1].Value, nil
}

// cloudAgentsReadKey reads an API connector's key: without echo from a
// terminal, else one line from stdin. A key never comes from a flag or an
// environment variable, so it lands in no shell history, process listing or
// log.
var cloudAgentsReadKey = func(in io.Reader, prompt io.Writer, label string) (string, error) {
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) { //nolint:gosec // G115: a descriptor number
		_, _ = fmt.Fprintf(prompt, "Paste your %s (not shown): ", label)
		b, err := term.ReadPassword(int(f.Fd())) //nolint:gosec // G115: a descriptor number
		_, _ = fmt.Fprintln(prompt)
		return string(b), err
	}
	line, err := bufio.NewReader(io.LimitReader(in, 8192)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return line, nil
}

// cloudAgentsCredentials gathers what connecting a connector takes: for an
// API connector the key (read here) and its declared parameters (flags);
// for a CLI connector nothing.
func cloudAgentsCredentials(cmd *cobra.Command, connector string, flags cloudAgentsParamFlags) (cloudagentssvc.Credentials, error) {
	c, ok := cloudagents.ConnectorByID(connector)
	if !ok {
		return cloudagentssvc.Credentials{}, fmt.Errorf("cloud-agents: unknown connector %q (connectors: %s)", connector, connectorIDs())
	}
	params := map[string]string{}
	for name, v := range map[string]string{cloudagents.ParamOrgID: flags.orgID, cloudagents.ParamRegion: flags.region} {
		if v != "" {
			params[name] = v
		}
	}
	if c.Kind != cloudagents.SourceAPI {
		if len(params) > 0 {
			return cloudagentssvc.Credentials{}, fmt.Errorf("cloud-agents: %s takes no --org-id or --region", connector)
		}
		return cloudagentssvc.Credentials{}, nil
	}
	for _, p := range c.Params {
		if strings.TrimSpace(params[p.Name]) != "" {
			continue
		}
		if len(p.Choices) > 0 {
			v, err := cloudAgentsPick(cmd.InOrStdin(), cmd.ErrOrStderr(), p)
			if err != nil {
				return cloudagentssvc.Credentials{}, fmt.Errorf("cloud-agents: %s needs --%s (%s: %s): %w", connector, paramFlagName[p.Name], p.Label, p.Hint, err)
			}
			params[p.Name] = v
			continue
		}
		return cloudagentssvc.Credentials{}, fmt.Errorf("cloud-agents: %s needs --%s (%s: %s)", connector, paramFlagName[p.Name], p.Label, p.Hint)
	}
	key, err := cloudAgentsReadKey(cmd.InOrStdin(), cmd.ErrOrStderr(), c.KeyLabel)
	if err != nil {
		return cloudagentssvc.Credentials{}, fmt.Errorf("cloud-agents: reading the key: %w", err)
	}
	return cloudagentssvc.Credentials{Key: key, Params: params}, nil
}

func newCloudAgentsTestCmd(configPath *string) *cobra.Command {
	var pf cloudAgentsParamFlags
	c := &cobra.Command{
		Use:   "test <connector>",
		Short: "Check that a connector can reach your account, without linking it",
		Long: "Runs the connector's probe and links nothing. An API connector (" + apiConnectorIDs() + ")\n" +
			"asks for its key without echo, or reads one line from stdin; the key is used\n" +
			"for the probe and then forgotten.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cred, err := cloudAgentsCredentials(cmd, args[0], pf)
			if err != nil {
				return err
			}
			return withCloudAgents(cmd, *configPath, func(svc *cloudagentssvc.Service) error {
				r, err := svc.TestWith(cmd.Context(), args[0], cred)
				if err != nil {
					return fmt.Errorf("%w (connectors: %s)", err, connectorIDs())
				}
				printProbe(cmd.OutOrStdout(), r)
				return nil
			})
		},
	}
	addParamFlags(c, &pf)
	return c
}

func newCloudAgentsConnectCmd(configPath *string) *cobra.Command {
	var noSync bool
	var pf cloudAgentsParamFlags
	c := &cobra.Command{
		Use:   "connect <connector>",
		Short: "Link a cloud-agent account and pull its sessions",
		Long: "Checks the connector can reach your account, links it, and runs a first\n" +
			"sync. Connectors: " + connectorIDs() + ".\n\n" +
			"  observer cloud-agents connect codex-cloud     # uses your `codex login`\n" +
			"  observer cloud-agents connect copilot-agent   # uses your `gh auth login`\n" +
			"  observer cloud-agents connect cursor-cloud    # asks for your Cursor API key\n" +
			"  observer cloud-agents connect devin --org-id org-<32 hex>  # then pick your Devin user\n" +
			"  observer cloud-agents connect openhands-cloud # asks for your OpenHands Cloud API key, then your OpenHands user\n" +
			"  observer cloud-agents connect warp-cloud      # asks for your Warp API key, then your Warp user\n" +
			"  observer cloud-agents connect qoder-cloud --region global  # asks for your Qoder access token\n" +
			"  observer cloud-agents connect cline-cloud     # asks for your Cline API key\n\n" +
			"An API key is read without echo (or as one line from stdin), checked against\n" +
			"the vendor, then stored in the OS keychain only; it is never a flag.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cred, err := cloudAgentsCredentials(cmd, args[0], pf)
			if err != nil {
				return err
			}
			return withCloudAgents(cmd, *configPath, func(svc *cloudagentssvc.Service) error {
				r, av, err := svc.ConnectWith(cmd.Context(), args[0], cred)
				if err != nil {
					return fmt.Errorf("%w (connectors: %s)", err, connectorIDs())
				}
				out := cmd.OutOrStdout()
				printProbe(out, r)
				if av == nil {
					return fmt.Errorf("cloud-agents: %s was not linked", args[0])
				}
				_, _ = fmt.Fprintf(out, "linked as account %d\n", av.ID)
				if c, ok := connectorInfo(cloudagentssvc.Catalog(), args[0]); ok && c.GroundingRank > 0 {
					_, _ = fmt.Fprintf(out, "coverage level: %s. %s\n", c.GroundingLabel, c.GroundingMeaning)
				}
				if av.UserState == cloudagents.VendorUserNotChosen {
					// A key that lists other people's sessions (Devin,
					// OpenHands, Warp): nothing is pulled until the
					// developer names their own user (CLOUDAGENTS-6).
					// The account is linked either way; a failed listing
					// leaves the choice for later, never a pull of everyone.
					if _, err := chooseVendorUser(cmd, svc, av.ID, ""); err != nil {
						_, _ = fmt.Fprintf(out, "%v; pick your user later: observer cloud-agents choose-user %d\n", err, av.ID)
					}
				}
				if noSync {
					return nil
				}
				res, err := svc.SyncAccount(cmd.Context(), av.ID)
				printSyncResult(out, res)
				return syncErr(err)
			})
		},
	}
	c.Flags().BoolVar(&noSync, "no-sync", false, "link only; the daemon pulls on its next tick")
	addParamFlags(c, &pf)
	return c
}

func newCloudAgentsSyncCmd(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "sync [account-id]",
		Short: "Pull now (every linked account, or one)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withCloudAgents(cmd, *configPath, func(svc *cloudagentssvc.Service) error {
				out := cmd.OutOrStdout()
				if len(args) == 1 {
					id, err := strconv.ParseInt(args[0], 10, 64)
					if err != nil {
						return fmt.Errorf("cloud-agents: account id %q is not a number (see `observer cloud-agents status`)", args[0])
					}
					res, err := svc.SyncAccount(cmd.Context(), id)
					if err == nil || cloudagentssvc.IsCollectionError(err) {
						printSyncResult(out, res)
					}
					return syncErr(err)
				}
				rs, err := svc.SyncAll(cmd.Context())
				if len(rs) == 0 && err == nil {
					_, _ = fmt.Fprintln(out, "No cloud-agent account linked. Nothing pulled.")
				}
				for _, r := range rs {
					printSyncResult(out, r)
				}
				return err
			})
		},
	}
}

// syncErr turns a recorded vendor-side failure into a short CLI error (the
// class, never vendor text); a local error passes through.
func syncErr(err error) error {
	if err == nil {
		return nil
	}
	if cloudagentssvc.IsCollectionError(err) {
		return fmt.Errorf("cloud-agents: sync failed (%s)", cloudagents.ClassOf(err))
	}
	return err
}

func printSyncResult(w io.Writer, r cloudagentssvc.SyncResult) {
	if r.UserState == cloudagents.VendorUserNotChosen {
		_, _ = fmt.Fprintf(w, "account %d (%s): no user chosen, nothing pulled. This key lists other people's sessions too; pick your own user: observer cloud-agents choose-user %d\n", r.AccountID, r.Connector, r.AccountID)
		return
	}
	if r.ErrorClass != "" {
		_, _ = fmt.Fprintf(w, "account %d (%s): failed (%s), coverage %s\n", r.AccountID, r.Connector, r.ErrorClass, r.Coverage.Label())
		if hint := classHint(r.ErrorClass, r.Connector); hint != "" {
			_, _ = fmt.Fprintln(w, "  "+hint)
		}
		return
	}
	partial := ""
	if r.Partial {
		partial = ", older history not reached"
	}
	// "re-read" counts a CLI connector's per-task views; an API connector
	// re-reads through its detail calls, counted on the next line.
	views := ""
	if c, ok := cloudagents.ConnectorByID(r.Connector); ok && c.Kind == cloudagents.SourceCLI {
		views = fmt.Sprintf(", %d re-read", r.Views)
	}
	_, _ = fmt.Fprintf(w, "account %d (%s): %d task(s) in %d page(s)%s, %d session(s) touched, %d new action(s), %d still running%s%s\n",
		r.AccountID, r.Connector, r.Tasks, r.Pages, views, r.SessionsNew, r.ActionsNew, r.OpenTasks, waitingNote(r.Waiting), partial)
	if r.Details+r.HistoryPages+r.Streams+r.DetailPending > 0 {
		_, _ = fmt.Fprintf(w, "  %d detail read(s), %d history page(s), %d run stream(s), %d session(s) left for the next pass\n",
			r.Details, r.HistoryPages, r.Streams, r.DetailPending)
	}
	if r.Owed > 0 {
		_, _ = fmt.Fprintf(w, "  %d finished session(s) still owed a read (a run stream or detail over this pass's budget): read on the next pass\n", r.Owed)
	}
	if r.StreamGaps > 0 {
		_, _ = fmt.Fprintf(w, "  %d run stream(s) could not be resumed: recorded as gaps (the run's final state stands)\n", r.StreamGaps)
	}
	if r.RepositoryNotReported > 0 {
		_, _ = fmt.Fprintf(w, "  %d task(s) filed under %s: %s\n",
			r.RepositoryNotReported, cloudagents.PlaceholderRoot(r.Connector), cloudagents.NoteRepositoryNotReported)
	}
	if n := r.SkippedOtherMember + r.SkippedServiceUser + r.SkippedNoUser; n > 0 {
		_, _ = fmt.Fprintf(w, "  %d session(s) not yours skipped (%d another member's, %d a service user's, %d naming no user): nothing of theirs was stored\n",
			n, r.SkippedOtherMember, r.SkippedServiceUser, r.SkippedNoUser)
	}
	if r.PurgedOtherMember > 0 {
		_, _ = fmt.Fprintf(w, "  %d session(s) pulled earlier that another member or a service user started were removed\n", r.PurgedOtherMember)
	}
	if r.PurgedLedgerOnly > 0 {
		_, _ = fmt.Fprintf(w, "  %d ledger row(s) of runs another member or a service account started (no session was written for them) were removed\n", r.PurgedLedgerOnly)
	}
	if r.NoToolRows > 0 {
		_, _ = fmt.Fprintf(w, "  %d task(s) ran under a harness with no Observer tool (Warp's own oz): their usage is in the ledger only, no session was written\n", r.NoToolRows)
	}
}

func newCloudAgentsDisconnectCmd(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "disconnect <account-id>",
		Short: "Unlink an account (its pulled sessions stay; collection stops)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("cloud-agents: account id %q is not a number (see `observer cloud-agents status`)", args[0])
			}
			return withCloudAgents(cmd, *configPath, func(svc *cloudagentssvc.Service) error {
				if err := svc.Disconnect(cmd.Context(), id); err != nil {
					return err
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "account %d unlinked; its sessions stay in Observer\n", id)
				return nil
			})
		},
	}
}

// waitingNote is the sync line's mention of sessions waiting for the user
// ("" when none, so a connector that never reports one reads as before).
func waitingNote(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(", %d waiting for the user", n)
}
