package main

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/attachrule"
	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/frontdoor"
	"github.com/marmutapp/superbased-observer/internal/managedconfig"
	"github.com/marmutapp/superbased-observer/internal/pairing"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// connect.go is the node's front door (managed SaaS plan 06 section 19.3;
// plan 07 M8.4): `observer connect [<server>]` runs two existing owners in
// sequence, never a merged protocol of its own.
//
//  1. Identity (owner: `observer cloud login`, internal/cloudcred), only
//     for --identity-only. Signing in never moves data (rule 1).
//  2. Attach (owner: `observer enroll`, the one enrolment sequence in
//     orgenrol_core.go), against the given server or the one company
//     config pre-sets. A pairing code from SBO_PAIR_CODE or --pair-file is
//     handed to enroll on its standard input (never an argument); with no
//     code, enroll signs in through the organization's device code (--idp).
//
// Before either runs, internal/attachrule's precedence table decides the
// request (rows 1-10: a lock, identity only, a switch that needs the old
// organization named, a refusal). Afterwards the command prints the one
// sentence internal/frontdoor builds, the same one `observer status` and the
// dashboard's Connect card show.
//
// Discovery (connect with no server and no company pre-set, rows 7-9, M8.7)
// signs in first when needed, lists the organizations the control plane knows
// for the signed-in account, and offers one, a chooser, or the personal org
// (connect_discover.go). It rides the existing cloud lanes through the consent
// gateway's Bootstrap family (D-IND-2, ledger row IND-2); no new network
// package. A build without Cloud Intelligence asks for the organization's
// address instead (row 9's "Enter its address").

// connectDeps are the command's seams.
type connectDeps struct {
	// attachPolicy reads the company-managed attach policy.
	attachPolicy func() managedconfig.AttachResult
	// loadEnrolment reads this machine's enrolment (nil when none).
	loadEnrolment func(ctx context.Context, configPath string) (*store.Enrolment, error)
	// identity reads the local SuperBased sign-in state.
	identity func(configPath string) frontdoor.Identity
	// runIdentity runs the identity owner (`observer cloud login`).
	runIdentity func(cmd *cobra.Command, args []string) error
	// runEnroll runs the attach owner (`observer enroll`) with args and
	// stdin.
	runEnroll func(cmd *cobra.Command, args []string, stdin io.Reader) error
	// getenv and readFile feed the pairing-code hand-off.
	getenv   func(string) string
	readFile func(string) ([]byte, error)
	// confirm asks a yes/no question on the terminal (rows 4, 7, 9).
	confirm func(cmd *cobra.Command, question string) bool
	// listOrgs and ensurePersonal are discovery (rows 7-9); both nil in a
	// build without Cloud Intelligence. Never called when a server or a
	// company pre-set is given (rule 4).
	listOrgs       func(ctx context.Context, o connectCloudOpts) (cloudcontract.DeviceOrgList, error)
	ensurePersonal func(ctx context.Context, o connectCloudOpts) (cloudcontract.EnsurePersonalOrgResponse, error)
	// sleep waits between polls for a new org to be ready.
	sleep func(ctx context.Context, d time.Duration) error
	// isTerminal reports an interactive terminal (row 8's chooser).
	isTerminal func(cmd *cobra.Command) bool
	// ask prints a question and reads one line (row 8's chooser).
	ask func(cmd *cobra.Command, question string) string
	// request is the connect request (Getting started v2, contract A):
	// connect with no address, or with a team name. All nil in a build
	// without Cloud Intelligence, and in older tests, which then take the
	// discovery rows above.
	request connectRequestSeams
	// openURL opens the approval page; hasBrowser reports whether one can.
	openURL    func(string)
	hasBrowser func() bool
	// hostname names this machine on the approval page.
	hostname func() (string, error)
	// recordConsent keeps this machine's copy of an approval.
	recordConsent func(configPath string, rec connectConsentRecord) error
	// recordConnection keeps the connection's display name and online
	// address with the enrolment it just made (store.SetEnrolmentConnection,
	// agent migration 255), for the local status after a restart. nil
	// records nothing.
	recordConnection func(ctx context.Context, configPath, orgID, displayName, onlineURL string) error
	// dashboardURL is the local dashboard's address for the closing lines.
	dashboardURL func(configPath string) string
}

func defaultConnectDeps() connectDeps {
	disc := defaultConnectDiscovery()
	return connectDeps{
		attachPolicy:  managedconfig.LoadAttach,
		loadEnrolment: loadConnectEnrolment,
		identity:      connectIdentityState,
		runIdentity:   runConnectIdentity,
		runEnroll: func(cmd *cobra.Command, args []string, stdin io.Reader) error {
			return runSubcommand(cmd, newEnrollCmd(), args, stdin)
		},
		getenv:   os.Getenv,
		readFile: readPairFile,
		confirm:  confirmOnTTY,
		// Discovery (rows 7-9).
		listOrgs:       disc.listOrgs,
		ensurePersonal: disc.ensurePersonal,
		sleep:          connectSleep,
		isTerminal:     func(*cobra.Command) bool { return stdinIsTerminal() },
		ask:            askOnTTY,
		// Connect request (contract A).
		request:          defaultConnectRequestSeams(),
		openURL:          openBrowser,
		hasBrowser:       connectHasBrowser,
		hostname:         os.Hostname,
		recordConsent:    writeConnectConsent,
		recordConnection: recordConnectConnection,
		dashboardURL:     connectLocalDashboardURL,
	}
}

func newConnectCmd() *cobra.Command { return newConnectCmdWith(defaultConnectDeps()) }

// connectFlags are the flags connect passes through to its two owners.
type connectFlags struct {
	configPath       string
	pairFile         string
	identityOnly     bool
	statusOnly       bool
	yes              bool
	dropUnsent       bool
	acceptGovernance bool
	acceptIntel      bool
	writeBlock       bool
	wireClients      bool
	baseURL          string
	devToken         string
	// jsonOut prints contract B's progress lines; noBrowser prints the code
	// instead of opening a browser.
	jsonOut   bool
	noBrowser bool
}

func newConnectCmdWith(deps connectDeps) *cobra.Command {
	var f connectFlags
	cmd := &cobra.Command{
		Use:   "connect [<team> | <server>]",
		Short: "Sign in and connect this machine to your personal dashboard or a team",
		Long: `One step to see this machine online: sign in to your SuperBased account and
choose where this machine's data goes, in one browser approval.

observer connect
    Opens a browser page on cloud.superbased.app. Sign in, choose your
    personal dashboard (the default) or one of your teams, read what is
    shared, then Connect, or Not now to only sign in. Nothing is sent before
    you approve. With no browser (an SSH session, --no-browser), it prints a
    short code to enter at cloud.superbased.app/connect on any phone or computer.

observer connect <team>
    The same, with that team chosen on the approval page.

    Share levels: a personal dashboard gets a summary only. A team gets full
    detail (prompts, responses, file paths), and its admins can read it.
    Only activity from now on is sent; earlier sessions stay on this machine.

observer connect <server>
    Connect to your company's own server at <server>. With a pairing code
    (made on that server's install page), the code is read from the
    ` + pairing.EnvVar + ` environment variable or --pair-file; a code is never
    accepted on the command line. With no code, approve this machine by
    signing in with your company account in a browser on any phone or computer.

observer connect --status
    Print the one-sentence status and change nothing.

--json prints one JSON object per line (waiting_approval, approved,
attaching, connected, signed_in_only, error) for the dashboard and editor
extensions; it exits 0 on connected and signed_in_only.

Undo any time: observer disconnect. A machine locked by company
configuration connects only where that configuration says.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConnect(cmd, deps, f, args)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	fl.StringVar(&f.pairFile, "pair-file", "", "read a pairing code from this file (else "+pairing.EnvVar+")")
	fl.BoolVar(&f.identityOnly, "identity-only", false, "sign in to SuperBased only; never changes where data goes")
	fl.BoolVar(&f.statusOnly, "status", false, "print the one-sentence status and exit")
	fl.BoolVar(&f.yes, "yes", false, "confirm without a prompt: switching away from a company-managed destination, or the one team (or your personal dashboard) offered by discovery")
	fl.BoolVar(&f.dropUnsent, "drop-unsent", false, "switch even when rows still waiting for the current dashboard cannot be sent to it")
	fl.BoolVar(&f.acceptGovernance, "accept-governance", false, "accept a team's governance grant without a prompt")
	fl.BoolVar(&f.acceptIntel, "accept-intel-consent", false, "accept a team's AI summaries terms without a prompt")
	fl.BoolVar(&f.writeBlock, "write-block", true, "write a default [org_client] block to config.toml")
	fl.BoolVar(&f.wireClients, "wire-clients", true, "register hooks, MCP and proxy routing for detected AI clients")
	fl.StringVar(&f.baseURL, "base-url", "", "SuperBased cloud address for sign-in (else $SBO_CLOUD_BASE_URL, else [cloud].base_url)")
	fl.StringVar(&f.devToken, "dev-token", "", "dev token for sign-in in local testing (never stored)")
	fl.BoolVar(&f.jsonOut, "json", false, "print one JSON object per line instead of text (for the dashboard and editor extensions)")
	fl.BoolVar(&f.noBrowser, "no-browser", false, "print the code-entry page and a short code instead of opening a browser")
	return cmd
}

// connectPlan is what runConnect decided to do.
type connectPlan struct {
	identity bool
	server   string
	confirm  string // the old organization a switch must name, "" for none
}

// errConnectNeedsAddress is rows 7-9: no address and no company pre-set, so
// discovery decides (or, without Cloud Intelligence, the user names one).
var errConnectNeedsAddress = errors.New("no server address given")

func runConnect(cmd *cobra.Command, deps connectDeps, f connectFlags, args []string) error {
	out := cmd.OutOrStdout()
	ctx := cmd.Context()
	server, team, err := connectArgs(deps, args)
	if err != nil {
		return err
	}
	pol := deps.attachPolicy()
	enr, err := deps.loadEnrolment(ctx, f.configPath)
	if err != nil {
		return fmt.Errorf("observer connect: read this machine's connection: %w", err)
	}
	status := func() frontdoor.Status { return connectStatus(enr, pol, deps.identity(f.configPath)) }
	if f.statusOnly {
		fmt.Fprintln(out, status().Sentence)
		return nil
	}
	if f.identityOnly && (server != "" || team != "") {
		return errors.New("observer connect: --identity-only signs in only; it takes no server or team")
	}
	taken, err := pairing.Take(pairing.Handoff{Env: deps.getenv(pairing.EnvVar), PairFile: f.pairFile, ReadFile: deps.readFile})
	if err != nil {
		return err
	}
	if f.identityOnly && taken.Source != pairing.SourceNone {
		return errors.New("observer connect: --identity-only signs in only; unset " + pairing.EnvVar + " or drop --pair-file")
	}
	if team != "" && pol.Status == managedconfig.AttachStatusValid && pol.DefaultOrgURL() != "" {
		// Company configuration names the destination (rule 4): the team
		// name is not used, and SuperBased is never asked.
		fmt.Fprintln(cmd.ErrOrStderr(), "Company configuration sets where this machine connects; the team name is not used.")
		team = ""
	}
	plan, err := planConnect(pol, enr, f.identityOnly, server)
	if useRequest, rerr := connectUsesRequest(deps, f, pol, team, taken, err); rerr != nil || useRequest {
		if rerr != nil {
			return rerr
		}
		return runConnectRequest(cmd, deps, f, pol, enr, team)
	}
	if errors.Is(err, errConnectNeedsAddress) {
		if !connectDiscoveryAvailable(deps) {
			printConnectNeedsAddress(out, status())
			return nil
		}
		if taken.Source != pairing.SourceNone {
			return errors.New("observer connect: a pairing code belongs to one team; give its server address too: observer connect <server>")
		}
		target, derr := runConnectDiscovery(cmd, deps, f, pol, enr)
		if derr != nil || target == "" {
			return derr
		}
		plan, err = connectPlan{server: target}, nil
	}
	if err != nil {
		return err
	}
	if plan.confirm != "" && !f.yes {
		q := fmt.Sprintf("This machine is managed by %s. Switch it to %s? Rows still waiting for %s are sent there first; later activity goes to the new team.", plan.confirm, plan.server, plan.confirm)
		if !deps.confirm(cmd, q) {
			return fmt.Errorf("observer connect: not switched; this machine stays with %s (pass --yes to confirm without a prompt)", plan.confirm)
		}
	}
	if plan.identity {
		if err := deps.runIdentity(cmd, connectIdentityArgs(f)); err != nil {
			return err
		}
	} else if err := deps.runEnroll(cmd, connectEnrollArgs(f, plan.server, taken), connectEnrollStdin(taken)); err != nil {
		return err
	}
	if enr, err = deps.loadEnrolment(ctx, f.configPath); err == nil {
		fmt.Fprintf(out, "\nNow: %s\n", status().Sentence)
	}
	return nil
}

// connectArgs splits connect's one argument into a server address or, when
// this build can make a connect request, a bare team name (`observer connect
// acme`). A pairing code is refused as an argument.
func connectArgs(deps connectDeps, args []string) (server, team string, err error) {
	if len(args) == 0 {
		return "", "", nil
	}
	if err := pairing.RefuseArgument(args[0]); err != nil {
		return "", "", err
	}
	server = strings.TrimSpace(args[0])
	if isConnectTeamSlug(server) && connectRequestAvailable(deps) {
		return "", server, nil
	}
	return server, "", nil
}

// connectUsesRequest decides whether the connect request flow runs: a named
// team always asks the cloud (attachrule judges the approved target before
// anything is attached), and so does no address at all (rows 7-9) when this
// build can make a request. A pairing code belongs to one server, so it
// never goes with either.
func connectUsesRequest(deps connectDeps, f connectFlags, pol managedconfig.AttachResult, team string, taken pairing.Taken, planErr error) (bool, error) {
	byTeam := team != "" && !f.identityOnly && pol.Status != managedconfig.AttachStatusInvalid
	byDiscovery := errors.Is(planErr, errConnectNeedsAddress) && connectRequestAvailable(deps)
	if !byTeam && !byDiscovery {
		return false, nil
	}
	if taken.Source != pairing.SourceNone {
		return false, errors.New("observer connect: a pairing code belongs to one server; give its address: observer connect <server>")
	}
	return true, nil
}

// planConnect walks attachrule's table for the request. server "" is a
// connect with no address: the company pre-set when there is one, else the
// discovery rows.
func planConnect(pol managedconfig.AttachResult, enr *store.Enrolment, identityOnly bool, server string) (connectPlan, error) {
	if pol.Status == managedconfig.AttachStatusInvalid {
		return connectPlan{}, checkManagedAttach(pol, attachrule.Destination{}, attachrule.IntentAttach, server)
	}
	in := attachrule.Input{Current: currentDestination(enr), Lock: pol.Lock(), Intent: attachrule.IntentAttach}
	if identityOnly {
		in.Intent = attachrule.IntentIdentityOnly
	}
	if server == "" && !identityOnly {
		server = pol.DefaultOrgURL()
	}
	if server != "" && !identityOnly {
		in.Requested = managedconfig.OrgDestination(server, "")
	}
	d := attachrule.Decide(in)
	switch d.Outcome {
	case attachrule.OutcomeAllow, attachrule.OutcomeAllowWithConfirmation:
		if d.DestinationUnchanged {
			return connectPlan{identity: true}, nil
		}
		target := server
		if target == "" {
			target = d.Target.OrgID // row 1: the lock's own destination
		}
		p := connectPlan{server: target}
		if d.Outcome == attachrule.OutcomeAllowWithConfirmation {
			p.confirm = d.ConfirmOrgName
		}
		return p, nil
	case attachrule.OutcomeOfferCreatePersonal, attachrule.OutcomeOfferOne, attachrule.OutcomeShowChooser:
		return connectPlan{}, errConnectNeedsAddress
	case attachrule.OutcomeRefuse:
		return connectPlan{}, connectRefusal(pol, d, server)
	}
	return connectPlan{}, fmt.Errorf("observer connect: unsupported request (attach rule row %d)", d.Row)
}

// connectRefusal words a refusal. A lock reuses M8.6's refusal so the
// message is the one `observer enroll` gives.
func connectRefusal(pol managedconfig.AttachResult, d attachrule.Decision, server string) error {
	reason := attachrule.RefusalUnsupported
	if d.Refusal != nil {
		reason = d.Refusal.Reason
	}
	switch reason {
	case attachrule.RefusalLocked:
		r := &attachPolicyRefusal{intent: attachrule.IntentAttach, source: pol.Source, requested: server}
		r.lockOrg, r.askWho = d.Refusal.LockOrgName, d.Refusal.AskWho
		return r
	case attachrule.RefusalAlreadyAttached:
		return fmt.Errorf("observer connect: this machine is already connected to %s; run `observer connect <server>` to connect it again", server)
	case attachrule.RefusalPersonalOnManaged, attachrule.RefusalPolicyNoSecondDestination:
		return errors.New("observer connect: a company-managed machine cannot also send to a personal dashboard")
	}
	if server == "" {
		return errors.New("observer connect: this machine is connected to a team; name the server to switch to (observer connect <server>), or leave with `observer disconnect`")
	}
	return fmt.Errorf("observer connect: cannot connect to %s from here (attach rule row %d)", server, d.Row)
}

// printConnectNeedsAddress is rows 7-9 in a build without Cloud
// Intelligence: there is no SuperBased sign-in to find organizations from.
func printConnectNeedsAddress(out io.Writer, st frontdoor.Status) {
	fmt.Fprintln(out, st.Sentence+".")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "To connect this machine, give your team's server address:")
	fmt.Fprintln(out, "  observer connect https://<your-team>.superbased.app   (or your company's own server)")
	fmt.Fprintln(out, "Make a pairing code on that team's install page and set "+pairing.EnvVar+" first,")
	fmt.Fprintln(out, "or run it without one to approve this machine in a browser.")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Finding your teams through a SuperBased sign-in is not in this build.")
}

// connectStatus builds the one sentence from this machine's facts.
func connectStatus(enr *store.Enrolment, pol managedconfig.AttachResult, id frontdoor.Identity) frontdoor.Status {
	d := frontdoor.Destination{}
	if enr != nil {
		d = frontdoor.Destination{
			Attached: true, OrgName: enr.OrgName, ServerURL: enr.OrgServerURL,
			Managed: enr.IsManaged(), MemberEmail: enr.UserEmail,
			DisplayName: enr.DisplayName, OnlineURL: enr.OnlineURL,
		}
		if lock := pol.Lock(); lock != nil {
			cur := currentDestination(enr)
			d.Locked = lock.Destination.OrgID == cur.OrgID
		}
	}
	return frontdoor.Sentence(frontdoor.Facts{Destination: d, Identity: id})
}

// connectEnrollArgs is `observer enroll`'s argv for an attach: the server
// and the code on stdin (--token-file -) when a pairing code was handed in,
// else the organization's device-code sign-in (--idp).
func connectEnrollArgs(f connectFlags, server string, taken pairing.Taken) []string {
	var args []string
	if taken.Source != pairing.SourceNone {
		args = []string{server, "--token-file", "-"}
	} else {
		args = []string{"--idp", server}
	}
	if f.configPath != "" {
		args = append(args, "--config", f.configPath)
	}
	args = append(args,
		fmt.Sprintf("--write-block=%t", f.writeBlock),
		fmt.Sprintf("--wire-clients=%t", f.wireClients),
	)
	if f.dropUnsent {
		args = append(args, "--drop-unsent")
	}
	if f.acceptGovernance {
		args = append(args, "--accept-governance")
	}
	if f.acceptIntel {
		args = append(args, "--accept-intel-consent")
	}
	return args
}

// connectEnrollStdin carries the pairing code to enroll's --token-file -.
func connectEnrollStdin(taken pairing.Taken) io.Reader {
	if taken.Source == pairing.SourceNone {
		return strings.NewReader("")
	}
	return strings.NewReader(taken.Code.String() + "\n")
}

// connectIdentityArgs is `observer cloud login`'s argv.
func connectIdentityArgs(f connectFlags) []string {
	var args []string
	if f.configPath != "" {
		args = append(args, "--config", f.configPath)
	}
	if f.baseURL != "" {
		args = append(args, "--base-url", f.baseURL)
	}
	if f.devToken != "" {
		args = append(args, "--dev-token", f.devToken)
	}
	return args
}

// runSubcommand runs a freshly built command as if typed, with this
// command's output and the given input.
func runSubcommand(parent, sub *cobra.Command, args []string, stdin io.Reader) error {
	sub.SetArgs(args)
	sub.SetOut(parent.OutOrStdout())
	sub.SetErr(parent.ErrOrStderr())
	sub.SetIn(stdin)
	sub.SilenceUsage = true
	sub.SilenceErrors = true
	ctx := parent.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	return sub.ExecuteContext(ctx)
}

// loadConnectEnrolment reads this machine's enrolment without creating the
// database (a fresh machine has none and is simply not enrolled).
func loadConnectEnrolment(ctx context.Context, configPath string) (*store.Enrolment, error) {
	_, database, cleanup, err := loadConfigAndDBNoCreate(ctx, configPath)
	if errors.Is(err, errNoNodeDatabase) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer cleanup()
	return store.New(database).LoadEnrolment(ctx)
}

// readPairFile reads a --pair-file through enroll's own hardened opener and
// bounded read (openEnrolTokenFile, readEnrolTokenBounded), judging the
// opened descriptor: it must be a regular file, and one other local users
// can read is refused on a system with permission bits.
func readPairFile(path string) ([]byte, error) {
	f, err := openEnrolTokenFile(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if pairFileTooOpen(info.Mode()) {
		return nil, fmt.Errorf("%s can be read by other users (mode %o); chmod 600 it", path, info.Mode().Perm())
	}
	return readEnrolTokenBounded(f)
}

// confirmOnTTY asks question on cmd's terminal and reads y/yes. A
// non-interactive input answers no.
func confirmOnTTY(cmd *cobra.Command, question string) bool {
	fmt.Fprintf(cmd.OutOrStdout(), "%s [y/N] ", question)
	line, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "y" || a == "yes"
}

// connectStatusLine is the sentence for `observer status`: the same facts,
// read the same way; an unreadable enrolment reads as local only.
func connectStatusLine(ctx context.Context, configPath string, st *store.Store) string {
	var enr *store.Enrolment
	if st != nil {
		enr, _ = st.LoadEnrolment(ctx) //nolint:errcheck // a status line degrades to local only
	}
	return connectStatus(enr, managedconfig.LoadAttach(), connectIdentityState(configPath)).Sentence
}

// pairFileTooOpen reports a --pair-file other users can read. Windows has
// no permission bits to judge, so it is never refused there.
func pairFileTooOpen(mode os.FileMode) bool {
	return runtime.GOOS != "windows" && mode.Perm()&0o004 != 0
}

// connectStatusSeam is the dashboard's ConnectStatus (dashapi.Options): this
// machine's enrolment and company lock, with the sign-in state the dashboard
// already probed, through the same mapping `observer status` uses.
func connectStatusSeam(database *sql.DB) func(ctx context.Context, id frontdoor.Identity) frontdoor.Status {
	return func(ctx context.Context, id frontdoor.Identity) frontdoor.Status {
		var enr *store.Enrolment
		if database != nil {
			enr, _ = store.New(database).LoadEnrolment(ctx) //nolint:errcheck // degrades to local only
		}
		return connectStatus(enr, managedconfig.LoadAttach(), id)
	}
}
