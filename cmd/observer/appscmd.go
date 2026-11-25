package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/componentsvc"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/firstrunstate"
	"github.com/marmutapp/superbased-observer/internal/planechoice"
	"github.com/marmutapp/superbased-observer/internal/service"
	sdkcatalog "github.com/marmutapp/superbased-observer/shared/lib"
)

// appscmd.go is `observer apps on|off|status` (first-run plan revision 2,
// sections 3.5 and 4.4; review P-08, P-09; lane POLISH-F2). One command
// for the whole local AI Apps setup, in place of `observer components add
// obs --yes` + `observer config set observability.enabled true` + a restart.
//
// It adds no enable path of its own. With a daemon serving this config's
// database (resolveDaemonHandoff, L-125) it calls the daemon's ONE enable
// seam over the owner-local dashboard routes F1 built (GET /api/apps/status
// for the confirm token and the consent facts, then POST /api/apps/enable
// or /api/apps/disable), the same seam the dashboard button and the VS Code
// action call. With no daemon it only writes the config, through the same
// two writers the seam uses (componentsvc for the obs component,
// setObsEnabledKey for the key), records the apps intent, and says how to
// start the daemon. It never daemonizes: it starts the background service
// only when one is installed, and never runs a restart.
//
// Rules it keeps (plan 3.5):
//   - it never says "AI Apps is on" unless the receiver reported listening;
//     a taken 4318/4317 fails loudly with the fix;
//   - a daemon older than the seam (404) or a process without it (501) gets
//     "restart `observer start` to finish", and nothing is restarted;
//   - an edition without AI Apps refuses with the exact reinstall command.

// appsDocsURL is where the CLI points for more: the public SDK quickstart
// for sending an app's traces to this machine (SR-31: the getting-started
// path it named before was never published and answered 404).
const appsDocsURL = "https://superbased.app/docs/sdk/quickstart-machine"

// appsDaemonTimeout bounds a status or disable exchange with the daemon.
// The enable waits for the receiver's bind (appsReceiverWait) plus margin.
const (
	appsDaemonTimeout = 15 * time.Second
	appsEnableTimeout = appsReceiverWait + 15*time.Second
)

// appsServiceWait bounds how long `apps on` waits for a service it started
// to answer, so it can report the receiver's bind.
var appsServiceWait = 20 * time.Second

// Package seams, so tests never open a browser, start a service or decide
// the build.
var (
	appsInBuild      = appObsCompiledIn
	appsOpenBrowser  = openBrowser
	appsInteractive  = isInteractiveTerminal
	appsNow          = time.Now
	appsStartService = startInstalledObserverService
)

// appsRefusal is an `apps on` that did not turn AI Apps on; the
// error text is the message and the fix.
type appsRefusal struct{ rep planechoice.EnableReport }

func (e appsRefusal) Error() string {
	if e.rep.Fix == "" {
		return e.rep.Message
	}
	return e.rep.Message + "\n" + e.rep.Fix
}

func newAppsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "apps",
		Short: "Trace the AI apps you build, on this machine (AI Apps on, off, status)",
		Long: "AI Apps keeps traces, cost and evals for the LLM apps and agents you build,\n" +
			"sent by the superbased SDKs or any OpenTelemetry exporter to this machine.\n\n" +
			"  observer apps on       turn it on (no restart with a running daemon)\n" +
			"  observer apps off      turn it off (takes effect at the next start)\n" +
			"  observer apps status   what is on, the receiver, the latest trace\n" +
			"  observer apps lane     route an app's model calls through this machine\n\n" +
			"Coding-agent capture is never changed by these commands.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newAppsOnCmd(), newAppsOffCmd(), newAppsStatusCmd(), newAppsLaneCmd())
	return cmd
}

// appsOnOptions are `apps on`'s flags.
type appsOnOptions struct {
	configPath string
	yes        bool
	noOpen     bool
	// installer: run by install.sh / install.ps1 for --apps: the intent is
	// recorded as the installer's, nothing is opened and no installed
	// service is started (the installer starts Observer itself).
	installer bool
}

func newAppsOnCmd() *cobra.Command {
	var o appsOnOptions
	c := &cobra.Command{
		Use:   "on",
		Short: "Turn AI Apps on: add the component and listen for your app's traces",
		Long: "Adds the AI Apps component, turns [observability] on and, with a running\n" +
			"daemon, starts the trace receiver at once (no restart). With no daemon it\n" +
			"writes the config and says how to start one; it never starts a daemon\n" +
			"itself, except a background service that is already installed.\n" +
			"If the receiver's port (4318 or 4317) is taken it fails with the fix.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return runAppsOn(cmd, o) },
	}
	c.Flags().StringVar(&o.configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	c.Flags().BoolVarP(&o.yes, "yes", "y", false, "Do not ask; turn AI Apps on")
	c.Flags().BoolVar(&o.noOpen, "no-open", false, "Do not open the dashboard in a browser")
	c.Flags().BoolVar(&o.installer, "installer", false, "Run by the installer (records the installer's intent; opens and starts nothing)")
	_ = c.Flags().MarkHidden("installer")
	return c
}

func newAppsOffCmd() *cobra.Command {
	var configPath string
	c := &cobra.Command{
		Use:   "off",
		Short: "Turn AI Apps off (takes effect at the next start of the daemon)",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return runAppsOff(cmd, configPath) },
	}
	c.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	return c
}

func newAppsStatusCmd() *cobra.Command {
	var (
		configPath string
		jsonOut    bool
	)
	c := &cobra.Command{
		Use:   "status",
		Short: "Show whether AI Apps is on, the receiver and the latest trace",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return runAppsStatus(cmd, configPath, jsonOut) },
	}
	c.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	c.Flags().BoolVar(&jsonOut, "json", false, "Print the status as JSON (the apps block the dashboard reads)")
	return c
}

// appsStatusBody is GET /api/apps/status (internal/intelligence/dashboard
// apps_enable.go firstRunApps plus the confirm token).
type appsStatusBody struct {
	InBuild      bool                       `json:"in_build"`
	Component    planechoice.ComponentState `json:"component"`
	On           bool                       `json:"on"`
	ConfiguredOn bool                       `json:"configured_on"`
	HotEnable    bool                       `json:"hot_enable"`
	Receiver     planechoice.Receiver       `json:"receiver"`
	LatestTrace  *planechoice.LatestTrace   `json:"latest_trace"`
	Consent      planechoice.Consent        `json:"consent"`
	Pending      []string                   `json:"pending_next_start,omitempty"`
	ConfirmToken string                     `json:"confirm_token,omitempty"`
}

// appsCLIDaemon is the running daemon this CLI hands AI Apps work to.
type appsCLIDaemon struct {
	t      daemonTarget
	client *http.Client
}

// appsDaemonAnswer classifies one exchange with the daemon.
type appsDaemonAnswer int

const (
	// appsAnswerOK: the route answered (any status with a body we read).
	appsAnswerOK appsDaemonAnswer = iota
	// appsAnswerNoSeam: the daemon predates the seam (404) or this process
	// has none (501): restart `observer start` to finish.
	appsAnswerNoSeam
	// appsAnswerGone: no daemon for this database after all (refused
	// connection, or the address changed hands): act as with none.
	appsAnswerGone
)

// resolveAppsDaemon returns the daemon serving this config's database, or
// nil. A daemon serving another database is named on stderr and not asked.
func resolveAppsDaemon(cmd *cobra.Command, configPath string) *appsCLIDaemon {
	if dashboardNotInBuildNote() != "" {
		return nil
	}
	t := resolveDaemonHandoff(cmd.Context(), configPath)
	if t.Use {
		return &appsCLIDaemon{t: t, client: &http.Client{}}
	}
	if t.Listening {
		fmt.Fprintf(cmd.ErrOrStderr(), "Not asking the daemon at %s (%s); working on this config only.\n", strings.TrimPrefix(t.Base, "http://"), t.Reason)
	}
	return nil
}

// status is GET /api/apps/status.
func (d *appsCLIDaemon) status(ctx context.Context) (appsStatusBody, appsDaemonAnswer, error) {
	ctx, cancel := context.WithTimeout(ctx, appsDaemonTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.t.Base+"/api/apps/status", nil)
	if err != nil {
		return appsStatusBody{}, appsAnswerGone, err
	}
	d.t.setDBIdentity(req)
	resp, err := d.client.Do(req) //nolint:gosec // G704: this node's own dashboard, resolved by resolveDaemonHandoff
	if err != nil {
		if isConnRefused(err) {
			return appsStatusBody{}, appsAnswerGone, nil
		}
		return appsStatusBody{}, appsAnswerOK, fmt.Errorf("the daemon at %s did not answer: %w", d.t.Base, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if isDBIdentityRefusal(resp, d.t.DBIdentity) {
		return appsStatusBody{}, appsAnswerGone, nil
	}
	switch resp.StatusCode {
	case http.StatusNotFound, http.StatusNotImplemented:
		return appsStatusBody{}, appsAnswerNoSeam, nil
	case http.StatusOK:
	default:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return appsStatusBody{}, appsAnswerOK, fmt.Errorf("the daemon answered HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var st appsStatusBody
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&st); err != nil {
		return appsStatusBody{}, appsAnswerOK, fmt.Errorf("the daemon's AI Apps status could not be read: %w", err)
	}
	return st, appsAnswerOK, nil
}

// post sends a confirmed POST to an /api/apps route and returns the status
// and body.
func (d *appsCLIDaemon) post(ctx context.Context, path, token string, timeout time.Duration) (int, []byte, appsDaemonAnswer, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.t.Base+path, bytes.NewReader([]byte(`{"source":"cli"}`)))
	if err != nil {
		return 0, nil, appsAnswerGone, err
	}
	req.Header.Set("Content-Type", "application/json")
	d.t.setDBIdentity(req)
	req.Header.Set(pushNowConfirmHeader, token)
	//nolint:gosec // G124: a request cookie (the double-submit half), not one this process sets
	req.AddCookie(&http.Cookie{Name: pushNowConfirmCookie, Value: token})
	resp, err := d.client.Do(req) //nolint:gosec // G704: this node's own dashboard, resolved by resolveDaemonHandoff
	if err != nil {
		if isConnRefused(err) {
			return 0, nil, appsAnswerGone, nil
		}
		return 0, nil, appsAnswerOK, fmt.Errorf("the daemon at %s did not finish: %w", d.t.Base, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if isDBIdentityRefusal(resp, d.t.DBIdentity) {
		return 0, nil, appsAnswerGone, nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusNotImplemented {
		return resp.StatusCode, b, appsAnswerNoSeam, nil
	}
	return resp.StatusCode, b, appsAnswerOK, nil
}

// enable is POST /api/apps/enable: the one enable seam.
func (d *appsCLIDaemon) enable(ctx context.Context, token string) (planechoice.EnableReport, appsDaemonAnswer, error) {
	code, body, ans, err := d.post(ctx, "/api/apps/enable", token, appsEnableTimeout)
	if err != nil || ans != appsAnswerOK {
		return planechoice.EnableReport{}, ans, err
	}
	var rep planechoice.EnableReport
	if jerr := json.Unmarshal(body, &rep); jerr != nil || rep.Outcome == "" {
		return planechoice.EnableReport{}, appsAnswerOK, fmt.Errorf("the daemon refused the enable (HTTP %d): %s", code, strings.TrimSpace(string(body)))
	}
	return rep, appsAnswerOK, nil
}

// localAppsFacts is what `apps on` knows with no daemon to ask.
type localAppsFacts struct {
	cfg       config.Config
	component planechoice.ComponentState
	consent   planechoice.Consent
}

// readLocalAppsFacts reads the component state, the saved key and the
// consent facts for configPath without creating the database.
func readLocalAppsFacts(ctx context.Context, configPath string) (localAppsFacts, error) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return localAppsFacts{}, fmt.Errorf("load config: %w", err)
	}
	f := localAppsFacts{cfg: cfg, component: planechoice.ComponentAbsent}
	if appsInBuild() {
		f.component = obsComponentState(configPath)
	}
	cf := planechoice.ConsentFacts{AllowNonLoopback: cfg.Ingest.OTel.AllowNonLoopback}
	if cfg.OrgClient.Enabled {
		if enr, eerr := loadConnectEnrolment(ctx, configPath); eerr == nil && enr != nil {
			cf.Enrolled, cf.Org = true, enr.OrgName
			cf.Tiers = obsShareTierKeys((&appsRuntime{}).shareOptions(cfg))
		}
	}
	f.consent = planechoice.BuildConsent(cf)
	return f, nil
}

// appsRefusalFor is the refusal for a component that cannot be turned on
// (not in this build, absent from the edition, blocked), or nil.
func appsRefusalFor(c planechoice.ComponentState) *planechoice.EnableReport {
	f := planechoice.EnableFacts{InBuild: appsInBuild(), Component: c, Editions: obsEditions()}
	if !f.InBuild || c == planechoice.ComponentAbsent || c == planechoice.ComponentBlocked {
		rep := planechoice.ClassifyEnable(f)
		return &rep
	}
	return nil
}

// receiverLine is the receiver address with the loopback note.
func receiverLine(addr string, c planechoice.Consent) string {
	if c.ReceiverNote != "" {
		return addr + " " + c.ReceiverNote
	}
	return addr
}

// printAppsPreview is the consent block before the question (plan 3.5).
func printAppsPreview(out io.Writer, componentActive bool, httpAddr string, c planechoice.Consent) {
	fmt.Fprintln(out, "Turning on AI Apps on this machine:")
	if !componentActive {
		fmt.Fprintln(out, "  - adds the AI Apps component")
	}
	fmt.Fprintf(out, "  - starts listening for your app's traces on %s\n", receiverLine(httpAddr, c))
	fmt.Fprintln(out, c.Sentence)
	fmt.Fprintln(out, "Turn it off with `observer apps off` (takes effect at the next start).")
}

// appsConfirm asks the question unless --yes. A non-terminal without --yes
// refuses rather than guess.
func appsConfirm(cmd *cobra.Command, yes bool) (bool, error) {
	if yes {
		return true, nil
	}
	if !appsInteractive(cmd) {
		return false, errors.New("not a terminal: pass --yes to turn AI Apps on without the question")
	}
	fmt.Fprint(cmd.OutOrStdout(), "Continue? [Y/n] ")
	line, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	if err != nil && line == "" {
		return false, nil
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "", "y", "yes":
		return true, nil
	}
	return false, nil
}

// runAppsOn is `observer apps on`.
func runAppsOn(cmd *cobra.Command, o appsOnOptions) error {
	ctx := cmd.Context()
	if !appsInBuild() {
		return appsRefusal{*appsRefusalFor(planechoice.ComponentAbsent)}
	}
	local, err := readLocalAppsFacts(ctx, o.configPath)
	if err != nil {
		return err
	}
	if d := resolveAppsDaemon(cmd, o.configPath); d != nil {
		st, ans, err := d.status(ctx)
		if err != nil {
			return err
		}
		switch ans {
		case appsAnswerOK:
			return appsOnWithDaemon(cmd, o, d, st)
		case appsAnswerNoSeam:
			return appsOnWriteConfig(cmd, o, local, appsNoSeamDaemon, false)
		}
	}
	return appsOnWriteConfig(cmd, o, local, appsNoDaemon, false)
}

// appsOnWithDaemon turns AI Apps on through the running daemon's seam.
func appsOnWithDaemon(cmd *cobra.Command, o appsOnOptions, d *appsCLIDaemon, st appsStatusBody) error {
	out := cmd.OutOrStdout()
	if !st.InBuild {
		return appsRefusal{*appsRefusalFor(planechoice.ComponentAbsent)}
	}
	if rep := appsRefusalFor(st.Component); rep != nil {
		return appsRefusal{*rep}
	}
	dashURL := d.t.Base + "/apps"
	if st.On && st.Receiver.State == planechoice.ReceiverListening {
		fmt.Fprintf(out, "AI Apps is already on.  Dashboard: %s\n", dashURL)
		fmt.Fprintf(out, "Receiver: listening on %s\n", receiverLine(st.Receiver.HTTPAddr, st.Consent))
		printAppsNextSteps(out)
		return nil
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: o.configPath})
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	printAppsPreview(out, st.Component == planechoice.ComponentActive, cfg.Ingest.OTel.HTTPAddr, st.Consent)
	ok, err := appsConfirm(cmd, o.yes)
	if err != nil {
		return err
	}
	if !ok {
		fmt.Fprintln(out, "Nothing changed.")
		return nil
	}
	fmt.Fprintln(out, "Turning AI Apps on in the running daemon (waits for the receiver to listen)...")
	rep, ans, err := d.enable(cmd.Context(), st.ConfirmToken)
	if err != nil {
		return err
	}
	switch ans {
	case appsAnswerNoSeam:
		local, lerr := readLocalAppsFacts(cmd.Context(), o.configPath)
		if lerr != nil {
			return lerr
		}
		return appsOnWriteConfig(cmd, o, local, appsNoSeamDaemon, true)
	case appsAnswerGone:
		return errors.New("the daemon stopped answering before the enable finished; check with `observer apps status`, then run `observer apps on` again")
	}
	if !rep.OK {
		return appsRefusal{rep}
	}
	appsPrintOn(cmd, o, dashURL, rep.Receiver.HTTPAddr, st.Consent, rep.Pending)
	return nil
}

// appsPrintOn is the success block (plan 3.5).
func appsPrintOn(cmd *cobra.Command, o appsOnOptions, dashURL, httpAddr string, c planechoice.Consent, pending []string) {
	out := cmd.OutOrStdout()
	open := !o.noOpen && !o.installer
	suffix := ""
	if open {
		suffix = "   (opening)"
	}
	fmt.Fprintf(out, "\nAI Apps is on.  Dashboard: %s%s\n", dashURL, suffix)
	fmt.Fprintf(out, "Receiver: listening on %s\n", receiverLine(httpAddr, c))
	if len(pending) > 0 {
		fmt.Fprintf(out, "Starts at the next start of the daemon: %s.\n", strings.Join(pending, ", "))
	}
	printAppsNextSteps(out)
	if open {
		appsOpenBrowser(dashURL)
	}
}

// printAppsNextSteps prints one row per SDK from the catalog (plan 3.9):
// the snippet up to its init call, after the SDK's setup command for a
// language that has one (setup installs the SDK, so it takes the install
// line's place; AI Apps SDK quickstart plan 3.5), else after its install
// line.
func printAppsNextSteps(out io.Writer) {
	rows, err := sdkcatalog.All()
	if err == nil && len(rows) > 0 {
		printSDKNextSteps(out, rows)
	}
	fmt.Fprintf(out, "More: %s\n", appsDocsURL)
}

// printSDKNextSteps is printAppsNextSteps' rows: per SDK the setup command
// (or the install line), then the init line.
func printSDKNextSteps(out io.Writer, rows []sdkcatalog.SDK) {
	fmt.Fprintln(out, "\nSend a trace from your app:")
	for _, r := range rows {
		first := r.Install()
		if r.Setup != "" {
			first = r.Setup
		}
		fmt.Fprintf(out, "  %-11s %s\n", r.Label, first)
		for _, l := range snippetHead(r.Snippet) {
			fmt.Fprintf(out, "  %-11s %s\n", "", l)
		}
	}
}

// snippetHead is a snippet's non-blank lines up to and including the first
// init call (every SDK's snippet has one); the whole snippet when none.
func snippetHead(lines []string) []string {
	var out []string
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		out = append(out, l)
		if strings.Contains(strings.ToLower(l), "init(") {
			return out
		}
	}
	return out
}

// appsWriteMode says why `apps on` only writes the config.
type appsWriteMode int

const (
	// appsNoDaemon: no daemon serves this database.
	appsNoDaemon appsWriteMode = iota
	// appsNoSeamDaemon: a daemon runs but cannot turn AI Apps on while it
	// runs (older than the seam, or a process without it).
	appsNoSeamDaemon
)

// appsOnWriteConfig writes the config through the seam's own two writers,
// records the intent and says what finishes it. It never starts a daemon,
// except an installed service when no daemon runs. asked: the question was
// already answered (a daemon that turned out to have no seam).
func appsOnWriteConfig(cmd *cobra.Command, o appsOnOptions, local localAppsFacts, mode appsWriteMode, asked bool) error {
	ctx := cmd.Context()
	out := cmd.OutOrStdout()
	if rep := appsRefusalFor(local.component); rep != nil {
		return appsRefusal{*rep}
	}
	httpAddr := local.cfg.Ingest.OTel.HTTPAddr
	if !asked {
		printAppsPreview(out, local.component == planechoice.ComponentActive, httpAddr, local.consent)
		ok, err := appsConfirm(cmd, o.yes)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintln(out, "Nothing changed.")
			return nil
		}
	}
	if rep := writeAppsConfig(ctx, o.configPath, local.component); rep != nil {
		return appsRefusal{*rep}
	}
	src := planechoice.SourceAppsOn
	if o.installer {
		src = planechoice.SourceInstaller
	}
	if _, _, err := firstrunstate.New(firstrunstate.Path(local.cfg.Observer.DBPath)).RecordIntent(planechoice.ChoiceApps, src, appsNow()); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "note: the AI Apps intent was not recorded for the dashboard: %v\n", err)
	}
	if mode == appsNoSeamDaemon {
		fmt.Fprintln(out, "\nAI Apps is set to on, but the running daemon cannot start it while it runs.")
		fmt.Fprintln(out, "Restart the daemon to finish: observer service restart (it takes the proxy routes off first")
		fmt.Fprintln(out, "and puts them back, so an AI session routed through it is not cut). Nothing was restarted.")
		return nil
	}
	// The receiver binds when the daemon starts; a port taken now would fail
	// it then, so say so now (plan 3.5: never "on" and then wait).
	if bindErr := appsProbeBind(local.cfg); bindErr != nil {
		return appsRefusal{planechoice.ClassifyEnable(planechoice.EnableFacts{
			InBuild: true, Component: planechoice.ComponentActive,
			Receiver: *bindErr,
		})}
	}
	if !o.installer {
		started, note := appsStartService(ctx)
		if started {
			fmt.Fprintln(out, "\nAI Apps is set to on. Started the installed observer service; AI Apps starts with it.")
			return appsAwaitService(cmd, o, local)
		}
		if note != "" {
			fmt.Fprintln(cmd.ErrOrStderr(), note)
		}
	}
	if o.installer {
		fmt.Fprintln(out, "\nAI Apps is set to on. The receiver opens on "+receiverLine(httpAddr, local.consent)+" when Observer starts.")
		return nil
	}
	fmt.Fprintln(out, "\nAI Apps is set to on. No daemon is running here, so nothing listens yet.")
	if launchdAvailable() || systemdAvailable() {
		fmt.Fprintln(out, "Run `observer start` (or `observer service install --now`): the receiver opens on "+receiverLine(httpAddr, local.consent)+".")
	} else {
		fmt.Fprintln(out, "Run `observer start`: the receiver opens on "+receiverLine(httpAddr, local.consent)+".")
	}
	printAppsNextSteps(out)
	return nil
}

// writeAppsConfig adds the obs component when it is only available and sets
// [observability] enabled, with the same writers and refusals as the
// daemon's enable seam (obs_wire_apps.go). nil when both are written.
func writeAppsConfig(ctx context.Context, configPath string, comp planechoice.ComponentState) *planechoice.EnableReport {
	f := planechoice.EnableFacts{InBuild: true, Component: comp, Editions: obsEditions()}
	fail := func() *planechoice.EnableReport { rep := planechoice.ClassifyEnable(f); return &rep }
	if comp == planechoice.ComponentAvailable {
		svc, err := newComponentsService(configPath, nil)
		if err == nil {
			_, err = svc.Apply(ctx, componentsvc.Change{Add: []string{"obs"}}, componentsvc.ApplyOptions{Principal: "apps-on"})
		}
		if err != nil {
			if errors.Is(err, componentsvc.ErrManagedByOrg) {
				f.Refused = err.Error()
			} else {
				f.WriteError = "adding the obs component: " + err.Error()
			}
			return fail()
		}
	}
	if err := setObsEnabledKey(ctx, configPath, true); err != nil {
		if errors.Is(err, errAppsKeyRefused) {
			f.Refused = strings.TrimPrefix(err.Error(), errAppsKeyRefused.Error()+": ")
		} else {
			f.WriteError = "setting observability.enabled: " + err.Error()
		}
		return fail()
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		f.WriteError = "the saved config did not load: " + err.Error()
		return fail()
	}
	if !cfg.Observability.Enabled {
		f.WriteError = "the saved config still reads AI Apps off (the component gate or an organization pin holds it off)"
		return fail()
	}
	return nil
}

// appsProbeBind tries the receiver's two addresses now; a taken one comes
// back as the bind failure the daemon would report.
func appsProbeBind(cfg config.Config) *planechoice.Receiver {
	for _, addr := range []string{cfg.Ingest.OTel.HTTPAddr, cfg.Ingest.OTel.GRPCAddr} {
		if strings.TrimSpace(addr) == "" {
			continue
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return &planechoice.Receiver{
				State: planechoice.ReceiverBindFailed, HTTPAddr: addr, Error: err.Error(),
			}
		}
		_ = ln.Close()
	}
	return nil
}

// appsAwaitService waits for a service it started to answer and reports the
// receiver as the daemon recorded it.
func appsAwaitService(cmd *cobra.Command, o appsOnOptions, local localAppsFacts) error {
	out := cmd.OutOrStdout()
	deadline := appsNow().Add(appsServiceWait)
	for appsNow().Before(deadline) {
		if d := resolveAppsDaemonQuiet(cmd, o.configPath); d != nil {
			st, ans, err := d.status(cmd.Context())
			if err == nil && ans == appsAnswerOK && st.Receiver.State != "" && st.Receiver.State != planechoice.ReceiverNotRunning {
				if st.Receiver.State != planechoice.ReceiverListening {
					return appsRefusal{planechoice.ClassifyEnable(planechoice.EnableFacts{
						InBuild: true, Component: planechoice.ComponentActive, Receiver: st.Receiver,
					})}
				}
				appsPrintOn(cmd, o, d.t.Base+"/apps", st.Receiver.HTTPAddr, st.Consent, st.Pending)
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	fmt.Fprintln(out, "The service has not answered yet. Check with `observer apps status`.")
	printAppsNextSteps(out)
	return nil
}

// resolveAppsDaemonQuiet is resolveAppsDaemon without the stderr note.
func resolveAppsDaemonQuiet(cmd *cobra.Command, configPath string) *appsCLIDaemon {
	if dashboardNotInBuildNote() != "" {
		return nil
	}
	if t := resolveDaemonHandoff(cmd.Context(), configPath); t.Use {
		return &appsCLIDaemon{t: t, client: &http.Client{}}
	}
	return nil
}

// startInstalledObserverService starts the per-user observer service when
// one is installed (a systemd user unit, or the launchd agent). It never
// installs one. started is true when the start command succeeded; note says
// why a found service was not started.
func startInstalledObserverService(_ context.Context) (bool, string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return false, ""
	}
	switch {
	case launchdAvailable():
		if _, err := os.Stat(service.LaunchAgentPath(home)); err != nil {
			return false, ""
		}
		if err := runLaunchdLifecycle("start", false, launchdDeps{}); err != nil {
			return false, "note: the installed observer service did not start: " + err.Error() + " (try `observer service start`)"
		}
		return true, ""
	case systemdAvailable():
		if _, err := os.Stat(service.UnitPath(service.ScopeUser, home)); err != nil {
			return false, ""
		}
		if err := runServiceCommand(service.Systemctl(service.ScopeUser, "start", service.UnitName)); err != nil {
			return false, "note: the installed observer service did not start: " + err.Error() + " (try `observer service start`)"
		}
		return true, ""
	}
	return false, ""
}

// runAppsOff is `observer apps off`: writes the key off; it takes effect at
// the next start of the daemon (a running mux cannot drop a route).
func runAppsOff(cmd *cobra.Command, configPath string) error {
	out := cmd.OutOrStdout()
	if !appsInBuild() {
		fmt.Fprintln(out, "This edition does not include AI Apps; there is nothing to turn off.")
		return nil
	}
	if d := resolveAppsDaemon(cmd, configPath); d != nil {
		st, ans, err := d.status(cmd.Context())
		if err != nil {
			return err
		}
		if ans == appsAnswerOK {
			code, body, ans2, perr := d.post(cmd.Context(), "/api/apps/disable", st.ConfirmToken, appsDaemonTimeout)
			if perr != nil {
				return perr
			}
			if ans2 == appsAnswerOK {
				if code != http.StatusOK {
					return fmt.Errorf("the daemon did not turn AI Apps off (HTTP %d): %s", code, strings.TrimSpace(string(body)))
				}
				var rep struct {
					Message string `json:"message"`
				}
				_ = json.Unmarshal(body, &rep)
				fmt.Fprintln(out, rep.Message)
				fmt.Fprintln(out, "Coding-agent capture is unchanged.")
				return nil
			}
		}
		if ans == appsAnswerNoSeam {
			if err := setObsEnabledKey(cmd.Context(), configPath, false); err != nil {
				return fmt.Errorf("AI Apps was not turned off: %w", err)
			}
			fmt.Fprintln(out, "AI Apps is set to off. It stops at the next start of the daemon.")
			return nil
		}
	}
	if err := setObsEnabledKey(cmd.Context(), configPath, false); err != nil {
		return fmt.Errorf("AI Apps was not turned off: %w", err)
	}
	fmt.Fprintln(out, "AI Apps is off. Coding-agent capture is unchanged.")
	return nil
}

// runAppsStatus is `observer apps status`.
func runAppsStatus(cmd *cobra.Command, configPath string, jsonOut bool) error {
	out := cmd.OutOrStdout()
	st, running, err := appsStatusFacts(cmd, configPath)
	if err != nil {
		return err
	}
	if jsonOut {
		st.ConfirmToken = ""
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			appsStatusBody
			DaemonRunning bool `json:"daemon_running"`
		}{st, running})
	}
	for _, l := range appsStatusLines(st, running) {
		fmt.Fprintln(out, l)
	}
	return nil
}

// appsStatusFacts asks the daemon, or reads the config and the receiver's
// last record with none.
func appsStatusFacts(cmd *cobra.Command, configPath string) (appsStatusBody, bool, error) {
	if d := resolveAppsDaemon(cmd, configPath); d != nil {
		st, ans, err := d.status(cmd.Context())
		if err != nil {
			return st, true, err
		}
		if ans == appsAnswerOK {
			return st, true, nil
		}
	}
	local, err := readLocalAppsFacts(cmd.Context(), configPath)
	if err != nil {
		return appsStatusBody{}, false, err
	}
	st := appsStatusBody{
		InBuild: appsInBuild(), Component: local.component,
		ConfiguredOn: local.cfg.Observability.Enabled, Consent: local.consent,
		Receiver: planechoice.Receiver{State: planechoice.ReceiverNotRunning},
	}
	if rec, ok, rerr := loadOTLPReceiverStatus(local.cfg); rerr == nil && ok {
		st.Receiver = planechoice.Receiver{
			State: planechoice.ReceiverState(rec.State), GRPCAddr: rec.GRPCAddr,
			HTTPAddr: rec.HTTPAddr, Error: rec.Error, At: rec.At,
		}
	}
	return st, false, nil
}

// appsStatusLines renders the status, one fact per line.
func appsStatusLines(st appsStatusBody, running bool) []string {
	var l []string
	switch {
	case !st.InBuild || st.Component == planechoice.ComponentAbsent:
		rep := *appsRefusalFor(planechoice.ComponentAbsent)
		return []string{"AI Apps     not in this edition", "  " + rep.Message, "  " + rep.Fix}
	case st.Component == planechoice.ComponentBlocked:
		return []string{"AI Apps     blocked on this machine (see `observer components status`)"}
	case st.On:
		line := "AI Apps     on"
		if !st.ConfiguredOn {
			line += " (set to off; stops at the next start)"
		}
		l = append(l, line)
	case st.ConfiguredOn && running:
		l = append(l, "AI Apps     set to on, not serving yet (run `observer apps on` to start it now)")
	case st.ConfiguredOn:
		l = append(l, "AI Apps     set to on; starts with `observer start`")
	default:
		l = append(l, "AI Apps     off (turn it on: observer apps on)")
	}
	if running {
		l = append(l, "Daemon      running")
	} else {
		l = append(l, "Daemon      not running")
	}
	rcv := "Receiver    " + string(st.Receiver.State)
	if st.Receiver.HTTPAddr != "" {
		rcv += " " + receiverLine(st.Receiver.HTTPAddr, st.Consent)
	}
	if !running && st.Receiver.At != "" {
		rcv += " (last recorded " + st.Receiver.At + ")"
	}
	l = append(l, rcv)
	if st.Receiver.Error != "" {
		l = append(l, "            "+st.Receiver.Error)
	}
	if st.LatestTrace != nil {
		t := st.LatestTrace
		l = append(l, fmt.Sprintf("Last trace  %s %s (%s) at %s", t.TraceID, t.Name, t.Service, t.StartedAt))
	} else if st.On {
		l = append(l, "Last trace  none yet")
	}
	l = append(l, "Data        "+st.Consent.Sentence)
	if len(st.Pending) > 0 {
		l = append(l, "Next start  "+strings.Join(st.Pending, ", "))
	}
	return l
}
