//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// terminal_sandbox_hosted_leftovers.go holds the user actions of the hosted
// rows (lane SBX-P7): consent (agree, revoke), credentials (connect,
// disconnect), the leftover-box list and its delete, E2B re-adoption, and
// the dashboard routes the Hosted sandboxes panel calls. Each vendor call
// here follows an explicit user action (a command, or a Local dashboard
// action with the confirm token), never a page view (invariant I6).

func init() { sandboxSubcommands = append(sandboxSubcommands, newSandboxHostedCmd) }

// hostedCLIConfig loads the effective [terminal.sandbox] block.
func hostedCLIConfig(ctx context.Context, cfgPath string) (config.TerminalSandboxConfig, error) {
	cfg, gov, err := config.LoadGovernance(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		return config.TerminalSandboxConfig{}, fmt.Errorf("load config: %w", err)
	}
	return cliEffectiveSandboxConfig(ctx, cfg, gov.PinsInForce), nil
}

// hostedObserverDir is the observer directory.
func hostedObserverDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".observer")
	if r, err := filepath.EvalSymlinks(dir); err == nil {
		dir = r
	}
	return dir, nil
}

// hostedActive reports whether a hosted driver's component is selected on
// this node (a variable so tests set it). While none is, the hosted routes
// answer 404 and the `observer sandbox hosted` verbs refuse (the SBX-P7
// merge's audit finding 5).
var hostedActive = func(_ context.Context, cfgPath string) bool {
	cfg, _, err := config.LoadGovernance(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		return false
	}
	return hostedAnyActive(cfg)
}

// hostedAnyActive reports whether any registered hosted driver's component
// is selected under cfg (the opt-in rule, sandboxDriverSelected).
func hostedAnyActive(cfg config.Config) bool {
	snap := componentSnapshotForConfig(cfg)
	for _, reg := range hostedVendorRegs {
		if reg.component != "" && sandboxDriverSelected(snap, reg.component) {
			return true
		}
	}
	return false
}

// errHostedNotActive is the verbs' refusal while no hosted driver is active.
func errHostedNotActive() error {
	comps := make([]string, 0, len(hostedVendorRegs))
	for _, reg := range hostedVendorRegs {
		if reg.component != "" {
			comps = append(comps, reg.component)
		}
	}
	sort.Strings(comps)
	return fmt.Errorf("hosted sandboxes are not active on this node: select %s in Settings > Components (or [components] add) to use these commands", strings.Join(comps, ", "))
}

// hostedVendorArg resolves a provider argument.
func hostedVendorArg(id string) (sandboxremote.Vendor, error) {
	v, ok := sandboxremote.VendorFor(id)
	if !ok {
		return v, fmt.Errorf("unknown provider %q (one of %s)", id, strings.Join(sandboxremote.VendorIDs(), ", "))
	}
	if _, ok := hostedVendorRegs[id]; !ok {
		return v, fmt.Errorf("the %s driver is not in this build", id)
	}
	return v, nil
}

// hostedConsentFor computes the consent facts and screen for provider over
// a workspace root under cfg.
func hostedConsentFor(ctx context.Context, cfg config.TerminalSandboxConfig, observerDir string, v sandboxremote.Vendor, root string) (sandboxremote.ConsentScreen, error) {
	pc := hostedVendorConfig(cfg.Hosted, v.ID)
	region, endpoint, ok := hostedResolve(v, pc)
	if !ok {
		return sandboxremote.ConsentScreen{}, fmt.Errorf("%s: %s", verdictHostedRegionUnknown, hostedResolveRefusal(v, pc))
	}
	prof, err := sandbox.ResolveEgress(cfg.Egress)
	if err != nil {
		return sandboxremote.ConsentScreen{}, err
	}
	tier := vocab.Tier(prof.Mode)
	if !hostedRow(v.ID).OffersTier(tier) {
		return sandboxremote.ConsentScreen{}, fmt.Errorf("%s has no %s tier; set [terminal.sandbox].egress to internet, proxy_only or none", v.Name, tier)
	}
	d := &hostedDriver{cfg: cfg.Hosted, vendor: v, r: &sandboxRuntime{cfg: cfg, observerDir: observerDir}}
	m, err := d.manifest(ctx, root)
	if err != nil {
		return sandboxremote.ConsentScreen{}, err
	}
	capture := hostedConsentCapture(v.ID, tier, vocab.KeyCustody(cfg.Hosted.KeyCustody))
	f := sandboxremote.ConsentFacts{
		Provider: v.ID, Endpoint: endpoint, Region: region, Custody: cfg.Hosted.KeyCustody,
		Tier: string(tier), Capture: capture, ScopeKey: m.ScopeKey, BoxBinary: hostedBoxBinaryLabel(pc),
		MemoryImages: cfg.Hosted.MemoryImages, MaxRunMinutes: cfg.Hosted.MaxRunMinutes, DailyBoxMinutes: cfg.Hosted.DailyBoxMinutes,
	}
	scr := sandboxremote.BuildConsentScreen(v, f, m, v.EstimateCost(cfg.Hosted.MaxRunMinutes))
	hostedApplyCredConsent(ctx, &scr, v.Name, capture)
	return scr, nil
}

func newSandboxHostedCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hosted",
		Short: "Hosted sandboxes (E2B, Modal, Vercel; beta): consent, credentials, leftover boxes",
		PersistentPreRunE: func(c *cobra.Command, _ []string) error {
			// cobra runs this instead of root's pre-run, so the crossmount
			// isolation step runs here too (LEFT2 audit S5).
			applyCrossmountIsolation(c)
			// The bare group only prints its help, whatever components are
			// active (WINFIX4 audit, TestEveryCommandGroupRejectsUnknownSubcommand
			// on Windows: it refused as not active instead).
			if c.Name() == "hosted" && c.HasSubCommands() {
				return nil
			}
			cfgPath := ""
			if f := c.Flags().Lookup("config"); f != nil {
				cfgPath = f.Value.String()
			}
			if !hostedActive(c.Context(), cfgPath) {
				return errHostedNotActive()
			}
			return nil
		},
	}
	cmd.AddCommand(newHostedConsentCmd(), newHostedConnectCmd(), newHostedDisconnectCmd(), newHostedLeftoversCmd(), newHostedDeleteCmd(), newHostedAdoptCmd(), newHostedStatusCmd())
	return cmd
}

// newHostedStatusCmd is `observer sandbox hosted status`: the runs still
// on record and every kept line saying why a run's staged diff did not come
// home (the record that held it is removed once the box is confirmed gone,
// P-094 residual).
func newHostedStatusCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the hosted runs still on record and why any run's changes were not saved home",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			obs, err := hostedObserverDir()
			if err != nil {
				return err
			}
			renderHostedStatus(cmd.OutOrStdout(), hostedLoadRecords(obs), hostedLoadDiffErrors(obs))
			renderHostedRelayLogs(cmd.OutOrStdout(), hostedKeptRelayLogs(obs))
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "", "config file")
	return cmd
}

// renderHostedStatus prints the records still held and the kept diff
// errors, newest last.
func renderHostedStatus(out io.Writer, recs []sandboxremote.Record, diffErrs []sandboxremote.DiffErrorLine) {
	if len(recs) == 0 {
		fmt.Fprintln(out, "Hosted runs on record: none")
	} else {
		fmt.Fprintf(out, "Hosted runs on record: %d (see `observer sandbox hosted leftovers`)\n", len(recs))
		for _, r := range recs {
			if r.DiffError != "" {
				fmt.Fprintf(out, "  %s (%s): changes not saved home: %s\n", r.RunID, r.Provider, r.DiffError)
			}
		}
	}
	if len(diffErrs) == 0 {
		return
	}
	fmt.Fprintln(out, "Runs whose changes were not saved home (kept after the box was deleted):")
	for _, l := range diffErrs {
		fmt.Fprintf(out, "  %s %s (%s): %s\n", l.At.Format(time.RFC3339), l.RunID, l.Provider, l.Error)
	}
}

// renderHostedRelayLogs lists the kept relay logs, newest first (lane
// SBX-UPD, finding H1): why each relay stream closed, kept after the box is
// deleted.
func renderHostedRelayLogs(out io.Writer, logs []keptHostedRelayLog) {
	if len(logs) == 0 {
		return
	}
	fmt.Fprintln(out, "Kept relay logs (why each relay stream closed; kept after the box is deleted):")
	for i, l := range logs {
		if i == 5 {
			fmt.Fprintf(out, "  and %d older\n", len(logs)-5)
			break
		}
		fmt.Fprintf(out, "  %s %s: %s\n", l.At.UTC().Format(time.RFC3339), l.RunID, l.Path)
	}
}

func newHostedConsentCmd() *cobra.Command {
	var (
		cfgPath, workspace string
		yes, revoke        bool
	)
	cmd := &cobra.Command{
		Use:   "consent <provider>",
		Short: "Show what leaves this machine for a provider and record your agreement",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := hostedVendorArg(args[0])
			if err != nil {
				return err
			}
			obs, err := hostedObserverDir()
			if err != nil {
				return err
			}
			if revoke {
				return hostedRevokeConsent(obs, v.ID)
			}
			cfg, err := hostedCLIConfig(cmd.Context(), cfgPath)
			if err != nil {
				return err
			}
			if workspace == "" {
				workspace, _ = os.Getwd()
			}
			if abs, err := filepath.Abs(workspace); err == nil {
				workspace = abs
			}
			scr, err := hostedConsentFor(cmd.Context(), cfg, obs, v, workspace)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			for _, l := range scr.Lines {
				fmt.Fprintf(out, "%-20s %s\n", l.Label+":", l.Value)
			}
			if len(scr.Uploaded) > 0 {
				fmt.Fprintln(out, "Sent to the box:")
				for _, p := range scr.Uploaded {
					fmt.Fprintf(out, "  %s\n", p)
				}
				if scr.UploadedMore > 0 {
					fmt.Fprintf(out, "  and %d more\n", scr.UploadedMore)
				}
			}
			if len(scr.Excluded) > 0 {
				fmt.Fprintln(out, "Kept on this machine:")
				for _, e := range scr.Excluded {
					fmt.Fprintf(out, "  %s (%s)\n", e.Path, e.Reason)
				}
			}
			if !yes {
				fmt.Fprint(out, "Type yes to agree: ")
				line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
				if strings.TrimSpace(line) != "yes" {
					return errors.New("not agreed; nothing recorded")
				}
			}
			return hostedSaveConsent(obs, sandboxremote.NewConsent(scr.Facts, time.Now().UTC().Format(time.RFC3339)))
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "", "config file")
	cmd.Flags().StringVar(&workspace, "workspace", "", "the workspace root to upload (default: the current directory)")
	cmd.Flags().BoolVar(&yes, "yes", false, "agree without the prompt (after reading the screen)")
	cmd.Flags().BoolVar(&revoke, "revoke", false, "remove the recorded agreement")
	return cmd
}

func newHostedConnectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "connect <provider>",
		Short: "Store a provider credential in the OS keychain, bound to the configured region's endpoint (read from stdin)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := hostedVendorArg(args[0])
			if err != nil {
				return err
			}
			cfg, err := hostedCLIConfig(cmd.Context(), "")
			if err != nil {
				return err
			}
			pc := hostedVendorConfig(cfg.Hosted, v.ID)
			_, endpoint, ok := hostedResolve(v, pc)
			if !ok {
				return errors.New("the configured region is unknown")
			}
			obs, err := hostedObserverDir()
			if err != nil {
				return err
			}
			fields := map[string]string{}
			r := bufio.NewReader(cmd.InOrStdin())
			for _, n := range v.EnvCredential {
				fmt.Fprintf(cmd.ErrOrStderr(), "%s: ", n)
				line, _ := r.ReadString('\n')
				fields[n] = strings.TrimSpace(line)
			}
			// Bound to the endpoint and, for a pinned one, its server key
			// (SBX-GOV-4).
			if err := hostedConnectCredential(obs, v, fields, endpoint, pc.EndpointSPKISHA256); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s credential stored, bound to %s\n", v.Name, endpoint)
			return nil
		},
	}
}

func newHostedDisconnectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disconnect <provider>",
		Short: "Remove a stored provider credential",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			v, err := hostedVendorArg(args[0])
			if err != nil {
				return err
			}
			obs, err := hostedObserverDir()
			if err != nil {
				return err
			}
			return hostedDisconnectCredential(obs, v)
		},
	}
}

func newHostedLeftoversCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "leftovers",
		Short: "List hosted boxes from earlier runs that may still be running (no provider is called)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			obs, err := hostedObserverDir()
			if err != nil {
				return err
			}
			recs := hostedLoadRecords(obs)
			list := sandboxremote.Leftovers(recs, hostedLiveRuns(recs), time.Now())
			if len(list) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no leftover hosted boxes")
				return nil
			}
			for _, l := range list {
				fmt.Fprintf(cmd.OutOrStdout(), "%s  %s  %s  box %s  age %s  stops by itself in %s  (%s)\n", l.RunID, l.Provider, l.State,
					orText(l.VendorID, "-"), time.Duration(l.AgeSeconds)*time.Second, time.Duration(l.ExpiresInSeconds)*time.Second, l.Action)
			}
			return nil
		},
	}
}

func newHostedDeleteCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "delete <run id>",
		Short: "Delete a leftover hosted box (calls the provider) and confirm it is gone",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			obs, err := hostedObserverDir()
			if err != nil {
				return err
			}
			return hostedDeleteRun(cmd.Context(), obs, args[0], force, cmd.OutOrStdout())
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "also delete a run that is still live in its terminal: stops its helper (which ends the agent in the box), then deletes the box")
	return cmd
}

// hostedFindRecord returns one run's teardown record.
func hostedFindRecord(observerDir, runID string) (sandboxremote.Record, error) {
	for _, r := range hostedLoadRecords(observerDir) {
		if r.RunID == runID {
			return r, nil
		}
	}
	return sandboxremote.Record{}, fmt.Errorf("no hosted box record for run %s", runID)
}

// hostedClientFor builds the vendor client for a record, its credential
// bound to the record's endpoint. Only user actions reach it.
func hostedClientFor(observerDir string, rec sandboxremote.Record) (sandboxremote.Client, sandboxremote.Credential, error) {
	v, err := hostedVendorArg(rec.Provider)
	if err != nil {
		return nil, sandboxremote.Credential{}, err
	}
	cred, err := hostedResolveCredential(observerDir, v)
	if err != nil {
		return nil, cred, err
	}
	if err := sandboxremote.CheckBinding(cred, v, rec.Endpoint); err != nil {
		return nil, cred, err
	}
	c, err := hostedVendorRegs[rec.Provider].newClient(cred, rec.Endpoint)
	return c, cred, err
}

// hostedHelperPIDKey is the record's Extra key for the helper's local pid.
const hostedHelperPIDKey = "helper_pid"

// hostedLiveRuns are the runs whose helper still runs on this machine: they
// are live in a terminal, not leftovers.
func hostedLiveRuns(recs []sandboxremote.Record) map[string]bool {
	live := map[string]bool{}
	for _, r := range recs {
		if hostedHelperAlive(r.Extra[hostedHelperPIDKey]) {
			live[r.RunID] = true
		}
	}
	return live
}

// hostedLeftoverList is the leftover list the panel and the CLI show.
func hostedLeftoverList(observerDir string) []sandboxremote.Leftover {
	recs := hostedLoadRecords(observerDir)
	return sandboxremote.Leftovers(recs, hostedLiveRuns(recs), time.Now())
}

// errHostedRunLive refuses a delete or adopt of a run still live in its
// terminal.
func errHostedRunLive(runID string) error {
	return fmt.Errorf("run %s is still live in its terminal on this machine; end it there (its teardown deletes the box)", runID)
}

// hostedDeleteLeftover deletes a leftover box (finding a lost create by its
// label first) and removes the record once the vendor confirms. A run whose
// helper still runs is refused (the dashboard's delete never forces).
func hostedDeleteLeftover(ctx context.Context, observerDir, runID string) error {
	return hostedDeleteRun(ctx, observerDir, runID, false, io.Discard)
}

// hostedDeleteRun is the delete with the CLI's --force: a run still live in
// its terminal is refused unless forced, and a forced delete says what it
// stops (the helper, so the agent in the box) before it stops it.
func hostedDeleteRun(ctx context.Context, observerDir, runID string, force bool, out io.Writer) error {
	rec, err := hostedFindRecord(observerDir, runID)
	if err != nil {
		return err
	}
	if pid := rec.Extra[hostedHelperPIDKey]; hostedHelperAlive(pid) {
		if !force {
			return fmt.Errorf("%w; `observer sandbox hosted delete --force %s` stops its helper (which ends the agent in the box) and deletes the box", errHostedRunLive(runID), runID)
		}
		fmt.Fprintf(out, "--force: stopping the live helper of run %s (pid %s): this ends the agent in its %s box; the helper's teardown pulls the transcripts, saves the diff and deletes the box\n", runID, pid, rec.Provider)
		if serr := hostedStopHelper(pid); serr != nil {
			fmt.Fprintf(out, "the helper did not stop cleanly (%v); deleting the box from here\n", serr)
		}
		if rec, err = hostedFindRecord(observerDir, runID); err != nil {
			fmt.Fprintf(out, "run %s: the helper's teardown deleted the box\n", runID)
			return nil
		}
	}
	c, cred, err := hostedClientFor(observerDir, rec)
	if err != nil {
		return err
	}
	ids := []string{rec.VendorID}
	if rec.VendorID == "" {
		list, err := c.ListByLabel(ctx, sandboxremote.LabelKey, runID)
		if err != nil {
			return errors.New(sandboxremote.Redact(err.Error(), cred.Secrets()))
		}
		ids = ids[:0]
		for _, b := range list {
			ids = append(ids, b.ID)
		}
	}
	for _, id := range ids {
		if err := hostedDeleteConfirmed(ctx, c, id); err != nil {
			return errors.New(sandboxremote.Redact(err.Error(), cred.Secrets()))
		}
	}
	settled := hostedSettleLeftover(observerDir, rec, time.Now())
	rec.State = sandboxremote.StateGone
	if err := hostedRemoveRecord(observerDir, rec); err != nil {
		return err
	}
	what := "no box carried the run's label"
	if len(ids) > 0 {
		what = fmt.Sprintf("deleted the %s box %s (confirmed by the provider)", rec.Provider, strings.Join(ids, ", "))
	}
	fmt.Fprintf(out, "run %s: %s; %s\n", runID, what, settled)
	return nil
}

// hostedSettleLeftoverNote is the ledger note of a leftover settled at its
// planned minutes.
const hostedSettleLeftoverNote = "deleted as a leftover; the box's start is not recorded, so the planned minutes stay charged"

// hostedSettleLeftover settles a deleted leftover's reservation (live run
// 2, finding F-B: it stayed charged at the whole timeout, unsettled): the
// minutes from the launch's recorded intent to now, at most the vendor
// timeout, or, when the record has no start, the planned charge with a
// note. It returns what it did, in words.
func hostedSettleLeftover(observerDir string, rec sandboxremote.Record, now time.Time) string {
	msg := "the spend ledger held no open reservation for the run"
	_ = hostedUpdateLedger(observerDir, now, func(l *sandboxremote.Ledger) error {
		if rec.CreatedAt.IsZero() {
			if m, ok := l.SettlePlanned(rec.RunID, hostedSettleLeftoverNote); ok {
				msg = fmt.Sprintf("settled at the planned %d box-minutes (the box's start is not recorded)", m)
			}
			return nil
		}
		end := now
		if !rec.Deadline.IsZero() && rec.Deadline.Before(end) {
			end = rec.Deadline
		}
		if m, ok := l.Settle(rec.RunID, end.Sub(rec.CreatedAt)); ok {
			msg = fmt.Sprintf("settled %d box-minutes (from the launch to the delete, at most the vendor timeout)", m)
		}
		return nil
	})
	return msg
}

func newHostedAdoptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "adopt <run id>",
		Short: "Re-attach this terminal to a running hosted box from an earlier run whose helper is gone (the scrollback before it is not replayed)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			obs, err := hostedObserverDir()
			if err != nil {
				return err
			}
			return hostedAdopt(cmd.Context(), obs, args[0], cmd.InOrStdin(), cmd.OutOrStdout())
		},
	}
}

// hostedAdoptReopen re-opens and re-keys a re-adopted run's capture relay
// (terminal_sandbox_hosted_adopt_linux.go; off Linux, where no hosted run
// starts, nothing is re-opened). stop closes it; note says what happened.
var hostedAdoptReopen = func(context.Context, string, sandboxremote.Record, sandboxremote.Vendor, sandboxremote.Client, sandboxremote.Credential, io.Writer) (func(), string) {
	return func() {}, "the capture relay is not re-opened on this OS, so checked actions in the box stay blocked"
}

// hostedAdoptGuestPTY re-attaches a guest helper's kept PTY (Linux).
var hostedAdoptGuestPTY = func(context.Context, string, sandboxremote.Record, sandboxremote.Vendor, sandboxremote.Client, sandboxremote.Credential, io.Reader, io.Writer) (int, error) {
	return 1, errors.New("re-attaching a guest PTY needs Linux")
}

// hostedGuestReattachOn is the one read of a row's GuestReattach flag (a
// variable so the dark path's tests can turn it on; every row holds it false
// until REM-13 is checked live, SBX-UPD audit finding 2).
var hostedGuestReattachOn = func(v sandboxremote.Vendor) bool { return v.GuestReattach }

// hostedAdoptNotice is the line a re-adopted terminal starts with: the
// scrollback is empty (the ring of the dead helper is gone), and what the
// relay re-open did (sandbox plan v2 section 5.5).
func hostedAdoptNotice(runID, vendor, relayNote string) string {
	return fmt.Sprintf("[observer: re-adopted run %s on %s; the terminal's scrollback before now is empty (output from before is not replayed); %s]\r\n", runID, vendor, relayNote)
}

// hostedAdopt re-attaches to a live run's agent whose helper is gone, on a
// row that can: by the agent's recorded pid on a row with native reattach
// (E2B), or through the guest helper's kept PTY on a guest PTY row (Modal,
// Vercel; lane SBX-UPD). The capture relay is re-opened with new keys
// first, the terminal is bridged to the agent, and the box is torn down
// when the agent ends.
func hostedAdopt(ctx context.Context, observerDir, runID string, in io.Reader, out io.Writer) error {
	rec, err := hostedFindRecord(observerDir, runID)
	if err != nil {
		return err
	}
	if hostedHelperAlive(rec.Extra[hostedHelperPIDKey]) {
		return errHostedRunLive(runID)
	}
	v, _ := sandboxremote.VendorFor(rec.Provider)
	pid := rec.Extra["pty_pid"]
	guest := hostedGuestReattachOn(v) && rec.Extra[sandboxremote.ExtraGuestAttach] == "1"
	native := v.Reattach && pid != ""
	if rec.VendorID == "" || (!guest && !native) {
		return fmt.Errorf("run %s cannot be re-adopted (%s offers no reattach for it, or the run never started its agent); delete it instead", runID, v.Name)
	}
	c, cred, err := hostedClientFor(observerDir, rec)
	if err != nil {
		return err
	}
	stopRelay, relayNote := hostedAdoptReopen(ctx, observerDir, rec, v, c, cred, out)
	defer stopRelay()
	if guest {
		fmt.Fprint(out, hostedAdoptNotice(runID, v.Name, relayNote))
		if _, err := hostedAdoptGuestPTY(ctx, observerDir, rec, v, c, cred, in, out); err != nil {
			return errors.New(sandboxremote.Redact(err.Error(), cred.Secrets()))
		}
	} else {
		p, err := c.Reattach(ctx, rec.VendorID, pid)
		if err != nil {
			return errors.New(sandboxremote.Redact(err.Error(), cred.Secrets()))
		}
		fmt.Fprint(out, hostedAdoptNotice(runID, v.Name, relayNote))
		go func() { _, _ = io.Copy(p, in) }()
		_, _ = io.Copy(out, p)
		_, _ = p.Wait(ctx)
	}
	stopRelay()
	if err := hostedDeleteConfirmed(context.WithoutCancel(ctx), c, rec.VendorID); err != nil {
		return errors.New(sandboxremote.Redact(err.Error(), cred.Secrets()))
	}
	rec.State = sandboxremote.StateGone
	return hostedRemoveRecord(observerDir, rec)
}

// ---- dashboard routes --------------------------------------------------------

// The confirm double-submit names the dashboard uses (manage_core.go).
const (
	hostedConfirmCookie = "sb_remote_confirm"
	hostedConfirmHeader = "X-Observer-Confirm" //nolint:gosec // G101: a header name
)

// hostedConfirmToken reads or mints the double-submit token.
func hostedConfirmToken(w http.ResponseWriter, r *http.Request) string {
	if ck, err := r.Cookie(hostedConfirmCookie); err == nil {
		if v := strings.TrimSpace(ck.Value); len(v) == 64 {
			if _, err := hex.DecodeString(v); err == nil {
				return v
			}
		}
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{Name: hostedConfirmCookie, Value: tok, Path: "/", Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode}) //nolint:gosec // G124: a double-submit token the page reads
	return tok
}

// hostedConfirmed checks the double-submit token and a JSON body.
func hostedConfirmed(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		http.Error(w, "application/json required", http.StatusUnsupportedMediaType)
		return false
	}
	h := strings.TrimSpace(r.Header.Get(hostedConfirmHeader))
	ck, err := r.Cookie(hostedConfirmCookie)
	if h == "" || err != nil || subtle.ConstantTimeCompare([]byte(h), []byte(strings.TrimSpace(ck.Value))) != 1 {
		http.Error(w, "forbidden: missing or mismatched confirm token - reload the panel", http.StatusForbidden)
		return false
	}
	return true
}

// hostedProviderView is one provider on the panel.
type hostedProviderView struct {
	ID             string                       `json:"id"`
	Name           string                       `json:"name"`
	Credential     string                       `json:"credential"`
	CredentialEnv  []string                     `json:"credential_env"`
	Consent        *sandboxremote.ConsentRecord `json:"consent,omitempty"`
	Screen         *sandboxremote.ConsentScreen `json:"screen,omitempty"`
	ScreenError    string                       `json:"screen_error,omitempty"`
	ConsentVerdict string                       `json:"consent_verdict,omitempty"`
	Unverified     []string                     `json:"unverified"`
	EndpointDocs   []sandboxremote.EndpointDoc  `json:"endpoint_docs"`
}

// hostedDashboardRoutes are the Hosted sandboxes panel's routes. Every one
// is Local: the read previews a workspace (it runs git in the path the
// request names and lists its files and excluded credential-shaped paths),
// so a paired remote viewer must not reach it; and every one answers 404
// while no hosted driver is active (the SBX-P7 merge's audit finding 5).
func hostedDashboardRoutes(configPath string) []dashapi.ExtraRoute {
	load := func(ctx context.Context) (config.TerminalSandboxConfig, error) {
		return hostedCLIConfig(ctx, configPath)
	}
	gate := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !hostedActive(r.Context(), configPath) {
				http.NotFound(w, r)
				return
			}
			h(w, r)
		}
	}
	return []dashapi.ExtraRoute{
		{Pattern: "GET /api/terminal/sandbox/hosted", Capability: dashapi.CapabilityLocal, Handler: gate(func(w http.ResponseWriter, r *http.Request) {
			hostedGetHandler(w, r, load)
		})},
		{Pattern: "POST /api/terminal/sandbox/hosted/consent", Capability: dashapi.CapabilityLocal, Handler: gate(func(w http.ResponseWriter, r *http.Request) {
			hostedConsentHandler(w, r, load)
		})},
		{Pattern: "POST /api/terminal/sandbox/hosted/leftovers/delete", Capability: dashapi.CapabilityLocal, Handler: gate(hostedLeftoverDeleteHandler)},
	}
}

func hostedGetHandler(w http.ResponseWriter, r *http.Request, load func(context.Context) (config.TerminalSandboxConfig, error)) {
	tok := hostedConfirmToken(w, r)
	cfg, err := load(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	obs, err := hostedObserverDir()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	workspace := strings.TrimSpace(r.URL.Query().Get("workspace"))
	ids := make([]string, 0, len(hostedVendorRegs))
	for id := range hostedVendorRegs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var providers []hostedProviderView
	for _, id := range ids {
		v, _ := sandboxremote.VendorFor(id)
		pv := hostedProviderView{ID: id, Name: v.Name, Credential: hostedCredentialSource(obs, v), CredentialEnv: v.EnvCredential, Consent: hostedLoadConsent(obs, id), Unverified: v.Unverified, EndpointDocs: v.Docs}
		if workspace != "" && filepath.IsAbs(workspace) {
			if scr, err := hostedConsentFor(r.Context(), cfg, obs, v, workspace); err != nil {
				pv.ScreenError = err.Error()
			} else {
				pv.Screen = &scr
				pv.ConsentVerdict = sandboxremote.CheckConsent(pv.Consent, scr.Facts)
			}
		}
		providers = append(providers, pv)
	}
	var ledger sandboxremote.Ledger
	if b, err := hostedReadOwned(hostedLedgerPath(obs)); err == nil {
		_ = json.Unmarshal(b, &ledger)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"confirm_token": tok, "providers": providers,
		"leftovers": hostedLeftoverList(obs),
		"spend":     ledger.Totals(),
	})
}

func hostedConsentHandler(w http.ResponseWriter, r *http.Request, load func(context.Context) (config.TerminalSandboxConfig, error)) {
	if !hostedConfirmed(w, r) {
		return
	}
	var body struct {
		Provider  string `json:"provider"`
		Workspace string `json:"workspace"`
		Revoke    bool   `json:"revoke"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	v, err := hostedVendorArg(body.Provider)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	obs, err := hostedObserverDir()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if body.Revoke {
		if err := hostedRevokeConsent(obs, v.ID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	cfg, err := load(r.Context())
	if err != nil || !filepath.IsAbs(body.Workspace) {
		http.Error(w, "a loaded config and an absolute workspace are required", http.StatusBadRequest)
		return
	}
	scr, err := hostedConsentFor(r.Context(), cfg, obs, v, body.Workspace)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := hostedSaveConsent(obs, sandboxremote.NewConsent(scr.Facts, time.Now().UTC().Format(time.RFC3339))); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func hostedLeftoverDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if !hostedConfirmed(w, r) {
		return
	}
	var body struct {
		RunID string `json:"run_id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil || body.RunID == "" {
		http.Error(w, "run_id required", http.StatusBadRequest)
		return
	}
	obs, err := hostedObserverDir()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := hostedDeleteLeftover(r.Context(), obs, body.RunID); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
	}
}

// hostedDeleteConfirmed deletes a box and confirms with the vendor's own
// get that it is gone.
func hostedDeleteConfirmed(ctx context.Context, c sandboxremote.Client, id string) error {
	if err := c.Delete(ctx, id); err != nil && !errors.Is(err, sandboxremote.ErrNotFound) {
		return err
	}
	for i := 0; i < 10; i++ {
		info, err := c.Get(ctx, id)
		if errors.Is(err, sandboxremote.ErrNotFound) || (err == nil && !info.Running) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return errors.New("the provider still lists the box after the delete")
}
