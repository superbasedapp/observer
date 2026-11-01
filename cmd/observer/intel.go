package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/orgintel"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// intel.go is the node's ORG-PLANE Cloud Intelligence surface (design
// docs/plans/cloud-intelligence-parity-design-2026-10-03.md sections 3.1-3.3
// and 3.7): `observer intel` and the shared functions the dashboard's
// /api/intel/* routes call (orgintel_dashboard.go), so the CLI and the
// dashboard run the SAME code (operator rule: every CLI action is doable from
// the dashboard). `observer cloud` stays exclusively the personal plane.
//
// The org rail is the sanctioned egress of an enrolled node (INV-2); these
// functions talk only to the org server this node is enrolled with, through
// internal/orgclient.

// Typed refusals the dashboard maps to statuses.
var (
	errOrgIntelNotEnrolled = errors.New("this machine is not enrolled in an organization; org session enrichment needs an enrolment (Settings, Organization)")
	errOrgIntelManaged     = errors.New("this machine is managed by your organization, which decides session enrichment; there is nothing to accept here")
	errOrgIntelNoTerms     = errors.New("your organization's server has not sent its Cloud Intelligence terms yet (it may predate this feature, or the next sync has not run); try again after a sync")
	errOrgIntelStale       = errors.New("the organization's terms changed since they were shown; review them again before accepting")
)

// orgIntelSnapshot is everything an org-plane surface renders, read once.
type orgIntelSnapshot struct {
	Enrolment   *store.Enrolment
	Requirement *store.OrgIntelRequirementRow
	Body        *orgcontract.IntelRequirementBody
	Active      *store.OrgIntelConsentEvent
	ConfigOptIn bool
	Inputs      orgintel.Inputs
	Status      orgintel.Status
}

// orgIntelNodeManaged reports whether the org decides org intel for this
// node with no developer consent: a managed enrolment, or one whose org
// switched it to enterprise (operator rulings P-204 and P-205; the org server
// admits such a member as managed). A grant read error falls back to the
// enrolment's own class, the answer before the switch was honoured.
func orgIntelNodeManaged(ctx context.Context, st *store.Store, enr *store.Enrolment) bool {
	managed, err := orgclient.NodeManagedFor(ctx, st, enr)
	if err != nil {
		return enr.IsManaged()
	}
	return managed
}

// loadOrgIntelSnapshot resolves the boundary inputs and derives the status
// through the pure orgintel table.
func loadOrgIntelSnapshot(ctx context.Context, st *store.Store, configOptIn bool, now time.Time) (orgIntelSnapshot, error) {
	snap := orgIntelSnapshot{ConfigOptIn: configOptIn}
	enr, err := st.LoadEnrolment(ctx)
	if err != nil {
		return snap, err
	}
	snap.Enrolment = enr
	managed, err := orgclient.NodeManagedFor(ctx, st, enr) // P-205: switched nodes are managed for org intel too
	if err != nil {
		return snap, err
	}
	in := orgintel.Inputs{Enrolled: enr != nil, Managed: managed, ConfigOptIn: configOptIn, Now: now}
	if enr != nil {
		if row, ok, rerr := st.GetOrgIntelRequirement(ctx); rerr != nil {
			return snap, rerr
		} else if ok && row.OrgID == enr.OrgID {
			if body, bok := row.Decoded(); bok {
				snap.Requirement, snap.Body = &row, &body
				in.Requirement = &body
			}
		}
		if ev, ok, aerr := st.ActiveOrgIntelConsent(ctx, enr.OrgID); aerr != nil {
			return snap, aerr
		} else if ok {
			snap.Active = &ev
			in.Active = &orgintel.Consent{
				RequirementVersion: ev.RequirementVersion, EvidenceLevel: ev.EvidenceLevel,
				Purposes: ev.Purposes, DisclosureDigest: ev.DisclosureDigest, AcceptedAt: ev.CreatedAt,
			}
			in.EverAccepted = true
		}
		// A node that accepted before and is now off reports a withdrawal; one
		// that never accepted has no answer to report yet (the org counts it
		// as outstanding).
		if !in.EverAccepted {
			hist, herr := st.OrgIntelConsentHistory(ctx, enr.OrgID, orgIntelHistoryLimit)
			if herr != nil {
				return snap, herr
			}
			for _, ev := range hist {
				if ev.Event == store.OrgIntelConsentAccept {
					in.EverAccepted = true
					break
				}
			}
		}
	}
	snap.Inputs = in
	snap.Status = orgintel.Derive(in)
	return snap, nil
}

// loadConfigOptIn reads the node-authored [intelligence].org_enrichment key
// from the config file as it is NOW (not as the daemon loaded it at start).
func loadConfigOptIn(configPath string) (bool, error) {
	path, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return false, err
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
	if err != nil {
		return false, err
	}
	return cfg.Intelligence.OrgEnrichment, nil
}

// setOrgEnrichmentKey writes [intelligence].org_enrichment through the shared
// surgical config patch (the dashboard's validated write path: comments kept
// when possible, atomic, backed up, decode-verified before landing).
func setOrgEnrichmentKey(configPath string, on bool) error {
	path, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return err
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
	if err != nil {
		return err
	}
	if cfg.Intelligence.OrgEnrichment == on {
		return nil
	}
	rhs := "false"
	if on {
		rhs = "true"
	}
	_, err = config.PatchFile(path, cfg, []config.Patch{{Dotted: "intelligence.org_enrichment", RHS: rhs, Scalar: true}})
	return err
}

// orgIntelActionResult is what accept / withdraw report back.
type orgIntelActionResult struct {
	Plan       orgintel.AcceptPlan `json:"plan"`
	Reported   bool                `json:"reported"`
	ReportNote string              `json:"report_note,omitempty"`
}

// reportOrgIntelConsent sends the node's current posture to its org server.
// A failure never undoes the local consent (the next push cycle re-reports);
// a refusal other than "not supported" is recorded in the local audit.
func reportOrgIntelConsent(ctx context.Context, b orgBundle, configPath string) (bool, string) {
	optIn, err := loadConfigOptIn(configPath)
	if err != nil {
		return false, "could not read config: " + err.Error()
	}
	snap, err := loadOrgIntelSnapshot(ctx, b.store, optIn, time.Now().UTC())
	if err != nil {
		return false, err.Error()
	}
	rep, ok := orgintel.Report(snap.Inputs, snap.Status)
	if !ok {
		return false, ""
	}
	if _, err := b.client.ReportIntelConsent(ctx, rep); err != nil {
		if errors.Is(err, orgclient.ErrIntelConsentNotSupported) {
			return false, "your organization's server does not record consent yet; it will be sent once it does"
		}
		orgID := ""
		if snap.Enrolment != nil {
			orgID = snap.Enrolment.OrgID
		}
		_ = b.store.AppendOrgIntelReceipt(ctx, store.OrgIntelReceipt{Kind: store.OrgIntelReceiptReportRefused, OrgID: orgID, Detail: "report_failed"})
		return false, "could not reach your organization's server; the consent is recorded here and will be sent on the next sync"
	}
	return true, ""
}

// acceptOrgIntel is THE interactive accept path (dashboard consent screen,
// `observer intel accept`, the enrolment consent step). It records exactly
// the coverage the disclosure describes, turns the node-authored opt-in key
// on, and reports the posture to the org server. shownDigest, when non-empty,
// must equal the digest of the CURRENT disclosure (the text the developer was
// shown); a changed text is refused as stale rather than accepted unseen.
// This is the only caller of RecordOrgIntelConsent's accept branch (INV-13).
func acceptOrgIntel(ctx context.Context, b orgBundle, configPath, shownDigest, mode string) (orgIntelActionResult, error) {
	enr, err := b.store.LoadEnrolment(ctx)
	if err != nil {
		return orgIntelActionResult{}, err
	}
	if enr == nil {
		return orgIntelActionResult{}, errOrgIntelNotEnrolled
	}
	if orgIntelNodeManaged(ctx, b.store, enr) {
		return orgIntelActionResult{}, errOrgIntelManaged
	}
	// Refresh the terms first (best effort: an unreachable server falls back
	// to the last verified document).
	_, _ = b.client.RefreshIntelRequirement(ctx)
	row, ok, err := b.store.GetOrgIntelRequirement(ctx)
	if err != nil {
		return orgIntelActionResult{}, err
	}
	if !ok || row.OrgID != enr.OrgID {
		return orgIntelActionResult{}, errOrgIntelNoTerms
	}
	body, bok := row.Decoded()
	if !bok {
		return orgIntelActionResult{}, errOrgIntelNoTerms
	}
	plan := orgintel.PlanAccept(body)
	if shownDigest != "" && shownDigest != plan.DisclosureDigest {
		return orgIntelActionResult{}, errOrgIntelStale
	}
	if _, err := b.store.RecordOrgIntelConsent(ctx, store.OrgIntelConsentEvent{
		OrgID: enr.OrgID, Event: store.OrgIntelConsentAccept,
		RequirementVersion: plan.RequirementVersion, EvidenceLevel: plan.EvidenceLevel,
		Purposes: plan.Purposes, DisclosureDigest: plan.DisclosureDigest,
		ConsentMode: mode, Actor: localConsentActor(),
	}); err != nil {
		return orgIntelActionResult{}, err
	}
	if err := setOrgEnrichmentKey(configPath, true); err != nil {
		return orgIntelActionResult{}, fmt.Errorf("the consent was recorded, but turning on [intelligence].org_enrichment failed: %w", err)
	}
	reported, note := reportOrgIntelConsent(ctx, b, configPath)
	return orgIntelActionResult{Plan: plan, Reported: reported, ReportNote: note}, nil
}

// How a consent event came to be, recorded on org_intel_consent.consent_mode
// (review M3-14: every accept used to say "interactive", including the two
// flag paths where nobody answered a prompt). The value is local evidence
// only; it is never on the org wire.
const (
	// orgIntelModePrompt: the developer answered the y/N prompt on a terminal.
	orgIntelModePrompt = "interactive"
	// orgIntelModeYesFlag: `observer intel accept --yes` (terms printed, no prompt).
	orgIntelModeYesFlag = "cli_yes_flag"
	// orgIntelModeEnrolFlag: `observer org enrol --accept-intel-consent`.
	orgIntelModeEnrolFlag = "enrol_flag"
	// orgIntelModeDashboard: the Accept or Withdraw button of the local dashboard.
	orgIntelModeDashboard = "dashboard"
	// orgIntelModeCLI: `observer intel withdraw`.
	orgIntelModeCLI = "cli"
)

// withdrawOrgIntel turns the org-plane opt-in off: a withdraw event, the key
// off, and the posture reported. On an org that requires consent this returns
// the node to PENDING (design section 3.7 step 5). mode is how the developer
// asked (orgIntelMode*).
func withdrawOrgIntel(ctx context.Context, b orgBundle, configPath, mode string) (orgIntelActionResult, error) {
	enr, err := b.store.LoadEnrolment(ctx)
	if err != nil {
		return orgIntelActionResult{}, err
	}
	if enr == nil {
		return orgIntelActionResult{}, errOrgIntelNotEnrolled
	}
	if orgIntelNodeManaged(ctx, b.store, enr) {
		return orgIntelActionResult{}, errOrgIntelManaged
	}
	if _, err := b.store.RecordOrgIntelConsent(ctx, store.OrgIntelConsentEvent{
		OrgID: enr.OrgID, Event: store.OrgIntelConsentWithdraw, ConsentMode: mode, Actor: localConsentActor(),
	}); err != nil {
		return orgIntelActionResult{}, err
	}
	if err := setOrgEnrichmentKey(configPath, false); err != nil {
		return orgIntelActionResult{}, fmt.Errorf("the withdrawal was recorded, but turning off [intelligence].org_enrichment failed: %w", err)
	}
	// The T-155d sweep runs now as well, so results pulled under the consent
	// that just ended leave this machine immediately.
	_, _ = b.store.SweepUnconsentedOrgIntelCache(ctx, time.Now().UTC())
	reported, note := reportOrgIntelConsent(ctx, b, configPath)
	return orgIntelActionResult{Reported: reported, ReportNote: note}, nil
}

// --- CLI ----------------------------------------------------------------

func newIntelCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "intel",
		Short: "Org-plane Cloud Intelligence: your organization's session enrichment on this machine",
		Long: `Session enrichment run by the organization this machine is enrolled with,
on the organization's own server and model (the org plane). The personal plane,
for sessions captured while not enrolled, is ` + "`observer cloud`" + `.

On an individual-tenancy enrolment nothing is sent until you accept the
organization's terms (` + "`observer intel accept`" + `). On a managed machine the
organization decides; ` + "`observer intel status`" + ` shows what it runs.`,
	}
	cmd.AddCommand(newIntelStatusCmd(), newIntelAcceptCmd("accept"), newIntelAcceptCmd("enable"), newIntelDisableCmd(),
		newIntelResultsCmd(), newIntelPreviewCmd(), newIntelEnrichCmd(), newIntelLedgerCmd())
	return cmd
}

func newIntelStatusCmd() *cobra.Command {
	var configPath string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show whether your organization runs session enrichment and your consent",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, err := buildOrgBundle(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer b.cleanup()
			_, _ = b.client.RefreshIntelRequirement(cmd.Context())
			snap, err := loadOrgIntelSnapshot(cmd.Context(), b.store, b.cfg.Intelligence.OrgEnrichment, time.Now().UTC())
			if err != nil {
				return err
			}
			noteManagedNoticeShown(cmd.Context(), b.store, snap)
			view, verr := buildOrgIntelStatusView(cmd.Context(), b.store, snap)
			if verr != nil {
				return verr
			}
			setOrgIntelManagedRail(&view, snap, orgIntelGovernance(cmd.Context(), b))
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(view)
			}
			printOrgIntelStatus(cmd.OutOrStdout(), snap, view.ManagedRail)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print the status as JSON")
	return cmd
}

func newIntelAcceptCmd(use string) *cobra.Command {
	var configPath string
	var yes bool
	cmd := &cobra.Command{
		Use:   use,
		Short: "Read your organization's Cloud Intelligence terms and accept them (turns org session enrichment on)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, err := buildOrgBundle(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer b.cleanup()
			res, err := runIntelAcceptCLI(cmd, b, configPath, yes, orgIntelModeYesFlag)
			if err != nil {
				return err
			}
			if res == nil {
				fmt.Fprintln(cmd.OutOrStdout(), "Not accepted. Nothing was recorded and nothing changed.")
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Accepted (terms version %d, level %s). Org session enrichment is on for this machine.\n",
				res.Plan.RequirementVersion, res.Plan.EvidenceLevel)
			if res.ReportNote != "" {
				fmt.Fprintln(cmd.OutOrStdout(), res.ReportNote)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&yes, "yes", false, "Accept the terms shown without prompting (the terms are still printed)")
	return cmd
}

// runIntelAcceptCLI prints the ONE disclosure and asks, then runs the shared
// accept path bound to the digest of the text it printed. A nil result means
// the developer declined. yesMode is the consent mode recorded when yes skips
// the prompt (which flag did it); an answered prompt records orgIntelModePrompt.
func runIntelAcceptCLI(cmd *cobra.Command, b orgBundle, configPath string, yes bool, yesMode string) (*orgIntelActionResult, error) {
	ctx := cmd.Context()
	enr, err := b.store.LoadEnrolment(ctx)
	if err != nil {
		return nil, err
	}
	if enr == nil {
		return nil, errOrgIntelNotEnrolled
	}
	if orgIntelNodeManaged(ctx, b.store, enr) {
		return nil, errOrgIntelManaged
	}
	_, _ = b.client.RefreshIntelRequirement(ctx)
	row, ok, err := b.store.GetOrgIntelRequirement(ctx)
	if err != nil {
		return nil, err
	}
	if !ok || row.OrgID != enr.OrgID {
		return nil, errOrgIntelNoTerms
	}
	body, bok := row.Decoded()
	if !bok {
		return nil, errOrgIntelNoTerms
	}
	plan := orgintel.PlanAccept(body)
	out := cmd.OutOrStdout()
	fmt.Fprintln(out, "Cloud Intelligence terms from your organization:")
	fmt.Fprintln(out)
	for _, ln := range strings.Split(plan.Disclosure, "\n") {
		fmt.Fprintln(out, "  "+ln)
	}
	mode := yesMode
	if !yes {
		mode = orgIntelModePrompt
		if !isInteractiveTerminal(cmd) {
			return nil, errors.New("not a terminal: re-run with --yes to accept the terms printed above, or accept them in the dashboard (Settings, Cloud Intelligence)")
		}
		accepted, perr := promptYesNo(cmd, "Accept these terms? [y/N] ")
		if perr != nil {
			return nil, perr
		}
		if !accepted {
			return nil, nil
		}
	}
	res, err := acceptOrgIntel(ctx, b, configPath, plan.DisclosureDigest, mode)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func newIntelDisableCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Withdraw your consent and turn org session enrichment off for this machine",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, err := buildOrgBundle(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer b.cleanup()
			res, err := withdrawOrgIntel(cmd.Context(), b, configPath, orgIntelModeCLI)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Withdrawn. Nothing more is sent for enrichment, and results cached under the old consent were removed from this machine.")
			snap, _ := loadOrgIntelSnapshot(cmd.Context(), b.store, false, time.Now().UTC())
			if snap.Status.Required {
				fmt.Fprintln(cmd.OutOrStdout(), "Your organization requires this consent; to stay a member, accept again (`observer intel accept`). To leave, run `observer unenroll`.")
			}
			if res.ReportNote != "" {
				fmt.Fprintln(cmd.OutOrStdout(), res.ReportNote)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	return cmd
}

// offerOrgIntelAtEnrol is the enrolment step of design 3.7: right after an
// individual-tenancy enrolment, fetch the org's terms and, when it requires
// Cloud Intelligence, print them and ask (or accept with
// --accept-intel-consent). The enrolment code is spent before the node can
// learn the requirement, so declining cannot abort it; it leaves the
// requirement PENDING with Accept / Leave, the same state the dashboard
// banner shows. Best effort: nothing here fails the enrolment.
func offerOrgIntelAtEnrol(cmd *cobra.Command, b orgBundle, configPath string, accept bool) {
	ctx := cmd.Context()
	out := cmd.OutOrStdout()
	enr, err := b.store.LoadEnrolment(ctx)
	if err != nil || enr == nil || orgIntelNodeManaged(ctx, b.store, enr) {
		return
	}
	if _, err := b.client.RefreshIntelRequirement(ctx); err != nil {
		return
	}
	snap, err := loadOrgIntelSnapshot(ctx, b.store, b.cfg.Intelligence.OrgEnrichment, time.Now().UTC())
	if err != nil || !snap.Status.Pending {
		return
	}
	fmt.Fprintln(out)
	if !accept && !isInteractiveTerminal(cmd) {
		fmt.Fprintln(out, orgIntelPendingLine(ctx, b))
		fmt.Fprintln(out, "Review the terms with `observer intel status`, or in the dashboard (Settings, Org enrichment).")
		return
	}
	res, err := runIntelAcceptCLI(cmd, b, configPath, accept, orgIntelModeEnrolFlag)
	switch {
	case err != nil:
		fmt.Fprintf(out, "Warn: the Cloud Intelligence consent was not recorded: %v\n", err)
		fmt.Fprintln(out, orgIntelPendingLine(ctx, b))
	case res == nil:
		fmt.Fprintln(out, "Not accepted. This machine is enrolled with the requirement pending.")
		fmt.Fprintln(out, orgIntelPendingLine(ctx, b))
	default:
		fmt.Fprintf(out, "Accepted (terms version %d). Org session enrichment is on for this machine.\n", res.Plan.RequirementVersion)
	}
}

// orgIntelPendingLine is the `observer org status` line for a pending
// compulsory requirement (design 3.7 step 3); empty when nothing is pending.
func orgIntelPendingLine(ctx context.Context, b orgBundle) string {
	// The bundle loaded the config for this command, so its key is current.
	snap, err := loadOrgIntelSnapshot(ctx, b.store, b.cfg.Intelligence.OrgEnrichment, time.Now().UTC())
	if err != nil || !snap.Status.Pending {
		return ""
	}
	org := snap.Enrolment.OrgName
	if org == "" {
		org = snap.Enrolment.OrgID
	}
	return orgIntelPendingSentence(org, snap.Status.PendingReason == orgintel.PendingTermsChanged, snap.Status.DeadlinePassed)
}

// orgIntelPendingSentence is orgIntelPendingLine's wording, pure so the
// dashboard's pointer swap (dashboardCLIPointers) is pinned against every
// variant (T-642).
func orgIntelPendingSentence(org string, termsChanged, deadlinePassed bool) string {
	if termsChanged {
		return fmt.Sprintf("Cloud Intelligence: %s changed its terms; enrichment continues under the terms you accepted. Review them: `observer intel accept`.", org)
	}
	line := fmt.Sprintf("Cloud Intelligence: %s now requires Cloud Intelligence. Accept (`observer intel accept`), or leave the organization (`observer unenroll`).", org)
	if deadlinePassed {
		line += " The deadline has passed."
	}
	return line
}

// orgIntelLevelLabel is the plain-language name of an evidence level, the same
// words the node dashboard (web/src/lib/orgIntel.ts) and the org dashboard
// (web2/src/lib/intelControlsModel.ts) use. "Title only" names a purpose,
// never a level (ruling Q5).
func orgIntelLevelLabel(level string) string {
	switch level {
	case "titles":
		return "Metadata and first prompt"
	case "excerpts":
		return "Metadata and bounded excerpts"
	default:
		return "Metadata only"
	}
}

// orgIntelPurposesLine names each purpose by its friendly label with the id
// beside it (ruling Q4: "Title only (structural_activity_insights)").
func orgIntelPurposesLine(purposes []string) string {
	if len(purposes) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(purposes))
	for _, p := range purposes {
		parts = append(parts, fmt.Sprintf("%s (%s)", cloudcontract.Purpose(p).Label(), p))
	}
	return strings.Join(parts, ", ")
}

// printOrgIntelStatus renders the status for `observer intel status`.
func printOrgIntelStatus(out io.Writer, snap orgIntelSnapshot, rail *dashapi.OrgIntelRailView) {
	st := snap.Status
	if st.Class == orgintel.ClassUnenrolled {
		fmt.Fprintln(out, "Not enrolled: there is no organization session enrichment on this machine. Personal Cloud Intelligence is `observer cloud`.")
		return
	}
	org := snap.Enrolment.OrgName
	if org == "" {
		org = snap.Enrolment.OrgID
	}
	fmt.Fprintf(out, "Organization: %s (%s tenancy)\n", org, st.Class)
	if snap.Body == nil {
		fmt.Fprintln(out, "Session enrichment: unknown (the organization's server has not sent its terms; it may predate this feature)")
		return
	}
	b := snap.Body
	if !b.Enabled {
		fmt.Fprintln(out, "Session enrichment: off (your organization has not turned it on)")
	} else {
		fmt.Fprintln(out, "Session enrichment: on")
	}
	provider := b.ProviderLabel
	if provider == "" {
		provider = "no provider configured"
	}
	model := b.Model
	if model == "" {
		model = "provider default"
	}
	fmt.Fprintf(out, "Provider / model:   %s / %s\n", provider, model)
	fmt.Fprintf(out, "Evidence level:     %s\n", orgIntelLevelLabel(b.EvidenceLevel))
	fmt.Fprintf(out, "Purposes:           %s\n", orgIntelPurposesLine(b.Purposes))
	if sw := orgintel.SweepFor(b); sw.On {
		fmt.Fprintf(out, "Background:         on (sessions idle %s with at least %d actions, up to %d days old)\n",
			sw.Quiet, sw.MinActions, int(sw.MaxAge.Hours()/24))
	} else {
		fmt.Fprintln(out, "Background:         off; sessions are enriched on demand only")
	}
	if st.NoticeOnly {
		fmt.Fprintln(out, "This machine is managed: your organization decides; there is nothing to accept.")
		if rail != nil {
			fmt.Fprintln(out, rail.Message)
		}
		return
	}
	switch {
	case st.Pending && st.PendingReason == orgintel.PendingTermsChanged:
		fmt.Fprintln(out, "Consent:            PENDING, the terms widened since you accepted; enrichment continues under your earlier terms. Run `observer intel accept` to review.")
	case st.Pending:
		fmt.Fprintf(out, "Consent:            PENDING, %s requires Cloud Intelligence. Accept (`observer intel accept`) or leave (`observer unenroll`).\n", org)
	case st.EffectiveOptIn:
		fmt.Fprintf(out, "Consent:            accepted (terms version %d)\n", snap.Active.RequirementVersion)
	default:
		fmt.Fprintln(out, "Consent:            not given; nothing is sent. Run `observer intel accept` to review the terms.")
	}
	if !st.DeadlineAt.IsZero() {
		fmt.Fprintf(out, "Deadline:           %s\n", st.DeadlineAt.Format(time.RFC3339))
	}
}
