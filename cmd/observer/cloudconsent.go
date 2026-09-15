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

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudgateway"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// cloudconsent.go is the CONSENT MANAGEMENT surface of `observer cloud consent`
// (divergence-remediation plan rev 4.1 §2 R2: "consent is revisitable — a
// dedicated settings surface in the node dashboard AND a CLI section
// (`observer cloud consent` grows list/grant/revoke management)"; the binding
// set is R1's).
//
// It sits ALONGSIDE the existing per-session flow, which is unchanged:
// `observer cloud consent --session <id> --purpose <p>` still confirms one
// previewed byte-string and enqueues it. The subcommands here manage STANDING
// grants, which authorize a SCHEMA rather than a byte-string:
//
//	observer cloud consent grant  --purpose structural_activity_insights
//	observer cloud consent revoke --purpose structural_activity_insights
//	observer cloud consent list
//
// Which purposes may be granted standing is NOT decided here — it is the
// purpose rule table in internal/cloudgateway, the same table the egress seam
// gates on, so the CLI can never offer a grant the gateway would not honor.

const (
	// cloudStandingGrantReviewMonths is how far ahead a standing grant's review
	// date is set. A grant that never expires is not a grant the developer keeps
	// choosing; twelve months is the review cadence R1 names.
	cloudStandingGrantReviewMonths = 12
	// cloudReceiptIDDisplayBytes is how much of a receipt id `list` shows. Ids
	// are prefix + 32 hex chars; the prefix plus a few bytes is enough to name
	// one on the command line without wrapping the table.
	cloudReceiptIDDisplayBytes = 14
)

// cloudStandingTerms is the wire term set ONE standing-grantable purpose
// binds: which endpoint it sends to, which schema version and data-dictionary
// digest describe its bytes, and which source-window rule it authorizes. Every
// one of these used to be hardcoded to the structural rail's values regardless
// of the purpose being granted — a community grant recorded and displayed the
// STRUCTURAL endpoint, schema, dictionary and window rule, so no receipt
// actually authorized the bytes/schema community sync went on to send (Sol
// review F2). This table is the single place those terms are sourced from.
type cloudStandingTerms struct {
	// endpoint resolves the CURRENT configured endpoint for this purpose's
	// rail, straight from the gateway (never a separately-hardcoded literal),
	// so the recorded receipt always binds the endpoint that rail actually
	// sends to.
	endpoint func(*cloudgateway.Gateway) (string, error)
	// envelopeSchemaVersion and dataDictionaryDigest name and fingerprint the
	// wire shape this purpose's uploads actually use.
	envelopeSchemaVersion string
	dataDictionaryDigest  func() string
	// sourceWindowRule is the versioned identifier of which activity this
	// purpose's standing grant covers, and sourceWindowRuleText is what that
	// identifier MEANS, printed beneath it on the binding screen so the
	// developer agrees to a stated rule, not to an opaque id.
	sourceWindowRule     string
	sourceWindowRuleText []string
	// fixedTimezone, when non-empty, pins the declared timezone for this
	// purpose: --timezone is refused unless it names exactly this zone, and
	// this zone is what is recorded, displayed and sent. Empty means the
	// developer's declared/host zone is used (the structural rail's day
	// windows). Community is UTC-fixed (Sol re-review N5): its windows are UTC
	// calendar months in the eligibility rule, the computation, the wire and
	// the hosted finalization, so any other declared zone would be a binding
	// term that changes nothing.
	fixedTimezone string
	// nextStep is the one-line "what to run now" printed after recording.
	nextStep string
	// fieldClasses are the cloudcontract.FieldClass values this purpose's
	// uploads can ever carry, recorded on the receipt and shown on the binding
	// screen.
	fieldClasses []string
}

// cloudStandingTermsByPurpose is the ONE table every standing grant's wire
// terms are read from (module rule #5: a rule table, not a growing if-ladder
// keyed on purpose). A purpose StandingGrantable() allows but absent here is a
// wiring defect — newCloudConsentGrantCmd fails closed rather than reusing
// another purpose's terms.
var cloudStandingTermsByPurpose = map[cloudcontract.Purpose]cloudStandingTerms{
	cloudcontract.PurposeStructuralInsights: {
		endpoint:              (*cloudgateway.Gateway).StructuralEndpoint,
		envelopeSchemaVersion: cloudcontract.StructuralSnapshotSchemaVersion,
		dataDictionaryDigest:  cloudcontract.StructuralDataDictionaryDigest,
		sourceWindowRule:      cloudStructuralSourceWindowRule,
		sourceWindowRuleText: []string{
			"completed calendar days in the declared timezone, trailing 30, from the day",
			"the grant is made; each day is captured once its clock has passed midnight",
		},
		fieldClasses: []string{string(cloudcontract.FieldClassStructuralMetrics)},
		nextStep:     "Run `observer cloud sync` to capture and send completed day windows.",
	},
	cloudcontract.PurposeCohortBenchmarking: {
		endpoint:              (*cloudgateway.Gateway).CommunityEndpoint,
		envelopeSchemaVersion: cloudcontract.CommunityContributionSchemaVersion,
		dataDictionaryDigest:  cloudcontract.CommunityDataDictionaryDigest,
		sourceWindowRule:      cloudCommunitySourceWindowRule,
		sourceWindowRuleText: []string{
			"the CURRENT, IN-PROGRESS UTC calendar month; the value is recomputed and",
			"re-sent on every sync until that month closes, then frozen server-side; the",
			"month you grant in is never contributed (first eligible month = the next one)",
		},
		fixedTimezone: cloudcontract.CommunityDeclaredTimezone,
		nextStep:      "Run `observer cloud sync` from next month on to contribute the in-progress month's value.",
		// Community contributions are a further aggregation of the same
		// structural session/verification counts — cloudcontract has no
		// dedicated community FieldClass, and inventing one for a value that
		// is semantically identical would be a distinction without a
		// difference.
		fieldClasses: []string{string(cloudcontract.FieldClassStructuralMetrics)},
	},
}

// newCloudConsentGrantCmd records a STANDING grant: the R1 binding set, printed
// in full before the confirmation prompt.
func newCloudConsentGrantCmd() *cobra.Command {
	var (
		configPath string
		baseURL    string
		purpose    string
		timezone   string
		yes        bool
	)
	cmd := &cobra.Command{
		Use:   "grant",
		Short: "Record a STANDING consent grant for a purpose (authorizes a schema, not one upload)",
		Long: "Records a standing consent grant. Unlike per-session consent (which binds the\n" +
			"exact bytes you previewed), a standing grant authorizes a SCHEMA: every future\n" +
			"upload under it still gets its own digest, its own local row, and a revocation\n" +
			"check immediately before it is sent.\n\n" +
			"The full binding is printed before you confirm. Revoke any time with\n" +
			"`observer cloud consent revoke --purpose <p>`.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := parseCloudPurpose(purpose)
			if err != nil {
				return err
			}
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)
			_, err = cloudRecordStandingGrant(cmd.Context(), st, cfg, p, baseURL, timezone, yes, cmd.InOrStdin(), cmd.OutOrStdout())
			return err
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "Cloud base URL (else $"+cloudBaseURLEnv+", else [cloud].base_url)")
	cmd.Flags().StringVar(&purpose, "purpose", "", "Consent purpose to grant standing (required)")
	cmd.Flags().StringVar(&timezone, "timezone", "", "IANA timezone the day windows are defined in (default: this host's zone)")
	cmd.Flags().BoolVar(&yes, "yes", false, "Skip the interactive confirmation")
	return cmd
}

// cloudRecordStandingGrant is the shared body of `observer cloud consent
// grant`'s RunE (extracted so `observer cloud enable` can record the SAME
// structural standing grant through the identical path — the same binding
// screen, the same supersede/generation logic, the same confirmation gate).
// cfg and st are already resolved by the caller; p is the already-parsed
// purpose. in/w are the confirmation prompt's reader/writer (cmd.InOrStdin()/
// cmd.OutOrStdout() from a cobra command, or the dashboard's own writer).
// The boolean is true only when the grant was recorded; declining is not success.
func cloudRecordStandingGrant(ctx context.Context, st *store.Store, cfg config.Config, p cloudcontract.Purpose, baseURLFlag, timezoneFlag string, yes bool, in io.Reader, w io.Writer) (bool, error) {
	if ok, reason := cloudgateway.StandingGrantable(p); !ok {
		return false, fmt.Errorf("%q cannot be granted standing consent: %s", string(p), reason)
	}
	terms, ok := cloudStandingTermsByPurpose[p]
	if !ok {
		// Defensive: StandingGrantable() said yes but this purpose has no
		// term set wired up above. The two tables are expected to stay in
		// lockstep; failing closed beats silently reusing another
		// purpose's terms (the exact bug Sol review F2 found).
		return false, fmt.Errorf("%q has no standing-grant term set wired up (internal error)", string(p))
	}
	zone, zoneNote, err := resolveDeclaredTimezone(timezoneFlag)
	if err != nil {
		return false, err
	}
	if terms.fixedTimezone != "" {
		zone, zoneNote, err = resolveFixedTimezone(p, terms.fixedTimezone, timezoneFlag)
		if err != nil {
			return false, err
		}
	}

	resolved := resolveCloudBaseURL(baseURLFlag, cfg)
	if resolved == "" {
		return false, fmt.Errorf("no cloud base URL — pass --base-url, set %s, or set [cloud].base_url in config.toml (the grant binds the upload endpoint)", cloudBaseURLEnv)
	}

	gw, err := openCloudGateway(cfg, resolved, "", st, nil)
	if err != nil {
		return false, err
	}
	thumbprint, err := gw.DeviceThumbprint()
	if err != nil {
		return false, err
	}
	endpoint, err := terms.endpoint(gw)
	if err != nil {
		return false, err
	}

	// The generation shown on the binding screen is a PREVIEW: it is
	// allocated for real inside ReplaceStandingConsentGrant's transaction
	// (F4 — a read here and an insert after an interactive prompt is a
	// race), and the recorded value is printed afterwards.
	priorGen, err := st.MaxCloudConsentGeneration(ctx, string(p))
	if err != nil {
		return false, err
	}
	superseded, err := cloudLiveStandingReceipts(ctx, st, p)
	if err != nil {
		return false, err
	}
	now := time.Now().UTC()
	reviewAt := now.AddDate(0, cloudStandingGrantReviewMonths, 0)
	receipt := store.CloudConsentReceipt{
		AccountPseudonym:       thumbprint,
		DeviceLabelRef:         thumbprint,
		Purpose:                string(p),
		FieldClassesJSON:       cloudStandingFieldClassesJSON(p),
		EnvelopeSchemaVersion:  terms.envelopeSchemaVersion,
		ScrubberVersion:        cloudScrubberVersion,
		Endpoint:               endpoint,
		RetentionPolicyVersion: cloudRetentionPolicyVersion,
		// A standing grant has no single upload to bind, so the receipt's
		// upload_digest carries the DATA-DICTIONARY digest — the
		// schema-level thing it actually authorizes (migration 098's reuse
		// note). DataDictionaryDigest carries the same value explicitly.
		UploadDigest:         terms.dataDictionaryDigest(),
		DataDictionaryDigest: terms.dataDictionaryDigest(),
		CreatedAt:            now,
		GrantMode:            store.CloudGrantStanding,
		DeclaredTimezone:     zone,
		SourceWindowRule:     terms.sourceWindowRule,
		ReviewAt:             &reviewAt,
		ConsentGeneration:    priorGen + 1,
	}

	cloudPrintStandingBinding(w, receipt, zoneNote)
	cloudPrintSupersedeWarning(w, superseded)
	if !yes {
		ok, cerr := cloudConfirm(in, w, "Record this standing grant?")
		if cerr != nil {
			return false, cerr
		}
		if !ok {
			fmt.Fprintln(w, "Aborted — nothing recorded, and nothing will be sent.")
			return false, nil
		}
	}

	rep, err := st.ReplaceStandingConsentGrant(ctx, receipt)
	if err != nil {
		return false, fmt.Errorf("record standing grant: %w", err)
	}
	fmt.Fprintf(w, "Recorded standing grant %s (generation %d).\n", rep.ReceiptID, rep.ConsentGeneration)
	if n := len(rep.SupersededReceiptIDs); n > 0 {
		fmt.Fprintf(w, "Superseded %d prior standing grant(s) for this purpose; %d queued snapshot(s) now need\n",
			n, rep.RequeuedForReconfirmation)
		fmt.Fprintln(w, "  reconfirmation and will NOT be sent under the new grant until they are re-captured.")
		// N2: the supersede cancelled the old receipts' dispatch leases
		// inside its transaction; now wait until none is still held, so
		// this command does not return while a send under the retired
		// terms can still begin. Bounded by the lease TTL.
		if err := cloudAwaitRetiredDispatch(ctx, st, rep.SupersededReceiptIDs, w); err != nil {
			return false, err
		}
	}
	fmt.Fprintln(w, terms.nextStep)
	return true, nil
}

// cloudPrintStandingBinding prints the ENTIRE R1 binding set on one screen,
// before the confirmation prompt. Everything the receipt will bind is shown —
// there is no field a developer agrees to without seeing it.
func cloudPrintStandingBinding(w io.Writer, r store.CloudConsentReceipt, zoneNote string) {
	fmt.Fprintf(w, "Standing consent grant — %s\n", r.Purpose)
	fmt.Fprintln(w, "  This authorizes a SCHEMA, not one upload. Every snapshot sent under it still")
	fmt.Fprintln(w, "  gets its own digest, its own local record, and a revocation check before it")
	fmt.Fprintln(w, "  is sent. Revoke any time; pending snapshots are cancelled with it.")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  purpose:                  %s\n", r.Purpose)
	fmt.Fprintf(w, "  grant mode:               %s\n", r.GrantMode)
	fmt.Fprintf(w, "  schema version:           %s\n", r.EnvelopeSchemaVersion)
	fmt.Fprintf(w, "  data-dictionary digest:   %s\n", r.DataDictionaryDigest)
	fmt.Fprintf(w, "  field classes:            %s\n", cloudFieldClassesDisplay(r.FieldClassesJSON))
	fmt.Fprintf(w, "  retention policy version: %s\n", r.RetentionPolicyVersion)
	fmt.Fprintf(w, "  declared timezone:        %s (%s)\n", r.DeclaredTimezone, zoneNote)
	fmt.Fprintf(w, "  source window rule:       %s\n", r.SourceWindowRule)
	for _, line := range cloudStandingTermsByPurpose[cloudcontract.Purpose(r.Purpose)].sourceWindowRuleText {
		fmt.Fprintf(w, "                            = %s\n", line)
	}
	fmt.Fprintf(w, "  endpoint:                 %s\n", r.Endpoint)
	fmt.Fprintf(w, "  review date:              %s\n", cloudDisplayTime(r.ReviewAt))
	fmt.Fprintf(w, "  consent generation:       %d\n", r.ConsentGeneration)
	fmt.Fprintln(w)
	for _, line := range cloudStandingDisclosureLines(cloudcontract.Purpose(r.Purpose)) {
		fmt.Fprintln(w, line)
	}
}

// cloudStandingDisclosureByPurpose is the purpose-specific "what this actually
// contains" paragraph shown before a standing grant is confirmed. Reusing one
// closing paragraph for every purpose described the STRUCTURAL snapshot's
// contents under a community grant too — the exact overstated-disclosure bug
// Sol review F2 found (this function used to be a single hardcoded paragraph
// at the end of cloudPrintStandingBinding).
var cloudStandingDisclosureByPurpose = map[cloudcontract.Purpose][]string{
	cloudcontract.PurposeStructuralInsights: {
		"  What a snapshot contains: one row per completed day — counts of sessions and",
		"  actions, the tool and model-family mix, token and cost sums, and two coverage",
		"  bands with their raw numerators. No paths, no commands, no excerpts, no repo",
		"  identity, no per-session rows. Only sessions classified PERSONAL are counted.",
	},
	cloudcontract.PurposeCohortBenchmarking: {
		"  What a contribution contains: one value per metric for the CURRENT, IN-PROGRESS",
		"  UTC calendar month — sessions per active day, and verification coverage as a",
		"  percentage — rounded to the published precision and folded into a global cohort",
		"  aggregate. The value is recomputed from this month's sessions so far and",
		"  re-sent on every sync until that month closes; after the close the server",
		"  freezes the last value it received and no later send can change it. No paths,",
		"  no commands, no excerpts, no repo identity, no per-session or per-day rows.",
		"  Windows are UTC months everywhere (the declared timezone is fixed to UTC). The",
		"  month you grant in is never contributed: the first eligible month is the next",
		"  one, so nothing from before this grant existed is ever folded into a value.",
	},
}

// cloudStandingDisclosureLines returns p's disclosure paragraph, or nil for a
// purpose with none decided — never another purpose's text.
func cloudStandingDisclosureLines(p cloudcontract.Purpose) []string {
	return cloudStandingDisclosureByPurpose[p]
}

// cloudLiveStandingReceipts returns the live STANDING receipts a new grant for
// the same purpose would supersede.
func cloudLiveStandingReceipts(ctx context.Context, st *store.Store, p cloudcontract.Purpose) ([]store.CloudConsentReceipt, error) {
	live, err := st.ListLiveCloudConsentReceipts(ctx, string(p))
	if err != nil {
		return nil, err
	}
	var out []store.CloudConsentReceipt
	for _, r := range live {
		if r.GrantMode == store.CloudGrantStanding {
			out = append(out, r)
		}
	}
	return out, nil
}

// cloudPrintSupersedeWarning states, BEFORE the confirmation, that recording
// this grant retires the one already in force and what that does to anything
// queued under it. There is exactly one live standing grant per purpose, and a
// developer must not discover that by finding their windows parked.
func cloudPrintSupersedeWarning(w io.Writer, superseded []store.CloudConsentReceipt) {
	if len(superseded) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  THIS SUPERSEDES the standing grant already in force for this purpose (%s",
		cloudShortReceiptID(superseded[0].ID))
	for _, r := range superseded[1:] {
		fmt.Fprintf(w, ", %s", cloudShortReceiptID(r.ID))
	}
	fmt.Fprintln(w, ").")
	fmt.Fprintln(w, "  It is revoked as part of recording this one, so only ONE standing grant is ever live.")
	fmt.Fprintln(w, "  Snapshots already queued under it are NOT sent and NOT deleted: they move to")
	fmt.Fprintln(w, "  reconfirmation_required, because they were built under the terms you are replacing.")
}

// newCloudConsentRevokeCmd invalidates a standing grant and cancels every
// pending snapshot bound to it.
func newCloudConsentRevokeCmd() *cobra.Command {
	var (
		configPath string
		purpose    string
	)
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke a standing consent grant and cancel anything queued under it",
		Long: "Invalidates every live standing grant for a purpose and cancels the queued\n" +
			"snapshots bound to them, so nothing already prepared can still be sent. It is\n" +
			"purely local and makes no network call.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := parseCloudPurpose(purpose)
			if err != nil {
				return err
			}
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)
			return cloudRevokeStanding(cmd.Context(), st, p, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&purpose, "purpose", "", "Consent purpose to revoke (required)")
	return cmd
}

// cloudRevokeStanding is the shared body of `observer cloud consent revoke`'s
// RunE (extracted so `observer cloud disable` can revoke the same structural
// standing grant through the identical path). It invalidates every live
// standing grant for p and cancels the snapshots queued under them; purely
// local, no network call. A purpose with no live standing grant is a no-op
// that says so, not an error.
func cloudRevokeStanding(ctx context.Context, st *store.Store, p cloudcontract.Purpose, w io.Writer) error {
	live, err := st.ListLiveCloudConsentReceipts(ctx, string(p))
	if err != nil {
		return err
	}
	var (
		revoked, cancelled int
		revokedIDs         []string
	)
	for _, r := range live {
		if r.GrantMode != store.CloudGrantStanding {
			continue // per-session receipts are revoked with their session flow
		}
		if err := st.InvalidateCloudConsentReceipt(ctx, r.ID); err != nil {
			return fmt.Errorf("revoke %s: %w", r.ID, err)
		}
		revoked++
		revokedIDs = append(revokedIDs, r.ID)
		n, cerr := st.CancelCloudOutboxForReceipt(ctx, r.ID)
		if cerr != nil {
			return fmt.Errorf("cancel queued items for %s: %w", r.ID, cerr)
		}
		cancelled += n
		// N2: no NEW dispatch lease can be taken under the receipt now
		// that it is invalidated; mark the held ones cancelled, and
		// wait for them below before promising anything.
		if _, lerr := st.CancelCloudDispatchLeasesForReceipt(ctx, r.ID); lerr != nil {
			return fmt.Errorf("cancel dispatch leases for %s: %w", r.ID, lerr)
		}
	}
	if revoked == 0 {
		fmt.Fprintf(w, "No live standing grant for %q — nothing to revoke.\n", string(p))
		return nil
	}
	fmt.Fprintf(w, "Revoked %d standing grant(s) for %q and cancelled %d queued item(s).\n",
		revoked, string(p), cancelled)
	if err := cloudAwaitRetiredDispatch(ctx, st, revokedIDs, w); err != nil {
		return err
	}
	fmt.Fprintln(w, "Nothing further will be sent under them. Data already delivered is removed")
	fmt.Fprintln(w, "through `observer cloud delete-account`, not by revoking a grant.")
	return nil
}

// newCloudConsentListCmd shows every recorded receipt. It is content-free: a
// receipt carries purposes, versions, digests and timestamps, never session data.
func newCloudConsentListCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List every consent receipt recorded on this device",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			w := cmd.OutOrStdout()
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)

			receipts, err := st.ListCloudConsentReceipts(cmd.Context())
			if err != nil {
				return err
			}
			if len(receipts) == 0 {
				fmt.Fprintln(w, "No consent receipts on this device — nothing has ever been authorized to leave it.")
				cloudPrintGrantableHelp(w)
				return nil
			}
			fmt.Fprintf(w, "%-16s %-30s %-11s %-11s %-11s %s\n",
				"RECEIPT", "PURPOSE", "MODE", "CREATED", "REVIEW", "STATE")
			for _, r := range receipts {
				state := "live"
				if r.InvalidatedAt != nil {
					state = "revoked " + r.InvalidatedAt.Format("2006-01-02")
				}
				mode := string(r.GrantMode)
				if mode == "" {
					mode = string(store.CloudGrantPerUpload)
				}
				fmt.Fprintf(w, "%-16s %-30s %-11s %-11s %-11s %s\n",
					cloudShortReceiptID(r.ID), r.Purpose, mode,
					cloudDisplayDay(r.CreatedAt), cloudDisplayTime(r.ReviewAt), state)
			}
			cloudPrintGrantableHelp(w)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	return cmd
}

// cloudPrintGrantableHelp names, honestly, which purposes can be granted
// standing right now and why the others cannot (honest-disabled-copy
// discipline: locked, never hidden).
func cloudPrintGrantableHelp(w io.Writer) {
	fmt.Fprintln(w)
	for _, p := range cloudcontract.AllPurposes() {
		if lane, ok := cloudgateway.LaneFor(p); !ok || lane == cloudgateway.LaneBootstrap {
			continue
		}
		if ok, _ := cloudgateway.StandingGrantable(p); ok {
			fmt.Fprintf(w, "  %s: grant with `observer cloud consent grant --purpose %s`\n", p, p)
			continue
		}
		_, reason := cloudgateway.StandingGrantable(p)
		fmt.Fprintf(w, "  %s: not grantable — %s\n", p, reason)
	}
}

// cloudPrintGrantSummary adds a content-free consent line to `observer cloud
// status`: how many receipts are live, and whether the structural rail is
// authorized at all. It degrades to silence rather than failing the command.
func cloudPrintGrantSummary(ctx context.Context, st *store.Store, w io.Writer) {
	live, err := st.ListLiveCloudConsentReceipts(ctx, "")
	if err != nil {
		return
	}
	var standing int
	for _, r := range live {
		if r.GrantMode == store.CloudGrantStanding {
			standing++
		}
	}
	fmt.Fprintf(w, "  live consent grants: %d (%d standing)\n", len(live), standing)
	if standing == 0 {
		fmt.Fprintln(w, "  structural rail:     not authorized — `observer cloud consent grant --purpose structural_activity_insights`")
	}
}

// --- helpers ----------------------------------------------------------------

// resolveDeclaredTimezone resolves the IANA zone a standing grant declares. The
// zone is part of what the developer agrees to (it decides what a "day" means),
// so this returns a NOTE explaining where the value came from, which the binding
// screen prints — a sniffed default is stated, never silent.
//
// A host with no named zone (or one this build's tzdata cannot load) falls back
// to UTC rather than guessing, and says so.
func resolveDeclaredTimezone(flagVal string) (zone, note string, err error) {
	if v := strings.TrimSpace(flagVal); v != "" {
		if _, lerr := time.LoadLocation(v); lerr != nil {
			return "", "", fmt.Errorf("--timezone %q is not a loadable IANA zone name: %w", v, lerr)
		}
		return v, "declared with --timezone", nil
	}
	name := time.Now().Location().String()
	if name == "" || name == "Local" {
		return "UTC", "this host exposes no named IANA zone, so UTC was recorded — pass --timezone to set it deliberately", nil
	}
	if _, lerr := time.LoadLocation(name); lerr != nil {
		return "UTC", fmt.Sprintf("this host's zone %q could not be loaded, so UTC was recorded — pass --timezone to set it deliberately", name), nil
	}
	return name, "taken from this host's clock", nil
}

// resolveFixedTimezone applies a purpose's pinned timezone (N5): an explicit
// --timezone naming any OTHER zone is refused with the reason, and the pinned
// zone is what gets recorded, with a note saying it was pinned rather than
// taken from the host.
func resolveFixedTimezone(p cloudcontract.Purpose, fixed, flagVal string) (zone, note string, err error) {
	if v := strings.TrimSpace(flagVal); v != "" && v != fixed {
		return "", "", fmt.Errorf("--timezone %q is not accepted for %s: this purpose's windows are %s calendar months "+
			"everywhere (eligibility, computation, wire and hosted finalization), so its declared timezone is fixed to %s "+
			"— omit --timezone or pass --timezone %s", v, string(p), fixed, fixed, fixed)
	}
	return fixed, fmt.Sprintf("fixed for this purpose — windows are %s calendar months", fixed), nil
}

// cloudDispatchLeaseFor is the production DispatchLease (Sol re-review N2) both
// standing rails hand the gateway: the store's cross-process lease under the
// EXACT receipt + consent generation the bytes were built under, bounded by
// the per-attempt HTTP timeout. One helper, so neither rail can wire it
// differently.
func cloudDispatchLeaseFor(st *store.Store, receiptID string, purpose cloudcontract.Purpose, generation int) cloudgateway.DispatchLease {
	return cloudDispatchLeaseForMode(st, receiptID, purpose, generation, store.CloudGrantStanding)
}

func cloudDispatchLeaseForMode(st *store.Store, receiptID string, purpose cloudcontract.Purpose, generation int, mode store.CloudGrantMode) cloudgateway.DispatchLease {
	return func(ctx context.Context) (time.Time, func(), error) {
		lease, err := st.AcquireCloudDispatchLease(ctx, store.CloudDispatchLeaseRequest{
			ReceiptID:         receiptID,
			GrantMode:         mode,
			Purpose:           string(purpose),
			ConsentGeneration: generation,
			TTL:               cloudgateway.DispatchLeaseTTL,
		})
		if err != nil {
			return time.Time{}, nil, err
		}
		release := func() { _ = st.ReleaseCloudDispatchLease(context.WithoutCancel(ctx), lease.ID) }
		return lease.ExpiresAt, release, nil
	}
}

// cloudAwaitRetiredDispatch waits until no dispatch lease under the retired
// receipts is still held (N2), so revoke / supersede never return while a send
// under the old terms can still begin. It says what it waited for; the wait is
// bounded by the lease TTL (the per-attempt HTTP timeout).
func cloudAwaitRetiredDispatch(ctx context.Context, st *store.Store, receiptIDs []string, w io.Writer) error {
	waited, err := st.AwaitCloudDispatchQuiescence(ctx, receiptIDs)
	if err != nil {
		return fmt.Errorf("wait for in-flight sends under the retired grant to finish: %w", err)
	}
	if waited > 0 {
		fmt.Fprintf(w, "Waited for %d in-flight send(s) under the retired grant to finish; none can begin now.\n", waited)
	}
	return nil
}

// cloudStandingFieldClassesJSON records the field classes a standing grant
// binds, read from cloudStandingTermsByPurpose — never a purpose-name string
// masquerading as a FieldClass (the placeholder this function used to fall
// back to for any non-structural purpose, which is not a member of
// cloudcontract's closed FieldClass vocabulary at all).
func cloudStandingFieldClassesJSON(p cloudcontract.Purpose) string {
	terms, ok := cloudStandingTermsByPurpose[p]
	if !ok {
		// Defensive: no field-class decision exists for this purpose. Saying
		// nothing beats reusing another purpose's classes or fabricating one.
		return "[]"
	}
	b, _ := json.Marshal(terms.fieldClasses)
	return string(b)
}

// cloudFieldClassesDisplay renders a receipt's field-class JSON for the binding
// screen, falling back to the raw column when it is not a JSON array.
func cloudFieldClassesDisplay(raw string) string {
	var classes []string
	if err := json.Unmarshal([]byte(raw), &classes); err != nil || len(classes) == 0 {
		return raw
	}
	sort.Strings(classes)
	return strings.Join(classes, ", ")
}

// cloudShortReceiptID truncates a receipt id for table display.
func cloudShortReceiptID(id string) string {
	if len(id) <= cloudReceiptIDDisplayBytes {
		return id
	}
	return id[:cloudReceiptIDDisplayBytes]
}

// cloudDisplayDay renders a stored timestamp as a date, or "-" when zero.
func cloudDisplayDay(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format("2006-01-02")
}

// cloudDisplayTime renders an optional stored timestamp as a date, or "(none)".
func cloudDisplayTime(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "(none)"
	}
	return t.UTC().Format("2006-01-02")
}
