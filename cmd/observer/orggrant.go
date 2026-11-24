package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/govern/sidecar"
	"github.com/marmutapp/superbased-observer/internal/grantverify"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/orgenrol"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Admin-controlled Plane B, the CLI consent surface
// (docs/plans/admin-controlled-plane-b-spec-2026-08-15.md §2.3/§2.4,
// adversarial review A4). The grant is written HERE and nowhere else:
// internal/orgclient has no TTY and, by the time it holds the response, it
// has already saved the bearer, written the enrolment and bumped the
// generation — there is no honest place there to ask a human anything.

// authorityPlainEnglish is the plain-language rendering of each authority
// token. The wording lives in internal/orgenrol so the CLI prompt and the
// dashboard consent screen show the same sentence for the same token.
func authorityPlainEnglish(tok string) string { return orgenrol.AuthorityPlainEnglish(tok) }

// consentModeForTenancy is grantverify.ConsentModeForTenancy, the one owner
// of the tenancy -> consent-mode rule (the stored-grant verifier admits the
// unsigned consent candidate on exactly this mode). grantConsent prefers the
// organization's own statement when there is one.
func consentModeForTenancy(tenancy string) string { return grantverify.ConsentModeForTenancy(tenancy) }

// grantConsent is the resolved answer to "who consented to this grant, how,
// and does this command still need to ask".
type grantConsent struct {
	Mode  string
	Actor string
	// AlreadyGiven is true when the consent act happened OUTSIDE this
	// process and re-prompting would be theatre, not diligence. Today that
	// means exactly one thing: an ACP-P6c browser approval after an
	// enterprise-IdP sign-in.
	AlreadyGiven bool
	// Summary is the one line printed in place of the prompt, naming who
	// consented and where.
	Summary string
}

// unnamedConsentActor is recorded when the organization declares a consent
// mode but no actor. It is deliberately NOT the local username: the whole
// value of an IdP-declared mode is that the actor is server-verified, and
// substituting $USER would dress an unverified local name up as one.
const unnamedConsentActor = "unknown"

// resolveGrantConsent decides what to record, preferring the ORGANISATION's
// declared consent mode over the node's tenancy-derived guess.
//
// Preference, and why: on the IdP rail the developer already proved who they
// are to the organization's identity provider and approved this enrolment in a
// browser. That is a strictly stronger consent record than a y/N on a terminal
// attributed to a spoofable $USER, so it wins — and the actor recorded is the
// verified address rather than the local username.
//
// It returns a non-empty `problem` for a declaration this node refuses. The
// caller then enrols UNGOVERNED, which is what every other grant refusal in
// this codebase does: the failure mode being defended against is recording
// managed-class consent that nobody managed-class ever gave.
//
// Two refusals, both narrow:
//   - "idp" on a NON-managed enrolment. ConsentIdP is managed-class
//     (govern.ManagedConsent), so accepting it on an individual enrolment
//     would hand managed-only authority to a node whose tenancy never
//     unlocked it. That combination cannot come from a correct server.
//   - a mode this build does not recognise, which is refused rather than
//     silently downgraded, so an operator finds out that their server is
//     asserting something this Observer cannot honour.
func resolveGrantConsent(offer *orgclient.GrantOffer) (grantConsent, string) {
	switch offer.ConsentMode {
	case "":
		// The token rail: no organization statement, so the node decides from
		// tenancy exactly as it did before ACP-P6c.
		return grantConsent{
			Mode:  consentModeForTenancy(offer.Tenancy),
			Actor: localConsentActor(),
		}, ""
	case govern.ConsentIdP:
		if offer.Tenancy != orgcontract.TenancyManaged {
			return grantConsent{}, "the organization says this enrolment was consented to by an identity-provider sign-in, " +
				"but it did not enrol this machine as organization-managed. Those two cannot both be true"
		}
		actor := strings.TrimSpace(offer.ConsentActor)
		if actor == "" {
			actor = unnamedConsentActor
		}
		return grantConsent{
			Mode:         govern.ConsentIdP,
			Actor:        actor,
			AlreadyGiven: true,
			Summary: fmt.Sprintf("Consent recorded from the organization sign-in approved by %s.\n"+
				"  That browser approval was the consent, so this command does not ask again.", actor),
		}, ""
	case govern.ConsentManaged:
		// A server restating what tenancy already implies. Accepted on a
		// managed enrolment because it grants nothing the tenancy did not
		// already grant - and crucially it does NOT skip the prompt: no
		// consent act happened anywhere else, so this command still has to
		// ask. Refusing a term this build's own vocabulary defines would be
		// an odd asymmetry.
		if offer.Tenancy != orgcontract.TenancyManaged {
			return grantConsent{}, "the organization declared managed consent for an enrolment it did not mark as organization-managed"
		}
		actor := strings.TrimSpace(offer.ConsentActor)
		if actor == "" {
			actor = localConsentActor()
		}
		return grantConsent{Mode: govern.ConsentManaged, Actor: actor}, ""
	default:
		return grantConsent{}, fmt.Sprintf("the organization declared a consent mode this version of Observer does not understand (%q)", offer.ConsentMode)
	}
}

// confirmAndStoreGrant prints the offered grant, obtains consent, and stores
// it. The rules, in the order they matter:
//
//   - an organization that itself carried out the consent act (the ACP-P6c
//     IdP browser approval) is not asked again: the developer already proved
//     who they are and approved this enrolment, and a second y/N would be
//     theatre. The full authority summary is STILL printed - the developer
//     must be able to read what was granted on the machine it applies to;
//   - a TTY gets an explicit y/N prompt naming every authority token;
//   - no TTY and no --accept-governance means ENROL WITHOUT THE GRANT, with
//     a loud warning naming the flag. Silently accepting governance because
//     nobody was watching would make the consent claim false, and the admin
//     sees an ungoverned node in fleet state, which is the honest signal;
//   - declining is not an error: the node is enrolled and ungoverned.
//
// grantOutcome is what confirmAndStoreGrant decided, for callers that need
// to act on an ACCEPTED grant (W-5: managed enrolment auto-writes the
// node-side [org_client.policy] consent for the families the accepted
// grant's authority governs). Every early-return path (refused, declined,
// no-TTY-no-flag) leaves Accepted false, which is the caller's single signal
// that nothing should be written.
type grantOutcome struct {
	// Accepted is true only when a human actually agreed to the grant, or
	// the organization itself already carried out the consent act
	// (ACP-P6c IdP browser approval).
	Accepted bool
	// Managed reports whether the enrolment that produced this grant is
	// organization-managed, as opposed to individual/BYO. Mirrors
	// offer.Tenancy == orgcontract.TenancyManaged — the same signal
	// govern.HonoredAuthority uses to decide whether managed-only
	// authorities are honoured at all.
	Managed bool
	// Authority is the raw token list from the accepted grant, unfiltered
	// (including tokens this build does not recognise).
	Authority []string
}

func confirmAndStoreGrant(cmd *cobra.Command, st *store.Store, offer *orgclient.GrantOffer, accept bool) (grantOutcome, error) {
	out := cmd.OutOrStdout()
	printGrantOffer(out, offer)

	consent, problem := resolveGrantConsent(offer)
	if problem != "" {
		fmt.Fprintf(out, "\nGrant REFUSED: %s.\n", problem)
		fmt.Fprintln(out, "  This machine is enrolled and reporting, but NOT governed. Nothing was recorded.")
		fmt.Fprintln(out, "  Tell your administrator what this said - it means the server and this machine")
		fmt.Fprintln(out, "  disagree about how this enrolment was authorised.")
		return grantOutcome{}, nil
	}

	switch {
	case consent.AlreadyGiven:
		fmt.Fprintln(out, "\n"+consent.Summary)
	case accept:
		fmt.Fprintln(out, "\nAccepted via --accept-governance.")
	case isInteractiveTerminal(cmd):
		ok, err := promptYesNo(cmd, "Accept these settings from this organization? [y/N]: ")
		if err != nil {
			return grantOutcome{}, err
		}
		if !ok {
			fmt.Fprintln(out, "\nDeclined. This machine is enrolled and reporting, but NOT governed:")
			fmt.Fprintln(out, "  nothing about this dashboard will be changed by the organization.")
			return grantOutcome{}, nil
		}
	default:
		fmt.Fprintln(out, "\nNot accepted: this is not an interactive terminal and --accept-governance was not passed.")
		fmt.Fprintln(out, "  This machine is enrolled and reporting, but NOT governed. Re-run `observer enroll`")
		fmt.Fprintln(out, "  interactively, or pass --accept-governance, to accept the settings above.")
		return grantOutcome{}, nil
	}

	gOut, err := storeGrantOffer(cmd.Context(), st, offer, consent)
	if err != nil {
		return grantOutcome{}, err
	}
	fmt.Fprintln(out, "Recorded. Run `observer org grant show` at any time to see exactly what this machine granted,")
	fmt.Fprintln(out, "and `observer unenroll` to revoke it.")
	return gOut, nil
}

// storeGrantOffer writes an offered grant under a resolved consent. It is the
// ONE grant writer: the CLI prompt above and the dashboard consent screen
// (orgenrol_dashboard.go) both decide consent their own way and then record
// it here, so the stored row is identical whichever surface was used.
func storeGrantOffer(ctx context.Context, st *store.Store, offer *orgclient.GrantOffer, consent grantConsent) (grantOutcome, error) {
	row := store.EnrolmentGrant{
		OrgKey:       offer.OrgKey,
		Generation:   offer.Generation,
		OrgID:        offer.Grant.OrgID,
		OrgName:      offer.Grant.OrgID,
		OrgServerURL: offer.Grant.OrgServerURL,
		KeyPinSHA256: offer.KeyPinSHA256,
		Authority:    offer.Grant.Authority,
		// Managed-class consent (govern.ManagedConsent: managed tenancy, or
		// an IdP-verified browser approval) is the signal
		// govern.HonoredAuthority / the resolver branch on to honour the
		// managed-only authorities (enforce.*/extract.managed) this grant
		// carries. An individual enrolment stays ConsentInteractive, so those
		// authorities remain inert even if the grant lists them. The actor is
		// the organization-verified identity when there is one, and the local
		// username only when the consent act happened here.
		ConsentMode:  consent.Mode,
		ConsentActor: consent.Actor,
		GrantedAt:    parseRFC3339OrNow(offer.Grant.GrantedAt),
		ExpiresAt:    parseRFC3339OrZero(offer.Grant.ExpiresAt),
		// The SIGNED window, set at the one moment it is by definition
		// identical to ExpiresAt (review M1). Without it, migration 083's
		// NOT NULL DEFAULT '' leaves it empty on every fresh enrolment, the
		// derived renewal TTL is NEGATIVE, and renewal silently never fires
		// for any node enrolled after Phase 1b ships.
		SignedExpiresAt: parseRFC3339OrZero(offer.Grant.ExpiresAt),
		Signature:       offer.Grant.Signature,
		ReceiptHash:     offer.ReceiptHash,
		// The signed initial component set (modular packaging P4): stored
		// with the grant because it is bound into the signature, and read by
		// every process that resolves component state.
		InitialComponents: offer.Grant.InitialComponents,
	}
	if err := st.WriteEnrolmentGrant(ctx, row); err != nil {
		return grantOutcome{}, fmt.Errorf("observer enroll: could not record the governance grant: %w", err)
	}
	return grantOutcome{
		Accepted:  true,
		Managed:   offer.Tenancy == orgcontract.TenancyManaged,
		Authority: offer.Grant.Authority,
	}, nil
}

// grantDisclosure is the consent screen for an offer, built by the one pure
// renderer the dashboard also uses (internal/orgenrol).
func grantDisclosure(offer *orgclient.GrantOffer, orgName ...string) orgenrol.Disclosure {
	name := ""
	if len(orgName) > 0 {
		name = orgName[0]
	}
	return orgenrol.BuildDisclosure(orgenrol.GrantFacts{
		OrgName:      name,
		OrgID:        offer.Grant.OrgID,
		ServerURL:    offer.Grant.OrgServerURL,
		ExpiresAt:    offer.Grant.ExpiresAt,
		Authority:    offer.Grant.Authority,
		Managed:      offer.Tenancy == orgcontract.TenancyManaged,
		OwnerManaged: offer.OwnerManaged,
	})
}

// printGrantOffer renders the offer. Plain hyphens, no em-dashes (the
// user-facing copy rule). The W-5 config-write disclosure (managed sign-in IS
// the consent, so accepting on a managed enrolment also writes the node-side
// [org_client.policy] keys those authorities need - see
// ensureManagedPolicyBlock) is said here, before the prompt, so the write is
// never a surprise.
func printGrantOffer(out io.Writer, offer *orgclient.GrantOffer) {
	d := grantDisclosure(offer)
	fmt.Fprintln(out)
	fmt.Fprintln(out, orgenrol.DisclosureIntro)
	fmt.Fprintf(out, "  Organization: %s\n", d.OrgID)
	fmt.Fprintf(out, "  Server:       %s\n", d.ServerURL)
	if d.ExpiresAt != "" {
		fmt.Fprintf(out, "  Expires:      %s (after this, local settings apply again)\n", d.ExpiresAt)
	}
	if d.Owner != "" {
		fmt.Fprintln(out)
		fmt.Fprintln(out, wrapIndented(d.Owner, "", ""))
	}
	fmt.Fprintln(out, "\nIf you accept, the organization may:")
	for _, l := range d.May {
		fmt.Fprintf(out, "  - %s\n     (%s)\n", l.Text, l.Token)
	}
	if len(d.ConfigWrites) > 0 {
		fmt.Fprintln(out, "\nAccepting will also write to this machine's config.toml:")
		for _, w := range d.ConfigWrites {
			fmt.Fprintf(out, "  %s\n", w)
		}
		fmt.Fprintln(out, wrapIndented(orgenrol.DisclosureConfigWritesNote, "  ", "  "))
	}
	if d.ManagedSummary != "" {
		fmt.Fprintln(out)
		fmt.Fprintln(out, wrapIndented(d.ManagedSummary, "", ""))
		for _, line := range d.ManagedLines {
			fmt.Fprintln(out, wrapIndented(line, "  - ", "     "))
		}
	}
	fmt.Fprintln(out, "\nIt may NOT:")
	for _, line := range d.MayNot {
		fmt.Fprintln(out, wrapIndented(line, "  - ", "     "))
	}
}

// wrapIndented word-wraps text at 78 columns: the first line is prefixed with
// first, continuation lines with rest.
func wrapIndented(text, first, rest string) string {
	const width = 78
	var b strings.Builder
	line := first
	lineHasWord := false
	for _, w := range strings.Fields(text) {
		if lineHasWord && len(line)+1+len(w) > width {
			b.WriteString(line)
			b.WriteByte('\n')
			line = rest
			lineHasWord = false
		}
		if lineHasWord {
			line += " "
		}
		line += w
		lineHasWord = true
	}
	b.WriteString(line)
	return b.String()
}

func localConsentActor() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u := os.Getenv("USERNAME"); u != "" {
		return u
	}
	return "local"
}

func parseRFC3339OrNow(s string) time.Time {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC()
	}
	return time.Now().UTC()
}

func parseRFC3339OrZero(s string) time.Time {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

// isInteractiveTerminal reports whether stdin is a real terminal. A cobra
// command whose InOrStdin is not os.Stdin (tests, pipes) is never
// interactive.
func isInteractiveTerminal(cmd *cobra.Command) bool {
	f, ok := cmd.InOrStdin().(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

func promptYesNo(cmd *cobra.Command, prompt string) (bool, error) {
	fmt.Fprint(cmd.OutOrStdout(), "\n"+prompt)
	reader := bufio.NewReader(cmd.InOrStdin())
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		return false, nil // EOF with no answer is a decline, never a crash
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

// newOrgGrantCmd is `observer org grant`. Its one subcommand prints the full
// stored grant with a verify line, so the developer (or an auditor) can
// always read what this machine handed over and to whom.
func newOrgGrantCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "grant",
		Short: "Show the organization governance grant this machine recorded at enrolment",
	}
	cmd.AddCommand(newOrgGrantShowCmd())
	return cmd
}

func newOrgGrantShowCmd() *cobra.Command {
	var configPath string
	c := &cobra.Command{
		Use:   "show",
		Short: "Print the recorded enrolment grant and what it authorises",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, err := buildOrgBundle(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer b.cleanup()
			rep, err := collectGrantShow(cmd.Context(), b, configPath)
			if err != nil {
				return err
			}
			printGrantShow(cmd.OutOrStdout(), rep, b.cfg, configPath)
			return nil
		},
	}
	c.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	return c
}

func formatGrantStamp(t time.Time) string {
	if t.IsZero() {
		return "(none)"
	}
	return t.Format(time.RFC3339)
}

func short(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12]
}

// expiryLine renders the grant's clock HONESTLY: the working expiry, plus —
// when the grant has been renewed — the signed expiry it was derived from.
//
// Both are printed because renewal deliberately does not destroy the
// evidence property (amendment A1 / §4.4): signed_expires_at preserves what
// the organization actually signed, so an auditor can still verify the
// stored signature against its own row, while expires_at is the working
// clock the resolver enforces.
func expiryLine(grant *govern.Grant, row store.EnrolmentGrant) string {
	line := fmt.Sprintf("Expires:      %s", formatGrantStamp(grant.ExpiresAt))
	if row.LastRenewedAt.IsZero() || row.SignedExpiresAt.IsZero() {
		return line
	}
	return fmt.Sprintf("%s (renewed %s; originally signed to expire %s)",
		line, row.LastRenewedAt.Format("2006-01-02"), row.SignedExpiresAt.Format("2006-01-02"))
}

// printGovernedFamilies is the W-7 share-directive surface on `observer org
// grant show`: for each [org_client.policy] family this grant's authority
// governs (govern.GovernedFamilies), it shows whether THIS machine's
// config.toml currently accepts it, and preauthorizes enforcement for it, so
// a developer can see exactly why extraction or enforcement for a granted
// authority is or is not flowing locally.
//
// Deliberately read-only and CONFIG-SIDE ONLY: it renders what this node's
// own [org_client.policy] currently holds, not the org-published
// node.governance share directives themselves or their live resolution
// state. Rendering that would need the same LKG/store plumbing
// printPinnedSettings uses for the PINNED directive class, which this
// command does not thread through for the share-directive class — so this
// section stays honestly scoped to what it can show without new plumbing.
func printGovernedFamilies(out io.Writer, authority []string, policy config.OrgClientPolicyConfig) {
	rows := governedFamilyRows(authority, policy)
	fmt.Fprintln(out, "\nPolicy families this authority governs:")
	if len(rows) == 0 {
		fmt.Fprintln(out, "  (none - nothing in this grant's authority maps to an [org_client.policy] family)")
		return
	}
	for _, r := range rows {
		switch {
		case !r.Accepted:
			fmt.Fprintf(out, "  - %-24s accept_families: MISSING (extraction/enforcement for this family will not flow)\n", r.Family)
		case !r.Preauthorized:
			fmt.Fprintf(out, "  - %-24s accept_families: present; preauthorize_enforce: MISSING (enforce mode installs inert)\n", r.Family)
		default:
			fmt.Fprintf(out, "  - %-24s accept_families: present; preauthorize_enforce: present\n", r.Family)
		}
	}
	fmt.Fprintln(out, "  Edit [org_client.policy] in config.toml to change this at any time.")
}

// printPinnedSettings is the §1.7 disclosure block. It is NON-NEGOTIABLE
// (threat T8): a developer must be able to see the MECHANISM, not just its
// output — which key, what value, who set it, where the file is, and
// crucially whether the config THIS VERY PROCESS loaded actually applied it.
func printPinnedSettings(out io.Writer, cfg config.Config, configPath string) {
	path := config.ResolveGovernanceSidecarPath(cfg, "")
	// The re-Load MUST honour the same --config the rest of this command
	// resolved, or the disclosure reads the DEFAULT machine config's sidecar
	// while printing this config's path — an "absent" verdict about a file
	// that exists.
	_, gout, err := config.LoadGovernance(config.LoadOptions{GlobalPath: configPath})
	fmt.Fprintln(out, "\nPinned settings:")
	fmt.Fprintf(out, "  Effective-settings file: %s\n", path)
	switch {
	case err != nil:
		// Structurally unreachable — Load never fails because of governance
		// — but reported rather than swallowed if it ever happens.
		fmt.Fprintf(out, "  Could not re-read this machine's configuration: %v\n", err)
		return
	case gout.Discarded:
		fmt.Fprintln(out, "  NONE APPLIED - the organization's settings were refused by this machine's own")
		fmt.Fprintf(out, "  configuration check and every one of them was ignored: %s\n", gout.DiscardErr)
		return
	case len(gout.Applied) == 0:
		fmt.Fprintf(out, "  None. (%s)\n", pinnedAbsenceReason(gout.Reason))
	default:
		for _, key := range gout.Applied {
			fmt.Fprintf(out, "  %-40s Source: your organization (policy v%d)\n", key, gout.Version)
		}
		fmt.Fprintln(out, "  These are the values THIS command's own configuration actually used.")
	}
	for key, why := range gout.Skipped {
		fmt.Fprintf(out, "  %-40s IGNORED by this machine: %s\n", key, why)
	}
	if !gout.WrittenAt.IsZero() {
		fmt.Fprintf(out, "  Last written: %s\n", gout.WrittenAt.Format(time.RFC3339))
	}
}

// pinnedAbsenceReason turns a sidecar read reason into a sentence a
// developer can act on.
func pinnedAbsenceReason(reason string) string {
	switch reason {
	case sidecar.ReasonAbsent:
		return "no settings file has been written on this machine"
	case sidecar.ReasonUnreadable:
		return "the settings file exists but cannot be read - check its permissions"
	case sidecar.ReasonOversize, sidecar.ReasonMalformed:
		return "the settings file is unreadable or damaged and is being ignored - delete it and restart `observer start`"
	case sidecar.ReasonSchemaTooNew:
		return "the settings file was written by a NEWER version of Observer and is being ignored"
	case sidecar.ReasonGrantExpired:
		return "the grant has expired, so nothing is applied"
	case sidecar.ReasonNotApplied:
		return "this machine is not currently governed"
	default:
		return "nothing is pinned"
	}
}
