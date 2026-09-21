package main

import (
	"bufio"
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
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Admin-controlled Plane B, the CLI consent surface
// (docs/plans/admin-controlled-plane-b-spec-2026-08-15.md §2.3/§2.4,
// adversarial review A4). The grant is written HERE and nowhere else:
// internal/orgclient has no TTY and, by the time it holds the response, it
// has already saved the bearer, written the enrolment and bumped the
// generation — there is no honest place there to ask a human anything.

// authorityPlainEnglish is the plain-language rendering of each authority
// token. A prompt that shows only machine tokens is a consent theatre, so
// every token in the closed vocabulary has a sentence here, and an UNKNOWN
// token is rendered honestly as "this version of Observer does not
// understand this, and will not act on it".
func authorityPlainEnglish(tok string) string {
	switch tok {
	case govern.AuthorityDashboardVisibility:
		return "hide or lock pages and settings sections in THIS dashboard"
	case govern.AuthoritySettingsPin:
		return "pin some local settings so they cannot be changed here"
	case govern.AuthorityCapturePin:
		return "reduce, or lock at its current level, what this machine shares with the organisation. It can never increase it"
	case govern.AuthorityCaptureRaise:
		// RETIRED (Phase 1b §2.3). A grant carrying it grants nothing. Say
		// so plainly: the fix is a fresh `observer enroll`, which is a
		// node-side act, not an admin action.
		return "RETIRED - this token grants nothing. Re-run `observer enroll` if your organisation needs to manage sharing"
	case govern.AuthorityFeatureLock:
		return "force some features on or off"
	case govern.AuthorityEnforceRouting:
		return "FORCE model-routing enforcement on this machine (managed tenancy only)"
	case govern.AuthorityEnforceAdmission:
		return "FORCE input-admission guardrail enforcement on this machine (managed tenancy only)"
	case govern.AuthorityEnforceEgress:
		return "FORCE egress-policy enforcement on this machine (managed tenancy only)"
	case govern.AuthorityEnforceBudget:
		return "make the organisation's spend cap AUTHORITATIVE on this machine - its numbers and enforcement mode replace your own, and if no verified organisation budget has reached this machine yet, proxied requests are refused until one does (managed tenancy only)"
	case govern.AuthorityExtractManaged:
		return "let the organisation RAISE what this machine shares, including tool inputs/outputs and other local data (managed tenancy only)"
	case govern.AuthorityExtractCodeintel:
		return "let the organisation RAISE extraction of this machine's code-intelligence index as a content-free per-project language/symbol/edge count aggregate - never symbol names, signatures, or file paths (managed tenancy only)"
	case govern.AuthorityExtractProcess:
		return "let the organisation RAISE extraction of this machine's process-observability data as a content-free per-day/tool run/exit/duration count aggregate - never executable paths, command arguments, or network bodies (managed tenancy only)"
	case govern.AuthorityExtractTerminal:
		return "let the organisation RAISE extraction of this machine's terminal-run and remote-access-audit activity as content-free count aggregates - never command text, session ids, peer addresses, or routes (managed tenancy only)"
	case govern.AuthorityExtractTasks:
		return "let the organisation RAISE extraction of this machine's task/to-do checklists as item statuses and status transitions - the plan text itself still needs full content (managed tenancy only)"
	case govern.AuthorityExtractToolAccounts:
		return "let the organisation RAISE extraction of which vendor account each AI tool was logged in as, as opaque account keys and status - the account e-mail/name/id still need full content (managed tenancy only)"
	case govern.AuthorityExtractIntel:
		return "let the organisation turn on this machine's pull of its own Cloud Intelligence results for your sessions - a request that comes back to this machine, never data shipped out (managed tenancy only)"
	case govern.AuthorityExtractToolBodies:
		return "let the organisation RAISE extraction of this machine's tool-call inputs, outputs, reasoning, and error text (managed tenancy only)"
	case govern.AuthorityExtractFolders:
		return "let the organisation RAISE extraction of this machine's raw project folder names, git remotes, and branches (managed tenancy only)"
	case govern.AuthorityExtractTraces:
		return "let the organisation RAISE extraction of this machine's full hosted-app traces, including span content and eval/admission detail (managed tenancy only)"
	case govern.AuthorityExtractCache:
		return "let the organisation RAISE extraction of this machine's prompt-cache activity as a content-free per-day model/kind aggregate (managed tenancy only)"
	case govern.AuthorityExtractRouting:
		return "let the organisation RAISE extraction of this machine's model-routing decisions as a per-day model/turn-kind aggregate (managed tenancy only)"
	case govern.AuthorityExtractPredictions:
		return "let the organisation RAISE extraction of this machine's cost/limit predictor snapshots as a content-free per-day provider utilization aggregate (managed tenancy only)"
	case govern.AuthorityExtractTargetActions:
		return "let the organisation RAISE which action types on this machine may ship a raw target, such as a file path or command, instead of only a hash (managed tenancy only)"
	case govern.AuthorityExtractScope:
		return "let the organisation RAISE this machine's own [org_client.scope] restriction lists - widen, remove, or override what is included (managed tenancy only)"
	case govern.AuthorityExtractPolicyState:
		return "let the organisation RAISE extraction of this machine's effective-policy-state reports - which governance settings are actually applied here (managed tenancy only)"
	case govern.AuthorityExtractObsEgress:
		return "let the organisation RAISE extraction of this machine's egress-routing decisions for its own hosted-app traffic - part of the same trace family as full traces (managed tenancy only)"
	default:
		return "UNKNOWN to this version of Observer - no description is available, though it is still recorded on this grant"
	}
}

// consentModeForTenancy maps the enrolment tenancy onto the govern consent
// mode recorded on the grant. Managed tenancy is the signal the resolver
// branches on to honour the managed-only authorities; individual enrolments
// stay interactive so those authorities are inert.
//
// This is the LOCAL answer: what the node concludes when the organisation
// said nothing about how consent was obtained. grantConsent prefers the
// organisation's own statement when there is one.
func consentModeForTenancy(tenancy string) string {
	if tenancy == orgcontract.TenancyManaged {
		return govern.ConsentManaged
	}
	return govern.ConsentInteractive
}

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

// unnamedConsentActor is recorded when the organisation declares a consent
// mode but no actor. It is deliberately NOT the local username: the whole
// value of an IdP-declared mode is that the actor is server-verified, and
// substituting $USER would dress an unverified local name up as one.
const unnamedConsentActor = "unknown"

// resolveGrantConsent decides what to record, preferring the ORGANISATION's
// declared consent mode over the node's tenancy-derived guess.
//
// Preference, and why: on the IdP rail the developer already proved who they
// are to the organisation's identity provider and approved this enrolment in a
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
		// The token rail: no organisation statement, so the node decides from
		// tenancy exactly as it did before ACP-P6c.
		return grantConsent{
			Mode:  consentModeForTenancy(offer.Tenancy),
			Actor: localConsentActor(),
		}, ""
	case govern.ConsentIdP:
		if offer.Tenancy != orgcontract.TenancyManaged {
			return grantConsent{}, "the organisation says this enrolment was consented to by an identity-provider sign-in, " +
				"but it did not enrol this machine as organisation-managed. Those two cannot both be true"
		}
		actor := strings.TrimSpace(offer.ConsentActor)
		if actor == "" {
			actor = unnamedConsentActor
		}
		return grantConsent{
			Mode:         govern.ConsentIdP,
			Actor:        actor,
			AlreadyGiven: true,
			Summary: fmt.Sprintf("Consent recorded from the organisation sign-in approved by %s.\n"+
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
			return grantConsent{}, "the organisation declared managed consent for an enrolment it did not mark as organisation-managed"
		}
		actor := strings.TrimSpace(offer.ConsentActor)
		if actor == "" {
			actor = localConsentActor()
		}
		return grantConsent{Mode: govern.ConsentManaged, Actor: actor}, ""
	default:
		return grantConsent{}, fmt.Sprintf("the organisation declared a consent mode this version of Observer does not understand (%q)", offer.ConsentMode)
	}
}

// confirmAndStoreGrant prints the offered grant, obtains consent, and stores
// it. The rules, in the order they matter:
//
//   - an organisation that itself carried out the consent act (the ACP-P6c
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
	// the organisation itself already carried out the consent act
	// (ACP-P6c IdP browser approval).
	Accepted bool
	// Managed reports whether the enrolment that produced this grant is
	// organisation-managed, as opposed to individual/BYO. Mirrors
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
		ok, err := promptYesNo(cmd, "Accept these settings from this organisation? [y/N]: ")
		if err != nil {
			return grantOutcome{}, err
		}
		if !ok {
			fmt.Fprintln(out, "\nDeclined. This machine is enrolled and reporting, but NOT governed:")
			fmt.Fprintln(out, "  nothing about this dashboard will be changed by the organisation.")
			return grantOutcome{}, nil
		}
	default:
		fmt.Fprintln(out, "\nNot accepted: this is not an interactive terminal and --accept-governance was not passed.")
		fmt.Fprintln(out, "  This machine is enrolled and reporting, but NOT governed. Re-run `observer enroll`")
		fmt.Fprintln(out, "  interactively, or pass --accept-governance, to accept the settings above.")
		return grantOutcome{}, nil
	}

	row := store.EnrolmentGrant{
		OrgKey:       offer.OrgKey,
		Generation:   offer.Generation,
		OrgID:        offer.Grant.OrgID,
		OrgName:      grantOrgName(cmd, offer),
		OrgServerURL: offer.Grant.OrgServerURL,
		KeyPinSHA256: offer.KeyPinSHA256,
		Authority:    offer.Grant.Authority,
		// Managed-class consent (govern.ManagedConsent: managed tenancy, or
		// an IdP-verified browser approval) is the signal
		// govern.HonoredAuthority / the resolver branch on to honour the
		// managed-only authorities (enforce.*/extract.managed) this grant
		// carries. An individual enrolment stays ConsentInteractive, so those
		// authorities remain inert even if the grant lists them. The actor is
		// the organisation-verified identity when there is one, and the local
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
	}
	if err := st.WriteEnrolmentGrant(cmd.Context(), row); err != nil {
		return grantOutcome{}, fmt.Errorf("observer enroll: could not record the governance grant: %w", err)
	}
	fmt.Fprintln(out, "Recorded. Run `observer org grant show` at any time to see exactly what this machine granted,")
	fmt.Fprintln(out, "and `observer unenroll` to revoke it.")
	return grantOutcome{
		Accepted:  true,
		Managed:   offer.Tenancy == orgcontract.TenancyManaged,
		Authority: offer.Grant.Authority,
	}, nil
}

// printGrantOffer renders the offer. Plain hyphens, no em-dashes (the
// user-facing copy rule).
func printGrantOffer(out io.Writer, offer *orgclient.GrantOffer) {
	fmt.Fprintln(out)
	fmt.Fprintln(out, "This organisation is asking to manage some of this machine's Observer settings.")
	fmt.Fprintf(out, "  Organisation: %s\n", offer.Grant.OrgID)
	fmt.Fprintf(out, "  Server:       %s\n", offer.Grant.OrgServerURL)
	if offer.Grant.ExpiresAt != "" {
		fmt.Fprintf(out, "  Expires:      %s (after this, local settings apply again)\n", offer.Grant.ExpiresAt)
	}
	fmt.Fprintln(out, "\nIf you accept, the organisation may:")
	for _, tok := range offer.Grant.Authority {
		fmt.Fprintf(out, "  - %s\n     (%s)\n", authorityPlainEnglish(tok), tok)
	}
	// W-5 disclosure (operator ruling): managed sign-in IS the consent, so
	// accepting on a managed enrolment also writes the node-side
	// [org_client.policy] keys those authorities need before extraction or
	// enforcement can flow at all — see ensureManagedPolicyBlock. Said here,
	// before the prompt, so the write is never a surprise.
	if offer.Tenancy == orgcontract.TenancyManaged {
		if families := govern.GovernedFamilies(offer.Grant.Authority); len(families) > 0 {
			fmt.Fprintln(out, "\nAccepting will also write to this machine's config.toml:")
			fmt.Fprintf(out, "  [org_client.policy] accept_families = %s\n", quotedTomlStringList(families))
			fmt.Fprintf(out, "  [org_client.policy] preauthorize_enforce = %s\n", quotedTomlStringList(families))
			fmt.Fprintln(out, "  (the families the authority above governs). You can edit or remove this at any")
			fmt.Fprintln(out, "  time - the organisation cannot rewrite it remotely.")
		}
	}
	fmt.Fprintln(out, "\nIt may NOT:")
	if offerHonoursExtraction(offer) {
		// The usual "it cannot read your code or your command output" bullet
		// is FALSE under an extraction grant on a managed machine:
		// extract.tool_bodies (and the umbrella extract.managed) raise the
		// tool-call input, output, reasoning and error columns, and a tool
		// call IS your command text. Printing it anyway would make this
		// screen consent theatre, so it is replaced by a line pointing at the
		// extraction authorities above - each already names what it reaches.
		fmt.Fprintln(out, "  - read anything beyond the lines above. This machine is organisation-managed,")
		fmt.Fprintln(out, "     so the extraction lines DO apply: some of them raise your tool inputs,")
		fmt.Fprintln(out, "     outputs, and command text. The Privacy page always shows what is shared.")
	} else {
		fmt.Fprintln(out, "  - read your code, your files, or your command output")
	}
	fmt.Fprintln(out, "  - hide the Privacy page or the enrolment settings, so you can always see")
	fmt.Fprintln(out, "     what is shared and who manages this machine")
	fmt.Fprintln(out, "  - stop you leaving: `observer unenroll` removes this at any time")
}

// offerHonoursExtraction reports whether this offer's authority will actually
// be able to RAISE what the machine shares - i.e. it carries an extraction
// token AND the enrolment is organisation-managed, the only tenancy under
// which govern.HonoredAuthority keeps those tokens.
//
// Both halves matter for honest copy. An individual enrolment handed an
// extract.* token honours nothing (each is rendered "managed tenancy only"
// above), so the plain "it cannot read your code" promise still holds there
// and must not be weakened.
func offerHonoursExtraction(offer *orgclient.GrantOffer) bool {
	if offer.Tenancy != orgcontract.TenancyManaged {
		return false
	}
	for _, tok := range offer.Grant.Authority {
		if govern.ExtractionAuthority(tok) {
			return true
		}
	}
	return false
}

// grantOrgName prefers the enrolment's own org name for display; the grant
// itself carries only the org id (the display name rides the signed policy
// body's notice, not the grant).
func grantOrgName(cmd *cobra.Command, offer *orgclient.GrantOffer) string {
	_ = cmd
	return offer.Grant.OrgID
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
		Short: "Show the organisation governance grant this machine recorded at enrolment",
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
			out := cmd.OutOrStdout()

			loader := governanceIdentityLoader(b.store)
			grant, live, err := loader(cmd.Context())
			if err != nil {
				return err
			}
			if !live.Enrolled {
				fmt.Fprintln(out, "Not enrolled, so nothing manages this machine.")
				return nil
			}
			if grant == nil {
				fmt.Fprintln(out, "Enrolled, but NOT governed: this machine granted no authority to the organisation.")
				fmt.Fprintln(out, "Your dashboard and settings are entirely local.")
				return nil
			}
			fmt.Fprintf(out, "Granted to:   %s (org_id %s)\n", grant.OrgName, grant.OrgID)
			fmt.Fprintf(out, "Server:       %s\n", grant.OrgServerURL)
			fmt.Fprintf(out, "Granted at:   %s\n", formatGrantStamp(grant.GrantedAt))
			row, _, _ := b.store.LoadEnrolmentGrant(cmd.Context(), live.OrgKey) //nolint:errcheck // display-only; a read failure just omits the renewal detail
			fmt.Fprintln(out, expiryLine(grant, row))
			fmt.Fprintf(out, "Consent:      %s (%s)\n", grant.ConsentMode, grant.ConsentActor)
			fmt.Fprintf(out, "Receipt:      %s\n", grant.ReceiptHash)
			fmt.Fprintln(out, "\nAuthority granted:")
			for _, tok := range grant.Authority {
				fmt.Fprintf(out, "  - %-24s %s\n", tok, authorityPlainEnglish(tok))
			}
			printGovernedFamilies(out, grant.Authority, b.cfg.OrgClient.Policy)

			// The one honest verification line: is the key this grant was
			// bound to still the key this node pins?
			switch {
			case grant.KeyPinSHA256 == "":
				fmt.Fprintln(out, "\nSigning key:  NOT BOUND (this grant predates key binding and will not be honoured)")
			case grant.KeyPinSHA256 == live.KeyPinSHA256:
				fmt.Fprintf(out, "\nSigning key:  verified against the pinned organisation key (%s)\n", short(grant.KeyPinSHA256))
			default:
				fmt.Fprintf(out, "\nSigning key:  MISMATCH - grant bound to %s, this machine now pins %s.\n",
					short(grant.KeyPinSHA256), short(live.KeyPinSHA256))
				fmt.Fprintln(out, "              The grant is NOT being honoured. Re-enrol to re-establish it.")
			}
			// Track C item 1: the RUNTIME re-verification verdict. The
			// "Signing key" line above answers "is this grant bound to the
			// key I pin?"; this one answers the question that was never
			// asked again after enrolment — "is this still the document the
			// organisation signed?".
			switch grant.Integrity {
			case govern.GrantIntegrityValid:
				fmt.Fprintln(out, "Signature:    re-verified just now against the organisation key recorded at enrolment")
			case govern.GrantIntegrityInvalid:
				fmt.Fprintln(out, "Signature:    DOES NOT VERIFY - the stored grant is not the document the organisation signed.")
				fmt.Fprintln(out, "              This machine's authority record has been altered. The grant is NOT being")
				fmt.Fprintln(out, "              honoured. Re-enrol to re-establish it; the organisation can see this too.")
			default:
				fmt.Fprintln(out, "Signature:    NOT RE-CHECKED - this machine holds no organisation signing key material")
				fmt.Fprintln(out, "              (an older enrolment, or a server that delivered no policy key). Re-enrol to record it.")
			}
			if grant.Generation != live.Generation {
				fmt.Fprintf(out, "Enrolment:    STALE - grant recorded for enrolment %d, this machine is on %d.\n",
					grant.Generation, live.Generation)
				fmt.Fprintln(out, "              The grant is NOT being honoured.")
			}
			if !grant.ExpiresAt.IsZero() && time.Now().UTC().After(grant.ExpiresAt) {
				fmt.Fprintln(out, "Status:       EXPIRED - local settings apply again.")
			}
			printPinnedSettings(out, b.cfg, configPath)
			fmt.Fprintln(out, "\nRun `observer unenroll` to revoke this at any time.")
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
	families := govern.GovernedFamilies(authority)
	fmt.Fprintln(out, "\nPolicy families this authority governs:")
	if len(families) == 0 {
		fmt.Fprintln(out, "  (none - nothing in this grant's authority maps to an [org_client.policy] family)")
		return
	}
	accepted := make(map[string]bool, len(policy.AcceptFamilies))
	for _, f := range policy.AcceptFamilies {
		accepted[f] = true
	}
	preauth := make(map[string]bool, len(policy.PreauthorizeEnforce))
	for _, f := range policy.PreauthorizeEnforce {
		preauth[f] = true
	}
	for _, f := range families {
		switch {
		case !accepted[f]:
			fmt.Fprintf(out, "  - %-24s accept_families: MISSING (extraction/enforcement for this family will not flow)\n", f)
		case !preauth[f]:
			fmt.Fprintf(out, "  - %-24s accept_families: present; preauthorize_enforce: MISSING (enforce mode installs inert)\n", f)
		default:
			fmt.Fprintf(out, "  - %-24s accept_families: present; preauthorize_enforce: present\n", f)
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
		fmt.Fprintln(out, "  NONE APPLIED - the organisation's settings were refused by this machine's own")
		fmt.Fprintf(out, "  configuration check and every one of them was ignored: %s\n", gout.DiscardErr)
		return
	case len(gout.Applied) == 0:
		fmt.Fprintf(out, "  None. (%s)\n", pinnedAbsenceReason(gout.Reason))
	default:
		for _, key := range gout.Applied {
			fmt.Fprintf(out, "  %-40s Source: your organisation (policy v%d)\n", key, gout.Version)
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
