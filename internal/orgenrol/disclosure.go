package orgenrol

import (
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/govern"
)

// AuthorityPlainEnglish is the plain-language rendering of each authority
// token. A consent screen that shows only machine tokens is consent theatre,
// so every token in the closed vocabulary has a sentence here, and an UNKNOWN
// token is rendered honestly as "this version of Observer does not understand
// this, and will not act on it". The CLI prompt and the dashboard consent
// screen both render these exact sentences.
//
//nolint:gocyclo // one case per authority token by design; complexity grows with the closed vocabulary, not logic depth.
func AuthorityPlainEnglish(tok string) string {
	switch tok {
	case govern.AuthorityDashboardVisibility:
		return "hide or lock pages and settings sections in THIS dashboard"
	case govern.AuthoritySettingsPin:
		return "pin some local settings so they cannot be changed here"
	case govern.AuthorityCapturePin:
		return "reduce, or lock at its current level, what this machine shares with the organization. It can never increase it"
	case govern.AuthorityCaptureRaise:
		// RETIRED (Phase 1b §2.3). A grant carrying it grants nothing. Say
		// so plainly: the fix is a fresh enrolment, which is a node-side act,
		// not an admin action.
		return "RETIRED - this token grants nothing. Re-run `observer enroll` if your organization needs to manage sharing"
	case govern.AuthorityFeatureLock:
		return "force some features on or off"
	case govern.AuthorityEnforceRouting:
		return "FORCE model-routing enforcement on this machine (managed tenancy only)"
	case govern.AuthorityEnforceAdmission:
		return "FORCE input-admission guardrail enforcement on this machine (managed tenancy only)"
	case govern.AuthorityEnforceEgress:
		return "FORCE egress-policy enforcement on this machine (managed tenancy only)"
	case govern.AuthorityEnforceBudget:
		return "make the organization's spend cap AUTHORITATIVE on this machine - its numbers and enforcement mode replace your own, and if no verified organization budget has reached this machine yet, proxied requests are refused until one does (managed tenancy only)"
	case govern.AuthorityEnforceMCPAccess:
		return "make the organization's MCP access policy (tools.mcp_access) AUTHORITATIVE on this machine - the org's enforcement mode replaces your own, and an MCP server the org registry does not know is refused rather than left ungoverned (managed tenancy only)"
	case govern.AuthorityEnforceSecurity:
		return "let the organization switch code security checks ON on this machine - which scanners and drivers run, with the organization's mirror as their source and its scan schedule; it never installs git hooks, never sends a credential and never turns on online lookups without showing you first (managed tenancy only)"
	case govern.AuthorityEnforceSandbox:
		return "let the organization switch sandboxed terminals ON on this machine - which sandbox backends are enabled and their preference order, within the limits this machine and the organization set; it never turns on a mode that loses capture and never sends a credential (managed tenancy only)"
	case govern.AuthorityExtractManaged:
		return "raise this machine to FULL content sharing - raw command bodies, assistant prose, tool inputs/outputs, raw folder names, git identity and file paths ship to the organization (managed tenancy only; the teams/enterprise capture posture, and what raises a machine enrolled before that default)"
	case govern.AuthorityExtractCodeintel:
		return "let the organization RAISE extraction of this machine's code-intelligence index as a content-free per-project language/symbol/edge count aggregate - never symbol names, signatures, or file paths (managed tenancy only)"
	case govern.AuthorityExtractProcess:
		return "let the organization RAISE extraction of this machine's process-observability data as a content-free per-day/tool run/exit/duration count aggregate - never executable paths, command arguments, or network bodies (managed tenancy only)"
	case govern.AuthorityExtractTerminal:
		return "let the organization RAISE extraction of this machine's terminal-run and remote-access-audit activity as content-free count aggregates - never command text, session ids, peer addresses, or routes (managed tenancy only)"
	case govern.AuthorityExtractTasks:
		return "let the organization RAISE extraction of this machine's task/to-do checklists as item statuses and status transitions - the plan text itself still needs full content (managed tenancy only)"
	case govern.AuthorityExtractToolAccounts:
		return "let the organization RAISE extraction of which vendor account each AI tool was logged in as, as opaque account keys and status - the account e-mail/name/id still need full content (managed tenancy only)"
	case govern.AuthorityExtractIntel:
		return "let the organization turn on Cloud Intelligence for your sessions - this machine builds evidence about each finished session at the organization's evidence level (up to bounded prompt excerpts), sends it to the organization's own server for enrichment, and pulls the results back (managed tenancy only)"
	case govern.AuthorityExtractToolBodies:
		return "let the organization RAISE extraction of this machine's tool-call inputs, outputs, reasoning, and error text (managed tenancy only)"
	case govern.AuthorityExtractFolders:
		return "let the organization RAISE extraction of this machine's raw project folder names, git remotes, and branches (managed tenancy only)"
	case govern.AuthorityExtractTraces:
		return "let the organization RAISE extraction of this machine's full hosted-app traces, including span content and eval/admission detail (managed tenancy only)"
	case govern.AuthorityExtractCache:
		return "let the organization RAISE extraction of this machine's prompt-cache activity as a content-free per-day model/kind aggregate (managed tenancy only)"
	case govern.AuthorityExtractRouting:
		return "let the organization RAISE extraction of this machine's model-routing decisions as a per-day model/turn-kind aggregate (managed tenancy only)"
	case govern.AuthorityExtractPredictions:
		return "let the organization RAISE extraction of this machine's cost/limit predictor snapshots as a content-free per-day provider utilization aggregate (managed tenancy only)"
	case govern.AuthorityExtractTargetActions:
		return "let the organization RAISE which action types on this machine may ship a raw target, such as a file path or command, instead of only a hash (managed tenancy only)"
	case govern.AuthorityExtractScope:
		return "let the organization RAISE this machine's own [org_client.scope] restriction lists - widen, remove, or override what is included (managed tenancy only)"
	case govern.AuthorityExtractPolicyState:
		return "let the organization RAISE extraction of this machine's effective-policy-state reports - which governance settings are actually applied here (managed tenancy only)"
	case govern.AuthorityExtractObsEgress:
		return "let the organization RAISE extraction of this machine's egress-routing decisions for its own hosted-app traffic - part of the same trace family as full traces (managed tenancy only)"
	case govern.AuthorityExtractHookActivity:
		return "let the organization RAISE extraction of which AI tool hooks fired in each session on this machine, as per-session counts, times and coarse route classes - the config-folder hash still needs full content (managed tenancy only)"
	default:
		return "UNKNOWN to this version of Observer - no description is available, though it is still recorded on this grant"
	}
}

// TOMLStringList renders items as a TOML inline array of quoted strings, e.g.
// ["admission.input", "node.governance"].
func TOMLStringList(items []string) string {
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = strconv.Quote(s)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// GrantFacts is what the consent screen needs to know about an offered grant.
type GrantFacts struct {
	OrgID string
	// OrgName is the enrolment's organization name when the caller has it
	// (the dashboard does; the CLI prompt does not need it).
	OrgName   string
	ServerURL string
	// ExpiresAt is the signed expiry as the org stated it (RFC 3339), or "".
	ExpiresAt string
	Authority []string
	// Managed is the enrolment's tenancy (organization-managed vs individual).
	Managed bool
}

// AuthorityLine is one "the organization may" row.
type AuthorityLine struct {
	Token string `json:"token"`
	Text  string `json:"text"`
}

// Disclosure is the governance-grant consent screen as data.
type Disclosure struct {
	// Intro is the opening sentence (DisclosureIntro), carried so the
	// dashboard renders the same words the CLI prints.
	Intro string `json:"intro"`
	// OrgDisplay is what the screen calls the organization (DisplayName):
	// never the org id. The CLI prompt keeps printing the id.
	OrgDisplay string `json:"org_display,omitempty"`
	OrgID      string `json:"org_id"`
	ServerURL  string `json:"server_url"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	Managed    bool   `json:"managed"`
	// May lists what the organization may do, one row per authority token,
	// in the grant's own order (unknown tokens included, honestly labelled).
	May []AuthorityLine `json:"may"`
	// ConfigWrites lists the config.toml lines accepting will also write
	// (W-5: managed sign-in is the consent for the families the authority
	// governs). Empty when nothing is written.
	ConfigWrites []string `json:"config_writes,omitempty"`
	// Families are the [org_client.policy] families those writes name.
	Families []string `json:"families,omitempty"`
	// ConfigWritesNote follows the config lines when there are any.
	ConfigWritesNote string `json:"config_writes_note,omitempty"`
	// MayNot lists what the organization may NOT do.
	MayNot []string `json:"may_not"`
}

// Fixed consent-screen sentences, shared by every renderer.
const (
	// DisclosureIntro opens the screen.
	DisclosureIntro = "This organization is asking to manage some of this machine's Observer settings."
	// DisclosureConfigWritesNote follows the config lines.
	DisclosureConfigWritesNote = "(the families the authority above governs). You can edit or remove this at any time - the organization cannot rewrite it remotely."
	mayNotReadAnything         = "read anything beyond the lines above. This machine is organization-managed, so the extraction lines DO apply: some of them raise your tool inputs, outputs, and command text. The Privacy page always shows what is shared."
	mayNotReadCode             = "read your code, your files, or your command output"
	mayNotHide                 = "hide the Privacy page or the enrolment settings, so you can always see what is shared and who manages this machine"
	mayNotStopLeaving          = "stop you leaving: Leave organization (Settings > Enrolment) or `observer unenroll` removes this at any time"
)

// BuildDisclosure renders the consent screen for an offered grant.
//
// The "it cannot read your code" promise is FALSE under an extraction grant on
// a managed machine (extract.tool_bodies and the extract.managed umbrella
// raise the tool-call input/output columns, and a tool call IS your command
// text), so it is replaced there by a line pointing at the extraction rows,
// which each name what they reach. On an individual enrolment every extract.*
// token is inert, so the plain promise still holds and is kept.
func BuildDisclosure(f GrantFacts) Disclosure {
	d := Disclosure{
		Intro:      DisclosureIntro,
		OrgDisplay: DisplayName(f.OrgID, f.ServerURL, f.OrgName),
		OrgID:      f.OrgID,
		ServerURL:  f.ServerURL,
		ExpiresAt:  f.ExpiresAt,
		Managed:    f.Managed,
	}
	for _, tok := range f.Authority {
		d.May = append(d.May, AuthorityLine{Token: tok, Text: AuthorityPlainEnglish(tok)})
	}
	if f.Managed {
		if families := govern.GovernedFamilies(f.Authority); len(families) > 0 {
			list := TOMLStringList(families)
			d.Families = families
			d.ConfigWritesNote = DisclosureConfigWritesNote
			d.ConfigWrites = []string{
				"[org_client.policy] accept_families = " + list,
				"[org_client.policy] preauthorize_enforce = " + list,
			}
		}
	}
	if HonoursExtraction(f) {
		d.MayNot = append(d.MayNot, mayNotReadAnything)
	} else {
		d.MayNot = append(d.MayNot, mayNotReadCode)
	}
	d.MayNot = append(d.MayNot, mayNotHide, mayNotStopLeaving)
	return d
}

// HonoursExtraction reports whether the offer's authority will actually be
// able to RAISE what the machine shares: it carries an extraction token AND
// the enrolment is organization-managed, the only tenancy under which
// govern.HonoredAuthority keeps those tokens.
func HonoursExtraction(f GrantFacts) bool {
	if !f.Managed {
		return false
	}
	for _, tok := range f.Authority {
		if govern.ExtractionAuthority(tok) {
			return true
		}
	}
	return false
}
