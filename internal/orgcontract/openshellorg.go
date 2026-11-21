package orgcontract

import (
	"regexp"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cidrcanon"
)

// The org-hosted OpenShell gateway's field of the managed sandbox body
// (tracker F-019, docs/plans/openshell/build/g1-design.md section 8.1, the
// HostedE2B data-only precedent). It is DATA only: it never enables the
// openshell-org row (the node's component, backends list and an explicit
// choice still decide), carries no credential, and is shown on the consent
// screen and the approval page. The server builds it per caller from its
// [openshell] block and serves it only to a node that advertised
// SandboxCapabilityOrgOpenShell, that is managed-tenancy, and whose member
// is in the org's allowed set (the body is closed, so an older node would
// refuse the whole body for it). An older server never sends it, and the row
// is then not offered. Two facts deliberately reuse existing body fields:
// remote_allowed_hosts and allow_remote_clone (one owner each).

// SandboxCapabilityOrgOpenShell is the token a node sends when it applies
// org_openshell on the sandbox rail.
const SandboxCapabilityOrgOpenShell = "sandbox.org_openshell"

// SandboxManagedOrgOpenShellV1 is the org-hosted OpenShell gateway as a node
// sees it.
type SandboxManagedOrgOpenShellV1 struct {
	// FrontURL is where the node connects: the front's own https origin.
	FrontURL string `json:"front_url"`
	// FrontTLSSPKISHA256 pins the front's certificate for an org on a
	// private CA (lowercase hex SHA-256 of the SubjectPublicKeyInfo).
	FrontTLSSPKISHA256 string `json:"front_tls_spki_sha256,omitempty"`
	// GatewayID, Issuer, Version, Image, IsoClass and Region say what the
	// gateway is. They are shown; the node never dials the gateway.
	GatewayID string `json:"gateway_id"`
	Issuer    string `json:"issuer"`
	Version   string `json:"version"`
	Image     string `json:"image"`
	IsoClass  string `json:"iso_class"`
	Region    string `json:"region,omitempty"`
	// Tiers, EgressAllowHosts, AllowCIDRs and BlockedCIDRs are the org's
	// network inputs (section 6.1). The node previews with them; the org's
	// compile is authoritative.
	Tiers            []string `json:"tiers"`
	EgressAllowHosts []string `json:"egress_allow_hosts,omitempty"`
	AllowCIDRs       []string `json:"allow_cidrs,omitempty"`
	BlockedCIDRs     []string `json:"blocked_cidrs,omitempty"`
	// CloneRepositories are the repository URLs of the git_providers rows
	// this member may clone (never a provider profile, team or member list,
	// G1-R17).
	CloneRepositories []string `json:"clone_repositories,omitempty"`
	// BoxBinary is upload or image (section 4.5).
	BoxBinary string `json:"box_binary"`
	// LaptopRelay is allowed or forbidden (section 3.7).
	LaptopRelay string `json:"laptop_relay"`
	// HoldPolicy, MaxHoldHours and ReturnToNode are shown at opt-in and in
	// the picker; the server enforces them.
	HoldPolicy   string `json:"hold_policy"`
	MaxHoldHours int    `json:"max_hold_hours"`
	ReturnToNode bool   `json:"return_to_node"`
	// MaxRunMinutes is the node's runtime lower cap of the row's lifetime.
	MaxRunMinutes int `json:"max_run_minutes"`
	// QuotaSummary is for display.
	QuotaSummary SandboxOrgOpenShellQuotaV1 `json:"quota_summary"`
}

// SandboxOrgOpenShellQuotaV1 is the org's quota summary as shown to a node.
type SandboxOrgOpenShellQuotaV1 struct {
	MaxConcurrentPerMember   int `json:"max_concurrent_per_member"`
	MaxBoxesPerMember        int `json:"max_boxes_per_member"`
	MaxHeldPerMember         int `json:"max_held_per_member"`
	DailyBoxMinutesPerMember int `json:"daily_box_minutes_per_member"`
	BoxCPU                   int `json:"box_cpu"`
	BoxMemoryMiB             int `json:"box_memory_mib"`
}

// SandboxOrgOpenShellForCaller is a sandbox body as served to one caller:
// unchanged when the caller advertised SandboxCapabilityOrgOpenShell, else
// without org_openshell. Pure.
func SandboxOrgOpenShellForCaller(p SandboxManagedPolicyV1, caps []string) SandboxManagedPolicyV1 {
	if p.OrgOpenShell == nil {
		return p
	}
	for _, c := range caps {
		if c == SandboxCapabilityOrgOpenShell {
			return p
		}
	}
	p.OrgOpenShell = nil
	return p
}

var (
	orgOpenShellGatewayIDRE = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	orgOpenShellVersionRE   = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	orgOpenShellImageRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]{0,254}@sha256:[0-9a-f]{64}$`)
	orgOpenShellRegionRE    = regexp.MustCompile(`^[A-Za-z0-9._-]{0,64}$`)
)

// OrgOpenShellBoxBinaryImage is the box_binary value that says the org's box
// image carries the in-box observer (design 4.5); "upload" is the other.
const OrgOpenShellBoxBinaryImage = "image"

// The closed vocabularies of the field.
var (
	orgOpenShellTiers       = []string{"none", "proxy_only", "internet"}
	orgOpenShellIsoClasses  = []string{"container", "userspace_kernel"}
	orgOpenShellBoxBinaries = []string{"upload", OrgOpenShellBoxBinaryImage}
	orgOpenShellRelays      = []string{"allowed", "forbidden"}
	orgOpenShellHolds       = []string{"off", "on_disconnect", "on_disconnect_and_end"}
)

func inSet(v string, set []string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

// validHTTPSURL reports whether s is an https URL with a host and no user,
// query or fragment (a path is allowed: the issuer has one).
func validHTTPSURL(s string) bool {
	rest, ok := strings.CutPrefix(s, "https://")
	if !ok || s == "" || len(s) > 512 || strings.ContainsAny(s, " \t\r\n?#@\\") {
		return false
	}
	host, _, _ := strings.Cut(rest, "/")
	return host != ""
}

// validate checks the field's closed vocabulary and bounds.
func (o *SandboxManagedOrgOpenShellV1) validate() error {
	// The field is the format's first word (code, never data), so a
	// refusal names it as structured data (FX1-A6).
	bad := func(format string, a ...any) error {
		field, _, _ := strings.Cut(format, " ")
		return fieldErr("org_openshell."+field, FieldClassInvalid, "org_openshell."+format, a...)
	}
	switch {
	case !ValidE2BOrigin(o.FrontURL):
		return bad("front_url %q is not an https origin", o.FrontURL)
	case o.FrontTLSSPKISHA256 != "" && !validSPKIPin(o.FrontTLSSPKISHA256):
		return bad("front_tls_spki_sha256 is not 64 lowercase hex characters")
	case !orgOpenShellGatewayIDRE.MatchString(o.GatewayID):
		return bad("gateway_id %q is not [a-z0-9-]{1,32}", o.GatewayID)
	case !validHTTPSURL(o.Issuer):
		return bad("issuer %q is not an https URL", o.Issuer)
	case !orgOpenShellVersionRE.MatchString(o.Version):
		return bad("version %q is not a release version", o.Version)
	case !orgOpenShellImageRE.MatchString(o.Image):
		return bad("image %q is not an image reference pinned by @sha256", o.Image)
	case !inSet(o.IsoClass, orgOpenShellIsoClasses):
		return bad("iso_class %q is not container or userspace_kernel", o.IsoClass)
	case !orgOpenShellRegionRE.MatchString(o.Region):
		return bad("region %q is not a region label", o.Region)
	case len(o.Tiers) == 0:
		return bad("tiers is empty")
	case !inSet(o.BoxBinary, orgOpenShellBoxBinaries):
		return bad("box_binary %q is not upload or image", o.BoxBinary)
	case !inSet(o.LaptopRelay, orgOpenShellRelays):
		return bad("laptop_relay %q is not allowed or forbidden", o.LaptopRelay)
	case !inSet(o.HoldPolicy, orgOpenShellHolds):
		return bad("hold_policy %q is not off, on_disconnect or on_disconnect_and_end", o.HoldPolicy)
	case o.MaxHoldHours < 1 || o.MaxHoldHours > 168:
		return bad("max_hold_hours %d not in 1 to 168", o.MaxHoldHours)
	case o.MaxRunMinutes < 5 || o.MaxRunMinutes > 1440:
		return bad("max_run_minutes %d not in 5 to 1440", o.MaxRunMinutes)
	}
	if err := checkList("org_openshell.tiers", o.Tiers, func(s string) bool { return inSet(s, orgOpenShellTiers) }); err != nil {
		return err
	}
	if err := checkList("org_openshell.egress_allow_hosts", o.EgressAllowHosts, validManagedHost); err != nil {
		return err
	}
	// The body carries only the canonical spelling: the org canonicalizes at
	// its boundary (the [openshell] config and the settings route), so a
	// node compares lists byte for byte (F-B1).
	cidr := func(s string) bool {
		c, ok := cidrcanon.Canonical(s)
		return ok && c == s
	}
	if err := checkList("org_openshell.allow_cidrs", o.AllowCIDRs, cidr); err != nil {
		return err
	}
	if err := checkList("org_openshell.blocked_cidrs", o.BlockedCIDRs, cidr); err != nil {
		return err
	}
	if err := checkList("org_openshell.clone_repositories", o.CloneRepositories, validCloneRepository); err != nil {
		return err
	}
	return nil
}

// validCloneRepository accepts an https or ssh repository URL with no
// whitespace, no embedded option and no transport helper.
func validCloneRepository(s string) bool {
	if s == "" || len(s) > 512 || strings.ContainsAny(s, " \t\r\n") || strings.Contains(s, "::") || strings.Contains(s, "--") {
		return false
	}
	return strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "ssh://")
}

// SandboxManagedKeyOrgHosted is the managed body's org_openshell field by
// its wire key (SandboxManagedKeys), the node's composition row for the
// org-hosted OpenShell row (lane G4).
const SandboxManagedKeyOrgHosted = "hosted.openshell-org"
