package sandboxremote

import (
	"errors"

	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// ErrDenyNotRenderable is a wire client's refusal of a create whose
// DenyCIDRs its vendor's API cannot carry. PrivateRangeDeny never asks such
// a vendor for a deny; the refusal keeps a mistake from making an open box
// the consent screen called denied.
var ErrDenyNotRenderable = errors.New("sandboxremote: this vendor's create request cannot carry a deny of address ranges")

// network.go is the one owner of what a person is told, before Start and on
// the consent screen, about a hosted box's own network and about the hooks
// that do not run there (lane UX, items H9 and H10), and of the private-range
// deny a hosted internet tier's create request carries (decision SBXD-7). The
// New Terminal dialog shows these as served by the probe; the consent screen
// adds them as lines.

// TierNetworkNotes are the sentences about the box's own network on tier,
// given the person's effective allow_private_ranges (allow): on a tier whose
// meaning the vendor does not document (Source claimed; every hosted internet
// tier but the org's own gateway), that the box's traffic is the vendor's,
// and whether the cloud metadata address and private ranges are denied by
// Observer's request, not deniable on that vendor, or allowed by the
// person's setting (PrivateRangeDeny); then the vendor's own NetworkNotes
// (what a live run saw, which can apply on any tier). An empty tier is
// internet, the hosted default. Nil when there is nothing to say.
func TierNetworkNotes(v Vendor, tier vocab.Tier, allow bool) []string {
	if tier == "" {
		tier = vocab.TierInternet
	}
	var out []string
	if s := privateRangeSentence(v, tier, PrivateRangeDeny(v, tier, allow).Posture); s != "" {
		out = append(out, s)
	}
	return append(out, v.NetworkNotes...)
}

// privateRangeSentence is the tier's own network sentence for one posture
// ("" on a tier whose mechanism is documented).
func privateRangeSentence(v Vendor, tier vocab.Tier, p PrivateRangePosture) string {
	lead := "On " + tierSettingWords(tier) + " the box reaches the network through " + v.Name + "'s own network, not through Observer: Observer does not carry that traffic"
	switch p {
	case PrivateRangesDenied:
		scope := "the cloud metadata address, link-local and private network ranges"
		if !v.DenyRanges.IPv6 {
			scope += " (their IPv4 ranges: " + v.Name + " documents no IPv6 deny)"
		}
		return lead + ". Observer's request asks " + v.Name + " to refuse " + scope + " for this box, and " + v.Name + " enforces that, not Observer; the rest of the internet stays open to the agent."
	case PrivateRangesNotDeniable:
		return lead + " and cannot stop it, and " + v.Name + " does not document refusing the cloud metadata address or private network ranges, so the agent may reach them. " + v.Name + "'s API takes no rule that would refuse them, so Observer cannot ask it to."
	case PrivateRangesAllowedBySetting:
		return lead + " and cannot stop it. Your setting allows private network ranges for " + v.Name + ", so Observer does not ask " + v.Name + " to refuse the cloud metadata address, link-local and private network ranges, and the agent may reach them."
	}
	return ""
}

// tierSettingWords names a tier as the network setting it is.
func tierSettingWords(t vocab.Tier) string {
	switch t {
	case vocab.TierInternet:
		return "the internet setting"
	case vocab.TierProxyOnly:
		return "the model-proxy-only setting"
	case vocab.TierNone:
		return "the no-network setting"
	}
	return "the " + string(t) + " setting"
}

// HostedHookNote is what a person is told about hooks in a hosted box when
// Observer does not set up its own there (guardhooks.go: guard_hooks off,
// guard enforcement off under auto, or a tool whose hook mechanism a box
// cannot be seeded for): the box's agent home is fresh, so this machine's
// hook registration is not there, and only a hook the project itself
// commits runs (through the relay, judged here). The registry disclosure
// no_hook_gating shows the same sentence, per tool and only when it applies
// (the probe's hook_notices).
const HostedHookNote = "No hook runs in the box unless the project itself commits one, so Observer's guard does not check or block the agent's commands and file edits there; what Observer sees is the model requests that come through this machine and the transcripts copied home."

// The private-range deny of a hosted internet tier (decision SBXD-7, audit
// H10, ledger SBX-NET-9). A vendor's internet tier is the vendor's own
// network, which Observer does not carry; where the vendor's create request
// takes deny rules, the request asks the vendor to refuse the cloud metadata
// address, link-local and private ranges while the rest of the network stays
// open. [terminal.sandbox.hosted].allow_private_ranges (default false, so the
// ranges are denied) turns it off for a box that must reach a private
// network, and [terminal.sandbox.hosted.<provider>].allow_private_ranges
// overrides it for one vendor. The vendor enforces the deny, not Observer:
// the notes and the consent screen say so. The proxy_only tier is block-all
// on every vendor row (blockAll), so the deny applies to the internet tier
// only; the org-hosted row's internet tier is the org gateway's compiled rule
// (private ranges removed there), documented, so it is not applicable either.

// PrivateRange is one range of the fixed deny list, with why it is there.
type PrivateRange struct {
	CIDR string
	IPv6 bool
	Why  string
}

// PrivateRanges is the fixed deny list, IPv4 first. Loopback is not on it
// (it is the box itself), and neither is any public range.
var PrivateRanges = []PrivateRange{
	{"169.254.0.0/16", false, "IPv4 link-local (RFC 3927): it holds the cloud metadata address 169.254.169.254 (AWS, Google Cloud, Azure and others answer instance credentials there) and other host-local cloud services such as a provider's own DNS and time servers"},
	{"10.0.0.0/8", false, "IPv4 private network (RFC 1918): the vendor's own internal network and anything peered with it"},
	{"172.16.0.0/12", false, "IPv4 private network (RFC 1918)"},
	{"192.168.0.0/16", false, "IPv4 private network (RFC 1918)"},
	{"100.64.0.0/10", false, "IPv4 shared address space (RFC 6598): carrier-grade NAT and provider-internal networks, which hold some clouds' metadata address (Alibaba Cloud answers at 100.100.100.200)"},
	{"fd00:ec2::254/128", true, "AWS's IPv6 instance metadata address (inside fc00::/7; listed on its own so the reason it is denied is visible)"},
	{"fc00::/7", true, "IPv6 unique local addresses (RFC 4193), the IPv6 private ranges"},
	{"fe80::/10", true, "IPv6 link-local (RFC 4291)"},
}

// DenyCapability is whether and how a vendor's create request refuses
// address ranges while leaving the rest of its network open. The zero value
// is "cannot": the vendor's API takes no rule that would (an allow list
// alone is not a deny), so the ranges stay reachable and are disclosed.
type DenyCapability struct {
	// How names the request field that carries the deny ("" when none).
	How string
	// IPv6: the field is documented (or was seen live) to take IPv6 ranges;
	// false sends the IPv4 ranges only, so an IPv6 range is never sent where
	// it might fail the create.
	IPv6 bool
	// Source grounds it: the vendor's reference, read on a stated date.
	Source string
}

// Supported reports whether the vendor's request can carry the deny.
func (d DenyCapability) Supported() bool { return d.How != "" }

// PrivateRangePosture is what a hosted box's own network does with the
// private ranges on its tier (a closed vocabulary).
type PrivateRangePosture string

// The closed PrivateRangePosture vocabulary.
const (
	// PrivateRangesNotApplicable: the tier's own documented mechanism decides
	// (block-all on none and proxy_only, the org gateway's compiled rule on
	// the org row), so there is nothing to deny.
	PrivateRangesNotApplicable PrivateRangePosture = ""
	// PrivateRangesDenied: Observer's create request asks the vendor to
	// refuse them.
	PrivateRangesDenied PrivateRangePosture = "denied_by_request"
	// PrivateRangesNotDeniable: the vendor's API takes no deny rule.
	PrivateRangesNotDeniable PrivateRangePosture = "not_deniable"
	// PrivateRangesAllowedBySetting: the vendor could refuse them, and the
	// person's allow_private_ranges setting says not to ask.
	PrivateRangesAllowedBySetting PrivateRangePosture = "allowed_by_setting"
)

// ConsentValue is the posture as the consent record binds it: the two
// postures a setting decides, and "" for the two it cannot change. So a
// record made before this fact existed still matches on a row or tier where
// nothing changed, and a setting change on a vendor that cannot deny
// reopens nothing.
func (p PrivateRangePosture) ConsentValue() string {
	switch p {
	case PrivateRangesDenied:
		return "denied"
	case PrivateRangesAllowedBySetting:
		return "allowed"
	}
	return ""
}

// RangeDeny is what one launch's create request carries.
type RangeDeny struct {
	Posture PrivateRangePosture
	// CIDRs are the ranges the request denies (PrivateRangesDenied only),
	// in PrivateRanges order, IPv6 ones only where the vendor takes them.
	CIDRs []string
}

// rangeDenyFacts are what a rule of rangeDenyRules reads.
type rangeDenyFacts struct {
	claimed  bool
	deniable bool
	allow    bool
}

// rangeDenyRules is the ordered rule table (CLAUDE.md rule 5): the first
// row that matches decides.
var rangeDenyRules = []struct {
	name    string
	match   func(rangeDenyFacts) bool
	posture PrivateRangePosture
}{
	{"the tier is documented or absent", func(f rangeDenyFacts) bool { return !f.claimed }, PrivateRangesNotApplicable},
	{"the vendor takes no deny rule", func(f rangeDenyFacts) bool { return !f.deniable }, PrivateRangesNotDeniable},
	{"the person allows private ranges", func(f rangeDenyFacts) bool { return f.allow }, PrivateRangesAllowedBySetting},
	{"deny", func(rangeDenyFacts) bool { return true }, PrivateRangesDenied},
}

// claimedTier reports whether tier is offered and its meaning is the
// vendor's own (the box reaches the network through the vendor's network,
// with nothing documented about private ranges).
func claimedTier(v Vendor, tier vocab.Tier) bool {
	m, ok := v.Tiers[tier]
	return ok && m.Mechanism != "" && m.Source != vocab.SourceDocumented
}

// PrivateRangeDeny decides what a launch on tier asks the vendor to deny,
// given the person's effective allow_private_ranges (allow). An empty tier
// is internet, the hosted default.
func PrivateRangeDeny(v Vendor, tier vocab.Tier, allow bool) RangeDeny {
	if tier == "" {
		tier = vocab.TierInternet
	}
	f := rangeDenyFacts{claimed: claimedTier(v, tier), deniable: v.DenyRanges.Supported(), allow: allow}
	for _, r := range rangeDenyRules {
		if !r.match(f) {
			continue
		}
		out := RangeDeny{Posture: r.posture}
		if r.posture == PrivateRangesDenied {
			for _, pr := range PrivateRanges {
				if !pr.IPv6 || v.DenyRanges.IPv6 {
					out.CIDRs = append(out.CIDRs, pr.CIDR)
				}
			}
		}
		return out
	}
	return RangeDeny{}
}
