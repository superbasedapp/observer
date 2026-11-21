package orgcontract

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"slices"
	"sort"
)

// securitypull_served.go holds the security managed pull's SERVED fields
// (lane LEFT-SHARED): fields the org server fills at serve time for the one
// calling node, never authored by an admin (the custom_catalog precedent),
// and served only to a node that advertised the matching capability token
// (ManagedPullCapabilitiesHeader), because the body is closed and an older
// node would refuse a body carrying a field it does not know.
//
//   - approved_baselines: the org's approvals (security plan 4.5.2 and 7.5,
//     internal/orgserver/secorg baselines.go) of the baseline references
//     THIS node's own finding rows reported. A node only labels its
//     baseline "approved by the org"; no verdict changes.
//   - org_dedupe: the org's finding dedupe key (security plan 4.5.1) with
//     its version, served only to a managed member's node. The node keeps
//     it in an owner-only file and computes each finding's org_key at push
//     composition; the key itself never rides the push wire.

// Capability tokens a node sends on the security rail.
const (
	// SecurityCapabilityBaselineApprovals: the node labels approved
	// baselines (reads approved_baselines).
	SecurityCapabilityBaselineApprovals = "security.baseline_approvals"
	// SecurityCapabilityOrgDedupe: the node keeps the org dedupe key and
	// computes org_key (reads org_dedupe).
	SecurityCapabilityOrgDedupe = "security.org_dedupe"
	// SecurityCapabilityPackageLookup: the node reads the authored package
	// lookup fields (package_lookup, package_lookup_private,
	// package_lookup_kinds; lane RM-3). They are authored, not served, but
	// the body is closed, so a node that does not name this token is served
	// the body with those fields removed: an older node keeps decoding its
	// pull, and it never looks a package up anyway.
	SecurityCapabilityPackageLookup = "security.package_lookup"
)

// MaxSecurityApprovedBaselines bounds the approvals served to one node.
const MaxSecurityApprovedBaselines = 64

// SecurityOrgDedupeKeyBytes is the dedupe key's length (32 random bytes).
const SecurityOrgDedupeKeyBytes = 32

// SecurityBaselineApproval is one org approval of a reference the node
// reported: the project key the wire row carried (org_project_id, else
// project_identity_hash), the reference kind and the reference.
type SecurityBaselineApproval struct {
	Project    string `json:"project"`
	RefKind    string `json:"ref_kind"`
	Ref        string `json:"ref"`
	ApprovedAt string `json:"approved_at"`
}

// SecurityOrgDedupe is the org's dedupe key as served: its version (moves on
// every rotation) and the 32 key bytes, base64 (standard, padded).
type SecurityOrgDedupe struct {
	Version int64  `json:"version"`
	Key     string `json:"key"`
}

// KeyBytes decodes the key, refusing a malformed one.
func (d SecurityOrgDedupe) KeyBytes() ([]byte, error) {
	k, err := base64.StdEncoding.Strict().DecodeString(d.Key)
	if err != nil || len(k) != SecurityOrgDedupeKeyBytes {
		return nil, fmt.Errorf("%w: org_dedupe.key must be %d bytes, base64", ErrSecurityManagedPolicy, SecurityOrgDedupeKeyBytes)
	}
	return k, nil
}

var (
	securityApprovalFieldRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	securityApprovedAtRe    = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
)

// SecurityServedFields names the served-only fields p carries; an admin
// write carrying any of them is refused (the server fills them).
func SecurityServedFields(p SecurityManagedPolicyV1) []string {
	var out []string
	if p.CustomCatalog != nil {
		out = append(out, "custom_catalog")
	}
	if p.ApprovedBaselines != nil {
		out = append(out, "approved_baselines")
	}
	if p.OrgDedupe != nil {
		out = append(out, "org_dedupe")
	}
	return out
}

// validateSecurityServed checks the served fields.
func validateSecurityServed(p SecurityManagedPolicyV1) error {
	if p.ApprovedBaselines != nil && len(p.ApprovedBaselines) == 0 {
		return fmt.Errorf("%w: approved_baselines is present but empty; leave it out instead", ErrSecurityManagedPolicy)
	}
	if len(p.ApprovedBaselines) > MaxSecurityApprovedBaselines {
		return fmt.Errorf("%w: approved_baselines has %d entries, max %d", ErrSecurityManagedPolicy, len(p.ApprovedBaselines), MaxSecurityApprovedBaselines)
	}
	seen := map[string]bool{}
	for _, a := range p.ApprovedBaselines {
		if !securityApprovalFieldRe.MatchString(a.Project) || !securityApprovalFieldRe.MatchString(a.Ref) ||
			!slices.Contains(SecurityBaselineRefKinds, a.RefKind) || !securityApprovedAtRe.MatchString(a.ApprovedAt) {
			return fmt.Errorf("%w: approved_baselines entry needs a project, a ref_kind (commit or ci_result), a ref and an RFC 3339 UTC approved_at", ErrSecurityManagedPolicy)
		}
		k := a.Project + "\x00" + a.RefKind + "\x00" + a.Ref
		if seen[k] {
			return fmt.Errorf("%w: approved_baselines names %s twice", ErrSecurityManagedPolicy, a.Ref)
		}
		seen[k] = true
	}
	if d := p.OrgDedupe; d != nil {
		if d.Version <= 0 {
			return fmt.Errorf("%w: org_dedupe.version must be positive", ErrSecurityManagedPolicy)
		}
		if _, err := d.KeyBytes(); err != nil {
			return err
		}
	}
	return nil
}

// canonicalSecurityServed sorts the served lists (the canonical form).
func canonicalSecurityServed(p *SecurityManagedPolicyV1) {
	if p.ApprovedBaselines != nil {
		p.ApprovedBaselines = append([]SecurityBaselineApproval(nil), p.ApprovedBaselines...)
		sort.Slice(p.ApprovedBaselines, func(i, j int) bool {
			a, b := p.ApprovedBaselines[i], p.ApprovedBaselines[j]
			if a.Project != b.Project {
				return a.Project < b.Project
			}
			if a.RefKind != b.RefKind {
				return a.RefKind < b.RefKind
			}
			return a.Ref < b.Ref
		})
	}
}

// SecurityServedInput is what the org server serves one caller beside the
// authored body: the approvals of references this node reported and the
// org's dedupe key (nil unless the caller may hold it).
type SecurityServedInput struct {
	Approvals []SecurityBaselineApproval
	Dedupe    *SecurityOrgDedupe
}

// ComposeSecurityServed returns the canonical body to sign for one caller:
// the authored body (an empty body reads as version 1 with nothing set)
// plus each served field the caller advertised a capability for. A caller
// that advertised none gets the authored body back unchanged, byte for
// byte, so an older node is served exactly what it was before; so is a
// caller with nothing to serve. Approvals past the cap keep the newest.
//
// The package lookup fields (lane RM-3) go the other way: a caller that did
// not name SecurityCapabilityPackageLookup is served the body without them
// (an older node's closed decoder would refuse the whole body otherwise),
// so for such a caller a body that carries them is never byte for byte.
func ComposeSecurityServed(body []byte, caps []string, in SecurityServedInput) ([]byte, error) {
	approvals := slices.Contains(caps, SecurityCapabilityBaselineApprovals) && len(in.Approvals) > 0
	dedupe := slices.Contains(caps, SecurityCapabilityOrgDedupe) && in.Dedupe != nil
	strip := false
	if !slices.Contains(caps, SecurityCapabilityPackageLookup) {
		if p, ok, err := DecodeSecurityManagedPolicy(body); err == nil && ok && securityHasPackageLookup(p) {
			strip = true
		}
	}
	if !approvals && !dedupe && !strip {
		return body, nil
	}
	p, ok, err := DecodeSecurityManagedPolicy(body)
	if err != nil {
		return nil, err
	}
	if !ok {
		p = SecurityManagedPolicyV1{Version: SecurityManagedPolicyVersion}
	}
	if strip {
		p.PackageLookup, p.PackageLookupPrivate, p.PackageLookupKinds = "", "", nil
	}
	if approvals {
		list := append([]SecurityBaselineApproval(nil), in.Approvals...)
		if len(list) > MaxSecurityApprovedBaselines {
			sort.SliceStable(list, func(i, j int) bool { return list[i].ApprovedAt > list[j].ApprovedAt })
			list = list[:MaxSecurityApprovedBaselines]
		}
		p.ApprovedBaselines = list
	}
	if dedupe {
		d := *in.Dedupe
		p.OrgDedupe = &d
	}
	return CanonicalSecurityManagedPolicy(p)
}
