package orgcontract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
)

// Project family sections on the guard bundle rail (security plan section
// 7.11 "Family bodies (security.scanning sections) merge with their
// per-field raise-only operators" and delivery item 1, lane sec-p3).
//
// An admin publishes a policy-family body (today security.scanning only)
// with a projects audience through the family's own publish route. The org
// server never serves such a body on the policy-resource rail: it carries it
// inside every per-project v3 envelope of that project, as a family member,
// to a node that advertises ProjectFamiliesCapability beside
// PolicyBindingV3Capability. The envelope's signature covers the members
// through ProjectBinding.FamiliesDigest (its own signing domain), so a member
// cannot be added, dropped, changed, or moved to another project's envelope,
// another member, org or epoch without the signature failing. A node that
// does not advertise the token is served no member and no project that only
// a family section reaches, so its envelopes and mapping are byte for byte
// what P1 served.

// ProjectFamiliesCapability is the ?policy_caps token a node sends, beside
// PolicyBindingV3Capability, to be served family members in its per-project
// envelopes. A server that predates it ignores it.
const ProjectFamiliesCapability = "project-families-v1"

// policyBundleSigningV3FamiliesDomain opens the v3 message of an envelope
// that carries family members.
const policyBundleSigningV3FamiliesDomain = "sbo-policy-bundle-v3-families"

// projectFamiliesDigestDomain opens the families digest's input.
const projectFamiliesDigestDomain = "sbo-project-families-v1"

// MaxProjectFamilyMembers caps the members of one envelope (one per newest
// section per audience key; a project rarely has more than a handful).
const MaxProjectFamilyMembers = 32

// ProjectFamilyMember is one published family section inside a per-project
// envelope.
type ProjectFamilyMember struct {
	// Family is the policy family ("security.scanning").
	Family string `json:"family"`
	// Version is the server's sequence of the stored section row.
	Version int64 `json:"version"`
	// Projects is the audience the section was published for, sorted (the
	// envelope's own project is one of them).
	Projects []string `json:"projects"`
	// Body is the canonical body the family's linked compiler produced.
	Body string `json:"body"`
	// BodyHash is the hex SHA-256 of Body.
	BodyHash string `json:"body_hash"`
	// RequiredCapabilities are the body-derived capability tokens, sorted.
	RequiredCapabilities []string `json:"required_capabilities,omitempty"`
}

// ProjectFamilyBodyHash is the hex SHA-256 of a canonical body.
func ProjectFamilyBodyHash(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

// sortedFamilyMembers returns members sorted by (family, version).
func sortedFamilyMembers(members []ProjectFamilyMember) []ProjectFamilyMember {
	out := append([]ProjectFamilyMember(nil), members...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].Version < out[j].Version
	})
	return out
}

// ProjectFamiliesDigest is hex(SHA-256) over the members' canonical form:
// the domain, the count, then per member (sorted by family and version) its
// family, version, projects, body hash and required capabilities, each
// length-prefixed. "" for no member, so an envelope without members keeps
// the P1 signing message. The body is covered through its hash, which
// CheckProjectFamilies recomputes.
func ProjectFamiliesDigest(members []ProjectFamilyMember) string {
	if len(members) == 0 {
		return ""
	}
	var buf bytes.Buffer
	buf.WriteString(projectFamiliesDigestDomain)
	sorted := sortedFamilyMembers(members)
	writeLPField(&buf, strconv.Itoa(len(sorted)))
	for _, m := range sorted {
		writeLPField(&buf, m.Family)
		writeLPField(&buf, strconv.FormatInt(m.Version, 10))
		projects := sortedUnique(m.Projects)
		writeLPField(&buf, strconv.Itoa(len(projects)))
		for _, p := range projects {
			writeLPField(&buf, p)
		}
		writeLPField(&buf, m.BodyHash)
		caps := sortedUnique(m.RequiredCapabilities)
		writeLPField(&buf, strconv.Itoa(len(caps)))
		for _, c := range caps {
			writeLPField(&buf, c)
		}
	}
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:])
}

// ErrProjectFamilies is every refusal of CheckProjectFamilies.
var ErrProjectFamilies = errors.New("orgcontract: project family members do not match their envelope")

// CheckProjectFamilies is the structural check of an envelope's family
// members, run by the node after the envelope's signature verified (the
// signature covers FamiliesDigest): members only on a per-project envelope,
// at most MaxProjectFamilyMembers, each with a family, a positive version,
// its envelope's project in its audience, a body that hashes to BodyHash, no
// version twice per family, and the whole set digesting to the bound value.
// An envelope with no member must bind no digest.
func CheckProjectFamilies(env PolicyBundle) error {
	pb := env.ProjectBinding
	if len(env.Families) == 0 {
		if pb != nil && pb.FamiliesDigest != "" {
			return fmt.Errorf("%w: a families digest with no member", ErrProjectFamilies)
		}
		return nil
	}
	if pb == nil || pb.OrgProjectID == "" {
		return fmt.Errorf("%w: members outside a per-project envelope", ErrProjectFamilies)
	}
	if len(env.Families) > MaxProjectFamilyMembers {
		return fmt.Errorf("%w: %d members, max %d", ErrProjectFamilies, len(env.Families), MaxProjectFamilyMembers)
	}
	seen := map[string]bool{}
	for _, m := range env.Families {
		key := m.Family + "\x00" + strconv.FormatInt(m.Version, 10)
		switch {
		case m.Family == "" || m.Version <= 0:
			return fmt.Errorf("%w: a member with no family or version", ErrProjectFamilies)
		case seen[key]:
			return fmt.Errorf("%w: %s v%d listed twice", ErrProjectFamilies, m.Family, m.Version)
		case ProjectFamilyBodyHash(m.Body) != m.BodyHash:
			return fmt.Errorf("%w: %s v%d body does not match its hash", ErrProjectFamilies, m.Family, m.Version)
		}
		seen[key] = true
		inAudience := false
		for _, p := range m.Projects {
			if p == pb.OrgProjectID {
				inAudience = true
				break
			}
		}
		if !inAudience {
			return fmt.Errorf("%w: %s v%d is not published for project %q", ErrProjectFamilies, m.Family, m.Version, pb.OrgProjectID)
		}
	}
	if ProjectFamiliesDigest(env.Families) != pb.FamiliesDigest {
		return fmt.Errorf("%w: the members do not digest to the signed value", ErrProjectFamilies)
	}
	return nil
}

// Per-section status of the project FAMILY sections on the policy-ack rail
// (security plan section 7.11 "policy status and ack or NACK are reported
// per project section", lane sec-p3): the gen6 guard-row field
// PolicyStateRow.ProjectFamilyStatus, beside P2B's guard-section list and
// sharing its truncation flag. One entry per family section the node holds
// in the envelope of a project of its signed mapping: the org project id, the
// family, the section's sequence and a closed status. No path, directory,
// repository identity or body crosses the wire.

// Project family section statuses (ProjectFamilySectionState.Status). The
// first four mean what ProjectSection* mean for the guard section of the same
// project's envelope; the last two are the family's own.
const (
	ProjectFamilyApplied      = ProjectSectionApplied
	ProjectFamilyNotMatched   = ProjectSectionNotMatched
	ProjectFamilyUnknown      = ProjectSectionUnknown
	ProjectFamilyNotDelivered = ProjectSectionNotDelivered
	// ProjectFamilyRefused: held and verified, but not applied on this
	// node: the body does not compile here to the bytes it carries, or it
	// cannot merge over the org-wide floor in force (an allow-set that would
	// allow nothing, a contradiction).
	ProjectFamilyRefused = "refused"
	// ProjectFamilyInert: held and verified, but the node has not
	// preauthorized the family's enforcement (accepted only).
	ProjectFamilyInert = "inert"
	// ProjectFamilyPartial: held, verified and applied except on the axes
	// named in RefusedAxes, which conflict with the org-wide floor in force
	// (SEC-P3 merge, finding 2: a section is refused per axis, never whole
	// for one conflicting axis). A NACK naming the axes.
	ProjectFamilyPartial = "partial"
)

// MaxProjectFamilyRefusedAxes bounds RefusedAxes (the family has fewer
// axes than this).
const MaxProjectFamilyRefusedAxes = 32

// projectFamilyAxisRe is the shape of a family axis name
// ("require.online_checks"). The server checks the shape rather than a copy
// of the family's axis table, as for the policy-state detector ids.
var projectFamilyAxisRe = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$`)

// projectFamilyStatuses is the closed vocabulary with ACK (true) or NACK.
var projectFamilyStatuses = map[string]bool{
	ProjectFamilyApplied:      true,
	ProjectFamilyNotMatched:   true,
	ProjectFamilyUnknown:      false,
	ProjectFamilyNotDelivered: false,
	ProjectFamilyRefused:      false,
	ProjectFamilyInert:        false,
	ProjectFamilyPartial:      false,
}

// ProjectFamilyStatusKnown reports whether s is in the closed vocabulary.
func ProjectFamilyStatusKnown(s string) bool {
	_, ok := projectFamilyStatuses[s]
	return ok
}

// ProjectFamilyAcked reports whether a status acknowledges its section
// (applied, not_matched); every other value, an unknown one included, is a
// NACK.
func ProjectFamilyAcked(s string) bool { return projectFamilyStatuses[s] }

// ProjectSectionFamilies is the closed set of families a project section may
// carry (the org server publishes only these).
var ProjectSectionFamilies = []string{"security.scanning"}

// ProjectFamilySectionState is one project family section's status on one
// node.
type ProjectFamilySectionState struct {
	OrgProjectID string `json:"org_project_id"`
	Family       string `json:"family"`
	Version      int64  `json:"version"`
	Status       string `json:"status"`
	// RefusedAxes names the axes of the section this node did not apply
	// (sorted, each once): required with ProjectFamilyPartial, allowed with
	// ProjectFamilyRefused, empty otherwise.
	RefusedAxes []string `json:"refused_axes,omitempty"`
}

// ValidProjectFamilyStatus checks a reported list: at most
// MaxProjectMappingProjects entries, each with a project id
// ValidProjectSectionStatus would accept, a family of ProjectSectionFamilies,
// a positive version, a status in the closed vocabulary, and each (project,
// family, version) once. Nil or empty is valid.
func ValidProjectFamilyStatus(list []ProjectFamilySectionState) bool {
	if len(list) > MaxProjectMappingProjects {
		return false
	}
	seen := map[string]bool{}
	for _, e := range list {
		if !ValidProjectSectionStatus([]ProjectSectionState{{OrgProjectID: e.OrgProjectID, Status: ProjectSectionApplied}}) {
			return false
		}
		known := false
		for _, f := range ProjectSectionFamilies {
			if e.Family == f {
				known = true
			}
		}
		key := e.OrgProjectID + "\x00" + e.Family + "\x00" + strconv.FormatInt(e.Version, 10)
		if !known || e.Version <= 0 || !ProjectFamilyStatusKnown(e.Status) || seen[key] || !validRefusedAxes(e) {
			return false
		}
		seen[key] = true
	}
	return true
}

// validRefusedAxes: RefusedAxes is bounded, strictly sorted, axis-shaped,
// present only on a partial or refused section, and present on a partial one.
func validRefusedAxes(e ProjectFamilySectionState) bool {
	switch e.Status {
	case ProjectFamilyPartial:
		if len(e.RefusedAxes) == 0 {
			return false
		}
	case ProjectFamilyRefused:
	default:
		return len(e.RefusedAxes) == 0
	}
	if len(e.RefusedAxes) > MaxProjectFamilyRefusedAxes {
		return false
	}
	for i, a := range e.RefusedAxes {
		if len(a) > 64 || !projectFamilyAxisRe.MatchString(a) || (i > 0 && e.RefusedAxes[i-1] >= a) {
			return false
		}
	}
	return true
}
