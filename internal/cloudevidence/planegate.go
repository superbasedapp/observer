package cloudevidence

import (
	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/dataauthority"
)

// planeRule is one row of the closed plane-eligibility decision table.
type planeRule struct {
	Plane     cloudcontract.Plane
	Authority string // normalized {personal, org, unknown} key (see authorityKey)
	Eligible  bool
}

// planeEligibility is the closed {personal, org, unknown} × {personal, org}
// decision table that pins INV-1: six rows, two accept, four refuse. The build
// is eligible ONLY when a row matches the (plane, authority) pair and is marked
// Eligible; a pair absent from the table, or present and not Eligible, is
// refused. It is walked as data (eligibleForPlane), never an if/else ladder —
// CLAUDE.md §5. The Eligible column is cross-checked against
// dataauthority's two predicates by TestPlaneTableMatchesAuthorityPredicates so
// the two cannot drift.
var planeEligibility = []planeRule{
	{cloudcontract.PlanePersonal, authorityKeyPersonal, true}, // personal data → personal plane
	{cloudcontract.PlanePersonal, authorityKeyOrg, false},     // org data ✗ personal plane
	{cloudcontract.PlanePersonal, authorityKeyUnknown, false}, // unknown ✗ personal plane
	{cloudcontract.PlaneOrg, authorityKeyPersonal, false},     // personal data ✗ org plane
	{cloudcontract.PlaneOrg, authorityKeyOrg, true},           // org data → org plane
	{cloudcontract.PlaneOrg, authorityKeyUnknown, false},      // unknown ✗ org plane
}

const (
	authorityKeyPersonal = "personal"
	authorityKeyOrg      = "org"
	authorityKeyUnknown  = "unknown"
)

// authorityKey collapses a Classification's authority into the closed
// {personal, org, unknown} vocabulary the table is keyed on. This is the
// boundary normalization (CLAUDE.md §3): any authority that is neither
// personal nor org — NULL, a pre-096 row, or a fail-closed enrolment read —
// becomes "unknown", which is ineligible for every plane.
func authorityKey(c dataauthority.Classification) string {
	switch c.Authority {
	case dataauthority.AuthorityPersonal:
		return authorityKeyPersonal
	case dataauthority.AuthorityOrg:
		return authorityKeyOrg
	default:
		return authorityKeyUnknown
	}
}

// eligibleForPlane reports whether a session with classification c may be built
// into an envelope for the given plane, by walking the planeEligibility table.
// An unrecognized plane (including the empty zero value) matches no row and is
// refused — so a caller must name the plane explicitly.
func eligibleForPlane(plane cloudcontract.Plane, c dataauthority.Classification) bool {
	key := authorityKey(c)
	for _, r := range planeEligibility {
		if r.Plane == plane && r.Authority == key {
			return r.Eligible
		}
	}
	return false
}
