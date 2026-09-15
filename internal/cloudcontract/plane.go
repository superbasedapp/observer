package cloudcontract

// Plane names which enrichment plane a unit of evidence is destined for. It is
// the closed vocabulary that cloudevidence.BuildEnvelope matches a session's
// data-authority against before it will build anything (INV-1):
//
//   - org-authority data builds only for PlaneOrg (the org-served rail),
//   - personal-authority data builds only for PlanePersonal (the personal
//     cloud plane),
//   - unknown authority builds for neither.
//
// Plane lives here, with the versioned wire/vocabulary owner, rather than in
// cloudevidence, so both the node (personal) and the org server (org) select
// the same closed tokens. The zero value is the empty string, which matches no
// plane and is therefore refused — a caller must name the plane explicitly.
type Plane string

const (
	// PlanePersonal is the personal cloud-intelligence plane (the signed-in
	// free spine); it accepts only AuthorityPersonal data.
	PlanePersonal Plane = "personal"
	// PlaneOrg is the org-served intelligence rail for enrolled nodes; it
	// accepts only AuthorityOrg data.
	PlaneOrg Plane = "org"
)
