// Package kics is the security.scan.kics driver (security pillar plan
// sections 4.2, 4.4 and 5.6 P2; gap G4; lane GATES-SEC): KICS over a
// project's infrastructure-as-code files with the queries tree beside its
// binary, digest-recorded after the first verified run and re-checked
// before each later run (X9).
//
// KICS v2.2.0 publishes no release binaries and no signature, so there is
// no guided install and no egress lane: a KICS on this machine is the
// developer's own install, decided by its digest (labelled unverified on an
// individual node, refused on a managed node unless the org mirror's
// engine manifest pins it). It also asks api.github.com for its latest
// release on every start with no flag to turn that off, so it runs only
// inside the isolation component's no-network one-shot.
package kics
