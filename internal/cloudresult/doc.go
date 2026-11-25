// Package cloudresult holds the post-call helpers the two cloud-intelligence
// rails share: the hosted personal service (internal/cloudserver/jobs) and
// the org-served rail (internal/orgserver/intel). Both fence the evidence
// they send a provider with an unpredictable per-request delimiter, and both
// secret-scrub every text field of the result a provider returns before it is
// stored. Those steps used to be written out twice, once per rail, because
// the org rail may not import internal/cloudserver (INV-2,
// tests/invariant/intel_import_boundary_test.go); this package is the one
// copy.
//
// It is pure: it imports only internal/cloudcontract and internal/scrub, plus
// the standard library, and does no I/O (pinned by imports_test.go), so both
// rails can import it without linking either side's I/O.
package cloudresult
