// Package secframework is the node-local framework coverage report of the
// security pillar (security pillar plan
// docs/plans/security-pillar-plan-2026-10-19.md sections 5.12 and 7.8; lane
// sec-h): for the framework ids section 7.8 names (OWASP Agentic Top 10
// 2026: ASI02, ASI04, ASI05; OWASP LLM Top 10 2026: LLM03; MITRE ATLAS
// v2026.09: AML.T0081, AML.T0083, AML.M0029, AML.M0030), which of
// Observer's own controls address it and whether they run on this node.
//
// The mapping is Observer's, written in Observer's words: no framework text
// is copied, and a reader checks the framework itself for what an id means.
// Each id lists requirement groups; a group is met by any one of its
// components. The status of an id comes from a decision table over what is
// compiled into this binary and what is selected: covered, partial, not
// selected or not built. It is a statement about which controls run, never
// a claim of compliance.
//
// Pure: the caller injects the catalog, build and selection predicates; no
// SQL, HTTP or process execution (imports_test.go). The fleet report waits
// for security Phase E.
package secframework
