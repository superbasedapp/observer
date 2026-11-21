// Package secrank is the ONE ranking rule of dependency findings (OS and CI
// vulnerability scanning plan sections 14.5 and 14.7, M3L-1; operator
// ruling Q14-4 (a): rank and label only). Every surface that orders
// findings (the Code security page's findings list, the MCP tool
// get_security_findings) orders them through Order:
//
//  1. listed in the CISA KEV catalog first,
//  2. then the reachability tier (imported, then imported from tests only,
//     then unknown, then not imported directly: secreach.Tier.SortRank),
//  3. then the EPSS score, highest first (no score last),
//  4. then the order the caller handed in (the existing severity order).
//
// The rule is an ordered table (rules), one test case per row. Only
// dependency findings carry these signals, so Order reorders the dependency
// findings among the places they already hold and leaves every other
// finding where the caller's order put it: a secret or a code finding is
// never moved by a dependency's labels.
//
// The labels never close, hide or re-grade a finding and never change its
// severity, and no posture reads them. A finding whose exploit data is
// unavailable ranks as "no KEV listing, no score": it is not claimed
// exploited or unexploited, it simply gains no rank from data that is not
// there.
//
// The package is pure (CLAUDE.md module rule 1): it takes keys and returns
// a permutation; imports_test.go pins it.
package secrank
