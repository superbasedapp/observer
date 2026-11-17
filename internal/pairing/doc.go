// Package pairing owns the pairing-code format both ends agree on (managed
// SaaS plan 06 section 19.3 rule 2, way 2; plan 07 M8.5): what a code looks
// like, how it is parsed, the entropy floor, the lifetime, and how a node
// takes one in (the SBO_PAIR_CODE environment variable or a --pair-file,
// never a command-line argument).
//
// A pairing code is minted by the TENANT (the org server's install page,
// under the member's or an admin's own session there), never by the control
// plane. On the server a code is an ordinary enrolment-token row minted with
// the "pair" origin, a 15-minute lifetime and a member binding, so the one
// enrolment exchange (POST /api/agent/enroll) redeems it and the node runs
// its one enrolment sequence. This package only carries the parts the two
// sides must agree on:
//
//	sbp1.<org>.<token_id>.<secret>
//
// <org> is the minting organization's id, base64url without padding (so an
// id containing a dot cannot split the code); <token_id>.<secret> is the
// enrolment token's compound credential. The org part is what lets the
// server refuse a code minted for another organization before it looks a
// token up or spends it.
//
// The package is pure: no database, network, file or process access. The
// file read of a --pair-file is injected (Handoff.ReadFile), so the caller
// owns I/O.
package pairing
