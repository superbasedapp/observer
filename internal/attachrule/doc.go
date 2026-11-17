// Package attachrule decides what happens when a user asks a node to attach to
// a destination, switch destination, disconnect, or only sign in.
//
// Identity (signed in to SuperBased) and destination (where this machine's
// data goes: none, the personal org, a team org or a private server) are
// separate. Decide walks ONE ordered table of rows (plan 06 section 19.3 rule
// 3), top-down, first match wins, so collisions are predictable. The package
// is pure: no database, network, file or process access. Callers pass the
// current state in and act on the Decision (M8.4 wires it into commands).
//
// # Ambiguities in rule 3 and the reading chosen
//
//   - Row 1 and an attach to the locked destination itself: allowed (the lock
//     means "only that destination", not "no attach"), including when already
//     attached there. A request that names no destination on a locked node is
//     read as the locked destination. A lock is matched on Kind and OrgID.
//   - Row 3 with no current destination: allowed with nothing to drain.
//   - Rows 4 and 6 with the SAME destination requested (same Kind and OrgID):
//     not a switch, so they do not match and row 10 refuses ("already
//     attached").
//   - Row 6 says "current destination is individual". A machine with no
//     destination and an explicit requested destination is also routed to
//     row 6 (allowed, nothing to drain, nothing left behind); otherwise
//     "connect <server>" on a fresh machine would fall to row 10. Rows 7-9
//     are the discovery rows: they need an attach intent, no current
//     destination and NO requested destination.
//   - Row 4 requires the request to be a team org or private server. Row 5
//     is the personal org. A managed node asked to attach with no requested
//     destination falls to row 10.
//   - Row 5 after M10: allowed only when MultiEnabled and
//     PolicyAllowsSecondDestination are both true; it adds a second
//     destination, so there is no drain and no old org to confirm.
//   - Row 6 is "allow" plus Drain and ShowLeftBehind; row 4 is
//     "allow with confirmation" naming the old org. The plan requires an
//     explicit confirmation only for row 4.
//   - Rows 7 and 8 also set ChooserMayBeIncomplete (the control plane lists
//     only orgs where it has seen this sign-in); row 9 sets it too and is the
//     only row that sets OfferEnterAddress, as the plan states.
//   - A zero Intent is invalid input and reaches row 10, as does an attach
//     whose shape matches no earlier row.
package attachrule
