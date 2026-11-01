// Package sandboxsignin decides whether a sandboxed run gets a copy of the
// tool's sign-in (lane BOXSIGNIN, operator ruling P-180 (6), tracker
// R-186), and words the consent it asks for.
//
// It is pure: no file, network or database access. The caller resolves the
// facts at its boundary (the tool's registry sign-in row, whether the box
// starts from projected tool state, whether the row is hosted, the org's
// forbid, the user's remembered and per-launch consent) and gets back one
// Decision from an ordered rule table. The copy itself (no-follow, regular
// files only, size-capped, owner-only) is the cmd seam's.
//
// The rules, in order (the first that matches decides):
//
//	R1 hosted      a hosted box (E2B, Modal, Vercel) would put the sign-in
//	               on a third party's machine: refused, and never offered.
//	R2 no_row      the tool has no grounded sign-in file: refused.
//	R3 keychain    the vendor keeps the sign-in in the system keychain on
//	               this OS: refused, file sign-ins only.
//	R4 bound       the backend binds the tool's own state directory (its
//	               sign-in is the host's file, not a copy): nothing to do.
//	R5 org         the organization forbids seeding: refused; it beats a
//	               local consent.
//	R6 declined    the user said no for this launch: not seeded.
//	R7 consented   the user said yes for this launch: seed exactly the
//	               row's files.
//	R8 remembered  [terminal.sandbox].sign_in_seed_tools names the tool:
//	               seed exactly the row's files.
//	R9 ask         an interactive launch with no answer yet: ask.
//	R10 headless   no answer and no one to ask: not seeded.
//
// A bound run (R4) shares the tool's own state, sign-in included (operator
// ruling P-183): SharedLine says so plainly on every such launch.
package sandboxsignin
