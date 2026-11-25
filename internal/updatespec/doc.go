// Package updatespec holds the neutral vocabulary of node self-update: the
// release Channel names and the maintenance Window grammar of the [update]
// config block, plus the node update State machine (State, Reason,
// ErrorClass, legal transitions, the persisted NodeState) and the install
// Method names. It also owns the SemVer 2.0 precedence order every wire field
// gate uses (ComparePrecedence, shared with the node.governance compiler) and
// the release manifest's small field checks (HashBytes, ValidBaseName,
// IsHexSHA256, shared with the signed content channel internal/update/content).
//
// It is split out of internal/update (the org.update feature: manifests,
// verification, the apply planner) in modular packaging phase PB (rev F1) so
// the core config loader and the store can validate and persist that
// vocabulary without importing the update feature. internal/update
// re-exports everything here as aliases, so the config check, the store and
// the apply gate still share ONE parser and ONE state machine and can never
// disagree about a string like "22:00-02:00". Error text still names
// update.ParseWindow.
//
// Pure: standard library only, no I/O.
package updatespec
