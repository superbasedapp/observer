// Package handoffsvc is the single boundary seam of the session-handoff
// feature (CLAUDE.md rule #2; plan §4): it composes the store substrate,
// the source adapter's transcript reader, the pure internal/handoff core,
// scrubbing, and delivery into one Build() entry that the CLI (and the P2
// dashboard/MCP surfaces) call. Callers receive a plain Result; handoff.*
// types do not spread past this package's signature.
package handoffsvc
