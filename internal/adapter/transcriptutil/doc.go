// Package transcriptutil holds the shared exchange builder every
// adapter's transcript reader folds its records through (session handoff,
// docs/session-handoff.md). The normalization rules are Phase 0's
// D-P0.3, identical across formats: consecutive assistant-side records
// merge into ONE assistant exchange per user prompt; tool results attach
// to the owning exchange's ToolCallRefs (never surfacing as user
// messages); thinking/reasoning is dropped by the caller (it simply never
// feeds the builder). Pure record-folding — no I/O, no SQL; adapters own
// their storage walk and feed this one message at a time.
//
// It also owns DecodeContent and TrimJSONSpace, the decoding of an
// Anthropic-shape message content field (a block array or a bare string)
// that the claudecode, cline and cowork parsers share.
package transcriptutil
