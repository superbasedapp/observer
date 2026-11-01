// Package secchangeexport maps a VERIFIED AI change record (internal/
// secchange) to two external formats (security plan 7.10 "Export adapters to
// Agent Trace and git-ai notes later", gap G7, lane GATES-SEC): an Agent
// Trace record and a git-ai authorship log. Each format is pinned to one
// spec version with its URL, the date it was read and its status (Specs);
// both are drafts as far as this build knows, so every output carries the
// `experimental` label in a field the spec allows.
//
// The package is pure: it verifies the envelope itself (an unverified
// record is refused, never exported), takes the commit's facts and its
// changed paths from the caller, and never reads a file, runs git or
// reaches the network. Fields a record lacks stay absent: the record has
// per-file line counts, not line ranges, so no range is ever invented, and
// it names prompts by opaque id only, never by text.
package secchangeexport
