// Package copilot implements the Adapter interface for GitHub Copilot
// Chat. See spec §4.5 (implemented in Phase 3) and
// docs/copilot-modern-format.md.
//
// # Three on-disk shapes, one adapter
//
// Copilot Chat has written three different stores over its lifetime, and
// this package parses all of them, dispatching on the file's path SHAPE
// (never on a tool or client identity — CLAUDE.md Module Boundaries #3):
//
//  1. Legacy agent debug log —
//     <workspaceStorage>/<ws>/GitHub.copilot-chat/debug-logs/<sess>/main.jsonl,
//     an event stream of llm_request / tool_call spans gated by the VS
//     Code setting github.copilot.chat.advanced.debug (which
//     EnsureDebugEnabled auto-flips).
//  2. Modern snapshot+patches —
//     <workspaceStorage>/<ws>/chatSessions/<id>.jsonl and
//     <globalStorage>/emptyWindowChatSessions/<id>.jsonl: a kind=0 session
//     snapshot followed by kind=1/kind=2 patches.
//  3. Modern empty-window document —
//     <globalStorage>/emptyWindowChatSessions/<id>.json: the whole file IS
//     the session state, i.e. exactly the object a kind=0 line carries
//     under `v`. It therefore shares the snapshot path's emitter, and a
//     regression test pins the two parses to identical rows.
//
// # Shapes 2 and 3 are mutually exclusive per session id
//
// Because the document and the snapshot log carry the same object, they
// derive the same SourceEventIDs — but they are DIFFERENT source files
// (`<id>.json` vs `<id>.jsonl`), so the store's
// UNIQUE(source_file, source_event_id) index cannot dedupe one against
// the other. A session id present in both shapes would be ingested
// twice.
//
// parseModernDocument therefore consults modernLogSiblingExists first
// and emits nothing but its watermark + surface stamp when a `.jsonl`
// log for the same session id exists in the document's directory or
// under any watch root. The LOG wins: it is append-structured, so it
// carries history the in-place-rewritten document cannot. Same shape as
// cursor's stateDBAlreadyCaptured gate. See docs/copilot-modern-format.md
// ("Double-ingest guard").
//
// # Watch roots
//
// Roots come from internal/platform/vscodehost, so EVERY VS Code-family
// product is covered — Code, Code - Insiders, VSCodium, Cursor, Windsurf,
// Kiro, Qoder, Trae, plus the .vscode-server / .cursor-server remote
// layouts — under every cross-mount-resolved $HOME. Copilot Chat installs
// into the forks too, and the previous hand-rolled Code-only switch missed
// every session recorded inside one.
//
// # Surface
//
// Every session this package parses is an IDE chat by construction (the
// Copilot CLI is a separate adapter with its own tool id), so each parse
// stamps one models.SessionSurface with Surface=models.SurfaceIDE and a
// SurfaceHost resolved from the path through the vscodehost product table.
package copilot
