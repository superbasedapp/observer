// Package sandboxsbpl is the pure core of the macOS Seatbelt sandbox row
// (sandbox plan v2 section 13 P5, lane SBX-P5): a Go generator of Seatbelt
// profiles (SBPL) built from the same bind and protect tables the bwrap
// planner reads (internal/sandbox), a strict SBPL checker and a small
// evaluator for oracle tests, the N6 table that decides what happens to an
// agent's own Seatbelt sandbox inside Observer's, the Seatbelt probe ladder
// over injected facts, and the judge of the launch self-test.
//
// Nothing here runs sandbox-exec, reads a file or opens a socket: the cmd
// layer (cmd/observer/terminal_sandbox_seatbelt*.go) supplies every fact and
// runs every process. The package is pinned pure by imports_test.go.
//
// Grounding: every rule shape is taken from vendor and open-source
// documentation (Apple's sandbox-exec(1) and the SBPL forms Chromium, the
// Codex CLI and Anthropic's sandbox-runtime publish), never from a live run;
// the row ships Verification = doc and is labelled beta until the section
// 13.9 register (MAC-1 to MAC-10, MAC-34, MAC-35, MAC-37) has receipts.
package sandboxsbpl
