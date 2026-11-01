package hook

import (
	"bytes"
	"encoding/json"

	"github.com/marmutapp/superbased-observer/internal/guard"
)

// FailClosedTimeoutReason is the developer-facing reason a fail-closed hook
// gives when it could not finish in time (hook-parity audit section 5.7).
const FailClosedTimeoutReason = "Observer could not evaluate this call in time; it is blocked because guard enforcement is on. Retry, or ask your admin if this repeats."

// FailClosedErrorReason is the developer-facing reason a fail-closed hook
// gives for every other failure (a crash, an unreadable config, a guard that
// could not be built, an unparseable payload).
const FailClosedErrorReason = "Observer could not evaluate this call because of an internal error; it is blocked because guard enforcement is on. Retry, or ask your admin if this repeats."

// FailClosedReply is a dialect's BLOCK, as bytes and an exit code, for a
// hook that failed while guard enforcement is on.
type FailClosedReply struct {
	// Stdout is the exact reply to write (nil = write nothing: the
	// dialect blocks by exit code alone).
	Stdout []byte
	// ExitCode is the process exit code that carries (or accompanies) the
	// block.
	ExitCode int
	// StderrReason is true when the dialect shows the hook's stderr to the
	// developer as the block reason; the reason is then written to stderr
	// through StderrBlockReason (the StderrBlockHeader and the reason on
	// one line), with no diagnostic noise on the same stream.
	StderrReason bool
}

// failClosedBuilders are the non-prompt gate dialects' block replies, keyed
// by the internal/integration HookBinding.Dialect id (data, never a tool
// name). The prompt dialects come from promptDialects, the one table their
// guarded receiver already uses.
var failClosedBuilders = map[string]func(reason string) FailClosedReply{
	// Cursor before* permission events: the same reply shape the guarded
	// cursor receiver writes for a deny.
	"cursor-permission": func(string) FailClosedReply {
		return FailClosedReply{Stdout: encodeReply(cursorReply{Permission: "deny", Continue: true})}
	},
	// Plugin hosts (pluginshim TS shim, Hermes Python plugin): the plugin
	// dialect's deny, which the plugin maps onto its host's block.
	PluginDialectToolGate: buildPluginFailClosedReply,
}

// failClosedToolGateNativeEvent is the hookEventName a tool-gate dialect's
// fail-closed deny names: every Claude-shaped tool-gate binding today is
// the vendor's "PreToolUse" event (the other dialects carry no event name).
const failClosedToolGateNativeEvent = "PreToolUse"

// BuildFailClosedReply returns dialect's block reply carrying reason.
// ok=false when Observer has no blocking reply for the dialect (unknown, or
// a warn-only prompt seam): such a hook cannot fail closed and keeps its
// fail-open behaviour. A tool-gate dialect blocks with its own deny (the
// same reply HandleToolGate writes for a deny verdict).
func BuildFailClosedReply(dialect, reason string) (FailClosedReply, bool) {
	if b, ok := toolGateBlockFor(dialect, failClosedToolGateNativeEvent, guard.Emission{
		Permission: "deny", Enforced: true, Reason: reason,
	}); ok {
		return FailClosedReply{Stdout: b.stdout, ExitCode: b.exitCode, StderrReason: b.stderrReason}, true
	}
	if b, ok := failClosedBuilders[dialect]; ok {
		return b(reason), true
	}
	d, ok := promptDialects[dialect]
	if !ok || !d.caps.Block {
		return FailClosedReply{}, false
	}
	// A prompt dialect that blocks by exit code shows the hook's stderr as
	// the block reason on that exit (Codex, Factory Droid, Qwen Code, Gemini
	// CLI, Poolside, Qoder, Claude Code). So a fail-closed reply that exits
	// non-zero writes the developer-facing reason there and nothing else,
	// even for a dialect whose normal guarded block answers in JSON (T-048:
	// on Codex 0.160.0 both the JSON exit-0 block and this exit-2 block
	// stop the prompt, live 2026-10-03; without this the reason Codex reads
	// for the exit-2 block was Observer's diagnostic line).
	out := FailClosedReply{ExitCode: d.blockExitCode, StderrReason: d.stderrReason || d.blockExitCode != 0}
	if d.reply != nil {
		if r := d.reply(promptReplyOutcome{Blocking: true, Reason: reason}); r != nil {
			out.Stdout = encodeReply(r)
		}
	}
	return out, true
}

// CanFailClosed reports whether BuildFailClosedReply has a block for
// dialect.
func CanFailClosed(dialect string) bool {
	_, ok := BuildFailClosedReply(dialect, "")
	return ok
}

func encodeReply(v any) []byte {
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(v)
	return buf.Bytes()
}
