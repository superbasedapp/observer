package codex

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/codexpatch"
)

// This file resolves modern Codex's UNIFIED EXEC tool call.
//
// Older Codex builds emit one response_item/function_call per tool with
// a self-describing name (`shell`, `exec_command`, `update_plan`, …) and
// a JSON argument object. Current builds — and the Open Interpreter
// rebadge, which reuses this parser verbatim — collapse the whole tool
// surface into a SINGLE response_item/custom_tool_call named "exec"
// whose `input` is a small JavaScript program that calls the real tool:
//
//	const r = await tools.exec_command({cmd:"sed -n '1,240p' PROGRESS.md",
//	    "workdir":"/home/u/repo","yield_time_ms":10000}); text(r.output);
//
//	const patch = "*** Begin Patch\n*** Update File: a.go\n@@\n-x\n+y\n*** End Patch";
//	const result = await tools.apply_patch(patch); text(result);
//
//	const p = await tools.update_plan({explanation:"…",plan:[
//	    {step:"Read PROGRESS.md",status:"completed"}]}); text(p);
//
//	const r = await tools.write_stdin({session_id:62552,chars:"",
//	    yield_time_ms:30000,max_output_tokens:12000}); text(JSON.stringify(r));
//
// `exec` is therefore a DISPATCHER, not a shell tool. Treating the whole
// family as one run_command with an empty Target (the pre-fix behaviour)
// both blinded every consumer of actions.target — command-class
// resolution, internal/guard's dangerous-command policy, run_command
// analytics — and over-counted codex's shell activity, because ~24% of
// the family is not a shell command at all.
//
// GROUNDING. Measured over every rollout JSONL under ~/.codex/sessions
// and ~/.openinterpreter/sessions on 2026-07-31 (7,087 custom_tool_call
// rows named "exec"), bucketed by the SET of tools.<name> calls the
// program contains:
//
//	exec_command                  5379
//	apply_patch                    818
//	write_stdin                    713
//	update_plan                     85
//	exec_command + update_plan      83
//	exec_command + write_stdin       4
//	apply_patch  + exec_command      2
//	(no tools.* call at all)          3
//
// Those four inner names are the ENTIRE observed vocabulary, and the
// taxonomy already has a row for each one (internal/tooltax): they
// resolve through the adapter's existing tooltax-sourced actionMap
// rather than through a hand-written switch, so no tooltax edit is
// needed and a fifth verb lands in the honest ActionUnknown bucket
// instead of being silently absorbed into run_command.
//
// The three programs with no tools.* call at all were harness
// introspection over the injected ALL_TOOLS array
// (`ALL_TOOLS.filter(x => x.name === "exec_command"); text(meta);`) —
// they invoke no tool, so they are the documented residual class; see
// unifiedExecResidualNote.

// jsToolCall is one `tools.<name>( … )` invocation located in a
// unified-exec program, with the RAW source of its argument list (the
// text between the outermost parentheses, un-decoded).
type jsToolCall struct {
	Name string
	Args string
	// At is the byte index in the program where this call's `tools.`
	// token starts. It bounds binding resolution: only an assignment
	// textually BEFORE the call site can have supplied its argument
	// (see codexpatch.StringBinding).
	At int
}

// unifiedExecCall is the resolved identity of a unified-exec program:
// which inner tool it invoked and that call's primary argument.
type unifiedExecCall struct {
	// Name is the inner tools.<name>. Empty when the program invoked
	// no tool at all (the residual class).
	Name string
	// Target is the decoded primary argument for every inner call
	// EXCEPT apply_patch: the command for exec_command, the written
	// characters for write_stdin, the plan explanation (or first
	// step) for update_plan. Empty is a legitimate value —
	// write_stdin polls a running session with chars:"" in 513 of
	// the 713 live rows, and there is genuinely no argument to
	// report.
	Target string
	// PatchText is apply_patch's decoded patch envelope. Callers run
	// it through applyPatchTarget so the row's Target follows the
	// adapter's existing patch-target convention (first changed
	// path, project-relative). All 820 live apply_patch calls pass
	// the envelope by IDENTIFIER (`const patch = "…"; await
	// tools.apply_patch(patch)`), so resolving the const binding is
	// the load-bearing path; an inline literal is accepted too.
	PatchText string
	// NoToolCall reports that the program PROVABLY invoked no tool —
	// it contains no reference to the dispatcher object in ANY form
	// (see programProvablyInvokesNoTool). Only that proof licenses the
	// emit site to type the row models.ActionHarnessCall. A program
	// the scanner merely FAILED to resolve leaves this false and falls
	// back to the taxonomy's conservative exec row; see RESIDUAL
	// CLASS 1.
	NoToolCall bool
}

// unifiedExecToolName is the outer custom_tool_call name that carries a
// JavaScript program instead of a tool-specific argument object.
const unifiedExecToolName = "exec"

// jsToolsPrefix is the dispatcher namespace every inner call is reached
// through. Nothing else in the program invokes a tool.
const jsToolsPrefix = "tools."

// unifiedExecArgKeys is the per-inner-call primary-argument ladder:
// the object-literal keys to try, IN ORDER, for that call's Target.
// One row per inner call, each key grounded in live rows — update_plan
// carries `explanation` in 92 live calls and only `plan[].step` in the
// other 76, which is why it needs two rungs and the others need one.
// A call with no row here contributes no Target rather than a guess.
var unifiedExecArgKeys = map[string][]string{
	"exec_command": {"cmd"},
	"write_stdin":  {"chars"},
	"update_plan":  {"explanation", "step"},
}

// unifiedExecPatchCalls are the inner calls whose primary argument is a
// raw patch envelope rather than an object-literal field.
var unifiedExecPatchCalls = map[string]bool{
	"apply_patch": true,
}

// unifiedExecBookkeeping marks inner calls that are a bookkeeping
// PREAMBLE rather than the substantive work of the program. A
// custom_tool_call becomes exactly one action row, so a program that
// updates the plan and then runs a command has to pick one identity:
// in all 86 live mixed programs the update_plan is the preamble and
// the other call is the work (73 are literally ordered update_plan →
// exec_command). Choosing the first NON-bookkeeping call reproduces
// that, and still yields todo_update for the 85 programs that only
// update the plan.
var unifiedExecBookkeeping = map[string]bool{
	"update_plan": true,
}

// RESIDUAL CLASS 1 — PROVABLY NO TOOL CALL. The FIRST honest residual:
// a program that invokes no tools.<name> at all (3 live rows, all
// ALL_TOOLS introspection over the injected tool descriptors). It is
// not a command, an edit, a plan update or a stdin write, and calling
// it any of those would be a fabrication — the emit site types it
// models.ActionHarnessCall with an empty Target.
//
// The membership test is a PROOF, not the scanner's silence. The
// scanner resolves the call SYNTAX Codex actually emits; syntax it does
// not model is invisible to it, and several such shapes reach the
// dispatcher object without ever emitting a `tools.<name>(` sequence:
//
//	text(`${await tools.exec_command({cmd:"rm -rf /tmp/x"})}`)  // template literal
//	await tools["exec_command"]({cmd:"..."})               // bracket access
//	await tools?.exec_command({cmd:"..."})                 // optional chaining
//
// Treating those as "no tool call" would type a REAL shell run as a
// harness call — losing the taxonomy's conservative exec row and
// skipping target-based safety classification entirely. So the residual
// is entered only when programProvablyInvokesNoTool says the dispatcher
// identifier appears NOWHERE in the program; everything else the
// scanner could not resolve falls back to the taxonomy's `exec` row
// (run_command) with an empty Target — the pre-fix behaviour, which is
// wrong-but-conservative rather than wrong-and-permissive.

// RESIDUAL CLASS 2 — HOISTED-ARRAY FAN-OUT. The SECOND honest
// residual. The program builds an array of work and maps the
// dispatcher over it, so the call site holds an identifier rather
// than a value:
//
//	const cmds = ["git status", "sed -n '1,80p' x.go"];
//	const rs = await Promise.all(cmds.map(cmd => tools.exec_command({cmd, …})));
//
//	const p = [{step:"Inspect current code", status:"in_progress"}, …];
//	await tools.update_plan({plan: p});
//
// Measured 2026-07-31 over all 7,087 live programs: 184 exec_command +
// 2 update_plan + 1 apply_patch = 187 programs, 2.6% of the family.
// These have no single primary argument, and the array element shapes
// are NOT uniform (plain strings, ["label", cmd] pairs, [cmd,
// token_budget] pairs, patch lines awaiting a join), so picking a slot
// would be a guess about which one is the command. They keep the
// correct ACTION TYPE and an EMPTY Target, and the whole program stays
// in raw_tool_input.
//
// A hoisted STRING is different and IS resolved: `const patch = "…";
// tools.apply_patch(patch)` binds exactly one value, so following the
// binding is a decode, not a choice (see codexpatch.StringBinding —
// this is the dominant apply_patch form, and with String.raw support it
// resolves 818 of the 819 live apply_patch calls).

// parseUnifiedExec resolves a unified-exec `input` program into the
// inner call it dispatched to plus that call's primary argument. It
// never panics and never errors: an unparseable, truncated or empty
// program simply yields the zero value, which the emit site treats as
// the residual class.
func parseUnifiedExec(input string) unifiedExecCall {
	calls := scanJSToolCalls(input)
	if len(calls) == 0 {
		// Silence is not proof: only a program with no reference to
		// the dispatcher object AT ALL is the residual class. See
		// RESIDUAL CLASS 1.
		return unifiedExecCall{NoToolCall: programProvablyInvokesNoTool(input)}
	}
	chosen := calls[0]
	for _, c := range calls {
		if !unifiedExecBookkeeping[c.Name] {
			chosen = c
			break
		}
	}
	out := unifiedExecCall{Name: chosen.Name}
	if unifiedExecPatchCalls[chosen.Name] {
		out.PatchText = codexpatch.PatchArgument(input, chosen.Args, chosen.At)
		return out
	}
	for _, key := range unifiedExecArgKeys[chosen.Name] {
		if v, ok := codexpatch.StringField(chosen.Args, key); ok {
			out.Target = v
			break
		}
	}
	return out
}

// unifiedExecDispatcherIdent is the injected dispatcher object every
// inner tool is reached through, in any syntax.
const unifiedExecDispatcherIdent = "tools"

// programProvablyInvokesNoTool reports whether a unified-exec program
// PROVABLY invokes no inner tool: the identifier `tools` does not occur
// anywhere in it as a whole token.
//
// This is deliberately a raw-byte scan — NOT string- and comment-aware
// like scanJSToolCalls. That asymmetry is the point. The scanner's job
// is to find the call Codex actually made, so it must ignore text
// inside literals (an apply_patch envelope embedding this very file
// would otherwise read as a shell command). This function's job is the
// opposite: to refuse to certify a program as tool-free. A `tools`
// occurrence inside a string or a comment could still be reached (the
// program could eval it, or the literal could be a truncation artefact
// of a real call), so any occurrence at all withdraws the proof and the
// caller falls back to the taxonomy's conservative exec row.
//
// Whole-token matching means `ALL_TOOLS` (uppercase — the shape all
// three live residual programs use) and `mytools` do not withdraw the
// proof; a bare `tools`, `tools.x`, `tools["x"]`, `tools?.x` and
// `const t = tools` all do.
//
// The proof scans the WHOLE program with no codexpatch.ScanLimit
// truncation: a dispatcher reference past the cap must still count, or
// an oversized program could be certified tool-free by being long.
func programProvablyInvokesNoTool(src string) bool {
	for i := 0; i+len(unifiedExecDispatcherIdent) <= len(src); {
		j := strings.Index(src[i:], unifiedExecDispatcherIdent)
		if j < 0 {
			return true
		}
		at := i + j
		end := at + len(unifiedExecDispatcherIdent)
		leftBoundary := at == 0 || !codexpatch.IsJSIdentByte(src[at-1])
		rightBoundary := end >= len(src) || !codexpatch.IsJSIdentByte(src[end])
		if leftBoundary && rightBoundary {
			return false
		}
		i = at + 1
	}
	return true
}

// scanJSToolCalls walks a program ONCE — tracking JavaScript string and
// comment state — and returns every `tools.<name>( … )` invocation in
// source order.
//
// String-awareness is load-bearing, not cosmetic. apply_patch programs
// embed whole source files inside a single JavaScript string literal,
// and those literals routinely contain the text "tools.exec_command("
// (this repository's own adapter sources do). A regexp over the raw
// program would mis-identify such a patch as a shell command — the exact
// class of over-typing this fix exists to remove.
func scanJSToolCalls(src string) []jsToolCall {
	if len(src) > codexpatch.ScanLimit {
		src = src[:codexpatch.ScanLimit]
	}
	var out []jsToolCall
	for i := 0; i < len(src); {
		switch {
		case codexpatch.IsJSQuote(src[i]):
			i = codexpatch.SkipJSString(src, i)
		case strings.HasPrefix(src[i:], "//"):
			nl := strings.IndexByte(src[i:], '\n')
			if nl < 0 {
				return out
			}
			i += nl + 1
		case strings.HasPrefix(src[i:], "/*"):
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return out
			}
			i += 2 + end + 2
		case strings.HasPrefix(src[i:], jsToolsPrefix) &&
			(i == 0 || !codexpatch.IsJSIdentByte(src[i-1])):
			name, after := codexpatch.ReadJSIdent(src, i+len(jsToolsPrefix))
			if name == "" {
				i += len(jsToolsPrefix)
				continue
			}
			open := codexpatch.SkipJSSpace(src, after)
			if open >= len(src) || src[open] != '(' {
				// `tools.exec_command` mentioned but not called
				// (the ALL_TOOLS introspection shape).
				i = after
				continue
			}
			args, end := codexpatch.ReadJSParenGroup(src, open)
			out = append(out, jsToolCall{Name: name, Args: args, At: i})
			i = end
		default:
			i++
		}
	}
	return out
}
