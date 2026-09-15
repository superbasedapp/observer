package codex

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

// TestParseUnifiedExec is the per-shape table for the modern Codex
// `exec` dispatcher. Every `program` below is the real live shape with
// only paths/commands swapped for fixture-safe ones — the key forms
// (bare `cmd:` vs quoted `"workdir":`), the const-binding indirection
// for apply_patch, the String.raw tagged template, the update_plan
// preamble ordering and the write_stdin poll are all reproduced
// verbatim from ~/.codex rollouts measured 2026-07-31.
func TestParseUnifiedExec(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		program   string
		wantName  string
		wantTgt   string
		wantPatch string // substring the decoded patch text must contain
		// wantNoCall is the PROOF flag: true only when the program
		// provably invokes no tool. Silence from the scanner is not
		// enough — see RESIDUAL CLASS 1 / WP-T6 finding F3.
		wantNoCall bool
	}{
		{
			name: "exec_command inline object",
			program: `const r = await tools.exec_command({cmd:"sed -n '1,240p' PROGRESS.md",` +
				`"workdir":"/repo","yield_time_ms":10000,"max_output_tokens":30000}); text(r.output);`,
			wantName: "exec_command",
			wantTgt:  "sed -n '1,240p' PROGRESS.md",
		},
		{
			name: "exec_command with escapes in the command",
			program: `const r = await tools.exec_command({cmd:"rg -n \"needle\" .\nnl -ba a.go",` +
				`"workdir":"/repo"}); text(r.output);`,
			wantName: "exec_command",
			wantTgt:  "rg -n \"needle\" .\nnl -ba a.go",
		},
		{
			name: "exec_command with a quoted cmd key",
			program: `const r = await tools.exec_command({"cmd":"go build ./...","workdir":"/repo"});` +
				` text(r.output);`,
			wantName: "exec_command",
			wantTgt:  "go build ./...",
		},
		{
			name: "update_plan preamble then exec_command — the work call wins",
			program: `const p = await tools.update_plan({plan:[` +
				`{step:"Read PROGRESS.md",status:"in_progress"},` +
				`{step:"Run the tests",status:"pending"}]});` + "\n" +
				`const r = await tools.exec_command({cmd:"go test ./...","workdir":"/repo"});` +
				` text(r.output);`,
			wantName: "exec_command",
			wantTgt:  "go test ./...",
		},
		{
			name: "exec_command then update_plan — order does not matter",
			program: `const r = await tools.exec_command({cmd:"git status --short","workdir":"/repo"});` + "\n" +
				`const p = await tools.update_plan({plan:[{step:"Inspect",status:"completed"}]});`,
			wantName: "exec_command",
			wantTgt:  "git status --short",
		},
		{
			name: "apply_patch through a hoisted const binding",
			program: `const patch = "*** Begin Patch\n*** Update File: /repo/a.go\n@@\n-x\n+y\n*** End Patch";` + "\n" +
				`const result = await tools.apply_patch(patch);` + "\n" + `text(result);`,
			wantName:  "apply_patch",
			wantPatch: "*** Update File: /repo/a.go",
		},
		{
			name: "apply_patch through a String.raw template keeps escapes inert",
			program: "const patch = String.raw`*** Begin Patch\n*** Add File: /repo/raw.go\n" +
				"+package raw\n+const tab = \"\\t\"\n*** End Patch`;\n" +
				"text(await tools.apply_patch(patch));",
			wantName:  "apply_patch",
			wantPatch: `+const tab = "\t"`,
		},
		{
			name:      "apply_patch with an inline literal",
			program:   `text(await tools.apply_patch("*** Begin Patch\n*** Delete File: /repo/gone.go\n*** End Patch"));`,
			wantName:  "apply_patch",
			wantPatch: "*** Delete File: /repo/gone.go",
		},
		{
			name: "apply_patch first, exec_command second — first non-bookkeeping call wins",
			program: `const patch = "*** Begin Patch\n*** Add File: /repo/probe.txt\n+DONE\n*** End Patch";` + "\n" +
				`const a = await tools.apply_patch(patch); text(a);` + "\n" +
				`const r = await tools.exec_command({cmd:"echo probe","workdir":"/repo"}); text(r.output);`,
			wantName:  "apply_patch",
			wantPatch: "*** Add File: /repo/probe.txt",
		},
		{
			name: "update_plan alone prefers the explanation",
			program: `const r = await tools.update_plan({explanation:"Source tracing is complete.",plan:[` +
				`{step:"Read the spec",status:"completed"}]}); text(r);`,
			wantName: "update_plan",
			wantTgt:  "Source tracing is complete.",
		},
		{
			name: "update_plan without an explanation falls back to the first step",
			program: `const r = await tools.update_plan({plan:[` +
				`{"step":"Enumerate the commit range","status":"completed"},` +
				`{"step":"Audit each arc","status":"pending"}]}); text(r);`,
			wantName: "update_plan",
			wantTgt:  "Enumerate the commit range",
		},
		{
			name: "write_stdin poll carries no argument",
			program: `const r = await tools.write_stdin({session_id:62552,chars:"",yield_time_ms:30000,` +
				`max_output_tokens:12000}); text(JSON.stringify(r));`,
			wantName: "write_stdin",
			wantTgt:  "",
		},
		{
			name: "write_stdin interrupt carries the written characters",
			program: `const r = await tools.write_stdin({ session_id: 38349, chars: "\u0003", ` +
				`yield_time_ms: 1000 }); text(r.output);`,
			wantName: "write_stdin",
			wantTgt:  "\u0003",
		},
		{
			name: "hoisted-array fan-out keeps the identity but has no single argument",
			program: `const cmds = [` + "\n" +
				`  "git status --short",` + "\n" +
				`  "go vet ./..."` + "\n" +
				`];` + "\n" +
				`const rs = await Promise.all(cmds.map(cmd => tools.exec_command({cmd,"workdir":"/repo"})));`,
			wantName: "exec_command",
			wantTgt:  "",
		},
		{
			name:     "hoisted-array plan keeps the identity but has no single argument",
			program:  `const p = [{step:"Inspect",status:"in_progress"}];` + "\n" + `await tools.update_plan({plan: p});`,
			wantName: "update_plan",
			wantTgt:  "",
		},
		{
			name:       "residual — ALL_TOOLS introspection invokes no tool",
			program:    `const meta = ALL_TOOLS.filter(x => x.name === "exec_command");` + "\n" + `text(meta);`,
			wantName:   "",
			wantTgt:    "",
			wantNoCall: true,
		},
		{
			// Live residual row 2 of 3, verbatim.
			name: "residual — ALL_TOOLS description search invokes no tool",
			program: `const hits = ALL_TOOLS.filter(x => x.name.includes("search_past") ||` +
				` x.description?.toLowerCase().includes("past output"));` + "\n" + `text(hits);`,
			wantName:   "",
			wantTgt:    "",
			wantNoCall: true,
		},
		{
			// Live residual row 3 of 3, verbatim — note the regex
			// literal, which must not be mistaken for a comment.
			name: "residual — ALL_TOOLS regex search invokes no tool",
			program: `const names = ALL_TOOLS.filter(x => /search|browse|github|web/i.test(` +
				`x.name+" "+x.description));` + "\n" + `text(names);`,
			wantName:   "",
			wantTgt:    "",
			wantNoCall: true,
		},
		{
			// NOT the residual class: the dispatcher IS referenced, so
			// the program is unresolved rather than proved tool-free
			// and the emit site must fall back to run_command.
			name:       "unresolved — tools.exec_command referenced but never called",
			program:    `const fn = tools.exec_command; text(typeof fn);`,
			wantName:   "",
			wantTgt:    "",
			wantNoCall: false,
		},
		{
			name:       "empty program",
			program:    "",
			wantName:   "",
			wantTgt:    "",
			wantNoCall: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := parseUnifiedExec(c.program)
			if got.Name != c.wantName {
				t.Fatalf("inner call = %q, want %q", got.Name, c.wantName)
			}
			if got.Target != c.wantTgt {
				t.Errorf("target = %q, want %q", got.Target, c.wantTgt)
			}
			if c.wantPatch != "" && !strings.Contains(got.PatchText, c.wantPatch) {
				t.Errorf("patch text %q does not contain %q", got.PatchText, c.wantPatch)
			}
			if c.wantPatch == "" && got.PatchText != "" {
				t.Errorf("unexpected patch text %q", got.PatchText)
			}
			if got.NoToolCall != c.wantNoCall {
				t.Errorf("NoToolCall = %v, want %v — the residual class needs a PROOF "+
					"that the dispatcher is untouched, not the scanner's silence",
					got.NoToolCall, c.wantNoCall)
			}
		})
	}
}

// TestScanJSToolCallsIgnoresStringLiterals is the load-bearing guard on
// the scanner's string-awareness. apply_patch programs embed whole
// source files inside one literal, and those files routinely contain
// the literal text "tools.exec_command(" — this repository's own codex
// adapter sources do. A regexp over the raw program would read that
// patch as a shell command, which is the exact over-typing this fix
// removes. Mutating scanJSToolCalls to skip the isJSQuote branch fails
// here.
func TestScanJSToolCallsIgnoresStringLiterals(t *testing.T) {
	t.Parallel()
	// The added patch line is deliberately EXECUTABLE-looking source, not
	// a comment: a comment would be skipped by the scanner's comment
	// branch even with string-awareness disabled, which would make this
	// guard pass against a mutant. (It did, until 2026-07-31.)
	program := `const patch = "*** Begin Patch\n*** Update File: /repo/unifiedexec.go\n` +
		`@@\n+\tr, err := tools.exec_command({cmd:\"rm -rf /\"})\n` +
		`*** End Patch";` + "\n" + `text(await tools.apply_patch(patch));`

	calls := scanJSToolCalls(program)
	if len(calls) != 1 {
		var names []string
		for _, c := range calls {
			names = append(names, c.Name)
		}
		t.Fatalf("scanJSToolCalls found %d calls (%v); want exactly 1 (apply_patch) — "+
			"the tools.exec_command( inside the patch literal is not a call", len(calls), names)
	}
	if calls[0].Name != "apply_patch" {
		t.Fatalf("call = %q, want apply_patch", calls[0].Name)
	}
	got := parseUnifiedExec(program)
	if got.Name != "apply_patch" {
		t.Errorf("inner call = %q, want apply_patch", got.Name)
	}
	if got.Target != "" {
		t.Errorf("target = %q; a patch must never yield a command target", got.Target)
	}
}

// TestUnresolvedProgramsFailClosedToRunCommand is the WP-T6 finding F3
// guard, asserted through the REAL emit site.
//
// The scanner models the call syntax Codex actually emits. Syntax it
// does not model is INVISIBLE to it — and a zero-call scan was being
// read as proof the program invoked no tool, typing the row
// models.ActionHarnessCall with an empty Target. Every program below
// runs a real (here: destructive) shell command that the scanner cannot
// see, so that reading silently demoted a run_command out of both
// run_command analytics and target-based safety classification.
//
// The fix fails CLOSED: unresolved keeps the taxonomy's own `exec` row
// (run_command). Mutating the emit site's `&& provablyNoCall` away —
// or making programProvablyInvokesNoTool return true unconditionally —
// fails here.
func TestUnresolvedProgramsFailClosedToRunCommand(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		program string
	}{
		{
			name:    "call inside a template-literal interpolation",
			program: "text(`${await tools.exec_command({cmd:\"rm -rf /tmp/x\"})}`);",
		},
		{
			name:    "call through bracket access",
			program: `const r = await tools["exec_command"]({cmd:"rm -rf /tmp/x"}); text(r.output);`,
		},
		{
			name:    "call through optional chaining",
			program: `const r = await tools?.exec_command({cmd:"rm -rf /tmp/x"}); text(r.output);`,
		},
		{
			name:    "call through an aliased dispatcher",
			program: `const t = tools; const r = await t.exec_command({cmd:"rm -rf /tmp/x"});`,
		},
		{
			name:    "dispatcher referenced but the call syntax is unknown",
			program: `const r = await Reflect.get(tools, "exec_command")({cmd:"rm -rf /tmp/x"});`,
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := parseUnifiedExec(c.program); got.NoToolCall {
				t.Fatalf("parseUnifiedExec claims the program provably invokes no tool; "+
					"it reaches the dispatcher: %q", c.program)
			}
			evt, _ := New().buildCustomToolCallEvent(
				"/tmp/rollout.jsonl", "call_unresolved", sessionContext{SessionID: "s"}, "",
				time.Time{},
				responseItemCustomToolCall{Name: "exec", Input: c.program}, "",
			)
			if evt.ActionType == models.ActionHarnessCall {
				t.Fatalf("action_type = harness_call for a program that runs a real " +
					"command; unresolved must fall back to the taxonomy's exec row")
			}
			if evt.ActionType != models.ActionRunCommand {
				t.Errorf("action_type = %q, want run_command (the conservative exec row)",
					evt.ActionType)
			}
			if evt.RawToolName != unifiedExecToolName {
				t.Errorf("raw_tool_name = %q, want %q — the inner name was never resolved, "+
					"so claiming one would be a fabrication",
					evt.RawToolName, unifiedExecToolName)
			}
			if evt.Target != "" {
				t.Errorf("target = %q, want empty — nothing was resolved", evt.Target)
			}
			if evt.RawToolInput == "" {
				t.Error("raw_tool_input is empty; the program is the only evidence left")
			}
		})
	}
}

// TestProgramProvablyInvokesNoTool pins the PROOF predicate itself: a
// whole-token scan for the dispatcher identifier over the raw bytes,
// with no string- or comment-awareness. The asymmetry with
// scanJSToolCalls is deliberate — the scanner must ignore literals to
// find the real call, this predicate must NOT, because a `tools`
// occurrence it cannot rule out withdraws the proof.
func TestProgramProvablyInvokesNoTool(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		program string
		want    bool
	}{
		// The three live residual programs, verbatim (2026-07-31).
		{"live residual 1", `const meta = ALL_TOOLS.filter(x => x.name === "exec_command");` +
			"\ntext(meta);\n", true},
		{"live residual 2", `const hits = ALL_TOOLS.filter(x => x.name.includes("search_past") ||` +
			` x.description?.toLowerCase().includes("past output"));` + "\ntext(hits);\n", true},
		{"live residual 3", `const names = ALL_TOOLS.filter(x => /search|browse|github|web/i.test(` +
			`x.name+" "+x.description));` + "\ntext(names);\n", true},

		{"empty program", "", true},
		{"uppercase ALL_TOOLS is a different identifier", `text(ALL_TOOLS.length);`, true},
		{"an identifier merely containing tools", `text(mytools.x); text(toolset);`, true},

		{"a plain call", `tools.exec_command({cmd:"x"});`, false},
		{"bracket access", `tools["exec_command"]({cmd:"x"});`, false},
		{"optional chaining", `tools?.exec_command({cmd:"x"});`, false},
		{"a bare alias", `const t = tools;`, false},
		{"inside a template literal", "text(`${tools.exec_command({cmd:\"x\"})}`);", false},
		// The proof is withdrawn even for a mention we could argue is
		// inert. Certifying THAT tool-free is exactly the class of
		// reasoning finding F3 removed.
		{"inside a comment", `// tools.exec_command({cmd:"x"})`, false},
		{"inside an unrelated string", `text("the tools array is injected");`, false},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := programProvablyInvokesNoTool(c.program); got != c.want {
				t.Errorf("programProvablyInvokesNoTool(%q) = %v, want %v",
					c.program, got, c.want)
			}
		})
	}
}

// TestParseUnifiedExecMalformedIsSafe pins the failure mode: a
// truncated, unbalanced or otherwise malformed program must return an
// honest partial (or zero) result and never panic. Rollouts are
// appended to live and are routinely read mid-write.
func TestParseUnifiedExecMalformedIsSafe(t *testing.T) {
	t.Parallel()
	programs := []string{
		`const r = await tools.exec_command({cmd:"sed -n '1,`,
		`const r = await tools.exec_command({cmd:`,
		`const r = await tools.exec_command(`,
		`const r = await tools.`,
		`tools.`,
		`tools..exec_command({cmd:"x"})`,
		`const patch = String.raw` + "`" + `*** Begin Patch`,
		`const patch = "*** Begin Patch\n*** Add File: /a\n+x`,
		`const p = await tools.update_plan({plan:[{step:"a"`,
		`/* unterminated comment tools.exec_command({cmd:"x"})`,
		`// tools.exec_command({cmd:"x"})`,
		`const r = await tools.write_stdin({chars:"\u00`,
		`const r = await tools.exec_command({cmd:"x\`,
		"\x00\xff\xfe not javascript at all",
		strings.Repeat("(", 5000),
		strings.Repeat(`"`, 5000),
		strings.Repeat("tools.exec_command(", 2000),
	}
	for _, p := range programs {
		p := p
		t.Run(strings.Map(func(r rune) rune {
			if r < 32 || r > 126 {
				return '.'
			}
			return r
		}, p[:min(40, len(p))]), func(t *testing.T) {
			t.Parallel()
			// The assertion is that this returns at all.
			_ = parseUnifiedExec(p)
		})
	}
}

// TestUnifiedExecInnerNamesResolveThroughTooltax pins the MECHANISM:
// the emit site does not hardcode an action type per inner call, it
// resolves the inner NATIVE NAME through the same tooltax-sourced
// actionMap every other codex path uses. Every name the parser can
// produce must therefore have a codex tooltax row — and the row's value
// is the taxonomy's answer, not the adapter's. This is what keeps the
// fix free of a tooltax edit and free of the emit-site-vs-table drift
// class (WP-T6 finding B4).
func TestUnifiedExecInnerNamesResolveThroughTooltax(t *testing.T) {
	t.Parallel()
	want := map[string]string{
		"exec_command": models.ActionRunCommand,
		"apply_patch":  models.ActionEditFile,
		"update_plan":  models.ActionTodoUpdate,
		"write_stdin":  models.ActionStdinWrite,
	}
	names := make(map[string]bool)
	for n := range unifiedExecArgKeys {
		names[n] = true
	}
	for n := range unifiedExecPatchCalls {
		names[n] = true
	}
	if len(names) != len(want) {
		t.Fatalf("parser knows %d inner names, table pins %d — a new inner call needs a "+
			"grounded row here AND a measured entry in unifiedexec.go's vocabulary comment",
			len(names), len(want))
	}
	for name := range names {
		at, ok := actionMap[name]
		if !ok {
			t.Errorf("no codex tooltax row for inner call %q — the emit site would type it "+
				"unknown; add the row in internal/tooltax rather than a switch here", name)
			continue
		}
		if at != want[name] {
			t.Errorf("actionMap[%q] = %q, want %q", name, at, want[name])
		}
		if tat, ok := tooltax.ResolveActionType(models.ToolOpenInterpreter, name); !ok || tat != at {
			t.Errorf("open-interpreter resolves %q to %q (ok=%v); the rebadged parser shares "+
				"this vocabulary and must agree with codex's %q", name, tat, ok, at)
		}
	}
}

// TestBookkeepingCallsAreNotWork pins the precedence rule as data. A
// custom_tool_call becomes exactly one action row, so a program that
// updates the plan AND does work has to pick one identity; in all 86
// live mixed programs the update_plan is the preamble.
func TestBookkeepingCallsAreNotWork(t *testing.T) {
	t.Parallel()
	if !unifiedExecBookkeeping["update_plan"] {
		t.Error("update_plan must be bookkeeping so a mixed program reports the work call")
	}
	for _, work := range []string{"exec_command", "apply_patch", "write_stdin"} {
		if unifiedExecBookkeeping[work] {
			t.Errorf("%q must NOT be bookkeeping — it is the work of the program", work)
		}
	}
}

// TestParseRolloutUnifiedExec drives the whole fix through the REAL
// assembly (ParseSessionFile over a rollout fixture), not just the
// parser: action type, target, raw_tool_name and content_bytes are all
// asserted on the rows an ingest would actually store.
//
// Pre-fix, every one of these eight rows was ActionRunCommand with an
// EMPTY target and raw_tool_name "exec" (WP-T6 finding B5).
func TestParseRolloutUnifiedExec(t *testing.T) {
	t.Parallel()
	a := New()
	// Bind the fixture to its own project, independent of whether /tmp lives
	// inside a workspace on the host running this test.
	project := t.TempDir()
	if err := os.Mkdir(filepath.Join(project, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(fixture(t, "rollout-unified-exec.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.ReplaceAll(string(raw), "/tmp/superbased-fixture-codex-uexec", filepath.ToSlash(project)))
	path := filepath.Join(project, "rollout-unified-exec.jsonl")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	byID := make(map[string]models.ToolEvent, len(res.ToolEvents))
	for _, evt := range res.ToolEvents {
		if evt.SourceEventID != "" {
			byID[evt.SourceEventID] = evt
		}
	}

	cases := []struct {
		callID     string
		wantAction string
		wantRaw    string
		wantTarget string // exact, unless wantTargetSub is set
		wantSub    string
		wantBytes  int64
	}{
		{
			callID:     "call_uexec_cmd",
			wantAction: models.ActionRunCommand,
			wantRaw:    "exec_command",
			wantTarget: `sed -n '1,240p' PROGRESS.md && rg -n "probe" docs`,
			wantBytes:  int64(len(`sed -n '1,240p' PROGRESS.md && rg -n "probe" docs`)),
		},
		{
			callID:     "call_uexec_mixed",
			wantAction: models.ActionRunCommand,
			wantRaw:    "exec_command",
			wantTarget: "go test ./internal/adapter/codex/...",
			wantBytes:  int64(len("go test ./internal/adapter/codex/...")),
		},
		{
			callID:     "call_uexec_patch",
			wantAction: models.ActionEditFile,
			wantRaw:    "apply_patch",
			wantTarget: "plan.md",
			wantBytes:  int64(len("new line")),
		},
		{
			callID:     "call_uexec_patch_raw",
			wantAction: models.ActionEditFile,
			wantRaw:    "apply_patch",
			wantTarget: "raw.go",
			wantBytes:  int64(len(`package raw`) + len(``) + len(`const tab = "\t"`)),
		},
		{
			callID:     "call_uexec_plan",
			wantAction: models.ActionTodoUpdate,
			wantRaw:    "update_plan",
			wantTarget: "Reading is done; tests are next.",
		},
		{
			callID:     "call_uexec_stdin",
			wantAction: models.ActionStdinWrite,
			wantRaw:    "write_stdin",
			wantTarget: "",
		},
		{
			callID:     "call_uexec_hoisted",
			wantAction: models.ActionRunCommand,
			wantRaw:    "exec_command",
			wantTarget: "",
		},
		{
			callID:     "call_uexec_residual",
			wantAction: models.ActionHarnessCall,
			wantRaw:    "exec",
			wantTarget: "",
		},
		// WP-T6 finding F3, through the real assembly: two calls the
		// scanner cannot see. Both ran a real command, so both must
		// keep the taxonomy's conservative exec row rather than being
		// demoted to harness_call.
		{
			callID:     "call_uexec_bracket",
			wantAction: models.ActionRunCommand,
			wantRaw:    "exec",
			wantTarget: "",
		},
		{
			callID:     "call_uexec_template",
			wantAction: models.ActionRunCommand,
			wantRaw:    "exec",
			wantTarget: "",
		},
		// WP-T6 finding F5, through the real assembly: a decoy binding,
		// a commented decoy and the real reassignment. Pre-fix the row
		// reported decoy.md; the file the program actually patches is
		// real.md.
		{
			callID:     "call_uexec_rebound",
			wantAction: models.ActionEditFile,
			wantRaw:    "apply_patch",
			wantTarget: "real.md",
		},
	}

	for _, c := range cases {
		t.Run(c.callID, func(t *testing.T) {
			row, ok := byID[c.callID]
			if !ok {
				t.Fatalf("no row for call_id %q", c.callID)
			}
			if row.ActionType != c.wantAction {
				t.Errorf("action_type = %q, want %q", row.ActionType, c.wantAction)
			}
			if row.RawToolName != c.wantRaw {
				t.Errorf("raw_tool_name = %q, want %q", row.RawToolName, c.wantRaw)
			}
			if c.wantSub != "" {
				if !strings.Contains(row.Target, c.wantSub) {
					t.Errorf("target %q does not contain %q", row.Target, c.wantSub)
				}
			} else if row.Target != c.wantTarget {
				t.Errorf("target = %q, want %q", row.Target, c.wantTarget)
			}
			if c.wantBytes != 0 && row.ContentBytes != c.wantBytes {
				t.Errorf("content_bytes = %d, want %d", row.ContentBytes, c.wantBytes)
			}
			// The evidence must survive regardless of what we resolved.
			if row.RawToolInput == "" {
				t.Errorf("raw_tool_input is empty; the JS program is the evidence trail")
			}
		})
	}
}

// TestUnifiedExecTargetsAreTruncated pins that a pathologically long
// command still obeys the adapter's 200-char Target convention.
func TestUnifiedExecTargetsAreTruncated(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", 500)
	evt, _ := New().buildCustomToolCallEvent(
		"/tmp/rollout.jsonl", "call_long", sessionContext{SessionID: "s"}, "",
		time.Time{}, responseItemCustomToolCall{
			Name:  "exec",
			Input: `const r = await tools.exec_command({cmd:"` + long + `"});`,
		}, "",
	)
	if len(evt.Target) != 200 {
		t.Errorf("target length = %d, want 200 (adapter truncation convention)", len(evt.Target))
	}
	if evt.ActionType != models.ActionRunCommand {
		t.Errorf("action_type = %q, want run_command", evt.ActionType)
	}
}

// TestLegacyApplyPatchCustomToolCallUnchanged is the no-regression pin
// for the OTHER custom_tool_call shape: a directly-named apply_patch
// whose input is raw patch text (444 live rows) must keep resolving
// exactly as before the unified-exec boundary was added.
func TestLegacyApplyPatchCustomToolCallUnchanged(t *testing.T) {
	t.Parallel()
	patch := "*** Begin Patch\n*** Update File: /repo/legacy.go\n@@\n-old\n+new\n*** End Patch\n"
	evt, _ := New().buildCustomToolCallEvent(
		"/tmp/rollout.jsonl", "call_legacy", sessionContext{SessionID: "s"}, "/repo",
		time.Time{}, responseItemCustomToolCall{Name: "apply_patch", Input: patch}, "",
	)
	if evt.ActionType != models.ActionEditFile {
		t.Errorf("action_type = %q, want edit_file", evt.ActionType)
	}
	if evt.RawToolName != "apply_patch" {
		t.Errorf("raw_tool_name = %q, want apply_patch", evt.RawToolName)
	}
	if evt.Target != "legacy.go" {
		t.Errorf("target = %q, want legacy.go (project-relative)", evt.Target)
	}
	if want := int64(len("new")); evt.ContentBytes != want {
		t.Errorf("content_bytes = %d, want %d", evt.ContentBytes, want)
	}
}

// TestUnknownInnerCallIsUnknownNotRunCommand pins the honesty rule for
// a FUTURE dispatcher verb: it must land in the unknown bucket under
// its own native name (so one tooltax row fixes it) rather than being
// absorbed into run_command the way the whole family was pre-fix.
func TestUnknownInnerCallIsUnknownNotRunCommand(t *testing.T) {
	t.Parallel()
	evt, _ := New().buildCustomToolCallEvent(
		"/tmp/rollout.jsonl", "call_future", sessionContext{SessionID: "s"}, "",
		time.Time{}, responseItemCustomToolCall{
			Name:  "exec",
			Input: `const r = await tools.teleport_agent({destination:"mars"}); text(r);`,
		}, "",
	)
	if evt.ActionType != models.ActionUnknown {
		t.Errorf("action_type = %q, want unknown", evt.ActionType)
	}
	if evt.RawToolName != "teleport_agent" {
		t.Errorf("raw_tool_name = %q, want teleport_agent so one tooltax row fixes it",
			evt.RawToolName)
	}
}
