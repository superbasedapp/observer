package tooltax_test

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

// TestCorpusKnownNatives pins tooltax against the 163 measured
// (tool, native) pairs the adapters already classify. Every row must
// resolve to the SAME action type the shipped adapter produces —
// this is the regression gate for the WP-T3 conversion.
func TestCorpusKnownNatives(t *testing.T) {
	for _, c := range corpusKnownNatives {
		t.Run(c.tool+"/"+c.native, func(t *testing.T) {
			got, ok := tooltax.ResolveActionType(c.tool, c.native)
			if !ok {
				t.Fatalf("Resolve(%q, %q) found no row; corpus says %q",
					c.tool, c.native, c.want)
			}
			if got != c.want {
				t.Errorf("Resolve(%q, %q) = %q; the live corpus classifies it %q "+
					"(code mapping wins — fix the table, not the expectation)",
					c.tool, c.native, got, c.want)
			}
		})
	}
}

// TestCorpusUnknownNatives pins the taxonomy DECISION for the 62
// measured (tool, native) pairs that currently land in `unknown` — the
// agent-orchestration + harness families plan §0 measured and migration
// 024 deferred. These expectations ARE the specification WP-T4's
// backfill migration implements.
func TestCorpusUnknownNatives(t *testing.T) {
	for _, c := range corpusUnknownNatives {
		t.Run(c.tool+"/"+c.native, func(t *testing.T) {
			e, ok := tooltax.Resolve(c.tool, c.native)
			if !ok {
				t.Fatalf("Resolve(%q, %q) found no row; want %q — every measured "+
					"unknown native must have a decision", c.tool, c.native, c.want)
			}
			if e.ActionType != c.want {
				t.Errorf("Resolve(%q, %q).ActionType = %q; want %q",
					c.tool, c.native, e.ActionType, c.want)
			}
		})
	}
}

// TestEveryRowResolvesToItself is the ordering pin: walking the table
// top-down must never let an earlier row SHADOW a later one into a
// different action type. Every literal row is looked up by its own
// (Tool, Native) and must come back with its own ActionType.
//
// A tool-less fallback row is probed with a synthetic tool id so it
// cannot be intercepted by a tool-specific row.
func TestEveryRowResolvesToItself(t *testing.T) {
	const probeTool = "zz-nonexistent-tool"
	for _, e := range tooltax.Table() {
		if e.IsGlob() {
			continue
		}
		tool := e.Tool
		if tool == "" {
			tool = probeTool
		}
		got, ok := tooltax.Resolve(tool, e.Native)
		if !ok {
			t.Errorf("row (%q, %q) does not resolve — unreachable table row", e.Tool, e.Native)
			continue
		}
		if got.ActionType != e.ActionType {
			t.Errorf("row (%q, %q) wants %q but an earlier row shadows it with %q",
				e.Tool, e.Native, e.ActionType, got.ActionType)
		}
		if got.Surface != e.Surface {
			t.Errorf("row (%q, %q) wants surface %q but resolved to %q",
				e.Tool, e.Native, e.Surface, got.Surface)
		}
	}
}

// TestGlobRowsSortLast pins the plan's stated precedence: specific
// (tool, native) rows first, glob and tool-less fallback rows last. Once
// a glob appears in the walk, no LITERAL row for the same tool may
// follow it — otherwise the glob would swallow it.
func TestGlobRowsSortLast(t *testing.T) {
	globbedTools := map[string]int{}
	for i, e := range tooltax.Table() {
		if e.IsGlob() {
			if _, seen := globbedTools[e.Tool]; !seen {
				globbedTools[e.Tool] = i
			}
			continue
		}
		if at, seen := globbedTools[e.Tool]; seen {
			t.Errorf("literal row (%q, %q) at index %d comes AFTER that tool's glob at index %d",
				e.Tool, e.Native, i, at)
		}
		if at, seen := globbedTools[""]; seen {
			t.Errorf("literal row (%q, %q) at index %d comes AFTER the tool-less glob at index %d",
				e.Tool, e.Native, i, at)
		}
	}
	if _, ok := globbedTools[""]; !ok {
		t.Error("no tool-less glob row in the table — the mcp__* catch-all is missing")
	}
}

// TestToolLessRowsSortAfterSpecificRows pins the other half of the
// precedence rule: a tool-specific row must never be preceded by a
// tool-less fallback, or the fallback would win.
func TestToolLessRowsSortAfterSpecificRows(t *testing.T) {
	firstFallback := -1
	for i, e := range tooltax.Table() {
		if e.Tool == "" {
			if firstFallback < 0 {
				firstFallback = i
			}
			continue
		}
		if firstFallback >= 0 {
			t.Fatalf("tool-specific row (%q, %q) at index %d comes AFTER the first "+
				"tool-less fallback at index %d", e.Tool, e.Native, i, firstFallback)
		}
	}
	if firstFallback < 0 {
		t.Error("no tool-less fallback rows in the table")
	}
}

// TestRowCategoryMatchesActionType pins Entry.Category as a pure
// function of Entry.ActionType, so the materialised field can never
// drift from the registry (see tooltax.entry).
func TestRowCategoryMatchesActionType(t *testing.T) {
	for _, e := range tooltax.Table() {
		want := tooltax.CategoryForActionType(e.ActionType)
		if e.Category != want {
			t.Errorf("row (%q, %q) has Category %q but action type %q is category %q",
				e.Tool, e.Native, e.Category, e.ActionType, want)
		}
	}
}

// TestEveryRowActionTypeIsRegistered pins that no row invents an action
// type outside the registry (which would silently take CategoryMeta via
// the fallback).
func TestEveryRowActionTypeIsRegistered(t *testing.T) {
	for _, e := range tooltax.Table() {
		if _, ok := tooltax.MetaForActionType(e.ActionType); !ok {
			t.Errorf("row (%q, %q) uses unregistered action type %q — add it to "+
				"actionTypes in actiontype.go", e.Tool, e.Native, e.ActionType)
		}
	}
}

// TestEveryRowCategoryIsCanonical + TestEveryRowSurfaceIsCanonical pin
// the two closed vocabularies.
func TestEveryRowCategoryIsCanonical(t *testing.T) {
	valid := map[string]bool{}
	for _, c := range tooltax.Categories() {
		valid[c] = true
	}
	if len(valid) != 10 {
		t.Fatalf("Categories() returned %d entries; the plan defines 10", len(valid))
	}
	for _, e := range tooltax.Table() {
		if !valid[e.Category] {
			t.Errorf("row (%q, %q) has non-canonical category %q", e.Tool, e.Native, e.Category)
		}
	}
}

func TestEveryRowSurfaceIsCanonical(t *testing.T) {
	valid := map[tooltax.Surface]bool{}
	for _, s := range tooltax.Surfaces() {
		valid[s] = true
	}
	if len(valid) != 4 {
		t.Fatalf("Surfaces() returned %d entries; the plan defines 4", len(valid))
	}
	for _, e := range tooltax.Table() {
		if !valid[e.Surface] {
			t.Errorf("row (%q, %q) has non-canonical surface %q", e.Tool, e.Native, e.Surface)
		}
	}
}

// TestNoDuplicateRows pins that no (Tool, Native) pair appears twice —
// a duplicate is either a copy-paste bug or a silent contradiction.
func TestNoDuplicateRows(t *testing.T) {
	type key struct{ tool, native string }
	seen := map[key]tooltax.Entry{}
	for _, e := range tooltax.Table() {
		k := key{e.Tool, e.Native}
		if prev, dup := seen[k]; dup {
			t.Errorf("duplicate row (%q, %q): %q then %q",
				e.Tool, e.Native, prev.ActionType, e.ActionType)
			continue
		}
		seen[k] = e
	}
}

// TestNoContradictoryNormalizedKeys pins that within ONE tool, two
// spellings that normalize to the same key never disagree on the action
// type — otherwise Resolve's normalized pass would return whichever
// happens to sort first, which is a coin flip dressed as a decision.
func TestNoContradictoryNormalizedKeys(t *testing.T) {
	type key struct{ tool, norm string }
	seen := map[key]tooltax.Entry{}
	for _, e := range tooltax.Table() {
		if e.IsGlob() {
			continue
		}
		k := key{e.Tool, normalizeForTest(e.Native)}
		if prev, dup := seen[k]; dup {
			if prev.ActionType != e.ActionType {
				t.Errorf("tool %q: %q and %q normalize to %q but map to %q vs %q",
					e.Tool, prev.Native, e.Native, k.norm, prev.ActionType, e.ActionType)
			}
			continue
		}
		seen[k] = e
	}
}

// normalizeForTest mirrors tooltax.normalizeKey (unexported).
func normalizeForTest(name string) string {
	key := strings.ToLower(strings.TrimSpace(name))
	key = strings.ReplaceAll(key, "_", "")
	key = strings.ReplaceAll(key, "-", "")
	key = strings.ReplaceAll(key, ".", "")
	return strings.Join(strings.Fields(key), "")
}

// TestResolveNormalizedPass pins the second lookup pass — the reason the
// corpus's capitalised cursor/copilot/grok spellings resolve at all.
func TestResolveNormalizedPass(t *testing.T) {
	cases := []struct {
		tool, native, want string
	}{
		{"cursor", "Read", tooltax.ActionReadFile},
		{"cursor", "SemanticSearch", tooltax.ActionSearchText},
		{"copilot", "read_file", tooltax.ActionReadFile},
		{"copilot", "grep_search", tooltax.ActionSearchText},
		{"grok", "run_terminal_command", tooltax.ActionRunCommand},
		{"qwen-code", "run_shell_command", tooltax.ActionRunCommand},
		// WP-T6 live probe finding B1 (2026-07-31): command-code's only
		// shell tool, distinct from "run_shell_command"/"runshellcommand".
		{"command-code", "shell_command", tooltax.ActionRunCommand},
		{"kimi-code", "Bash", tooltax.ActionRunCommand},
		// `.` folding: cmd.exe / cmd_exe / cmdexe are one tool.
		{"claude-code", "cmd_exe", tooltax.ActionRunCommand},
		{"cursor", "cmd.exe", tooltax.ActionRunCommand},
	}
	for _, c := range cases {
		got, ok := tooltax.ResolveActionType(c.tool, c.native)
		if !ok || got != c.want {
			t.Errorf("Resolve(%q, %q) = (%q, %v); want %q", c.tool, c.native, got, ok, c.want)
		}
	}
}

// TestToolSpecificRowsBeatFallbacks pins the precedence that makes
// per-tool disagreements expressible: cline's `search_files` is a TEXT
// search, command-code's `searchfiles` is file discovery, and the
// tool-less table deliberately carries neither.
func TestToolSpecificRowsBeatFallbacks(t *testing.T) {
	if got, _ := tooltax.ResolveActionType("cline", "search_files"); got != tooltax.ActionSearchText {
		t.Errorf("cline/search_files = %q; want %q (cline greps file BODIES)",
			got, tooltax.ActionSearchText)
	}
	if got, _ := tooltax.ResolveActionType("command-code", "searchfiles"); got != tooltax.ActionSearchFiles {
		t.Errorf("command-code/searchfiles = %q; want %q", got, tooltax.ActionSearchFiles)
	}
	// hermes `send_message` is an outbound gateway bridge (mcp_call);
	// codex `send_message` is inter-agent (agent_message). Same name,
	// different tool, different meaning.
	if got, _ := tooltax.ResolveActionType("hermes", "send_message"); got != tooltax.ActionMCPCall {
		t.Errorf("hermes/send_message = %q; want %q", got, tooltax.ActionMCPCall)
	}
	if got, _ := tooltax.ResolveActionType("codex", "send_message"); got != tooltax.ActionAgentMessage {
		t.Errorf("codex/send_message = %q; want %q", got, tooltax.ActionAgentMessage)
	}
}

// TestFallbackRowsApplyToUnknownTools pins that a brand-new adapter gets
// a sane floor before it has any rows of its own.
func TestFallbackRowsApplyToUnknownTools(t *testing.T) {
	cases := map[string]string{
		"read_file":   tooltax.ActionReadFile,
		"write_file":  tooltax.ActionWriteFile,
		"apply_patch": tooltax.ActionEditFile,
		"bash":        tooltax.ActionRunCommand,
		"grep":        tooltax.ActionSearchText,
		"glob":        tooltax.ActionSearchFiles,
		"web_fetch":   tooltax.ActionWebFetch,
	}
	for native, want := range cases {
		if got, ok := tooltax.ResolveActionType("brand-new-tool", native); !ok || got != want {
			t.Errorf("brand-new-tool/%s = (%q, %v); want %q", native, got, ok, want)
		}
	}
}

// TestMCPGlobIsTheCatchAll pins the single highest-value row: any tool,
// any `mcp__…` name, mcp_call — the repair for the 264 unresolved
// `mcp__*` rows plan §0 measured.
func TestMCPGlobIsTheCatchAll(t *testing.T) {
	for _, tool := range []string{"claude-code", "codex", "cowork", "some-future-tool"} {
		e, ok := tooltax.Resolve(tool, "mcp__brand__new_server_tool")
		if !ok {
			t.Fatalf("%s: mcp__ glob did not fire", tool)
		}
		if e.ActionType != tooltax.ActionMCPCall {
			t.Errorf("%s: mcp__ glob gave %q; want %q", tool, e.ActionType, tooltax.ActionMCPCall)
		}
		if e.Surface != tooltax.SurfaceMCP {
			t.Errorf("%s: mcp__ glob gave surface %q; want %q", tool, e.Surface, tooltax.SurfaceMCP)
		}
	}
	// …but a LITERAL row still wins over the glob: cowork's
	// mcp__workspace__bash is a shell, not an opaque MCP call.
	if got, _ := tooltax.ResolveActionType("cowork", "mcp__workspace__bash"); got != tooltax.ActionRunCommand {
		t.Errorf("cowork/mcp__workspace__bash = %q; want %q — the literal must beat the glob",
			got, tooltax.ActionRunCommand)
	}
}

// TestGlobsDoNotFireOnTheNormalizedPass pins the anti-heuristic rule:
// normalizeKey strips `_`, so if globs participated in the normalized
// pass the `mcp__*` row would degrade into a bare `mcp` prefix match —
// exactly the loose heuristic (HasPrefix(lower, "mcp") /
// Contains(name, "__")) that several adapters carry and that this table
// replaces with identities. A name that is not literally in the `mcp__`
// namespace must resolve to NO row, not to a guess.
func TestGlobsDoNotFireOnTheNormalizedPass(t *testing.T) {
	for _, native := range []string{
		"mcpfoo",        // bare mcp prefix
		"MCP__Server",   // wrong case
		"mcp_server",    // single underscore
		"mcp-tool",      // kebab
		"mcpstatus",     // no separator at all
		"some__thing",   // the Contains("__") heuristic
		"a___b",         // the kiro-cli Contains("___") heuristic
		"my_mcp_bridge", // Contains("mcp") heuristic
	} {
		if e, ok := tooltax.Resolve("some-future-tool", native); ok {
			t.Errorf("Resolve(_, %q) matched %+v; a non-namespaced name must NOT be "+
				"laundered into an MCP identity", native, e)
		}
	}
	// The literal namespace still resolves, of course.
	if _, ok := tooltax.Resolve("some-future-tool", "mcp__srv__tool"); !ok {
		t.Error("the literal mcp__ namespace must still resolve")
	}
}

// TestForMatchesResolve pins For(tool) as a faithful materialisation of
// Resolve over the literal rows — the property WP-T3 relies on when it
// swaps each adapter's private actionMap for tooltax.For.
func TestForMatchesResolve(t *testing.T) {
	for _, tool := range tooltax.Tools() {
		m := tooltax.For(tool)
		if len(m) == 0 {
			t.Errorf("For(%q) is empty", tool)
			continue
		}
		for native, want := range m {
			got, ok := tooltax.ResolveActionType(tool, native)
			if !ok || got != want {
				t.Errorf("For(%q)[%q] = %q but Resolve gives (%q, %v)", tool, native, want, got, ok)
			}
		}
	}
}

// TestForIncludesFallbacks pins that For() carries the tool-less floor
// too, so a converted adapter that only does map lookups still gets it.
func TestForIncludesFallbacks(t *testing.T) {
	m := tooltax.For("pi")
	if m["web_fetch"] != tooltax.ActionWebFetch {
		t.Errorf("For(pi)[web_fetch] = %q; want %q", m["web_fetch"], tooltax.ActionWebFetch)
	}
	// A tool-specific row must override the fallback in the map, not
	// just in Resolve.
	if m2 := tooltax.For("cline"); m2["search_files"] != tooltax.ActionSearchText {
		t.Errorf("For(cline)[search_files] = %q; want %q (tool-specific must win)",
			m2["search_files"], tooltax.ActionSearchText)
	}
}

// TestForExcludesGlobs pins that glob patterns never leak into the map
// as if they were tool names.
func TestForExcludesGlobs(t *testing.T) {
	for _, tool := range tooltax.Tools() {
		for native := range tooltax.For(tool) {
			if strings.HasSuffix(native, "*") {
				t.Errorf("For(%q) contains glob %q", tool, native)
			}
		}
	}
}

func TestResolveEmptyNative(t *testing.T) {
	if _, ok := tooltax.Resolve("claude-code", ""); ok {
		t.Error("Resolve with an empty native name must not match")
	}
	if got, ok := tooltax.ResolveActionType("claude-code", ""); ok || got != tooltax.ActionUnknown {
		t.Errorf("ResolveActionType(_, \"\") = (%q, %v); want (unknown, false)", got, ok)
	}
}

// TestCoverageDepth pins the plan §4 honesty input: capture depth varies
// wildly, and the like-to-like surface must be able to say so.
func TestCoverageDepth(t *testing.T) {
	deep := tooltax.CoverageDepth("claude-code")
	shallow := tooltax.CoverageDepth("aider")
	if deep <= shallow {
		t.Errorf("CoverageDepth: claude-code %d must exceed aider %d", deep, shallow)
	}
	if tooltax.CoverageDepth("no-such-tool") != 0 {
		t.Error("CoverageDepth of an unknown tool must be 0")
	}
}

// TestCategoriesForTool pins the WP-T5 coverage accessor: display order,
// no duplicates, only canonical categories, honest zero for a tool with
// no declared vocabulary, and agreement with CoverageDepth.
func TestCategoriesForTool(t *testing.T) {
	order := tooltax.Categories()
	rank := map[string]int{}
	for i, c := range order {
		rank[c] = i
	}
	for _, tool := range tooltax.Tools() {
		got := tooltax.CategoriesForTool(tool)
		if len(got) == 0 {
			t.Errorf("CategoriesForTool(%q) is empty but the tool has rows", tool)
		}
		if len(got) != tooltax.CoverageDepth(tool) {
			t.Errorf("CategoriesForTool(%q)=%v disagrees with CoverageDepth=%d",
				tool, got, tooltax.CoverageDepth(tool))
		}
		seen := map[string]bool{}
		prev := -1
		for _, c := range got {
			if seen[c] {
				t.Errorf("CategoriesForTool(%q) repeats %q", tool, c)
			}
			seen[c] = true
			r, ok := rank[c]
			if !ok {
				t.Errorf("CategoriesForTool(%q) returned non-canonical %q", tool, c)
				continue
			}
			if r <= prev {
				t.Errorf("CategoriesForTool(%q)=%v is not in Categories() display order", tool, got)
			}
			prev = r
		}
	}
	if got := tooltax.CategoriesForTool("no-such-tool"); len(got) != 0 {
		t.Errorf("CategoriesForTool of an unknown tool = %v; want empty", got)
	}
	// The tool-less fallback + glob rows must NOT be credited to a tool:
	// "" is not a tool, and every tool would otherwise share a floor.
	if got := tooltax.CategoriesForTool(""); len(got) != 0 {
		t.Errorf(`CategoriesForTool("") = %v; want empty`, got)
	}
}

// TestActionTypesInCategory pins the accessor the Patterns engine derives
// its SQL action-type sets from (WP-T5): every registered action type
// lands in exactly one category bucket, buckets are sorted, and an
// unknown category is an empty (never match-everything) set.
func TestActionTypesInCategory(t *testing.T) {
	all := map[string]int{}
	for _, cat := range tooltax.Categories() {
		got := tooltax.ActionTypesInCategory(cat)
		if len(got) == 0 {
			t.Errorf("ActionTypesInCategory(%q) is empty", cat)
		}
		for i, at := range got {
			if i > 0 && got[i-1] >= at {
				t.Errorf("ActionTypesInCategory(%q)=%v is not sorted", cat, got)
			}
			if c := tooltax.CategoryForActionType(at); c != cat {
				t.Errorf("ActionTypesInCategory(%q) yielded %q whose category is %q", cat, at, c)
			}
			all[at]++
		}
	}
	for _, at := range tooltax.ActionTypes() {
		if all[at] != 1 {
			t.Errorf("action type %q appears in %d category buckets; want exactly 1", at, all[at])
		}
	}
	if got := tooltax.ActionTypesInCategory("no-such-category"); len(got) != 0 {
		t.Errorf("ActionTypesInCategory of an unknown category = %v; want empty", got)
	}
}

// TestTableIsDefensivelyCopied pins that a caller cannot mutate the
// package's own table.
func TestTableIsDefensivelyCopied(t *testing.T) {
	a := tooltax.Table()
	if len(a) == 0 {
		t.Fatal("empty table")
	}
	a[0] = tooltax.Entry{Tool: "mutated"}
	if tooltax.Table()[0].Tool == "mutated" {
		t.Error("Table() leaked the package's backing array")
	}
	cats := tooltax.Categories()
	cats[0] = "mutated"
	if tooltax.Categories()[0] == "mutated" {
		t.Error("Categories() leaked its backing array")
	}
	surfaces := tooltax.Surfaces()
	surfaces[0] = "mutated"
	if tooltax.Surfaces()[0] == "mutated" {
		t.Error("Surfaces() leaked its backing array")
	}
}

// TestCategoryForActionTypeFallsBackToMeta mirrors the dashboard's
// actionMeta() behaviour for an unregistered type.
func TestCategoryForActionTypeFallsBackToMeta(t *testing.T) {
	if got := tooltax.CategoryForActionType("no_such_action_type"); got != tooltax.CategoryMeta {
		t.Errorf("CategoryForActionType(unregistered) = %q; want %q", got, tooltax.CategoryMeta)
	}
}

// TestNewActionTypesAreRegisteredAndCategorised pins the eight new
// canonical action types this work package introduces.
func TestNewActionTypesAreRegisteredAndCategorised(t *testing.T) {
	want := map[string]string{
		tooltax.ActionSubagentWait: tooltax.CategoryAgent,
		tooltax.ActionAgentMessage: tooltax.CategoryAgent,
		tooltax.ActionAgentControl: tooltax.CategoryAgent,
		tooltax.ActionStdinWrite:   tooltax.CategoryAgent,
		tooltax.ActionSkillInvoke:  tooltax.CategorySkill,
		tooltax.ActionSchedule:     tooltax.CategoryMeta,
		tooltax.ActionToolSearch:   tooltax.CategoryMeta,
		tooltax.ActionHarnessCall:  tooltax.CategoryMeta,
	}
	for at, cat := range want {
		m, ok := tooltax.MetaForActionType(at)
		if !ok {
			t.Errorf("new action type %q is not registered", at)
			continue
		}
		if m.Category != cat {
			t.Errorf("%q category = %q; want %q", at, m.Category, cat)
		}
		if m.Label == "" {
			t.Errorf("%q has no display label", at)
		}
	}
}

// TestAliasVocabulariesMatchSource pins the rebadge aliases: an alias
// tool must resolve every one of its source's names identically.
func TestAliasVocabulariesMatchSource(t *testing.T) {
	pairs := []struct{ alias, source string }{
		{"open-interpreter", "codex"},
		{"antigravity-cli", "antigravity"},
		{"roo-code", "cline"},
		{"zoo-code", "cline"},
		{"kilo-code", "cline"},
	}
	for _, p := range pairs {
		src := tooltax.For(p.source)
		alias := tooltax.For(p.alias)
		for native, want := range src {
			if alias[native] != want {
				t.Errorf("For(%q)[%q] = %q; source %q says %q",
					p.alias, native, alias[native], p.source, want)
			}
		}
		// Spot-check a glob too.
		if got, _ := tooltax.ResolveActionType(p.alias, "mcp__x__y"); got != tooltax.ActionMCPCall {
			t.Errorf("%s: mcp__ glob = %q", p.alias, got)
		}
	}
}
