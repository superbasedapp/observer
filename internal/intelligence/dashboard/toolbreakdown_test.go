package dashboard

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudagents"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

// breakdownGroup is the test-side shape for one (tool, action_type,
// raw_tool_name) observation. Production folds two SEPARATE scans (exact
// action-type totals + a capped native-name pass); these helpers replay
// both halves from one table so the unit tests stay readable.
type breakdownGroup struct {
	Tool        string
	ActionType  string
	RawToolName string
	Count       int
}

// foldGroups replays groups through both accumulator passes, in the same
// order the handler runs them (surface pass first).
func foldGroups(groups []breakdownGroup) []toolBreakdown {
	acc := newBreakdownAccumulator()
	for _, g := range groups {
		acc.AddNativeCount(g.Tool, g.RawToolName, g.Count)
	}
	for _, g := range groups {
		acc.AddActionTypeCount(g.Tool, g.ActionType, g.Count)
	}
	return acc.Rows()
}

func rowByTool(rows []toolBreakdown, tool string) toolBreakdown {
	for _, r := range rows {
		if r.Tool == tool {
			return r
		}
	}
	return toolBreakdown{}
}

// TestSummarizeToolBreakdownCategories pins the canonical category
// dimension /api/tools/breakdown gained in WP-T5: every group folds
// through tooltax.CategoryForActionType, an unregistered action type
// lands in the same fallback the dashboard renders, and the per-category
// counts always re-sum to the row total.
func TestSummarizeToolBreakdownCategories(t *testing.T) {
	groups := []breakdownGroup{
		{Tool: "claude-code", ActionType: "read_file", RawToolName: "Read", Count: 7},
		{Tool: "claude-code", ActionType: "edit_file", RawToolName: "Edit", Count: 3},
		{Tool: "claude-code", ActionType: "run_command", RawToolName: "Bash", Count: 5},
		{Tool: "claude-code", ActionType: "mcp_call", RawToolName: "mcp__observer__get_file", Count: 2},
		{Tool: "claude-code", ActionType: "not_a_registered_type", RawToolName: "Whatever", Count: 1},
	}
	out := foldGroups(groups)
	if len(out) != 1 {
		t.Fatalf("expected 1 tool row, got %d", len(out))
	}
	row := out[0]
	want := map[string]int{
		tooltax.CategoryFile: 10, // read 7 + edit 3
		tooltax.CategoryCmd:  5,
		tooltax.CategoryMCP:  2,
		// The unregistered type falls back exactly like actionMeta does.
		tooltax.CategoryForActionType("not_a_registered_type"): 1,
	}
	if len(row.ByCategory) != len(want) {
		t.Fatalf("by_category = %v; want %v", row.ByCategory, want)
	}
	for cat, n := range want {
		if row.ByCategory[cat] != n {
			t.Errorf("by_category[%q] = %d; want %d (full: %v)", cat, row.ByCategory[cat], n, row.ByCategory)
		}
	}
	if row.Total != 18 {
		t.Errorf("total = %d; want 18", row.Total)
	}
	sum := 0
	for _, n := range row.ByCategory {
		sum += n
	}
	if sum != row.Total {
		t.Errorf("by_category sums to %d but total is %d", sum, row.Total)
	}
	// The pre-WP-T5 by_type contract is untouched.
	if row.ByType["read_file"] != 7 || row.ByType["mcp_call"] != 2 {
		t.Errorf("by_type regressed: %v", row.ByType)
	}
}

// TestSummarizeToolBreakdownSurfaces pins the surface dimension,
// including the honest unresolved bucket: a missing or unmapped native
// name is NOT silently called a builtin.
func TestSummarizeToolBreakdownSurfaces(t *testing.T) {
	groups := []breakdownGroup{
		{Tool: "claude-code", ActionType: "read_file", RawToolName: "Read", Count: 4},
		{Tool: "claude-code", ActionType: "mcp_call", RawToolName: "mcp__observer__get_file", Count: 3},
		{Tool: "claude-code", ActionType: "read_file", RawToolName: "", Count: 2},
		{Tool: "claude-code", ActionType: "read_file", RawToolName: "NoSuchNativeToolName", Count: 1},
	}
	row := foldGroups(groups)[0]
	want := map[string]int{
		string(tooltax.SurfaceBuiltin): 4,
		string(tooltax.SurfaceMCP):     3,
		SurfaceUnresolved:              3, // empty name + unmapped name
	}
	if len(row.BySurface) != len(want) {
		t.Fatalf("by_surface = %v; want %v", row.BySurface, want)
	}
	for surface, n := range want {
		if row.BySurface[surface] != n {
			t.Errorf("by_surface[%q] = %d; want %d (full: %v)", surface, row.BySurface[surface], n, row.BySurface)
		}
	}
	sum := 0
	for _, n := range row.BySurface {
		sum += n
	}
	if sum != row.Total {
		t.Errorf("by_surface sums to %d but total is %d", sum, row.Total)
	}
	// Category and surface are orthogonal: the MCP-surface group is
	// category mcp here, but nothing forces them to agree — a group can
	// be surface mcp and category cmd (cowork's mcp__workspace__bash).
	if e, ok := tooltax.Resolve("cowork", "mcp__workspace__bash"); ok {
		if e.Surface == tooltax.SurfaceMCP && e.Category == tooltax.CategoryMCP {
			t.Error("the orthogonality example collapsed; pick a new one")
		}
	}
}

// TestSummarizeToolBreakdownCoverage pins the §4 capture-depth honesty
// block, including the honest zero: a tool with no declared vocabulary
// reports vocabulary_declared=false rather than "expresses 0 categories".
func TestSummarizeToolBreakdownCoverage(t *testing.T) {
	groups := []breakdownGroup{
		{Tool: "claude-code", ActionType: "read_file", RawToolName: "Read", Count: 4},
		{Tool: "claude-code", ActionType: "run_command", RawToolName: "Bash", Count: 3},
		{Tool: "chatgpt-web", ActionType: "assistant_message", RawToolName: "", Count: 2},
	}
	out := foldGroups(groups)

	cc := rowByTool(out, "claude-code")
	if cc.Coverage.ObservedCategories != 2 {
		t.Errorf("claude-code observed_categories = %d; want 2", cc.Coverage.ObservedCategories)
	}
	if cc.Coverage.ObservedBeyondDeclared != 0 {
		t.Errorf("claude-code observed_beyond_declared = %d; want 0 (file + cmd are both declared)",
			cc.Coverage.ObservedBeyondDeclared)
	}
	if !cc.Coverage.VocabularyDeclared {
		t.Error("claude-code must have a declared vocabulary")
	}
	if cc.Coverage.ExpressibleCategories != tooltax.CoverageDepth("claude-code") {
		t.Errorf("claude-code expressible_categories = %d; want %d",
			cc.Coverage.ExpressibleCategories, tooltax.CoverageDepth("claude-code"))
	}
	if cc.Coverage.ExpressibleCategories <= cc.Coverage.ObservedCategories {
		t.Errorf("claude-code should express more than the 2 categories observed here: %+v", cc.Coverage)
	}
	if cc.Coverage.CanonicalCategories != len(tooltax.Categories()) {
		t.Errorf("canonical_categories = %d; want %d",
			cc.Coverage.CanonicalCategories, len(tooltax.Categories()))
	}

	web := rowByTool(out, "chatgpt-web")
	if web.Coverage.VocabularyDeclared || web.Coverage.ExpressibleCategories != 0 {
		t.Errorf("chatgpt-web has no tooltax rows; want an honest zero, got %+v", web.Coverage)
	}
	if web.Coverage.ObservedCategories != 1 {
		t.Errorf("chatgpt-web observed_categories = %d; want 1", web.Coverage.ObservedCategories)
	}
	// Undeclared vocabulary ⇒ every observed category is beyond it. That
	// is what makes the client render "capture depth not mapped" rather
	// than any comparison at all.
	if web.Coverage.ObservedBeyondDeclared != web.Coverage.ObservedCategories {
		t.Errorf("chatgpt-web observed_beyond_declared = %d; want %d",
			web.Coverage.ObservedBeyondDeclared, web.Coverage.ObservedCategories)
	}
}

// TestCoverageObservedMayExceedDeclared is the M1 regression: the
// "9 of 8" scenario.
//
// The backend counts every observed category, including ones outside the
// tool's declared vocabulary — tooltax's global `mcp__*` glob resolves
// for every adapter, so claude-code (declared span: 8 categories, no mcp)
// legitimately observes 9. That is NOT an error to be truncated away; it
// is a fact, and the two numbers are simply not a ratio. This test pins
// the shape the client needs to say so coherently: observed stays
// un-truncated AND observed_beyond_declared explains the excess.
func TestCoverageObservedMayExceedDeclared(t *testing.T) {
	declared := tooltax.CategoriesForTool("claude-code")
	if len(declared) == 0 {
		t.Fatal("claude-code must have a declared vocabulary for this scenario")
	}
	declaredSet := map[string]bool{}
	for _, c := range declared {
		declaredSet[c] = true
	}
	// One action type per declared category, plus an mcp_call — whose
	// category claude-code's own vocabulary does NOT declare (the global
	// mcp__* glob is tool-less, and CategoriesForTool deliberately does
	// not credit tool-less rows to any tool).
	if declaredSet[tooltax.CategoryMCP] {
		t.Skip("claude-code now declares the mcp category; pick another beyond-vocabulary example")
	}
	var groups []breakdownGroup
	for _, c := range declared {
		types := tooltax.ActionTypesInCategory(c)
		if len(types) == 0 {
			t.Fatalf("category %q has no action types", c)
		}
		groups = append(groups, breakdownGroup{
			Tool: "claude-code", ActionType: types[0], RawToolName: "Read", Count: 1,
		})
	}
	groups = append(groups, breakdownGroup{
		Tool: "claude-code", ActionType: tooltax.ActionMCPCall,
		RawToolName: "mcp__observer__get_file", Count: 1,
	})

	row := foldGroups(groups)[0]
	if row.Coverage.ExpressibleCategories != len(declared) {
		t.Fatalf("expressible_categories = %d; want %d", row.Coverage.ExpressibleCategories, len(declared))
	}
	if row.Coverage.ObservedCategories != len(declared)+1 {
		t.Fatalf("observed_categories = %d; want %d - observations must NOT be truncated to the declared span",
			row.Coverage.ObservedCategories, len(declared)+1)
	}
	if row.Coverage.ObservedBeyondDeclared != 1 {
		t.Fatalf("observed_beyond_declared = %d; want 1 (the mcp_call resolved by the global glob)",
			row.Coverage.ObservedBeyondDeclared)
	}
	// The excess must always be explicable: observed can exceed
	// expressible ONLY by the beyond-declared count. If this ever fails,
	// any client formatting the pair as "N of M" is printing nonsense.
	if row.Coverage.ObservedCategories-row.Coverage.ObservedBeyondDeclared > row.Coverage.ExpressibleCategories {
		t.Errorf("observed(%d) - beyond(%d) exceeds expressible(%d): the excess is unexplained",
			row.Coverage.ObservedCategories, row.Coverage.ObservedBeyondDeclared,
			row.Coverage.ExpressibleCategories)
	}
}

// TestSummarizeToolBreakdownOrdering pins the pre-WP-T5 ordering
// contract: densest tool first, ties in first-appearance order — and
// specifically that the order comes from the TOTALS pass, not from
// whichever order the capped surface pass happened to return.
func TestSummarizeToolBreakdownOrdering(t *testing.T) {
	acc := newBreakdownAccumulator()
	// Surface pass first, in a deliberately different order.
	acc.AddNativeCount("codex", "shell", 2)
	acc.AddNativeCount("claude-code", "Read", 9)
	acc.AddNativeCount("cursor", "edit_file", 2)
	// Totals pass in the query's `ORDER BY tool, COUNT(*) DESC` order.
	acc.AddActionTypeCount("cursor", "edit_file", 2)
	acc.AddActionTypeCount("claude-code", "read_file", 9)
	acc.AddActionTypeCount("codex", "run_command", 2)

	out := acc.Rows()
	got := []string{out[0].Tool, out[1].Tool, out[2].Tool}
	want := []string{"claude-code", "cursor", "codex"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ordering = %v; want %v", got, want)
		}
	}
}

// TestBreakdownSurfaceRemainderIsUnresolved is the M2 unit-level
// regression: whatever the capped native-name pass never saw must land
// in the unresolved bucket so sum(by_surface) == total holds.
func TestBreakdownSurfaceRemainderIsUnresolved(t *testing.T) {
	acc := newBreakdownAccumulator()
	// The surface pass saw only the two densest names (cap bit here).
	acc.AddNativeCount("claude-code", "Read", 5)
	acc.AddNativeCount("claude-code", "Bash", 4)
	// The totals pass is exact and uncapped.
	acc.AddActionTypeCount("claude-code", "read_file", 5)
	acc.AddActionTypeCount("claude-code", "run_command", 4)
	acc.AddActionTypeCount("claude-code", "search_text", 3)
	acc.AddActionTypeCount("claude-code", "web_fetch", 2)
	acc.AddActionTypeCount("claude-code", "mcp_call", 1)

	row := acc.Rows()[0]
	if row.Total != 15 {
		t.Fatalf("total = %d; want 15", row.Total)
	}
	sum := 0
	for _, n := range row.BySurface {
		sum += n
	}
	if sum != row.Total {
		t.Fatalf("by_surface %v sums to %d; must equal total %d", row.BySurface, sum, row.Total)
	}
	if row.BySurface[SurfaceUnresolved] != 6 {
		t.Errorf("unresolved = %d; want 6 (the 15 total minus the 9 the capped pass attributed)",
			row.BySurface[SurfaceUnresolved])
	}
	// A tool the surface pass over-counted (rows pruned between the two
	// scans) must not produce a negative bucket.
	acc2 := newBreakdownAccumulator()
	acc2.AddNativeCount("codex", "shell", 50)
	acc2.AddActionTypeCount("codex", "run_command", 10)
	row2 := acc2.Rows()[0]
	for surface, n := range row2.BySurface {
		if n < 0 {
			t.Errorf("by_surface[%q] = %d; buckets must never go negative", surface, n)
		}
	}
}

// TestBreakdownDropsSurfaceOnlyTools pins that a tool seen ONLY by the
// surface pass (zero counted actions) never reaches the response — a
// zero-total phantom row would put an adapter on the chart that did
// nothing in the window.
func TestBreakdownDropsSurfaceOnlyTools(t *testing.T) {
	acc := newBreakdownAccumulator()
	acc.AddNativeCount("ghost-tool", "Read", 3)
	acc.AddNativeCount("claude-code", "Read", 2)
	acc.AddActionTypeCount("claude-code", "read_file", 2)
	out := acc.Rows()
	if len(out) != 1 || out[0].Tool != "claude-code" {
		t.Fatalf("rows = %v; want only claude-code", out)
	}
}

// TestBreakdownSurfaceKeys pins the emitted key space: every canonical
// surface, in tooltax display order, then the unresolved bucket — which
// must NOT be one of the canonical surfaces.
func TestBreakdownSurfaceKeys(t *testing.T) {
	keys := breakdownSurfaceKeys()
	surfaces := tooltax.Surfaces()
	if len(keys) != len(surfaces)+1 {
		t.Fatalf("surface keys = %v; want %d canonical + unresolved", keys, len(surfaces))
	}
	for i, s := range surfaces {
		if keys[i] != string(s) {
			t.Errorf("surface key %d = %q; want %q", i, keys[i], s)
		}
		if string(s) == SurfaceUnresolved {
			t.Errorf("%q is a canonical surface; the unresolved bucket must be distinct", s)
		}
	}
	if keys[len(keys)-1] != SurfaceUnresolved {
		t.Errorf("last surface key = %q; want %q", keys[len(keys)-1], SurfaceUnresolved)
	}
}

// TestSummarizeToolBreakdownEmpty pins that an empty window yields an
// empty (never nil-panicking) slice.
func TestSummarizeToolBreakdownEmpty(t *testing.T) {
	if got := newBreakdownAccumulator().Rows(); len(got) != 0 {
		t.Errorf("empty accumulator produced %v; want no rows", got)
	}
}

// TestCloudAgentToolSurfaces pins the surface of tool calls a cloud-agent
// connector wrote, one row per connector that lands tool calls: the native
// name resolves under the vocabulary of the connector that wrote the row
// (cloudagents.VocabularyForSource), so Cline Cloud's cline-cli names
// (run_commands, editor) resolve under tool cline instead of reading as
// unresolved, while the same name on a local cline row stays unresolved
// (cline's own vocabulary does not hold it, and it is never guessed).
func TestCloudAgentToolSurfaces(t *testing.T) {
	builtin := string(tooltax.SurfaceBuiltin)
	cases := []struct {
		name, tool, sourceFile, raw, want string
	}{
		{"cline cloud run_commands", models.ToolCline, cloudagents.SourceFile(cloudagents.ConnectorClineCloud), "run_commands", builtin},
		{"cline cloud editor", models.ToolCline, cloudagents.SourceFile(cloudagents.ConnectorClineCloud), "editor", builtin},
		{"cline cloud read_files", models.ToolCline, cloudagents.SourceFile(cloudagents.ConnectorClineCloud), "read_files", builtin},
		{"cline cloud spawn_agent", models.ToolCline, cloudagents.SourceFile(cloudagents.ConnectorClineCloud), "spawn_agent", string(tooltax.SurfaceOrchestration)},
		{"cline cloud submit_and_exit", models.ToolCline, cloudagents.SourceFile(cloudagents.ConnectorClineCloud), "submit_and_exit", string(tooltax.SurfaceMeta)},
		{"cline cloud unknown name", models.ToolCline, cloudagents.SourceFile(cloudagents.ConnectorClineCloud), "definitely_not_a_tool", SurfaceUnresolved},
		{"local cline execute_command", models.ToolCline, "/home/u/task/api_conversation_history.json", "execute_command", builtin},
		{"local cline run_commands", models.ToolCline, "/home/u/task/api_conversation_history.json", "run_commands", SurfaceUnresolved},
		{"cursor cloud read_file", models.ToolCursor, cloudagents.SourceFile(cloudagents.ConnectorCursorCloud), "read_file", builtin},
		{"qoder cloud Bash", models.ToolQoder, cloudagents.SourceFile(cloudagents.ConnectorQoderCloud), "Bash", builtin},
		{"warp claude harness Read", models.ToolClaudeCode, cloudagents.SourceFile(cloudagents.ConnectorWarpCloud), "Read", builtin},
		{"warp codex harness shell", models.ToolCodex, cloudagents.SourceFile(cloudagents.ConnectorWarpCloud), "shell", builtin},
	}
	for _, tc := range cases {
		acc := newBreakdownAccumulator()
		acc.AddNativeCountIn(tc.tool, cloudagents.VocabularyForSource(tc.tool, tc.sourceFile), tc.raw, 1)
		acc.AddActionTypeCount(tc.tool, models.ActionRunCommand, 1)
		row := rowByTool(acc.Rows(), tc.tool)
		if row.BySurface[tc.want] != 1 {
			t.Errorf("%s: by_surface = %v, want 1 in %q", tc.name, row.BySurface, tc.want)
		}
	}
}
