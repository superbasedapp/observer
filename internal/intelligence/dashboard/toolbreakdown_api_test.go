package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudagents"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

// breakdownFixture seeds a database with the given events and returns a
// decoded /api/tools/breakdown response.
func breakdownFixture(t *testing.T, events []models.ToolEvent) map[string]any {
	t.Helper()
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if _, err := store.New(database).Ingest(context.Background(), events, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/tools/breakdown?days=30", nil))
	if rr.Code != 200 {
		t.Fatalf("/api/tools/breakdown: %d body=%s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	return got
}

func breakdownRow(t *testing.T, resp map[string]any, tool string) map[string]any {
	t.Helper()
	rows, _ := resp["tools"].([]any)
	for _, r := range rows {
		row, _ := r.(map[string]any)
		if row["tool"] == tool {
			return row
		}
	}
	t.Fatalf("no breakdown row for %q in %v", tool, resp["tools"])
	return nil
}

func breakdownNum(m map[string]any, key string) int {
	v, ok := m[key].(float64)
	if !ok {
		return -1
	}
	return int(v)
}

// sumBuckets sums a JSON histogram, reporting -1 for a malformed value so
// a wrong shape fails as a diff rather than a panic.
func sumBuckets(m map[string]any) int {
	total := 0
	for _, v := range m {
		n, ok := v.(float64)
		if !ok {
			return -1
		}
		total += int(n)
	}
	return total
}

// TestAPIToolsBreakdownObservedExceedsDeclared is the M1 regression at
// the API boundary: the exact "9 of 8" corpus.
//
// claude-code's DECLARED vocabulary spans 8 canonical categories; a real
// window also contains an mcp_call (tooltax's global `mcp__*` glob is
// tool-less, so it resolves for every adapter without being credited to
// any adapter's declared span). The response must therefore report
// observed=9 against expressible=8 WITHOUT the client being able to read
// that as a ratio — which is what observed_beyond_declared is for.
func TestAPIToolsBreakdownObservedExceedsDeclared(t *testing.T) {
	declared := tooltax.CategoriesForTool(models.ToolClaudeCode)
	if len(declared) == 0 {
		t.Fatal("claude-code must have a declared vocabulary")
	}
	for _, c := range declared {
		if c == tooltax.CategoryMCP {
			t.Skip("claude-code now declares the mcp category; pick another beyond-vocabulary example")
		}
	}
	root := t.TempDir()
	now := time.Now().UTC()
	var events []models.ToolEvent
	add := func(actionType, rawName string) {
		i := len(events)
		events = append(events, models.ToolEvent{
			SourceFile: "f1", SourceEventID: fmt.Sprintf("e%d", i), SessionID: "sA",
			ProjectRoot: root, Timestamp: now.Add(-time.Duration(i+1) * time.Minute),
			Tool: models.ToolClaudeCode, ActionType: actionType, RawToolName: rawName,
			Target: "t.go", Success: true,
		})
	}
	// One action per declared category…
	for _, c := range declared {
		types := tooltax.ActionTypesInCategory(c)
		if len(types) == 0 {
			t.Fatalf("category %q has no action types", c)
		}
		add(types[0], "Read")
	}
	// …plus the beyond-vocabulary one.
	add(tooltax.ActionMCPCall, "mcp__observer__get_file")

	row := breakdownRow(t, breakdownFixture(t, events), models.ToolClaudeCode)
	cov, _ := row["coverage"].(map[string]any)
	if got := breakdownNum(cov, "expressible_categories"); got != len(declared) {
		t.Fatalf("expressible_categories = %d; want %d", got, len(declared))
	}
	if got := breakdownNum(cov, "observed_categories"); got != len(declared)+1 {
		t.Fatalf("observed_categories = %d; want %d - a real observation must not be truncated away",
			got, len(declared)+1)
	}
	if got := breakdownNum(cov, "observed_beyond_declared"); got != 1 {
		t.Fatalf("observed_beyond_declared = %d; want 1 - without it, observed>expressible looks impossible",
			got)
	}
	if !cov["vocabulary_declared"].(bool) {
		t.Error("vocabulary_declared must be true for claude-code")
	}
}

// TestAPIToolsBreakdownNativeGroupCap is the M2 regression at the API
// boundary: with the native-name cap lowered, the surface pass sees only
// the densest groups, and everything it missed must be reconciled into
// the unresolved bucket so sum(by_surface) == total still holds — while
// total / by_type / by_category stay EXACT (they come from the separate
// uncapped pass).
func TestAPIToolsBreakdownNativeGroupCap(t *testing.T) {
	orig := breakdownNativeGroupCap
	breakdownNativeGroupCap = 2
	t.Cleanup(func() { breakdownNativeGroupCap = orig })

	root := t.TempDir()
	now := time.Now().UTC()
	var events []models.ToolEvent
	add := func(actionType, rawName string) {
		i := len(events)
		events = append(events, models.ToolEvent{
			SourceFile: "f1", SourceEventID: fmt.Sprintf("e%d", i), SessionID: "sA",
			ProjectRoot: root, Timestamp: now.Add(-time.Duration(i+1) * time.Minute),
			Tool: models.ToolClaudeCode, ActionType: actionType, RawToolName: rawName,
			Target: "t.go", Success: true,
		})
	}
	// Five distinct native names with descending frequency, so the
	// 2-group cap keeps Read (5) + Bash (4) and drops the other 6.
	for i := 0; i < 5; i++ {
		add(models.ActionReadFile, "Read")
	}
	for i := 0; i < 4; i++ {
		add(models.ActionRunCommand, "Bash")
	}
	for i := 0; i < 3; i++ {
		add(models.ActionSearchText, "Grep")
	}
	for i := 0; i < 2; i++ {
		add(models.ActionWebFetch, "WebFetch")
	}
	add(models.ActionMCPCall, "mcp__observer__get_file")

	row := breakdownRow(t, breakdownFixture(t, events), models.ToolClaudeCode)
	if got := breakdownNum(row, "total"); got != 15 {
		t.Fatalf("total = %d; want 15 - the cap must never truncate the totals pass", got)
	}
	byType, _ := row["by_type"].(map[string]any)
	if got := sumBuckets(byType); got != 15 {
		t.Errorf("by_type %v sums to %d; want the exact 15", byType, got)
	}
	if got := breakdownNum(byType, models.ActionMCPCall); got != 1 {
		t.Errorf("by_type[mcp_call] = %d; want 1 - the least frequent group is still counted exactly", got)
	}
	byCategory, _ := row["by_category"].(map[string]any)
	if got := sumBuckets(byCategory); got != 15 {
		t.Errorf("by_category %v sums to %d; want the exact 15", byCategory, got)
	}

	bySurface, _ := row["by_surface"].(map[string]any)
	if got := sumBuckets(bySurface); got != 15 {
		t.Fatalf("by_surface %v sums to %d; the invariant sum(by_surface)==total is broken", bySurface, got)
	}
	// Read (5) + Bash (4) are both builtin and survived the cap; the
	// remaining 6 actions were never surface-attributed and must be
	// honestly unresolved rather than silently dropped or guessed.
	if got := breakdownNum(bySurface, string(tooltax.SurfaceBuiltin)); got != 9 {
		t.Errorf("by_surface[builtin] = %d; want 9 (the two groups that survived the cap)", got)
	}
	if got := breakdownNum(bySurface, SurfaceUnresolved); got != 6 {
		t.Errorf("by_surface[unresolved] = %d; want 6 (everything the capped pass never saw)", got)
	}
}

// TestAPIToolsBreakdownSurfaceSumsToTotal pins the invariant on the
// ORDINARY (uncapped) path too, across two tools with a mix of resolved,
// unresolvable and absent native names.
func TestAPIToolsBreakdownSurfaceSumsToTotal(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	var events []models.ToolEvent
	add := func(tool, actionType, rawName string) {
		i := len(events)
		events = append(events, models.ToolEvent{
			SourceFile: "f1", SourceEventID: fmt.Sprintf("e%d", i), SessionID: "s" + tool,
			ProjectRoot: root, Timestamp: now.Add(-time.Duration(i+1) * time.Minute),
			Tool: tool, ActionType: actionType, RawToolName: rawName,
			Target: "t.go", Success: true,
		})
	}
	add(models.ToolClaudeCode, models.ActionReadFile, "Read")
	add(models.ToolClaudeCode, models.ActionMCPCall, "mcp__observer__get_file")
	add(models.ToolClaudeCode, models.ActionReadFile, "") // never captured
	add(models.ToolClaudeCode, models.ActionReadFile, "NoSuchNativeToolName")
	add(models.ToolCodex, models.ActionRunCommand, "shell")
	add(models.ToolCodex, models.ActionRunCommand, "")

	resp := breakdownFixture(t, events)
	rows, _ := resp["tools"].([]any)
	if len(rows) != 2 {
		t.Fatalf("expected 2 tool rows, got %d", len(rows))
	}
	for _, r := range rows {
		row, _ := r.(map[string]any)
		bySurface, _ := row["by_surface"].(map[string]any)
		total := breakdownNum(row, "total")
		if got := sumBuckets(bySurface); got != total {
			t.Errorf("%v: by_surface %v sums to %d; want total %d", row["tool"], bySurface, got, total)
		}
	}
}

// TestAPIToolsBreakdownCloudAgentSurfaces is the Cline Cloud surface gap
// at the API boundary: a cline-cloud session lands under tool cline, and
// its tool calls (cline-cli names, written with the connector's
// source_file) must resolve to a surface instead of "unresolved", while a
// local cline row with the same raw name in the same window stays
// unresolved. sum(by_surface) == total still holds.
func TestAPIToolsBreakdownCloudAgentSurfaces(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	cloud := cloudagents.SourceFile(cloudagents.ConnectorClineCloud)
	var events []models.ToolEvent
	add := func(sourceFile, session, actionType, rawName string) {
		i := len(events)
		events = append(events, models.ToolEvent{
			SourceFile: sourceFile, SourceEventID: fmt.Sprintf("e%d", i), SessionID: session,
			ProjectRoot: root, Timestamp: now.Add(-time.Duration(i+1) * time.Minute),
			Tool: models.ToolCline, ActionType: actionType, RawToolName: rawName,
			Target: "t.go", Success: true,
		})
	}
	add(cloud, "ses-cloud", models.ActionRunCommand, "run_commands")
	add(cloud, "ses-cloud", models.ActionRunCommand, "run_commands")
	add(cloud, "ses-cloud", models.ActionEditFile, "editor")
	add("local-task.json", "ses-local", models.ActionUnknown, "run_commands")

	row := breakdownRow(t, breakdownFixture(t, events), models.ToolCline)
	bySurface, _ := row["by_surface"].(map[string]any)
	if got := breakdownNum(bySurface, string(tooltax.SurfaceBuiltin)); got != 3 {
		t.Errorf("by_surface[builtin] = %d, want 3 (the cline-cloud calls); full %v", got, bySurface)
	}
	if got := breakdownNum(bySurface, SurfaceUnresolved); got != 1 {
		t.Errorf("by_surface[unresolved] = %d, want 1 (the local row); full %v", got, bySurface)
	}
	if got, total := sumBuckets(bySurface), breakdownNum(row, "total"); got != total {
		t.Errorf("by_surface sums to %d, want total %d", got, total)
	}
}
