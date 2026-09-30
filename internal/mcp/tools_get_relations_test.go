package mcp

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/codeintel"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/mcp/audit"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// getRelationsFixture wires the get_relations MCP tool against a real
// NATIVE codeintel index seeded inline. Mirrors getSymbolsFixture's
// shape. The synthetic node/edge graph is persisted through the store
// seam — see seedCodeIntel.
type getRelationsFixture struct {
	s       *Server
	root    string
	auditDB *sql.DB
}

func newGetRelationsFixture(t *testing.T, seeds []symbolSeed, edges []edgeSeed, opts GetRelationsOptions) *getRelationsFixture {
	t.Helper()
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "obs.db")
	database, err := db.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	auditW := audit.NewSQLWriter(database, slog.New(slog.NewTextHandler(io.Discard, nil)), audit.SQLWriterOptions{
		FlushInterval: 10 * time.Millisecond,
		BatchSize:     8,
	})
	t.Cleanup(func() { _ = auditW.Close() })

	root := filepath.Join(tmp, "proj")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, s := range seeds {
		abs := filepath.Join(root, s.relPath)
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(s.content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	st := store.New(database)
	seedCodeIntel(t, st, root, seeds, edges)

	s, err := New(Options{
		DB:                  database,
		ServerName:          "test",
		ServerVersion:       "0",
		CodeIntel:           codeintel.NewEngine(st),
		AuditWriter:         auditW,
		GetRelationsEnabled: true,
		GetRelations:        opts,
	})
	if err != nil {
		t.Fatalf("mcp.New: %v", err)
	}
	return &getRelationsFixture{s: s, root: root, auditDB: database}
}

// callsCycleSeed returns the A→B→C→A + A→D cycle graph as structured
// seeds: one file "graph.ts" with four functions, name-matched CALLS
// edges resolved by seedCodeIntel.
func callsCycleSeed() ([]symbolSeed, []edgeSeed) {
	seeds := []symbolSeed{{
		relPath: "graph.ts",
		content: "// stub\n",
		nodes: []nodeSeed{
			{id: 1, kind: "function", name: "A", fqn: "A", startLine: 10, endLine: 20, language: "typescript"},
			{id: 2, kind: "function", name: "B", fqn: "B", startLine: 30, endLine: 40, language: "typescript"},
			{id: 3, kind: "function", name: "C", fqn: "C", startLine: 50, endLine: 60, language: "typescript"},
			{id: 4, kind: "function", name: "D", fqn: "D", startLine: 70, endLine: 80, language: "typescript"},
		},
	}}
	edges := []edgeSeed{
		{sourceID: 1, targetID: 2, kind: "CALLS"},
		{sourceID: 2, targetID: 3, kind: "CALLS"},
		{sourceID: 3, targetID: 1, kind: "CALLS"},
		{sourceID: 1, targetID: 4, kind: "CALLS"},
	}
	return seeds, edges
}

func defaultGetRelationsOpts() GetRelationsOptions {
	return GetRelationsOptions{
		AllowExtensions: []string{"ts", "tsx", "go"},
		MaxDepth:        5,
		MaxResults:      100,
	}
}

func TestGetRelations_CalleesHappyPath(t *testing.T) {
	seeds, edges := callsCycleSeed()
	f := newGetRelationsFixture(t, seeds, edges, defaultGetRelationsOpts())

	res := callTool(t, f.s, "get_relations", map[string]any{
		"project_root": f.root,
		"file":         "graph.ts",
		"name":         "A",
		"kind":         "callees",
		"depth":        1,
	})
	if !res["ok"].(bool) {
		t.Fatalf("ok=false: %+v", res)
	}
	if res["kind"] != "callees" || int(res["depth"].(float64)) != 1 {
		t.Errorf("kind/depth: %+v", res)
	}
	results := res["results"].([]any)
	if len(results) != 2 {
		t.Fatalf("want 2 callees (B, D), got %d: %+v", len(results), results)
	}
	r0 := results[0].(map[string]any)
	sym := r0["symbol"].(map[string]any)
	if sym["name"] != "B" || int(r0["depth"].(float64)) != 1 || r0["via_edge"] != "CALLS" {
		t.Errorf("result[0]: %+v", r0)
	}
}

func TestGetRelations_CallersHappyPath(t *testing.T) {
	seeds, edges := callsCycleSeed()
	f := newGetRelationsFixture(t, seeds, edges, defaultGetRelationsOpts())

	res := callTool(t, f.s, "get_relations", map[string]any{
		"project_root": f.root,
		"file":         "graph.ts",
		"name":         "A",
		"kind":         "callers",
	})
	// Default depth = 1; only C calls A.
	results := res["results"].([]any)
	if len(results) != 1 || results[0].(map[string]any)["symbol"].(map[string]any)["name"] != "C" {
		t.Errorf("callers: %+v", results)
	}
}

// TestGetRelations_ContainsPopulated proves the native engine now
// traverses CONTAINS edges, derived at index time from intra-file span
// nesting. module pkg (1-100) ⊃ class Foo (10-50) ⊃ method bar (20-30),
// so a contains query from pkg returns Foo (depth 1) and bar (depth 2).
// The explicit CONTAINS edges in the DSL are still dropped by
// seedCodeIntel — these edges come purely from the node SPANS.
func TestGetRelations_ContainsPopulated(t *testing.T) {
	seeds := []symbolSeed{{
		relPath: "mod.ts",
		content: "// stub\n",
		nodes: []nodeSeed{
			{id: 1, kind: "module", name: "pkg", fqn: "pkg", startLine: 1, endLine: 100, language: "typescript"},
			{id: 2, kind: "class", name: "Foo", fqn: "pkg.Foo", startLine: 10, endLine: 50, language: "typescript"},
			{id: 3, kind: "method", name: "bar", fqn: "pkg.Foo.bar", startLine: 20, endLine: 30, language: "typescript"},
		},
	}}
	f := newGetRelationsFixture(t, seeds, nil, defaultGetRelationsOpts())

	res := callTool(t, f.s, "get_relations", map[string]any{
		"project_root": f.root,
		"file":         "mod.ts",
		"name":         "pkg",
		"kind":         "contains",
		"depth":        5,
	})
	if !res["ok"].(bool) {
		t.Fatalf("ok should be true: %+v", res)
	}
	if deg, _ := res["degraded"].(bool); deg {
		t.Errorf("contains should NOT be degraded now that it is populated: %+v", res)
	}
	results := res["results"].([]any)
	got := map[string]bool{}
	endLines := map[string]int{}
	for _, r := range results {
		sym := r.(map[string]any)["symbol"].(map[string]any)
		name := sym["name"].(string)
		got[name] = true
		endLines[name] = int(sym["end_line"].(float64))
	}
	if !got["Foo"] || !got["bar"] {
		t.Fatalf("contains from pkg should reach Foo + bar, got %+v", results)
	}
	// Regression guard: the result symbol must carry its real end_line, not 0
	// (the get_relations mapping previously omitted EndLine). The seeds make
	// Foo span 10-50 and bar span 20-30.
	if endLines["Foo"] != 50 {
		t.Errorf("Foo end_line should be 50, got %d", endLines["Foo"])
	}
	if endLines["bar"] != 30 {
		t.Errorf("bar end_line should be 30, got %d", endLines["bar"])
	}
}

func TestGetRelations_AmbiguousAnchor_RequiresFQN(t *testing.T) {
	seeds := []symbolSeed{{
		relPath: "graph.ts",
		content: "// stub\n",
		nodes: []nodeSeed{
			{id: 1, kind: "function", name: "handleClick", fqn: "handleClick", startLine: 50, endLine: 80, language: "typescript"},
			{id: 2, kind: "method", name: "handleClick", fqn: "Editor.handleClick", startLine: 200, endLine: 210, language: "typescript"},
		},
	}}
	f := newGetRelationsFixture(t, seeds, nil, defaultGetRelationsOpts())

	res := callTool(t, f.s, "get_relations", map[string]any{
		"project_root": f.root,
		"file":         "graph.ts",
		"name":         "handleClick",
		"kind":         "callers",
	})
	if res["ok"].(bool) {
		t.Errorf("ambiguous anchor should land ok=false: %+v", res)
	}
	if !strings.Contains(res["reason"].(string), "ambiguous anchor") {
		t.Errorf("reason: %q", res["reason"])
	}
	candidates := res["candidates"].([]any)
	if len(candidates) != 2 {
		t.Fatalf("want 2 candidates, got %d", len(candidates))
	}
	fqns := map[string]bool{
		candidates[0].(map[string]any)["fqn"].(string): true,
		candidates[1].(map[string]any)["fqn"].(string): true,
	}
	if !fqns["handleClick"] || !fqns["Editor.handleClick"] {
		t.Errorf("candidates missing expected fqns: %+v", candidates)
	}
}

// TestGetRelations_FQNDisambiguation_Resolves pins fqn anchor
// disambiguation. Two symbols share the name "handleClick"; the caller
// lives in the same file as the METHOD overload, so the native
// name-matched resolver's same-file locality rule binds the call to the
// method (codeintel/resolve.Resolve). The fqn pin then selects that
// method as the anchor and its single caller comes back.
func TestGetRelations_FQNDisambiguation_Resolves(t *testing.T) {
	seeds := []symbolSeed{
		{
			relPath: "a.ts",
			content: "// stub\n",
			nodes: []nodeSeed{
				{id: 1, kind: "function", name: "handleClick", fqn: "handleClick", startLine: 50, endLine: 80, language: "typescript"},
			},
		},
		{
			relPath: "b.ts",
			content: "// stub\n",
			nodes: []nodeSeed{
				{id: 2, kind: "method", name: "handleClick", fqn: "Editor.handleClick", startLine: 200, endLine: 210, language: "typescript"},
				{id: 3, kind: "function", name: "caller", fqn: "caller", startLine: 220, endLine: 230, language: "typescript"},
			},
		},
	}
	// caller (b.ts) calls handleClick; same-file locality resolves it to
	// the method overload (id 2, also in b.ts).
	edges := []edgeSeed{{sourceID: 3, targetID: 2, kind: "CALLS"}}
	f := newGetRelationsFixture(t, seeds, edges, defaultGetRelationsOpts())

	res := callTool(t, f.s, "get_relations", map[string]any{
		"project_root": f.root,
		"file":         "b.ts",
		"name":         "handleClick",
		"fqn":          "Editor.handleClick",
		"kind":         "callers",
	})
	if !res["ok"].(bool) {
		t.Fatalf("fqn-pinned should resolve, got: %+v", res)
	}
	results := res["results"].([]any)
	if len(results) != 1 || results[0].(map[string]any)["symbol"].(map[string]any)["name"] != "caller" {
		t.Errorf("expected single 'caller' result, got %+v", results)
	}
}

func TestGetRelations_DefaultDepthIsOne(t *testing.T) {
	seeds, edges := callsCycleSeed()
	f := newGetRelationsFixture(t, seeds, edges, defaultGetRelationsOpts())

	// Omit depth.
	res := callTool(t, f.s, "get_relations", map[string]any{
		"project_root": f.root,
		"file":         "graph.ts",
		"name":         "A",
		"kind":         "callees",
	})
	if int(res["depth"].(float64)) != 1 {
		t.Errorf("default depth should be 1, got %v", res["depth"])
	}
	if len(res["results"].([]any)) != 2 {
		t.Errorf("depth-1 from A should reach 2 nodes (B, D)")
	}
}

func TestGetRelations_DepthClampedToMax(t *testing.T) {
	opts := defaultGetRelationsOpts()
	opts.MaxDepth = 2
	seeds, edges := callsCycleSeed()
	f := newGetRelationsFixture(t, seeds, edges, opts)

	res := callTool(t, f.s, "get_relations", map[string]any{
		"project_root": f.root,
		"file":         "graph.ts",
		"name":         "A",
		"kind":         "callees",
		"depth":        99,
	})
	if int(res["depth"].(float64)) != 2 {
		t.Errorf("depth=99 with MaxDepth=2 should clamp to 2, got %v", res["depth"])
	}
}

func TestGetRelations_InvalidKind(t *testing.T) {
	seeds, edges := callsCycleSeed()
	f := newGetRelationsFixture(t, seeds, edges, defaultGetRelationsOpts())

	errText := callToolExpectError(t, f.s, "get_relations", map[string]any{
		"project_root": f.root,
		"file":         "graph.ts",
		"name":         "A",
		"kind":         "bogus",
	})
	if !strings.Contains(errText, "invalid kind") {
		t.Errorf("expected invalid-kind error, got %q", errText)
	}
}

func TestGetRelations_PathDenied(t *testing.T) {
	seeds, edges := callsCycleSeed()
	f := newGetRelationsFixture(t, seeds, edges, defaultGetRelationsOpts())

	// Point outside the project root.
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, "out.ts"), []byte("// x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := callTool(t, f.s, "get_relations", map[string]any{
		"project_root": f.root,
		"file":         filepath.Join(other, "out.ts"),
		"name":         "A",
		"kind":         "callees",
	})
	if res["ok"].(bool) {
		t.Errorf("path outside root should land ok=false")
	}
	if !strings.Contains(res["reason"].(string), "outside project_root") {
		t.Errorf("reason: %q", res["reason"])
	}
}

func TestGetRelations_IndexUnavailable(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "obs.db")
	database, _ := db.Open(context.Background(), db.Options{Path: dbPath})
	t.Cleanup(func() { database.Close() })

	auditW := audit.NewSQLWriter(database, slog.New(slog.NewTextHandler(io.Discard, nil)), audit.SQLWriterOptions{FlushInterval: 10 * time.Millisecond})
	t.Cleanup(func() { _ = auditW.Close() })

	root := filepath.Join(tmp, "proj")
	_ = os.MkdirAll(root, 0o755)
	_ = os.WriteFile(filepath.Join(root, "x.ts"), []byte("// x\n"), 0o600)

	s, _ := New(Options{
		DB:                  database,
		ServerName:          "test",
		ServerVersion:       "0",
		CodeIntel:           codeintel.Unavailable(),
		AuditWriter:         auditW,
		GetRelationsEnabled: true,
		GetRelations:        defaultGetRelationsOpts(),
	})
	res := callTool(t, s, "get_relations", map[string]any{
		"project_root": root,
		"file":         "x.ts",
		"name":         "anything",
		"kind":         "callees",
	})
	if deg, _ := res["degraded"].(bool); !deg {
		t.Errorf("expected degraded=true, got %+v", res)
	}
	if !strings.Contains(res["reason"].(string), "code index unavailable") {
		t.Errorf("reason: %q", res["reason"])
	}
	// V7-17: warnings should include index_unavailable in-band.
	warnings, _ := res["warnings"].([]any)
	found := false
	for _, w := range warnings {
		if w == "index_unavailable" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected index_unavailable in warnings, got %v", warnings)
	}
}

func TestGetRelations_ContainsEmpty_HintsUpstream(t *testing.T) {
	// A graph with CALLS edges only — no CONTAINS at all.
	seeds, edges := callsCycleSeed()
	f := newGetRelationsFixture(t, seeds, edges, defaultGetRelationsOpts())

	res := callTool(t, f.s, "get_relations", map[string]any{
		"project_root": f.root,
		"file":         "graph.ts",
		"name":         "A",
		"kind":         "contains",
	})
	if !res["ok"].(bool) {
		t.Fatalf("ok should stay true even when degraded, got %+v", res)
	}
	if deg, _ := res["degraded"].(bool); !deg {
		t.Errorf("CONTAINS empty should be degraded, got %+v", res)
	}
	if !strings.Contains(res["reason"].(string), "not populated") {
		t.Errorf("reason should mention not populated, got %q", res["reason"])
	}
}

func TestGetRelations_TruncationFlag(t *testing.T) {
	opts := defaultGetRelationsOpts()
	opts.MaxResults = 2 // force truncation
	seeds, edges := callsCycleSeed()
	f := newGetRelationsFixture(t, seeds, edges, opts)

	res := callTool(t, f.s, "get_relations", map[string]any{
		"project_root": f.root,
		"file":         "graph.ts",
		"name":         "A",
		"kind":         "callees",
		"depth":        5,
	})
	if trunc, _ := res["truncated"].(bool); !trunc {
		t.Errorf("expected truncated=true at MaxResults=2, got %+v", res)
	}
	if len(res["results"].([]any)) != 2 {
		t.Errorf("expected 2 results, got %d", len(res["results"].([]any)))
	}
}

func TestGetRelations_AuditRowPerCall(t *testing.T) {
	seeds, edges := callsCycleSeed()
	f := newGetRelationsFixture(t, seeds, edges, defaultGetRelationsOpts())

	_ = callTool(t, f.s, "get_relations", map[string]any{
		"project_root": f.root,
		"file":         "graph.ts",
		"name":         "A",
		"kind":         "callees",
		"session_id":   "sess-relations",
	})
	if got := auditRowCount(t, f.auditDB,
		"tool_name = 'get_relations' AND session_id = ?", "sess-relations"); got != 1 {
		t.Errorf("expected 1 audit row, got %d", got)
	}
}

func TestGetRelations_NotRegisteredWhenDisabled(t *testing.T) {
	tmp := t.TempDir()
	database, _ := db.Open(context.Background(), db.Options{Path: filepath.Join(tmp, "obs.db")})
	t.Cleanup(func() { database.Close() })
	s, _ := New(Options{
		DB: database, ServerName: "test", ServerVersion: "0",
		GetRelationsEnabled: false,
	})
	resp := rpcCall(t, s, "tools/list", 1, nil)
	for _, raw := range resp["result"].(map[string]any)["tools"].([]any) {
		if raw.(map[string]any)["name"] == "get_relations" {
			t.Errorf("get_relations registered even though disabled")
		}
	}
}
