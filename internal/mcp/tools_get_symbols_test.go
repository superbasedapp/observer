package mcp

import (
	"context"
	"database/sql"
	"fmt"
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

// getSymbolsFixture wires the get_symbols MCP tool against a real
// NATIVE codeintel index seeded inline with V7-15 ranking cases.
// project_root is a temp dir; the codeintel_files rows are keyed off
// the abs path inside that root so file-resolution works end-to-end.
// The fixture seeds the native store directly via the same store seam
// the indexer uses.
type getSymbolsFixture struct {
	s       *Server
	root    string
	auditDB *sql.DB
}

// symbolSeed describes one file: its content lines AND its symbol
// metadata. nodeSeed/edgeSeed are the synthetic graph DSL shared by the
// get_symbols and get_relations fixtures.
type symbolSeed struct {
	relPath string
	content string
	nodes   []nodeSeed
}

type nodeSeed struct {
	id        int64
	kind      string
	name      string
	fqn       string
	startLine int
	endLine   int
	language  string
}

type edgeSeed struct {
	sourceID int64
	targetID int64
	kind     string
}

// seedCodeIntel persists the synthetic symbolSeed/edgeSeed graph into
// the NATIVE codeintel store. Each seed file's nodes become codeintel_nodes; each CALLS
// edge becomes a call site enclosed by its source symbol whose callee
// name is the edge target's name, then the project-level name-matched
// resolver fills in the edge's dst — reproducing the caller/callee
// graph the tests assert against.
//
// Explicit CONTAINS edges in the edgeSeed DSL are intentionally NOT
// inserted here — the native engine DERIVES CONTAINS at index time from
// intra-file node SPAN nesting (CodeIntelSaveFile). So a CONTAINS query
// returns the hierarchy when the seeded nodes nest by line span, and the
// "not populated" hint only when a project genuinely has no nesting — see
// the get_relations contains tests.
func seedCodeIntel(t *testing.T, st *store.Store, project string, seeds []symbolSeed, edges []edgeSeed) {
	t.Helper()
	ctx := context.Background()

	// id -> (name, seed index, node index) so an edge's source/target
	// can be located across files.
	type loc struct {
		name    string
		seedIdx int
		nodeIdx int
	}
	byID := map[int64]loc{}
	for si, s := range seeds {
		for ni, n := range s.nodes {
			byID[n.id] = loc{name: n.name, seedIdx: si, nodeIdx: ni}
		}
	}

	for si, s := range seeds {
		abs := filepath.Join(project, s.relPath)
		fr := codeintel.FileResult{
			Project:     project,
			Path:        abs,
			Lang:        codeintel.Language(seedLang(s)),
			Parser:      "test-seed",
			ContentHash: "seed",
		}
		for _, n := range s.nodes {
			fr.Nodes = append(fr.Nodes, codeintel.Node{
				Kind:      n.kind,
				Name:      n.name,
				FQN:       n.fqn,
				StartLine: n.startLine,
				EndLine:   n.endLine,
			})
		}
		// CALLS edges whose SOURCE node lives in this file become call
		// sites enclosed by that source node; the callee name comes from
		// the edge's target, resolved (cross-file) by the sweep below.
		for _, e := range edges {
			if e.kind != "CALLS" {
				continue
			}
			src, ok := byID[e.sourceID]
			if !ok || src.seedIdx != si {
				continue
			}
			dst, ok := byID[e.targetID]
			if !ok {
				continue
			}
			fr.Calls = append(fr.Calls, codeintel.CallSite{
				Name:      dst.name,
				Enclosing: src.nodeIdx,
				StartLine: s.nodes[src.nodeIdx].startLine,
			})
		}
		if err := st.CodeIntelSaveFile(ctx, fr); err != nil {
			t.Fatalf("CodeIntelSaveFile(%s): %v", s.relPath, err)
		}
	}
	if _, err := st.CodeIntelResolveCalls(ctx, project); err != nil {
		t.Fatalf("CodeIntelResolveCalls: %v", err)
	}
}

// seedLang picks the FileResult language for a seed: the first node's
// declared language, else inferred from the file extension.
func seedLang(s symbolSeed) string {
	for _, n := range s.nodes {
		if n.language != "" {
			return n.language
		}
	}
	switch strings.ToLower(filepath.Ext(s.relPath)) {
	case ".go":
		return "go"
	case ".ts", ".tsx":
		return "typescript"
	case ".js", ".jsx":
		return "javascript"
	case ".py":
		return "python"
	}
	return ""
}

func newGetSymbolsFixture(t *testing.T, seeds []symbolSeed, edges []edgeSeed, opts GetSymbolsOptions) *getSymbolsFixture {
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
	// Real files on disk so readSlice can extract bodies.
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
		DB:                database,
		ServerName:        "test",
		ServerVersion:     "0",
		CodeIntel:         codeintel.NewEngine(st),
		AuditWriter:       auditW,
		GetSymbolsEnabled: true,
		GetSymbols:        opts,
	})
	if err != nil {
		t.Fatalf("mcp.New: %v", err)
	}
	return &getSymbolsFixture{s: s, root: root, auditDB: database}
}

// editorTSXContent is a 250-line file with a handleClick function at
// line 50 and an Editor class at line 120. Used for body extraction
// + V7-15 ranking tests.
func editorTSXContent() string {
	var sb strings.Builder
	for i := 1; i <= 250; i++ {
		switch i {
		case 50:
			sb.WriteString("function handleClick(e) {\n")
		case 80:
			sb.WriteString("}\n")
		case 120:
			sb.WriteString("class Editor {\n")
		case 200:
			sb.WriteString("  handleClick(e) { /* method */ }\n")
		case 240:
			sb.WriteString("}\n")
		default:
			sb.WriteString(fmt.Sprintf("// line %d\n", i))
		}
	}
	return sb.String()
}

func defaultGetSymbolsOpts() GetSymbolsOptions {
	return GetSymbolsOptions{
		AllowExtensions: []string{"tsx", "ts", "js", "go"},
		MaxResponseKB:   100,
		MaxCallers:      20,
		MaxCallees:      20,
	}
}

func TestGetSymbols_SingleNamedMatch(t *testing.T) {
	seeds := []symbolSeed{
		{
			relPath: "src/Editor.tsx",
			content: editorTSXContent(),
			nodes: []nodeSeed{
				{
					id: 1, kind: "function", name: "handleClick", fqn: "handleClick",
					startLine: 50, endLine: 80, language: "typescript",
				},
			},
		},
	}
	f := newGetSymbolsFixture(t, seeds, nil, defaultGetSymbolsOpts())
	res := callTool(t, f.s, "get_symbols", map[string]any{
		"project_root": f.root,
		"requests": []map[string]any{
			{"file": "src/Editor.tsx", "name": "handleClick"},
		},
	})
	if ok, _ := res["ok"].(bool); !ok {
		t.Fatalf("top-level ok=false: %+v", res)
	}
	results := res["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	r0 := results[0].(map[string]any)
	matches := r0["matches"].([]any)
	if len(matches) != 1 {
		t.Fatalf("got %d matches, want 1: %+v", len(matches), r0)
	}
	m := matches[0].(map[string]any)
	if m["name"] != "handleClick" || m["fqn"] != "handleClick" {
		t.Errorf("match name/fqn: %+v", m)
	}
	body := m["body"].(string)
	if !strings.Contains(body, "function handleClick") {
		t.Errorf("body missing function decl: %q", body)
	}
	if int(m["start_line"].(float64)) != 50 || int(m["end_line"].(float64)) != 80 {
		t.Errorf("line range: %+v", m)
	}
}

func TestGetSymbols_AmbiguousMatches_V715(t *testing.T) {
	seeds := []symbolSeed{
		{
			relPath: "src/Editor.tsx",
			content: editorTSXContent(),
			nodes: []nodeSeed{
				{
					id: 1, kind: "function", name: "handleClick", fqn: "handleClick",
					startLine: 50, endLine: 80, language: "typescript",
				},
				{
					id: 2, kind: "method", name: "handleClick", fqn: "Editor.handleClick",
					startLine: 200, endLine: 200, language: "typescript",
				},
			},
		},
	}
	f := newGetSymbolsFixture(t, seeds, nil, defaultGetSymbolsOpts())
	res := callTool(t, f.s, "get_symbols", map[string]any{
		"project_root": f.root,
		"requests": []map[string]any{
			{"file": "src/Editor.tsx", "name": "handleClick"},
		},
	})
	r0 := res["results"].([]any)[0].(map[string]any)
	matches := r0["matches"].([]any)
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}
	// V7-15 ranking: start_line ASC → function (50) before method (200).
	if matches[0].(map[string]any)["fqn"] != "handleClick" ||
		matches[1].(map[string]any)["fqn"] != "Editor.handleClick" {
		t.Errorf("V7-15 ranking wrong: %+v", matches)
	}
	if amb, _ := r0["ambiguous"].(bool); !amb {
		t.Errorf("expected ambiguous=true, got %+v", r0)
	}
	hint, _ := r0["disambiguation_hint"].(string)
	if !strings.Contains(hint, "fqn") || !strings.Contains(hint, "handleClick") {
		t.Errorf("disambiguation_hint missing recipe: %q", hint)
	}
}

func TestGetSymbols_FQNDisambiguation(t *testing.T) {
	seeds := []symbolSeed{
		{
			relPath: "src/Editor.tsx",
			content: editorTSXContent(),
			nodes: []nodeSeed{
				{
					id: 1, kind: "function", name: "handleClick", fqn: "handleClick",
					startLine: 50, endLine: 80, language: "typescript",
				},
				{
					id: 2, kind: "method", name: "handleClick", fqn: "Editor.handleClick",
					startLine: 200, endLine: 200, language: "typescript",
				},
			},
		},
	}
	f := newGetSymbolsFixture(t, seeds, nil, defaultGetSymbolsOpts())
	res := callTool(t, f.s, "get_symbols", map[string]any{
		"project_root": f.root,
		"requests": []map[string]any{
			{"file": "src/Editor.tsx", "fqn": "Editor.handleClick"},
		},
	})
	r0 := res["results"].([]any)[0].(map[string]any)
	matches := r0["matches"].([]any)
	if len(matches) != 1 || matches[0].(map[string]any)["fqn"] != "Editor.handleClick" {
		t.Errorf("fqn-pinned match wrong: %+v", matches)
	}
	if amb, _ := r0["ambiguous"].(bool); amb {
		t.Errorf("ambiguous should NOT fire when fqn pins the match")
	}
}

func TestGetSymbols_KindFilter(t *testing.T) {
	seeds := []symbolSeed{
		{
			relPath: "src/Editor.tsx",
			content: editorTSXContent(),
			nodes: []nodeSeed{
				{
					id: 1, kind: "function", name: "handleClick", fqn: "handleClick",
					startLine: 50, endLine: 80, language: "typescript",
				},
				{
					id: 2, kind: "class", name: "handleClick", fqn: "handleClickClass",
					startLine: 120, endLine: 200, language: "typescript",
				},
			},
		},
	}
	f := newGetSymbolsFixture(t, seeds, nil, defaultGetSymbolsOpts())
	res := callTool(t, f.s, "get_symbols", map[string]any{
		"project_root": f.root,
		"requests": []map[string]any{
			{"file": "src/Editor.tsx", "name": "handleClick", "kind": "function"},
		},
	})
	matches := res["results"].([]any)[0].(map[string]any)["matches"].([]any)
	if len(matches) != 1 || matches[0].(map[string]any)["kind"] != "function" {
		t.Errorf("kind filter: got %+v", matches)
	}
}

func TestGetSymbols_DiscoveryMode_OmitsBody(t *testing.T) {
	seeds := []symbolSeed{
		{
			relPath: "src/Editor.tsx",
			content: editorTSXContent(),
			nodes: []nodeSeed{
				{
					id: 1, kind: "function", name: "handleClick", fqn: "handleClick",
					startLine: 50, endLine: 80, language: "typescript",
				},
				{
					id: 2, kind: "class", name: "Editor", fqn: "Editor",
					startLine: 120, endLine: 240, language: "typescript",
				},
			},
		},
	}
	f := newGetSymbolsFixture(t, seeds, nil, defaultGetSymbolsOpts())
	res := callTool(t, f.s, "get_symbols", map[string]any{
		"project_root": f.root,
		"requests": []map[string]any{
			{"file": "src/Editor.tsx"},
		},
	})
	matches := res["results"].([]any)[0].(map[string]any)["matches"].([]any)
	if len(matches) != 2 {
		t.Fatalf("discovery: got %d matches, want 2", len(matches))
	}
	for _, m := range matches {
		mm := m.(map[string]any)
		if body, ok := mm["body"]; ok && body != "" {
			t.Errorf("discovery mode should omit body, got %q", body)
		}
		// Metadata still populated.
		if mm["name"] == "" || mm["fqn"] == "" || mm["kind"] == "" {
			t.Errorf("discovery match missing metadata: %+v", mm)
		}
	}
}

func TestGetSymbols_IncludeRelations(t *testing.T) {
	seeds := []symbolSeed{
		{
			relPath: "src/Editor.tsx",
			content: editorTSXContent(),
			nodes: []nodeSeed{
				{
					id: 1, kind: "function", name: "handleClick", fqn: "handleClick",
					startLine: 50, endLine: 80, language: "typescript",
				},
				{
					id: 2, kind: "class", name: "Editor", fqn: "Editor",
					startLine: 120, endLine: 240, language: "typescript",
				},
				{
					id: 3, kind: "method", name: "render", fqn: "Editor.render",
					startLine: 200, endLine: 220, language: "typescript",
				},
			},
		},
	}
	// Editor.render → handleClick (call edge). handleClick called by render.
	edges := []edgeSeed{
		{sourceID: 3, targetID: 1, kind: "CALLS"},
		{sourceID: 2, targetID: 1, kind: "CALLS"},
	}
	f := newGetSymbolsFixture(t, seeds, edges, defaultGetSymbolsOpts())
	res := callTool(t, f.s, "get_symbols", map[string]any{
		"project_root": f.root,
		"requests": []map[string]any{
			{"file": "src/Editor.tsx", "name": "handleClick", "include_relations": true},
		},
	})
	m := res["results"].([]any)[0].(map[string]any)["matches"].([]any)[0].(map[string]any)
	if cc, _ := m["callers_count"].(float64); int(cc) != 2 {
		t.Errorf("callers_count: got %v want 2", m["callers_count"])
	}
	if cl, _ := m["callees_count"].(float64); int(cl) != 0 {
		t.Errorf("callees_count: got %v want 0", m["callees_count"])
	}
	callers, _ := m["callers"].([]any)
	if len(callers) != 2 {
		t.Errorf("callers list len: got %d want 2", len(callers))
	}
}

func TestGetSymbols_BatchedMixedResults(t *testing.T) {
	seeds := []symbolSeed{
		{
			relPath: "src/Editor.tsx",
			content: editorTSXContent(),
			nodes: []nodeSeed{
				{
					id: 1, kind: "function", name: "handleClick", fqn: "handleClick",
					startLine: 50, endLine: 80, language: "typescript",
				},
			},
		},
	}
	f := newGetSymbolsFixture(t, seeds, nil, defaultGetSymbolsOpts())
	// A genuinely-absolute, existing path OUTSIDE the project root, built
	// in a separate temp dir. A hardcoded POSIX literal like "/etc/passwd"
	// is not absolute on Windows (filepath.IsAbs needs a drive letter), so
	// it would be joined under the root and resolve to "file not found"
	// instead of the intended "outside project_root" denial. Mirrors
	// TestGetFile_Denial_OutsideRoot / TestGetRelations_PathDenied.
	outside := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(outside, []byte("nope\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := callTool(t, f.s, "get_symbols", map[string]any{
		"project_root": f.root,
		"requests": []map[string]any{
			{"file": "src/Editor.tsx", "name": "handleClick"},  // exists
			{"file": "src/Editor.tsx", "name": "doesNotExist"}, // miss
			{"file": outside, "name": "x"},                     // path denial
		},
	})
	if ok, _ := res["ok"].(bool); !ok {
		t.Errorf("top-level ok should stay true on mixed batch, got %+v", res)
	}
	results := res["results"].([]any)
	if len(results) != 3 {
		t.Fatalf("results len: got %d want 3", len(results))
	}
	// Result 0: success
	if !results[0].(map[string]any)["ok"].(bool) {
		t.Errorf("result[0] should be ok=true")
	}
	// Result 1: ok=true, empty matches, reason "symbol not found"
	r1 := results[1].(map[string]any)
	if !r1["ok"].(bool) {
		t.Errorf("result[1] ok should stay true (miss is not denial)")
	}
	if len(r1["matches"].([]any)) != 0 {
		t.Errorf("result[1] matches should be empty")
	}
	if !strings.Contains(r1["reason"].(string), "not found") {
		t.Errorf("result[1] reason: %q", r1["reason"])
	}
	// Result 2: ok=false (path denial)
	r2 := results[2].(map[string]any)
	if r2["ok"].(bool) {
		t.Errorf("result[2] should be ok=false (path denial)")
	}
	if !strings.Contains(r2["reason"].(string), "outside project_root") {
		t.Errorf("result[2] reason: %q", r2["reason"])
	}
}

func TestGetSymbols_IndexUnavailable(t *testing.T) {
	// Build a fixture with an unavailable code index using New()
	// directly with codeintel.Unavailable().
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "obs.db")
	database, _ := db.Open(context.Background(), db.Options{Path: dbPath})
	t.Cleanup(func() { database.Close() })

	auditW := audit.NewSQLWriter(database, slog.New(slog.NewTextHandler(io.Discard, nil)), audit.SQLWriterOptions{
		FlushInterval: 10 * time.Millisecond,
	})
	t.Cleanup(func() { _ = auditW.Close() })

	root := filepath.Join(tmp, "proj")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "x.ts"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	s, _ := New(Options{
		DB:                database,
		ServerName:        "test",
		ServerVersion:     "0",
		CodeIntel:         codeintel.Unavailable(),
		AuditWriter:       auditW,
		GetSymbolsEnabled: true,
		GetSymbols:        defaultGetSymbolsOpts(),
	})
	res := callTool(t, s, "get_symbols", map[string]any{
		"project_root": root,
		"requests":     []map[string]any{{"file": "x.ts", "name": "anything"}},
	})
	if deg, _ := res["degraded"].(bool); !deg {
		t.Errorf("expected top-level degraded=true, got %+v", res)
	}
	r0 := res["results"].([]any)[0].(map[string]any)
	if deg, _ := r0["degraded"].(bool); !deg {
		t.Errorf("expected per-result degraded=true, got %+v", r0)
	}
	// V7-17: envelope warnings should include index_unavailable.
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

// TestGetSymbols_RegexFallback_Unavailable (V7-17 item 2) pins that
// index-unavailable requests now return regex-derived matches
// instead of empty results. The matches carry degraded=true and the
// envelope warnings list includes index_unavailable.
func TestGetSymbols_RegexFallback_Unavailable(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "obs.db")
	database, _ := db.Open(context.Background(), db.Options{Path: dbPath})
	t.Cleanup(func() { database.Close() })

	auditW := audit.NewSQLWriter(database, slog.New(slog.NewTextHandler(io.Discard, nil)), audit.SQLWriterOptions{
		FlushInterval: 10 * time.Millisecond,
	})
	t.Cleanup(func() { _ = auditW.Close() })

	root := filepath.Join(tmp, "proj")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `import React from "react";
export function handleClick(e: MouseEvent) {}
export class Editor {}
`
	if err := os.WriteFile(filepath.Join(root, "Editor.tsx"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	s, _ := New(Options{
		DB:                database,
		ServerName:        "test",
		ServerVersion:     "0",
		CodeIntel:         codeintel.Unavailable(),
		AuditWriter:       auditW,
		GetSymbolsEnabled: true,
		GetSymbols:        defaultGetSymbolsOpts(),
	})
	res := callTool(t, s, "get_symbols", map[string]any{
		"project_root": root,
		"requests": []map[string]any{
			{"file": "Editor.tsx", "name": "handleClick"},
		},
	})
	if deg, _ := res["degraded"].(bool); !deg {
		t.Errorf("expected top-level degraded=true")
	}
	r0 := res["results"].([]any)[0].(map[string]any)
	matches := r0["matches"].([]any)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match from regex fallback, got %d (full: %v)", len(matches), r0)
	}
	m := matches[0].(map[string]any)
	if m["name"] != "handleClick" {
		t.Errorf("match name: got %v, want handleClick", m["name"])
	}
	if m["kind"] != "function" {
		t.Errorf("match kind: got %v, want function", m["kind"])
	}
	if m["language"] != "typescript" {
		t.Errorf("match language: got %v, want typescript", m["language"])
	}
}

// TestGetSymbols_RegexFallback_UnsupportedLanguage pins the
// fallback's honest "I don't know" path: a .csv file under an
// unavailable index returns empty matches + the explicit
// regex_fallback_language_unsupported warning.
func TestGetSymbols_RegexFallback_UnsupportedLanguage(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "obs.db")
	database, _ := db.Open(context.Background(), db.Options{Path: dbPath})
	t.Cleanup(func() { database.Close() })

	auditW := audit.NewSQLWriter(database, slog.New(slog.NewTextHandler(io.Discard, nil)), audit.SQLWriterOptions{
		FlushInterval: 10 * time.Millisecond,
	})
	t.Cleanup(func() { _ = auditW.Close() })

	root := filepath.Join(tmp, "proj")
	_ = os.MkdirAll(root, 0o755)
	_ = os.WriteFile(filepath.Join(root, "data.csv"), []byte("a,b,c\n1,2,3\n"), 0o600)

	opts := defaultGetSymbolsOpts()
	opts.AllowExtensions = []string{"csv"}
	s, _ := New(Options{
		DB:                database,
		ServerName:        "test",
		ServerVersion:     "0",
		CodeIntel:         codeintel.Unavailable(),
		AuditWriter:       auditW,
		GetSymbolsEnabled: true,
		GetSymbols:        opts,
	})
	res := callTool(t, s, "get_symbols", map[string]any{
		"project_root": root,
		"requests":     []map[string]any{{"file": "data.csv", "name": "anything"}},
	})
	r0 := res["results"].([]any)[0].(map[string]any)
	matches := r0["matches"].([]any)
	if len(matches) != 0 {
		t.Errorf("expected empty matches for unsupported language, got %d", len(matches))
	}
	warnings, _ := res["warnings"].([]any)
	found := false
	for _, w := range warnings {
		if w == "regex_fallback_language_unsupported" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected regex_fallback_language_unsupported in warnings, got %v", warnings)
	}
}

// TestGetSymbols_DriftSignal (V7-17 item 4) pins the stale-index
// path. The index places handleClick at line 50 but the live file has
// it at a different line; Stale() fires because we bump the file's
// mtime. The response includes IndexLines (the index) + LiveLines
// (regex) so the agent sees the drift.
func TestGetSymbols_DriftSignal(t *testing.T) {
	seeds := []symbolSeed{
		{
			relPath: "src/Editor.tsx",
			content: `import React from "react";

export class Editor extends React.Component {}

export function unrelated() {}

export function handleClick(e: MouseEvent) {}
`,
			nodes: []nodeSeed{
				{
					id: 1, kind: "function", name: "handleClick", fqn: "handleClick",
					startLine: 50, endLine: 80, language: "typescript",
				},
			},
		},
	}
	f := newGetSymbolsFixture(t, seeds, nil, defaultGetSymbolsOpts())

	// Bump the file mtime to far-future so Stale() triggers
	// (slack window = 5s; 1h is well past).
	filePath := filepath.Join(f.root, "src/Editor.tsx")
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(filePath, future, future); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	res := callTool(t, f.s, "get_symbols", map[string]any{
		"project_root": f.root,
		"requests":     []map[string]any{{"file": "src/Editor.tsx", "name": "handleClick"}},
	})
	// Envelope-level: warnings should include index_stale.
	warnings, _ := res["warnings"].([]any)
	found := false
	for _, w := range warnings {
		if w == "index_stale" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected index_stale in warnings, got %v", warnings)
	}

	r0 := res["results"].([]any)[0].(map[string]any)
	if deg, _ := r0["degraded"].(bool); !deg {
		t.Errorf("expected per-result degraded=true")
	}
	matches := r0["matches"].([]any)
	if len(matches) != 1 {
		t.Fatalf("expected 1 drift match, got %d", len(matches))
	}
	m := matches[0].(map[string]any)
	idxLines, _ := m["index_lines"].(map[string]any)
	if idxLines == nil {
		t.Fatalf("missing index_lines: %v", m)
	}
	if int(idxLines["start"].(float64)) != 50 {
		t.Errorf("IndexLines.Start: got %v, want 50 (index value)", idxLines["start"])
	}
	liveLines, _ := m["live_lines"].(map[string]any)
	if liveLines == nil {
		t.Fatalf("missing live_lines: %v", m)
	}
	if int(liveLines["start"].(float64)) <= 0 {
		t.Errorf("LiveLines.Start: got %v, want positive", liveLines["start"])
	}
	// The live position MUST differ from index — that's the whole
	// point of the drift signal.
	if int(idxLines["start"].(float64)) == int(liveLines["start"].(float64)) {
		t.Errorf("IndexLines and LiveLines identical — drift signal degenerate")
	}
}

// TestGetSymbols_IncludeNearby (V7-17 item 1) pins the opt-in
// neighbor list: include_nearby: 2 returns up to 2 symbols before
// + 2 after by start_line. Anchor itself is excluded.
func TestGetSymbols_IncludeNearby(t *testing.T) {
	seeds := []symbolSeed{
		{
			relPath: "src/Editor.tsx",
			content: editorTSXContent(),
			nodes: []nodeSeed{
				// 5 symbols, anchor is the middle one (Editor at 220).
				{id: 1, kind: "function", name: "handleClick", fqn: "handleClick", startLine: 140, endLine: 187, language: "typescript"},
				{id: 2, kind: "function", name: "handleKeyDown", fqn: "handleKeyDown", startLine: 158, endLine: 200, language: "typescript"},
				{id: 3, kind: "class", name: "Editor", fqn: "Editor", startLine: 220, endLine: 350, language: "typescript"},
				{id: 4, kind: "function", name: "useEffect", fqn: "useEffect", startLine: 256, endLine: 270, language: "typescript"},
				{id: 5, kind: "function", name: "useMemo", fqn: "useMemo", startLine: 288, endLine: 300, language: "typescript"},
			},
		},
	}
	f := newGetSymbolsFixture(t, seeds, nil, defaultGetSymbolsOpts())

	res := callTool(t, f.s, "get_symbols", map[string]any{
		"project_root": f.root,
		"requests": []map[string]any{
			{"file": "src/Editor.tsx", "name": "Editor", "include_nearby": 2},
		},
	})
	r0 := res["results"].([]any)[0].(map[string]any)
	matches := r0["matches"].([]any)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	m := matches[0].(map[string]any)
	nearby, ok := m["nearby_symbols"].([]any)
	if !ok {
		t.Fatalf("missing nearby_symbols: %v", m)
	}
	// Editor sits at idx 2 (sorted by start_line ASC); include_nearby:2
	// → 2 before (handleClick, handleKeyDown) + 2 after (useEffect, useMemo) = 4.
	if len(nearby) != 4 {
		t.Errorf("got %d nearby, want 4: %v", len(nearby), nearby)
	}
	names := map[string]bool{}
	for _, n := range nearby {
		nm := n.(map[string]any)
		names[nm["name"].(string)] = true
	}
	for _, want := range []string{"handleClick", "handleKeyDown", "useEffect", "useMemo"} {
		if !names[want] {
			t.Errorf("missing nearby symbol %q (got %v)", want, names)
		}
	}
	// Anchor itself MUST NOT appear in its own nearby list.
	if names["Editor"] {
		t.Errorf("anchor Editor leaked into its own nearby list")
	}
}

// TestGetSymbols_IncludeNearby_DefaultOmitted pins the BC: when
// include_nearby is unset or 0, the nearby_symbols field is
// omitted from the JSON entirely.
func TestGetSymbols_IncludeNearby_DefaultOmitted(t *testing.T) {
	seeds := []symbolSeed{
		{
			relPath: "src/Editor.tsx",
			content: editorTSXContent(),
			nodes: []nodeSeed{
				{id: 1, kind: "function", name: "handleClick", fqn: "handleClick", startLine: 140, endLine: 187, language: "typescript"},
				{id: 2, kind: "class", name: "Editor", fqn: "Editor", startLine: 220, endLine: 350, language: "typescript"},
			},
		},
	}
	f := newGetSymbolsFixture(t, seeds, nil, defaultGetSymbolsOpts())

	res := callTool(t, f.s, "get_symbols", map[string]any{
		"project_root": f.root,
		"requests":     []map[string]any{{"file": "src/Editor.tsx", "name": "handleClick"}},
	})
	r0 := res["results"].([]any)[0].(map[string]any)
	m := r0["matches"].([]any)[0].(map[string]any)
	if _, present := m["nearby_symbols"]; present {
		t.Errorf("nearby_symbols leaked into default response: %v", m)
	}
}

func TestGetSymbols_AuditWrittenPerRequest(t *testing.T) {
	seeds := []symbolSeed{
		{
			relPath: "src/Editor.tsx",
			content: editorTSXContent(),
			nodes: []nodeSeed{
				{
					id: 1, kind: "function", name: "handleClick", fqn: "handleClick",
					startLine: 50, endLine: 80, language: "typescript",
				},
			},
		},
	}
	f := newGetSymbolsFixture(t, seeds, nil, defaultGetSymbolsOpts())
	_ = callTool(t, f.s, "get_symbols", map[string]any{
		"project_root": f.root,
		"session_id":   "sess-audit",
		"requests": []map[string]any{
			{"file": "src/Editor.tsx", "name": "handleClick"},
			{"file": "src/Editor.tsx", "name": "missing"},
		},
	})
	if got := auditRowCountAtLeast(t, f.auditDB, 2,
		"tool_name = 'get_symbols' AND session_id = ?", "sess-audit"); got != 2 {
		t.Errorf("expected 2 audit rows, got %d", got)
	}
}

func TestGetSymbols_PathSafetyDeniesEnv(t *testing.T) {
	seeds := []symbolSeed{
		{
			relPath: ".env",
			content: "SECRET=1\n",
			nodes:   nil, // the index wouldn't cover .env anyway
		},
	}
	opts := defaultGetSymbolsOpts()
	opts.DenyPaths = []string{".env*"}
	opts.AllowExtensions = nil // skip extension check to isolate deny-glob
	f := newGetSymbolsFixture(t, seeds, nil, opts)
	res := callTool(t, f.s, "get_symbols", map[string]any{
		"project_root": f.root,
		"requests":     []map[string]any{{"file": ".env", "name": "x"}},
	})
	r0 := res["results"].([]any)[0].(map[string]any)
	if r0["ok"].(bool) {
		t.Errorf(".env should be denied")
	}
	if !strings.Contains(r0["reason"].(string), "deny pattern") {
		t.Errorf("expected deny-pattern reason, got %q", r0["reason"])
	}
}

func TestGetSymbols_TooManyRequests(t *testing.T) {
	f := newGetSymbolsFixture(t, nil, nil, defaultGetSymbolsOpts())
	requests := make([]map[string]any, 26)
	for i := range requests {
		requests[i] = map[string]any{"file": "x.ts", "name": "f"}
	}
	errText := callToolExpectError(t, f.s, "get_symbols", map[string]any{
		"project_root": f.root,
		"requests":     requests,
	})
	if !strings.Contains(errText, "exceeds max 25") {
		t.Errorf("expected max-25 error, got %q", errText)
	}
}

func TestGetSymbols_NotRegisteredWhenDisabled(t *testing.T) {
	tmp := t.TempDir()
	database, _ := db.Open(context.Background(), db.Options{Path: filepath.Join(tmp, "obs.db")})
	t.Cleanup(func() { database.Close() })
	s, _ := New(Options{
		DB: database, ServerName: "test", ServerVersion: "0",
		GetSymbolsEnabled: false,
	})
	resp := rpcCall(t, s, "tools/list", 1, nil)
	for _, raw := range resp["result"].(map[string]any)["tools"].([]any) {
		if raw.(map[string]any)["name"] == "get_symbols" {
			t.Errorf("get_symbols registered even though GetSymbolsEnabled=false")
		}
	}
}

func TestGetSymbols_RegisteredWhenEnabledEvenWithoutIndex(t *testing.T) {
	tmp := t.TempDir()
	database, _ := db.Open(context.Background(), db.Options{Path: filepath.Join(tmp, "obs.db")})
	t.Cleanup(func() { database.Close() })
	s, _ := New(Options{
		DB: database, ServerName: "test", ServerVersion: "0",
		GetSymbolsEnabled: true,
		// Intentionally no CodeIntel provider — must still register
		// (degrades at call time, not at registration time).
	})
	resp := rpcCall(t, s, "tools/list", 1, nil)
	found := false
	for _, raw := range resp["result"].(map[string]any)["tools"].([]any) {
		if raw.(map[string]any)["name"] == "get_symbols" {
			found = true
		}
	}
	if !found {
		t.Errorf("get_symbols missing from tools/list when enabled but code index missing")
	}
}

func TestGetSymbols_BodyCapTruncation(t *testing.T) {
	// 25 symbols × ~10KB body each = 250KB → exceeds 200KB cap.
	// Build a 10KB-per-symbol file (each "symbol" is its own 100-line
	// chunk in the file, index entries pointing at them).
	var sb strings.Builder
	for i := 1; i <= 2500; i++ {
		sb.WriteString(strings.Repeat("x", 100)) // 100 char line
		sb.WriteString("\n")
	}
	seed := symbolSeed{
		relPath: "big.tsx",
		content: sb.String(),
	}
	for i := 0; i < 25; i++ {
		seed.nodes = append(seed.nodes, nodeSeed{
			id:        int64(i + 1),
			kind:      "function",
			name:      fmt.Sprintf("f%d", i),
			fqn:       fmt.Sprintf("f%d", i),
			startLine: i*100 + 1,
			endLine:   (i + 1) * 100,
			language:  "typescript",
		})
	}
	f := newGetSymbolsFixture(t, []symbolSeed{seed}, nil, defaultGetSymbolsOpts())
	// Discovery + include_body=true forces full bodies.
	includeBody := true
	res := callTool(t, f.s, "get_symbols", map[string]any{
		"project_root": f.root,
		"requests": []map[string]any{
			{"file": "big.tsx", "include_body": includeBody},
		},
	})
	if trunc, _ := res["truncated"].(bool); !trunc {
		t.Errorf("expected top-level truncated=true, got %+v", res)
	}
	matches := res["results"].([]any)[0].(map[string]any)["matches"].([]any)
	// Earlier matches should have body; later ones flagged truncated.
	someTruncated := false
	for _, m := range matches {
		if bt, _ := m.(map[string]any)["body_truncated"].(bool); bt {
			someTruncated = true
		}
	}
	if !someTruncated {
		t.Errorf("expected some per-match body_truncated=true")
	}
}
