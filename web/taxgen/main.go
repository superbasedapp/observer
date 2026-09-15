// Command taxgen emits the shared/lib/actiontax.gen.* artifacts — the
// TypeScript mirror of the canonical tool/MCP taxonomy owned by
// internal/tooltax.
//
// # Why this exists (WP-T2 of
// docs/plans/tool-taxonomy-standardization-plan-2026-07-31.md §1)
//
// The dashboard has carried its OWN action-type taxonomy since before
// there was a Go one: web/src/lib/actions.ts hand-maintained a 34-row
// ACTION_REGISTRY (9 categories) plus its own `mcp__server__tool`
// parser. The plan's §0 measurement found that de-facto frontend
// taxonomy already drifting from the Go side — different category sets,
// and an MCP parser that disagreed with Go on the degenerate
// `mcp____tool` shape.
//
// WP-T1 made internal/tooltax the one owner. This generator is what
// keeps the dashboard ON that owner: the category list, the
// action-type → {category, label} registry and the MCP parse rules are
// emitted from tooltax, and actions.ts reads them instead of declaring
// them.
//
// # What it writes
//
// Three files, all into one directory (-outdir, default shared/lib):
//
//   - actiontax.gen.json — the DATA: categories, the fallback category,
//     the action-type → {category, label} registry, the MCP parse rules.
//   - actiontax.gen.ts — the TYPES: the ActionCategory literal union.
//     actions.ts imports it and keys its colour map off it, so a
//     category added in Go without a colour is a tsc COMPILE error
//     rather than a silent meta-gray chip.
//   - actiontax.vectors.gen.json — test VECTORS for the real TypeScript
//     parser, with Go as the oracle. scripts/verify-taxonomy-ts.sh
//     compiles the actual actions.ts and asserts mcpIdentity over every
//     vector; that — not any Go-side reference implementation — is the
//     cross-language parity gate. A Go re-implementation of the TS
//     parser proves only that Go agrees with Go.
//
// # What is deliberately NOT emitted
//
// The ~500-row (tool, native) table, and Surface. The browser never
// resolves a raw native tool name — the adapters did that at ingest — so
// shipping the table would be dead bundle weight. Surface waits for
// WP-T5.
//
// # Determinism contract
//
// Generation is pure: no clock, no environment, no filesystem reads, no
// map iteration order (struct field order for the envelopes,
// encoding/json's sorted keys for the registry, literal slice order for
// the vectors). That is what makes the byte-diff drift gate
// (`make verify-taxonomy-build`) meaningful rather than flaky.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

// defaultOutDir is the directory holding the committed artifacts,
// relative to the repo root (the directory `make taxonomy-build` runs
// from). The gate points it at a scratch dir instead.
const defaultOutDir = "shared/lib"

// The generated file names. The generator owns the names; the caller
// only chooses the directory, so the drift gate cannot diff a subset by
// accident.
const (
	jsonName    = "actiontax.gen.json"
	typesName   = "actiontax.gen.ts"
	vectorsName = "actiontax.vectors.gen.json"
)

// probeUnregistered is a deliberately unregistered action type, used to
// READ the fallback category out of tooltax rather than re-declaring it.
const probeUnregistered = "\x00taxgen-probe-unregistered"

// mcpNote records the corpus decisions behind the MCP parse rules, so a
// reader of the generated file does not have to go find the plan.
const mcpNote = "Canonical MCP tool-name form is prefix + <server> + separator + <tool>. " +
	"On a display-normalised TARGET the colon form <server>:<tool> is also accepted " +
	"(emitted by the codex adapter; 151 rows in the 321,675-row corpus measured " +
	"2026-07-31). The third historical form <server>/<tool> is DROPPED: zero corpus " +
	"rows, and '/' is the path separator, so a path-shaped target would fabricate a " +
	"server name. A separator at an offset below separatorMinIndex is NOT a split " +
	"point — see internal/tooltax.MCPSeparatorMinIndex."

// The two oracle classes in the emitted vector file. A vector says which
// one produced its expectation, because they are not equally strong: the
// Go-oracle cases are DERIVED from tooltax.MCPIdentity at generation
// time, while the guard cases pin TypeScript-only presentation behaviour
// that has no Go counterpart at all (actions.ts also runs this parse
// against `target`, which for many adapters is a file path).
const (
	oracleGo      = "tooltax.MCPIdentity"
	oracleTSGuard = "ts-only-path-guard"
)

// vectorsNote is the emitted file's own explanation of the two classes.
const vectorsNote = "Test vectors for shared/lib/actions.ts::mcpIdentity, consumed by " +
	"scripts/verify-taxonomy-ts.sh (which COMPILES the real TypeScript and runs it). " +
	"oracle=\"" + oracleGo + "\" cases carry expectations DERIVED from the Go parser at " +
	"generation time — Go is the owner, TypeScript must agree. oracle=\"" + oracleTSGuard +
	"\" cases pin the path/URL guards on the colon form, which are a TypeScript-only " +
	"presentation extra with no Go counterpart: mcpIdentity also runs against `target`, " +
	"which is a file path for many adapters, and a mis-split there would invent a server " +
	"name in the Tools panel. A null `want` means mcpIdentity returns null for that row."

// categoryPattern is what a category must look like to be emitted into a
// TypeScript literal union. strconv.Quote would escape anything, but a
// category with punctuation in it is a mistake upstream, not something
// to render faithfully.
var categoryPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// doc is the generated JSON file's envelope. Field order here IS the key
// order in the output; do not reorder casually.
type doc struct {
	Generated generatedMeta `json:"generated"`
	// Categories is tooltax.Categories() — the canonical categories in
	// display order (concrete work first, then coordination, then noise).
	Categories []string `json:"categories"`
	// Surfaces is tooltax.Surfaces() — WHERE a tool lives (builtin / mcp
	// / orchestration / meta), in display order. Orthogonal to Categories
	// on purpose: cowork's `mcp__workspace__bash` is surface mcp but
	// category cmd. The dashboard renders /api/tools/breakdown's
	// by_surface histogram in THIS order rather than inventing one.
	Surfaces []string `json:"surfaces"`
	// FallbackCategory is the category an UNREGISTERED action type
	// resolves to, read out of tooltax.CategoryForActionType.
	FallbackCategory string `json:"fallbackCategory"`
	// ActionTypes is the canonical action-type registry, keyed by action
	// type. Emitted as a map so encoding/json sorts the keys for us.
	ActionTypes map[string]actionTypeMeta `json:"actionTypes"`
	// ToolCoverage is the per-adapter capture-depth honesty input (plan
	// §4): which canonical categories each tool's DECLARED native
	// vocabulary can express. Keyed by tool; a tool with no tooltax rows
	// is ABSENT rather than present-with-an-empty-list, so the dashboard
	// can distinguish "this adapter's capture is shallow" from "we have
	// not mapped this adapter yet" — the honest zero.
	//
	// This is the §7 "Surface waits for WP-T5" hook, and it is
	// deliberately the DERIVED per-tool category set, not the ~1,074-row
	// (tool, native) table: the browser never resolves a raw native tool
	// name (the adapters did that at ingest), so shipping the table would
	// be dead bundle weight. This is ~30 short string arrays.
	ToolCoverage map[string]toolCoverage `json:"toolCoverage"`
	// MCP carries the parse rules, not a parser: the TS side implements
	// the same three-line rule off these values.
	MCP mcpRules `json:"mcp"`
}

type generatedMeta struct {
	By         string `json:"by"`
	From       string `json:"from"`
	Output     string `json:"output"`
	Regenerate string `json:"regenerate"`
	Gate       string `json:"gate"`
	DoNotEdit  bool   `json:"doNotEdit"`
}

type actionTypeMeta struct {
	Category string `json:"category"`
	Label    string `json:"label"`
}

// toolCoverage is one tool's declared capture depth.
type toolCoverage struct {
	// Categories are the canonical categories this tool's declared
	// vocabulary can express, in Categories() display order.
	Categories []string `json:"categories"`
}

type mcpRules struct {
	Prefix            string `json:"prefix"`
	Separator         string `json:"separator"`
	SeparatorMinIndex int    `json:"separatorMinIndex"`
	TargetSeparator   string `json:"targetSeparator"`
	Note              string `json:"note"`
}

// artifact is one generated file. Name is a base name — the generator
// never picks a directory.
type artifact struct {
	Name string
	Data []byte
}

func main() {
	outDir := flag.String("outdir", defaultOutDir, "directory the generated files are written to")
	flag.Parse()

	arts, err := generateAll()
	if err != nil {
		log.Fatalf("taxgen: %v", err)
	}
	for _, a := range arts {
		if err := write(filepath.Join(*outDir, a.Name), a.Data); err != nil {
			log.Fatalf("taxgen: %v", err)
		}
	}
}

// generateAll builds every artifact, in a fixed order. Like generate()
// it is pure: no filesystem, no clock, no environment — which is what
// makes the drift gate meaningful.
func generateAll() ([]artifact, error) {
	data, err := generate()
	if err != nil {
		return nil, err
	}
	types, err := generateTypes()
	if err != nil {
		return nil, err
	}
	vectors, err := generateVectors()
	if err != nil {
		return nil, err
	}
	return []artifact{
		{Name: jsonName, Data: data},
		{Name: typesName, Data: types},
		{Name: vectorsName, Data: vectors},
	}, nil
}

// meta is the provenance block shared by both generated JSON files.
func meta() generatedMeta {
	return generatedMeta{
		By:         "web/taxgen",
		From:       "internal/tooltax",
		Output:     "shared/lib",
		Regenerate: "make taxonomy-build",
		Gate:       "make verify-taxonomy-build",
		DoNotEdit:  true,
	}
}

// generate builds the data file's bytes from internal/tooltax.
func generate() ([]byte, error) {
	types := tooltax.ActionTypes()
	if len(types) == 0 {
		return nil, fmt.Errorf("tooltax.ActionTypes() is empty — refusing to emit a vacuous registry")
	}
	registry := make(map[string]actionTypeMeta, len(types))
	for _, at := range types {
		m, ok := tooltax.MetaForActionType(at)
		if !ok {
			// ActionTypes() enumerates the registry, so this is
			// unreachable unless tooltax grows a second source of truth.
			return nil, fmt.Errorf("action type %q is enumerated but has no metadata", at)
		}
		if m.Label == "" || m.Category == "" {
			return nil, fmt.Errorf("action type %q has an empty category or label", at)
		}
		registry[at] = actionTypeMeta{Category: m.Category, Label: m.Label}
	}

	surfaces := tooltax.Surfaces()
	if len(surfaces) == 0 {
		return nil, fmt.Errorf("tooltax.Surfaces() is empty — refusing to emit a vacuous surface list")
	}
	surfaceNames := make([]string, 0, len(surfaces))
	for _, s := range surfaces {
		if s == "" {
			return nil, fmt.Errorf("tooltax.Surfaces() contains an empty surface")
		}
		surfaceNames = append(surfaceNames, string(s))
	}

	tools := tooltax.Tools()
	if len(tools) == 0 {
		return nil, fmt.Errorf("tooltax.Tools() is empty — refusing to emit a vacuous coverage map")
	}
	coverage := make(map[string]toolCoverage, len(tools))
	for _, tool := range tools {
		cats := tooltax.CategoriesForTool(tool)
		if len(cats) == 0 {
			// Tools() enumerates tools that HAVE rows, and every row
			// carries a category, so this is unreachable unless tooltax
			// grows a second source of truth.
			return nil, fmt.Errorf("tool %q has rows but expresses no category", tool)
		}
		coverage[tool] = toolCoverage{Categories: cats}
	}

	d := doc{
		Generated:        meta(),
		Categories:       tooltax.Categories(),
		Surfaces:         surfaceNames,
		FallbackCategory: tooltax.CategoryForActionType(probeUnregistered),
		ActionTypes:      registry,
		ToolCoverage:     coverage,
		MCP: mcpRules{
			Prefix:            tooltax.MCPPrefix,
			Separator:         tooltax.MCPSeparator,
			SeparatorMinIndex: tooltax.MCPSeparatorMinIndex,
			TargetSeparator:   tooltax.MCPTargetSeparator,
			Note:              mcpNote,
		},
	}
	return encodeJSON(d)
}

// typesHeader is the generated TypeScript file's preamble. It is a
// constant, not a template: nothing in it varies per run.
const typesHeader = `// Code generated by web/taxgen from internal/tooltax. DO NOT EDIT.
//
// Regenerate with ` + "`make taxonomy-build`" + `; the ` + "`taxonomy-build-drift`" + ` CI job
// (` + "`make verify-taxonomy-build`" + `) fails until the regenerated file is
// committed.
//
// This file carries the TYPES; actiontax.gen.json carries the data. The
// split exists so that a category added on the Go side is a COMPILE
// error in the dashboards rather than a silent meta-gray chip:
// shared/lib/actions.ts keys its CATEGORY_COLOR map on ActionCategory,
// so a new member with no --act-<category> colour fails ` + "`npm run typecheck`" + `.

/** The canonical action categories — tooltax.Categories(), in display
 * order (concrete work first, then coordination, then noise). */
`

// generateTypes builds shared/lib/actiontax.gen.ts: the ActionCategory
// literal union, generated from tooltax.Categories().
func generateTypes() ([]byte, error) {
	cats := tooltax.Categories()
	if len(cats) == 0 {
		return nil, fmt.Errorf("tooltax.Categories() is empty — refusing to emit an uninhabited union")
	}
	var buf bytes.Buffer
	buf.WriteString(typesHeader)
	buf.WriteString("export type ActionCategory =\n")
	for i, c := range cats {
		if !categoryPattern.MatchString(c) {
			return nil, fmt.Errorf("category %q is not a plain lower-snake identifier", c)
		}
		buf.WriteString("  | ")
		buf.WriteString(strconv.Quote(c))
		if i == len(cats)-1 {
			buf.WriteString(";")
		}
		buf.WriteString("\n")
	}
	return buf.Bytes(), nil
}

// identity is one expected {server, tool} pair. A nil *identity in a
// vector means mcpIdentity returns null.
type identity struct {
	Server string `json:"server"`
	Tool   string `json:"tool"`
}

// vectorRow is the row shape actions.ts::mcpIdentity accepts. All three
// keys are always emitted (null when unset) so the gate feeds the TS
// function exactly what the vector says, with no defaulting of its own.
type vectorRow struct {
	ActionType  *string `json:"action_type"`
	RawToolName *string `json:"raw_tool_name"`
	Target      *string `json:"target"`
}

type vectorCase struct {
	Name   string    `json:"name"`
	Why    string    `json:"why"`
	Oracle string    `json:"oracle"`
	Row    vectorRow `json:"row"`
	Want   *identity `json:"want"`
}

type vectorsDoc struct {
	Generated generatedMeta `json:"generated"`
	Note      string        `json:"note"`
	Cases     []vectorCase  `json:"cases"`
}

func strptr(s string) *string { return &s }

// goOracleNames are raw_tool_name inputs whose expectation is DERIVED
// from tooltax.MCPIdentity. With action_type unset, actions.ts::
// mcpIdentity is exactly the name parse: a name outside the `mcp__`
// namespace yields null (Go ok=false), and a name inside it yields the
// Go split verbatim — including both degenerate forms.
var goOracleNames = []struct{ name, why string }{
	{"mcp__observer__get_file", "canonical prefix + server + separator + tool"},
	{"mcp__observer__get_session_summary", "canonical, underscored tool name"},
	{"mcp__ide__executeCode", "canonical, camelCase tool name"},
	{"mcp__a__b__c", "multiple separators — the FIRST one splits"},
	{"mcp__server", "degenerate: no second separator"},
	{"mcp__server__", "degenerate: empty tool half"},
	{"mcp__", "degenerate: bare prefix"},
	{"mcp____tool", "THE divergence WP-T2 closed: separatorMinIndex makes this {\"__tool\",\"\"}, not {\"\",\"tool\"}"},
	{"mcp_notaprefix", "single underscore — not the namespace"},
	{"Read", "a builtin tool name"},
	{"", "empty name"},
	{" mcp__a__b", "leading space — MCPIdentity does not trim raw names"},
	{"node_repl:js", "colon form in raw_tool_name WITHOUT the mcp_call signal — not MCP"},
	{"observer/get_file", "the dropped slash form — never a split"},
}

// tsGuardCases pin the TypeScript-only path/URL guards on the colon
// form. They have no Go oracle by construction: tooltax.MCPIdentity does
// not accept the colon form at all, and tooltax.MCPIdentityFromTarget
// (which does) has no path guards because it never runs against a
// display target that might be a file path. Expectations are stated
// here, on the Go side, so the gate is a contract and not a snapshot of
// whatever the TypeScript happens to do.
var tsGuardCases = []vectorCase{
	{
		Name:   "colon form in raw_tool_name",
		Why:    "codex/copilot-cli emit <server>:<tool>; the mcp_call signal is what admits it",
		Row:    vectorRow{ActionType: strptr("mcp_call"), RawToolName: strptr("node_repl:js")},
		Want:   &identity{Server: "node_repl", Tool: "js"},
		Oracle: oracleTSGuard,
	},
	{
		Name:   "colon form in target",
		Why:    "cursor/codex/cline carry the identity in target, not raw_tool_name",
		Row:    vectorRow{ActionType: strptr("mcp_call"), Target: strptr("observer:get_session_summary")},
		Want:   &identity{Server: "observer", Tool: "get_session_summary"},
		Oracle: oracleTSGuard,
	},
	{
		Name:   "windows path with a backslash",
		Why:    "C:\\repo\\file.txt must not split into server=C",
		Row:    vectorRow{ActionType: strptr("mcp_call"), Target: strptr(`C:\repo\file.txt`)},
		Want:   &identity{Server: `C:\repo\file.txt`, Tool: ""},
		Oracle: oracleTSGuard,
	},
	{
		Name:   "windows path with a forward-slash drive",
		Why:    "C:/repo/file.txt is the same path with the other separator (finding 3)",
		Row:    vectorRow{ActionType: strptr("mcp_call"), Target: strptr("C:/repo/file.txt")},
		Want:   &identity{Server: "C:/repo/file.txt", Tool: ""},
		Oracle: oracleTSGuard,
	},
	{
		Name:   "lower-case drive letter",
		Why:    "the drive-letter guard is case-insensitive",
		Row:    vectorRow{ActionType: strptr("mcp_call"), Target: strptr("c:/Users/me/file.txt")},
		Want:   &identity{Server: "c:/Users/me/file.txt", Tool: ""},
		Oracle: oracleTSGuard,
	},
	{
		Name:   "posix absolute path containing a colon",
		Why:    "/tmp/socket:query must not split into server=/tmp/socket (finding 3)",
		Row:    vectorRow{ActionType: strptr("mcp_call"), Target: strptr("/tmp/socket:query")},
		Want:   &identity{Server: "/tmp/socket:query", Tool: ""},
		Oracle: oracleTSGuard,
	},
	{
		Name:   "url",
		Why:    "https://example.com/x — the // guard",
		Row:    vectorRow{ActionType: strptr("mcp_call"), Target: strptr("https://example.com/x")},
		Want:   &identity{Server: "https://example.com/x", Tool: ""},
		Oracle: oracleTSGuard,
	},
	{
		Name:   "prose with a colon",
		Why:    "a server half containing a space is prose, not an identity",
		Row:    vectorRow{ActionType: strptr("mcp_call"), Target: strptr("meeting note: follow up")},
		Want:   &identity{Server: "meeting note: follow up", Tool: ""},
		Oracle: oracleTSGuard,
	},
	{
		Name:   "trailing colon",
		Why:    "an empty tool half is not a split",
		Row:    vectorRow{ActionType: strptr("mcp_call"), Target: strptr("server:")},
		Want:   &identity{Server: "server:", Tool: ""},
		Oracle: oracleTSGuard,
	},
	{
		Name:   "leading colon",
		Why:    "an empty server half is not a split",
		Row:    vectorRow{ActionType: strptr("mcp_call"), Target: strptr(":tool")},
		Want:   &identity{Server: ":tool", Tool: ""},
		Oracle: oracleTSGuard,
	},
	{
		Name:   "mcp_call with a bare name",
		Why:    "cowork emits bare targets; the bare name becomes the server",
		Row:    vectorRow{ActionType: strptr("mcp_call"), RawToolName: strptr("deep-research")},
		Want:   &identity{Server: "deep-research", Tool: ""},
		Oracle: oracleTSGuard,
	},
	{
		Name: "mcp_call with the canonical name AND a path target",
		Why:  "the name parse wins; target is never consulted",
		Row: vectorRow{
			ActionType:  strptr("mcp_call"),
			RawToolName: strptr("mcp__observer__get_file"),
			Target:      strptr("C:/repo/file.txt"),
		},
		Want:   &identity{Server: "observer", Tool: "get_file"},
		Oracle: oracleTSGuard,
	},
	{
		Name:   "non-mcp row with a colon in the target",
		Why:    "no mcp_call signal and no mcp__ name — not an MCP row at all",
		Row:    vectorRow{ActionType: strptr("read_file"), Target: strptr("observer:get_file")},
		Want:   nil,
		Oracle: oracleTSGuard,
	},
	{
		Name:   "empty row",
		Why:    "nothing to identify",
		Row:    vectorRow{},
		Want:   nil,
		Oracle: oracleTSGuard,
	},
}

// generateVectors builds the test-vector file the real-TypeScript gate
// consumes.
func generateVectors() ([]byte, error) {
	cases := make([]vectorCase, 0, len(goOracleNames)+len(tsGuardCases))
	for _, n := range goOracleNames {
		server, tool, ok := tooltax.MCPIdentity(n.name)
		var want *identity
		if ok {
			want = &identity{Server: server, Tool: tool}
		}
		cases = append(cases, vectorCase{
			Name:   "raw_tool_name=" + strconv.Quote(n.name),
			Why:    n.why,
			Oracle: oracleGo,
			Row:    vectorRow{RawToolName: strptr(n.name)},
			Want:   want,
		})
	}
	cases = append(cases, tsGuardCases...)

	seen := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		if _, dup := seen[c.Name]; dup {
			return nil, fmt.Errorf("duplicate vector name %q", c.Name)
		}
		seen[c.Name] = struct{}{}
	}
	return encodeJSON(vectorsDoc{Generated: meta(), Note: vectorsNote, Cases: cases})
}

// encodeJSON is the one JSON shape both generated data files use:
// 2-space indent, no HTML escaping (the taxonomy has no HTML in it, and
// escaping would make the emitted bytes depend on incidental
// punctuation), exactly one trailing newline.
func encodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}
	// json.Encoder.Encode already terminates with exactly one newline.
	return buf.Bytes(), nil
}

// write puts the bytes at path, creating the parent directory when the
// gate points it at a scratch location.
func write(path string, data []byte) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}
	//nolint:gosec // G306: a committed, publicly-distributed source artifact; world-readable is intended.
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
