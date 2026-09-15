package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/codeintel"
	"github.com/marmutapp/superbased-observer/internal/mcp/audit"
)

// -----------------------------------------------------------------------------
// get_relations — V7-12 retrieval-surface MCP tool (v1.7.10, third of four).
//
// Native code-index graph traversal. Single anchor, single relation
// kind (callers | callees | contains), BFS over the codeintel edges
// up to a configurable depth. Returns reachable symbols (metadata
// only — agent calls get_symbols for bodies).
//
// Path-safety knobs (allow/deny lists) reuse the v1.7.8 get_file
// config block. Audit row written per call.
//
// Ambiguity-as-error contract: if (file, name) matches multiple
// symbols and no `fqn` was supplied, return ok: false with a
// candidates list so the agent re-calls with fqn. Auto-picking the
// wrong anchor wastes more tokens than the round-trip.
// -----------------------------------------------------------------------------

// GetRelationsOptions tunes the get_relations tool at registration
// time. Path-safety fields are intentionally shared with
// [GetFileOptions] / [GetSymbolsOptions] (read by the server wiring
// from [config.IntelligenceMCPGetFileConfig]). MaxDepth + MaxResults
// come from [config.IntelligenceMCPGetRelationsConfig].
type GetRelationsOptions struct {
	AllowExtensions []string
	DenyPaths       []string
	MaxDepth        int
	MaxResults      int
}

func (o GetRelationsOptions) withDefaults() GetRelationsOptions {
	if o.MaxDepth <= 0 {
		o.MaxDepth = 5
	}
	if o.MaxResults <= 0 {
		o.MaxResults = 100
	}
	return o
}

type getRelationsTool struct {
	opts  GetRelationsOptions
	cg    codeintel.Provider
	audit audit.Writer
}

func newGetRelationsTool(opts GetRelationsOptions, cg codeintel.Provider, w audit.Writer) Tool {
	if w == nil {
		w = audit.NewNoopWriter()
	}
	if cg == nil {
		cg = codeintel.Unavailable()
	}
	return &getRelationsTool{
		opts:  opts.withDefaults(),
		cg:    cg,
		audit: w,
	}
}

func (*getRelationsTool) Name() string { return "get_relations" }

func (*getRelationsTool) Description() string {
	return "Graph traversal over the codebase's CALLS / CONTAINS edges. Ask " +
		"\"what calls handleClick within 2 hops\" and get back a flat list of " +
		"reachable symbols with their depth + the edge that brought them in. " +
		"Returns metadata only (name, fqn, kind, file, start_line); use " +
		"get_symbols for bodies. Single anchor per call — when the same `name` " +
		"appears in multiple scopes, pin via `fqn`. CONTAINS edges may be empty " +
		"in some codebases; an empty result with `degraded: true` is normal."
}

func (*getRelationsTool) InputSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"project_root": map[string]any{
				"type":        "string",
				"description": "Absolute path to the project root. Required.",
			},
			"file": map[string]any{
				"type":        "string",
				"description": "Absolute or project-relative path to the file containing the anchor symbol. Required.",
			},
			"name": map[string]any{
				"type":        "string",
				"description": "Symbol name to use as the BFS anchor. Required. Use `fqn` to disambiguate when the same name appears in multiple scopes.",
			},
			"fqn": map[string]any{
				"type":        "string",
				"description": "Optional fully-qualified name (e.g. 'Editor.handleClick'). Disambiguates when multiple symbols share `name`.",
			},
			"kind": map[string]any{
				"type":        "string",
				"enum":        []string{"callers", "callees", "contains"},
				"description": "Relation kind to traverse. 'callers' = inbound CALLS edges; 'callees' = outbound CALLS edges; 'contains' = outbound CONTAINS edges (parent -> child).",
			},
			"depth": map[string]any{
				"type":        "integer",
				"minimum":     1,
				"description": "BFS depth (hops from anchor). Default 1 (immediate neighbors). Clamped to the operator-configured max_depth ceiling.",
			},
			"session_id": map[string]any{
				"type":        "string",
				"description": "Optional. Threads the audit row into the V7-14 mcp_audit log for per-session forensics.",
			},
		},
		"required": []string{"project_root", "file", "name", "kind"},
	}
}

type getRelationsArgs struct {
	ProjectRoot string `json:"project_root"`
	File        string `json:"file"`
	Name        string `json:"name"`
	FQN         string `json:"fqn"`
	Kind        string `json:"kind"`
	Depth       int    `json:"depth"`
	SessionID   string `json:"session_id"`
}

type getRelationsAnchor struct {
	Name                string `json:"name"`
	FQN                 string `json:"fqn"`
	Kind                string `json:"kind"`
	File                string `json:"file"`
	ProjectRelativePath string `json:"project_relative_path"`
	StartLine           int    `json:"start_line"`
}

type getRelationsCandidate struct {
	FQN       string `json:"fqn"`
	Kind      string `json:"kind"`
	StartLine int    `json:"start_line"`
}

type getRelationsRow struct {
	Symbol  symbolMatch `json:"symbol"`
	Depth   int         `json:"depth"`
	ViaEdge string      `json:"via_edge"`
}

type getRelationsResult struct {
	OK         bool                    `json:"ok"`
	Anchor     *getRelationsAnchor     `json:"anchor,omitempty"`
	Kind       string                  `json:"kind,omitempty"`
	Depth      int                     `json:"depth,omitempty"`
	Results    []getRelationsRow       `json:"results"`
	Truncated  bool                    `json:"truncated,omitempty"`
	Degraded   bool                    `json:"degraded,omitempty"`
	Reason     string                  `json:"reason,omitempty"`
	Candidates []getRelationsCandidate `json:"candidates,omitempty"`
	// Warnings is the V7-17 closed-set tag slice. Empty (nil) →
	// omitted. See internal/mcp/warnings.go for the tag constants.
	Warnings []string `json:"warnings,omitempty"`
}

func (t *getRelationsTool) Invoke(ctx context.Context, raw json.RawMessage) (any, error) {
	started := time.Now()
	var args getRelationsArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	if args.ProjectRoot == "" || args.File == "" || args.Name == "" || args.Kind == "" {
		return nil, errors.New("project_root, file, name, and kind are required")
	}
	direction, ok := relationDirectionFor(args.Kind)
	if !ok {
		return nil, fmt.Errorf("invalid kind %q (allowed: callers, callees, contains)", args.Kind)
	}

	// Path safety — same defenses as get_file / get_symbols.
	abs, err := safeResolvePath(args.ProjectRoot, args.File)
	if err != nil {
		res := getRelationsResult{Results: []getRelationsRow{}, Reason: "get_relations: " + err.Error()}
		t.recordAudit(args, res, "", started)
		return res, nil
	}
	if !extensionAllowed(abs, t.opts.AllowExtensions) {
		ext := strings.TrimPrefix(filepath.Ext(abs), ".")
		res := getRelationsResult{
			Results: []getRelationsRow{},
			Reason:  fmt.Sprintf("get_relations: extension %q not in allow list", ext),
		}
		t.recordAudit(args, res, abs, started)
		return res, nil
	}
	rootResolved, _ := filepath.EvalSymlinks(args.ProjectRoot)
	if rootResolved == "" {
		rootResolved, _ = filepath.Abs(args.ProjectRoot)
	}
	rel, relErr := filepath.Rel(rootResolved, abs)
	if relErr != nil {
		res := getRelationsResult{
			Results: []getRelationsRow{},
			Reason:  "get_relations: relative-path resolution failed",
		}
		t.recordAudit(args, res, abs, started)
		return res, nil
	}
	rel = filepath.ToSlash(rel)
	if matchesAny(rel, t.opts.DenyPaths) {
		res := getRelationsResult{
			Results: []getRelationsRow{},
			Reason:  fmt.Sprintf("get_relations: path %q matches deny pattern", rel),
		}
		t.recordAudit(args, res, abs, started)
		return res, nil
	}

	// Index unavailable → degraded with hint.
	if !t.cg.Available() {
		res := getRelationsResult{
			OK:       true,
			Kind:     args.Kind,
			Results:  []getRelationsRow{},
			Degraded: true,
			Reason:   "code index unavailable; fall back to get_file",
			Warnings: []string{WarningIndexUnavailable},
		}
		// Corpus archival P2.3: an archived project reaches here looking
		// exactly like a never-indexed one. Reason is the field this tool
		// already uses to explain itself, so the honest explanation replaces
		// the generic one rather than being bolted alongside it.
		if note, archived := archivedNote(ctx, t.cg, args.ProjectRoot); archived {
			res.Reason = note
			res.Warnings = appendWarning(res.Warnings, WarningProjectArchived)
		}
		t.recordAudit(args, res, abs, started)
		return res, nil
	}
	// Stale → degraded with hint.
	if t.cg.Stale(abs) {
		res := getRelationsResult{
			OK:       true,
			Kind:     args.Kind,
			Results:  []getRelationsRow{},
			Degraded: true,
			Reason:   "code index stale relative to file; fall back to get_file",
			Warnings: []string{WarningIndexStale},
		}
		t.recordAudit(args, res, abs, started)
		return res, nil
	}

	// Resolve anchor via FindSymbols. fqn pin wins; otherwise we use
	// name and require disambiguation if multiple match.
	anchors, err := t.cg.FindSymbols(ctx, abs, args.Name, args.FQN, "")
	if err != nil || len(anchors) == 0 {
		res := getRelationsResult{
			OK:      true,
			Kind:    args.Kind,
			Results: []getRelationsRow{},
			Reason:  "anchor symbol not found",
		}
		t.recordAudit(args, res, abs, started)
		return res, nil
	}
	if len(anchors) > 1 && args.FQN == "" {
		candidates := make([]getRelationsCandidate, 0, len(anchors))
		for _, a := range anchors {
			candidates = append(candidates, getRelationsCandidate{
				FQN: a.FQN, Kind: a.Kind, StartLine: a.StartLine,
			})
		}
		res := getRelationsResult{
			OK:      false,
			Results: []getRelationsRow{},
			Reason: fmt.Sprintf(
				"get_relations: ambiguous anchor; %d symbols named %q in %s — supply fqn to disambiguate",
				len(anchors), args.Name, rel,
			),
			Candidates: candidates,
		}
		t.recordAudit(args, res, abs, started)
		return res, nil
	}
	anchor := anchors[0]

	// Clamp depth.
	depth := args.Depth
	if depth <= 0 {
		depth = 1
	}
	if depth > t.opts.MaxDepth {
		depth = t.opts.MaxDepth
	}

	reached, truncated, err := t.cg.Reachable(ctx, anchor.ID, direction, depth, t.opts.MaxResults)
	if err != nil {
		res := getRelationsResult{
			OK:      true,
			Anchor:  anchorView(anchor, rootResolved),
			Kind:    args.Kind,
			Depth:   depth,
			Results: []getRelationsRow{},
			Reason:  "get_relations: code index query failed",
		}
		t.recordAudit(args, res, abs, started)
		return res, nil
	}

	res := getRelationsResult{
		OK:        true,
		Anchor:    anchorView(anchor, rootResolved),
		Kind:      args.Kind,
		Depth:     depth,
		Results:   make([]getRelationsRow, 0, len(reached)),
		Truncated: truncated,
	}
	for _, r := range reached {
		row := getRelationsRow{
			Symbol: symbolMatch{
				Name:      r.Name,
				FQN:       r.FQN,
				Kind:      r.Kind,
				File:      r.File,
				Language:  r.Language,
				StartLine: r.StartLine,
				EndLine:   r.EndLine,
			},
			Depth:   r.Depth,
			ViaEdge: r.ViaEdge,
		}
		if relPath, err := filepath.Rel(rootResolved, r.File); err == nil {
			row.Symbol.ProjectRelativePath = filepath.ToSlash(relPath)
		}
		res.Results = append(res.Results, row)
	}

	// CONTAINS-empty-upstream hint: when contains was requested AND
	// no results came back, check whether ANY CONTAINS edges exist
	// across the whole graph. If zero, mark degraded with the
	// upstream-population hint so the agent doesn't waste turns
	// re-trying.
	if args.Kind == "contains" && len(res.Results) == 0 {
		total, _ := t.cg.CountEdgesByKind(ctx, "CONTAINS")
		if total == 0 {
			res.Degraded = true
			res.Reason = "edge kind 'contains' not populated by the code index for this project; fall back to get_symbols or get_file"
		}
	}

	t.recordAudit(args, res, abs, started)
	return res, nil
}

// relationDirectionFor maps the kind enum to the codeintel
// RelationDirection. Returns (_, false) for invalid kinds so callers
// can return a transport error.
func relationDirectionFor(kind string) (codeintel.RelationDirection, bool) {
	switch kind {
	case "callers":
		return codeintel.RelationCallers, true
	case "callees":
		return codeintel.RelationCallees, true
	case "contains":
		return codeintel.RelationContains, true
	default:
		return 0, false
	}
}

func anchorView(a codeintel.SymbolMatch, rootResolved string) *getRelationsAnchor {
	v := &getRelationsAnchor{
		Name:      a.Name,
		FQN:       a.FQN,
		Kind:      a.Kind,
		File:      a.File,
		StartLine: a.StartLine,
	}
	if rel, err := filepath.Rel(rootResolved, a.File); err == nil {
		v.ProjectRelativePath = filepath.ToSlash(rel)
	}
	return v
}

func (t *getRelationsTool) recordAudit(args getRelationsArgs, res getRelationsResult, absPath string, started time.Time) {
	if absPath == "" {
		absPath = args.File
	}
	t.audit.Record(context.Background(), audit.Row{
		Tool:              "get_relations",
		SessionID:         args.SessionID,
		RequestHash:       audit.RequestHash("get_relations", args),
		PathRequested:     absPath,
		ResponseBytes:     0, // metadata-only tool — no body bytes returned
		ResponseTruncated: res.Truncated,
		ResponseOK:        res.OK,
		Reason:            res.Reason,
		Duration:          time.Since(started),
	})
}
