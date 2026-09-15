package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/codeintel"
	"github.com/marmutapp/superbased-observer/internal/codeintel/parse/livesym"
	"github.com/marmutapp/superbased-observer/internal/mcp/audit"
)

// -----------------------------------------------------------------------------
// get_symbols — V7-12 retrieval-surface MCP tool (v1.7.9, second of four).
//
// Batched symbol lookup. One MCP turn returns N symbol bodies across
// M files via the codegraph index, bypassing codex's shell tool so
// the response isn't re-fed to LogsCompressor.
//
// Pairs with v1.7.7 marker enrichment + v1.7.8 get_file: marker tells
// the agent "contains fn handleClick (140), class Editor (220)";
// get_symbols fetches one or both bodies plus optional callers/callees
// in a single batched call.
//
// Path-safety knobs (allow/deny lists, max response KB) reuse the
// v1.7.8 get_file config block. Audit rows written per-request — N
// requests in a single get_symbols call produce N mcp_audit rows.
// -----------------------------------------------------------------------------

// GetSymbolsOptions tunes the get_symbols tool at registration time.
// Path-safety fields are intentionally shared with [GetFileOptions]
// (read by the server wiring from [config.IntelligenceMCPGetFileConfig]).
// MaxCallers / MaxCallees come from
// [config.IntelligenceMCPGetSymbolsConfig].
type GetSymbolsOptions struct {
	AllowExtensions []string
	DenyPaths       []string
	MaxResponseKB   int
	MaxCallers      int
	MaxCallees      int
}

func (o GetSymbolsOptions) withDefaults() GetSymbolsOptions {
	if o.MaxResponseKB <= 0 {
		o.MaxResponseKB = 100
	}
	if o.MaxCallers <= 0 {
		o.MaxCallers = 20
	}
	if o.MaxCallees <= 0 {
		o.MaxCallees = 20
	}
	return o
}

// totalBodyCapBytes is the package-internal hard cap on cumulative
// body bytes returned across all matches in a single get_symbols
// call. Set to 200 KB matching the V7-12 design. The cap is
// per-batch, not per-match.
const totalBodyCapBytes = 200 * 1024

type getSymbolsTool struct {
	opts  GetSymbolsOptions
	cg    codeintel.Provider
	audit audit.Writer
}

func newGetSymbolsTool(opts GetSymbolsOptions, cg codeintel.Provider, w audit.Writer) Tool {
	if w == nil {
		w = audit.NewNoopWriter()
	}
	if cg == nil {
		cg = codeintel.Unavailable()
	}
	return &getSymbolsTool{
		opts:  opts.withDefaults(),
		cg:    cg,
		audit: w,
	}
}

func (*getSymbolsTool) Name() string { return "get_symbols" }

func (*getSymbolsTool) Description() string {
	return "Batched symbol lookup across the project's code index. Returns symbol " +
		"bodies + metadata for {file, name?, kind?, fqn?} requests, all in one MCP " +
		"turn — far cheaper than spawning `cat | grep` per symbol through the shell " +
		"tool. Discovery mode: omit `name` and the response lists every user-facing " +
		"symbol in the file (without body) so you can pick which bodies to actually " +
		"fetch. When the code index is stale or missing for a file, that " +
		"request's `degraded` flag is set; fall back to `get_file` for the bytes."
}

func (*getSymbolsTool) InputSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"project_root": map[string]any{
				"type":        "string",
				"description": "Absolute path to the project root. Required.",
			},
			"session_id": map[string]any{
				"type":        "string",
				"description": "Optional. Threads each per-request audit row into the V7-14 mcp_audit log so per-session forensics work.",
			},
			"requests": map[string]any{
				"type":        "array",
				"minItems":    1,
				"maxItems":    25,
				"description": "Per-symbol lookup requests. Up to 25 per call.",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"file": map[string]any{
							"type":        "string",
							"description": "Absolute or project-relative path. Required.",
						},
						"name": map[string]any{
							"type":        "string",
							"description": "Symbol name (function, class, etc.). Omit for discovery mode (returns all user-facing symbols in file, no bodies).",
						},
						"fqn": map[string]any{
							"type":        "string",
							"description": "Fully-qualified name (e.g. 'Editor.handleClick'). Disambiguates when multiple symbols share the same `name`.",
						},
						"kind": map[string]any{
							"type":        "string",
							"description": "Optional kind filter: 'function' | 'method' | 'class' | 'interface' | 'type'.",
						},
						"include_relations": map[string]any{
							"type":        "boolean",
							"description": "When true, adds callers/callees lists + counts to each match. Default false.",
						},
						"include_body": map[string]any{
							"type":        "boolean",
							"description": "When false, omits the body field. Default true (false in discovery mode).",
						},
						"include_nearby": map[string]any{
							"type":        "integer",
							"minimum":     0,
							"description": "When > 0, adds nearby_symbols: [{name, kind, start_line}] to each match — up to N symbols defined just before AND N just after (by start_line) in the same file. Default 0 (omitted). Capped server-side at 20 each side.",
						},
					},
					"required": []string{"file"},
				},
			},
		},
		"required": []string{"project_root", "requests"},
	}
}

// getSymbolsRequest mirrors the JSON request shape.
type getSymbolsRequest struct {
	File             string `json:"file"`
	Name             string `json:"name"`
	FQN              string `json:"fqn"`
	Kind             string `json:"kind"`
	IncludeRelations bool   `json:"include_relations"`
	IncludeBody      *bool  `json:"include_body"` // pointer so "false" survives JSON
	// V7-17 item 1: when > 0, adds nearby_symbols: [{name, kind,
	// start_line}] to each match — up to N before and N after by
	// start_line. Default 0 = no enrichment.
	IncludeNearby int `json:"include_nearby"`
}

type getSymbolsArgs struct {
	ProjectRoot string              `json:"project_root"`
	SessionID   string              `json:"session_id"`
	Requests    []getSymbolsRequest `json:"requests"`
}

// getSymbolsResult is the unified envelope. ok=true at the top level
// even when individual results denied — top-level only goes false on
// transport-level failures.
type getSymbolsResult struct {
	OK        bool `json:"ok"`
	Degraded  bool `json:"degraded,omitempty"`
	Truncated bool `json:"truncated,omitempty"`
	// Warnings is the V7-17 closed-set tag slice. Empty (nil) →
	// omitted. See internal/mcp/warnings.go for the tag constants.
	Warnings []string `json:"warnings,omitempty"`
	// Note explains a degraded answer in operator terms — today only the
	// corpus-archival case. The machine-readable half is `warnings`.
	Note    string               `json:"note,omitempty"`
	Results []getSymbolsResponse `json:"results"`
}

type getSymbolsResponse struct {
	Request            getSymbolsRequest `json:"request"`
	OK                 bool              `json:"ok"`
	Matches            []symbolMatch     `json:"matches"`
	Ambiguous          bool              `json:"ambiguous,omitempty"`
	DisambiguationHint string            `json:"disambiguation_hint,omitempty"`
	Degraded           bool              `json:"degraded,omitempty"`
	Reason             string            `json:"reason,omitempty"`
	// envelopeWarning is consumed by the envelope loop (V7-17) to
	// populate the top-level Warnings field. Unexported → not
	// marshaled by encoding/json. Empty string = no signal.
	envelopeWarning string
}

type symbolMatch struct {
	Name                string          `json:"name"`
	FQN                 string          `json:"fqn"`
	Kind                string          `json:"kind"`
	File                string          `json:"file"`
	ProjectRelativePath string          `json:"project_relative_path"`
	Language            string          `json:"language,omitempty"`
	StartLine           int             `json:"start_line"`
	EndLine             int             `json:"end_line"`
	Body                string          `json:"body,omitempty"`
	BodyTruncated       bool            `json:"body_truncated,omitempty"`
	CallersCount        *int            `json:"callers_count,omitempty"`
	CalleesCount        *int            `json:"callees_count,omitempty"`
	Callers             []symbolRelLink `json:"callers,omitempty"`
	Callees             []symbolRelLink `json:"callees,omitempty"`
	// V7-17 item 1: populated when the request opts in via
	// IncludeNearby > 0. Up to N symbols defined just before and N
	// just after the match by start_line, same file. Each carries
	// minimal metadata (no body) — agent re-issues a focused
	// get_symbols call for the bodies it wants.
	NearbySymbols []symbolNearby `json:"nearby_symbols,omitempty"`
	// V7-17 drift signal: emitted only when codegraph index disagrees
	// with the live file's regex-parsed positions (Stale path). When
	// populated, IndexLines holds the codegraph numbers and LiveLines
	// holds the regex numbers — the agent sees the divergence
	// explicitly. Omitted when codegraph and file agree (steady state).
	IndexLines *lineSpan `json:"index_lines,omitempty"`
	LiveLines  *lineSpan `json:"live_lines,omitempty"`
}

// lineSpan is the {start, end} pair surfaced in IndexLines /
// LiveLines. End may be -1 ("regex didn't know"); JSON marshals as
// the literal -1 (not null) for shape determinism. Operators
// distinguish "unknown" via the sentinel.
type lineSpan struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

type symbolRelLink struct {
	Name      string `json:"name"`
	FQN       string `json:"fqn,omitempty"`
	Kind      string `json:"kind,omitempty"`
	File      string `json:"file,omitempty"`
	StartLine int    `json:"start_line,omitempty"`
}

// symbolNearby is one entry in NearbySymbols. Minimal metadata so the
// nearby list stays cheap even at IncludeNearby=20 each side. No body
// or end-line — the agent re-issues a focused get_symbols for the
// bodies it actually wants. (V7-17 item 1.)
type symbolNearby struct {
	Name      string `json:"name"`
	Kind      string `json:"kind,omitempty"`
	StartLine int    `json:"start_line"`
}

func (t *getSymbolsTool) Invoke(ctx context.Context, raw json.RawMessage) (any, error) {
	var args getSymbolsArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	if args.ProjectRoot == "" {
		return nil, errors.New("project_root is required")
	}
	if len(args.Requests) == 0 {
		return nil, errors.New("requests must contain at least one entry")
	}
	if len(args.Requests) > 25 {
		return nil, fmt.Errorf("requests exceeds max 25 entries (got %d)", len(args.Requests))
	}

	out := getSymbolsResult{
		OK:      true,
		Results: make([]getSymbolsResponse, 0, len(args.Requests)),
	}
	if !t.cg.Available() {
		// Top-level degraded: every result will be empty + degraded.
		// Agent should fall back to get_file. Audit each request
		// regardless so operators see the unavailability.
		out.Degraded = true
		// V7-17: surface the same signal in-band as a closed-set tag.
		out.Warnings = appendWarning(out.Warnings, WarningIndexUnavailable)
	}
	// Corpus archival P2.3: "no index" and "this project's index is in cold
	// storage" are different situations with different fixes, and the regex
	// fallback below answers both identically. One indexed marker lookup tells
	// them apart, and only an actually-archived project gets the tag.
	if note, archived := archivedNote(ctx, t.cg, args.ProjectRoot); archived {
		out.Degraded = true
		out.Warnings = appendWarning(out.Warnings, WarningProjectArchived)
		out.Note = note
	}

	totalBodyBytes := 0
	for _, req := range args.Requests {
		started := time.Now()
		resp := t.handleOne(ctx, args, req, &totalBodyBytes)
		// V7-17: collect envelope-level warnings from per-result
		// signals (index_unavailable / index_stale).
		if resp.envelopeWarning != "" {
			out.Warnings = appendWarning(out.Warnings, resp.envelopeWarning)
		}
		out.Results = append(out.Results, resp)
		t.recordAudit(args.SessionID, req, resp, started)
		if anyTruncated(resp) {
			out.Truncated = true
		}
	}
	return out, nil
}

func anyTruncated(r getSymbolsResponse) bool {
	for _, m := range r.Matches {
		if m.BodyTruncated {
			return true
		}
	}
	return false
}

func (t *getSymbolsTool) handleOne(ctx context.Context, args getSymbolsArgs, req getSymbolsRequest, totalBodyBytes *int) getSymbolsResponse {
	resp := getSymbolsResponse{Request: req, OK: true, Matches: []symbolMatch{}}

	if req.File == "" {
		resp.OK = false
		resp.Reason = "get_symbols: file is required"
		return resp
	}

	abs, err := safeResolvePath(args.ProjectRoot, req.File)
	if err != nil {
		resp.OK = false
		resp.Reason = "get_symbols: " + err.Error()
		return resp
	}
	if !extensionAllowed(abs, t.opts.AllowExtensions) {
		ext := strings.TrimPrefix(filepath.Ext(abs), ".")
		resp.OK = false
		resp.Reason = fmt.Sprintf("get_symbols: extension %q not in allow list", ext)
		return resp
	}
	rootResolved, _ := filepath.EvalSymlinks(args.ProjectRoot)
	if rootResolved == "" {
		rootResolved, _ = filepath.Abs(args.ProjectRoot)
	}
	rel, relErr := filepath.Rel(rootResolved, abs)
	if relErr != nil {
		resp.OK = false
		resp.Reason = "get_symbols: relative-path resolution failed"
		return resp
	}
	rel = filepath.ToSlash(rel)
	if matchesAny(rel, t.opts.DenyPaths) {
		resp.OK = false
		resp.Reason = fmt.Sprintf("get_symbols: path %q matches deny pattern", rel)
		return resp
	}

	// Index unavailable → V7-17 regex fallback. The live parser
	// returns approximate symbols (start_line correct, end_line null,
	// no body); the agent gets SOMETHING vs. nothing. Degraded flag
	// stays true so the agent calibrates trust.
	if !t.cg.Available() {
		resp.Degraded = true
		resp.Reason = "code index unavailable; matches are regex-derived approximations"
		resp.envelopeWarning = WarningIndexUnavailable
		liveSyms, langUnsupported, parseErr := livesym.Parse(abs)
		if langUnsupported {
			resp.envelopeWarning = WarningRegexFallbackLanguageUnsupported
			resp.Reason = "code index unavailable; file extension unsupported by regex fallback"
			return resp
		}
		if parseErr != nil {
			// Fall through to empty matches — same as pre-v1.7.16
			// behavior. Operator sees the parse error in audit reason.
			resp.Reason = "code index unavailable; regex fallback failed to parse file"
			return resp
		}
		resp.Matches = matchLiveSymbols(rel, abs, liveSyms, req)
		return resp
	}
	// Index stale → per-result degraded with V7-17 drift signal.
	// We still query the index for its positions, then run the live
	// regex parser to compute live positions, and surface both per
	// match so the agent sees the divergence explicitly. If the regex
	// can't parse (unsupported language) we fall back to the
	// pre-v1.7.16 behavior: empty matches + degraded.
	if t.cg.Stale(abs) {
		resp.Degraded = true
		resp.Reason = "code index stale relative to file; fall back to get_file"
		resp.envelopeWarning = WarningIndexStale
		liveSyms, langUnsupported, parseErr := livesym.Parse(abs)
		if langUnsupported || parseErr != nil {
			return resp
		}
		indexMatches, idxErr := t.cg.FindSymbols(ctx, abs, req.Name, req.FQN, req.Kind)
		if idxErr != nil || len(indexMatches) == 0 {
			return resp
		}
		resp.Matches = attachDriftSignal(rel, abs, indexMatches, liveSyms)
		return resp
	}

	matches, err := t.cg.FindSymbols(ctx, abs, req.Name, req.FQN, req.Kind)
	if err != nil {
		// provider methods are nil-on-error per contract, but defend
		// in depth — surface as a per-request denial.
		resp.OK = false
		resp.Reason = "get_symbols: code index query failed"
		return resp
	}
	if len(matches) == 0 {
		resp.Reason = "symbol not found"
		return resp
	}

	rankMatches(matches)

	discovery := req.Name == "" && req.FQN == ""
	includeBody := !discovery
	if req.IncludeBody != nil {
		includeBody = *req.IncludeBody
	}

	// V7-17 item 1: pre-fetch the file's full symbol list once when
	// IncludeNearby is opted into; serves every match without N+1.
	var nearbyPool []codeintel.Symbol
	if req.IncludeNearby > 0 {
		nearbyPool, _ = t.cg.SymbolsInFile(ctx, abs)
	}

	for _, m := range matches {
		sm := buildMatch(m, rootResolved, includeBody, totalBodyBytes)
		if req.IncludeRelations {
			t.enrichRelations(ctx, m.ID, &sm)
		}
		if req.IncludeNearby > 0 {
			sm.NearbySymbols = nearbySymbolsAround(nearbyPool, m.StartLine, m.Name, req.IncludeNearby)
		}
		resp.Matches = append(resp.Matches, sm)
	}

	// V7-15 ambiguity signal: multiple matches AND no fqn pinned in
	// the request. Hint uses the first match's fqn as the concrete
	// example so the agent can pattern-match the recipe.
	if len(matches) > 1 && req.FQN == "" {
		resp.Ambiguous = true
		hintFQN := matches[0].FQN
		if hintFQN == "" {
			hintFQN = matches[0].Name
		}
		resp.DisambiguationHint = fmt.Sprintf(
			"Use fqn (e.g. %q) to select a specific match.", hintFQN,
		)
	}
	return resp
}

// rankMatches applies the V7-15 stable sort. Exact-fqn matching and
// kind-filter are applied at SQL time in FindSymbols, so this only
// handles the residual ordering: start_line ASC → fqn ASC → file ASC
// → id ASC.
//
// `is_exported` ranking factor from V7-15 design is DEFERRED — the
// codegraph schema doesn't carry it. Documented in the operator
// reference + plan §10 risks.
func rankMatches(matches []codeintel.SymbolMatch) {
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].StartLine != matches[j].StartLine {
			return matches[i].StartLine < matches[j].StartLine
		}
		if matches[i].FQN != matches[j].FQN {
			return matches[i].FQN < matches[j].FQN
		}
		if matches[i].File != matches[j].File {
			return matches[i].File < matches[j].File
		}
		return matches[i].ID < matches[j].ID
	})
}

func buildMatch(m codeintel.SymbolMatch, rootResolved string, includeBody bool, totalBodyBytes *int) symbolMatch {
	sm := symbolMatch{
		Name:      m.Name,
		FQN:       m.FQN,
		Kind:      m.Kind,
		File:      m.File,
		Language:  m.Language,
		StartLine: m.StartLine,
		EndLine:   m.EndLine,
	}
	if rel, err := filepath.Rel(rootResolved, m.File); err == nil {
		sm.ProjectRelativePath = filepath.ToSlash(rel)
	}
	if !includeBody {
		return sm
	}
	if *totalBodyBytes >= totalBodyCapBytes {
		sm.BodyTruncated = true
		return sm
	}
	remaining := totalBodyCapBytes - *totalBodyBytes
	body, _, _, err := readSlice(m.File, m.StartLine, m.EndLine, remaining)
	if err != nil {
		// Body read failed (file gone, etc.); surface as truncated
		// rather than an error — metadata is still useful.
		sm.BodyTruncated = true
		return sm
	}
	sm.Body = string(body)
	*totalBodyBytes += len(body)
	if *totalBodyBytes >= totalBodyCapBytes {
		// Hit the cap exactly while reading this match — flag as
		// truncated so the agent knows to retry tighter even if body
		// happens to look complete.
		sm.BodyTruncated = true
	}
	return sm
}

func (t *getSymbolsTool) enrichRelations(ctx context.Context, symbolID int64, sm *symbolMatch) {
	if callersCount, err := t.cg.CountCallers(ctx, symbolID); err == nil {
		c := callersCount
		sm.CallersCount = &c
	}
	if calleesCount, err := t.cg.CountCallees(ctx, symbolID); err == nil {
		c := calleesCount
		sm.CalleesCount = &c
	}
	if callers, err := t.cg.CallersOfSymbol(ctx, symbolID, t.opts.MaxCallers); err == nil {
		for _, c := range callers {
			sm.Callers = append(sm.Callers, symbolRelLink{
				Name: c.Name, FQN: c.FQN, Kind: c.Kind,
				File: c.File, StartLine: c.StartLine,
			})
		}
	}
	if callees, err := t.cg.CalleesOfSymbol(ctx, symbolID, t.opts.MaxCallees); err == nil {
		for _, c := range callees {
			sm.Callees = append(sm.Callees, symbolRelLink{
				Name: c.Name, FQN: c.FQN, Kind: c.Kind,
				File: c.File, StartLine: c.StartLine,
			})
		}
	}
}

func (t *getSymbolsTool) recordAudit(sessionID string, req getSymbolsRequest, resp getSymbolsResponse, started time.Time) {
	var bodyBytes int
	for _, m := range resp.Matches {
		bodyBytes += len(m.Body)
	}
	bodyTruncated := false
	for _, m := range resp.Matches {
		if m.BodyTruncated {
			bodyTruncated = true
			break
		}
	}
	t.audit.Record(context.Background(), audit.Row{
		Tool:              "get_symbols",
		SessionID:         sessionID,
		RequestHash:       audit.RequestHash("get_symbols", req),
		PathRequested:     resolvedPath(resp, req.File),
		ResponseBytes:     bodyBytes,
		ResponseTruncated: bodyTruncated,
		ResponseOK:        resp.OK,
		Reason:            resp.Reason,
		Duration:          time.Since(started),
	})
}

// resolvedPath returns the absolute path actually accessed if the
// request resolved at all; otherwise the raw request path so the
// audit row still carries something useful for "why was this
// denied?" queries.
func resolvedPath(resp getSymbolsResponse, fallback string) string {
	if len(resp.Matches) > 0 && resp.Matches[0].File != "" {
		return resp.Matches[0].File
	}
	return fallback
}

// nearbySymbolsAround picks up to N symbols defined just before and
// N just after the anchor symbol (by start_line), in the same file.
// Skips the anchor itself by matching its name + start_line.
//
// Caller pre-sorts pool via SymbolsInFile's contract (ORDER BY
// start_line) so this helper just slices around the anchor's index.
// V7-17 item 1.
const maxIncludeNearby = 20

func nearbySymbolsAround(pool []codeintel.Symbol, anchorStart int, anchorName string, n int) []symbolNearby {
	if len(pool) == 0 || n <= 0 {
		return nil
	}
	if n > maxIncludeNearby {
		n = maxIncludeNearby
	}
	// Find anchor index. Pool is sorted by start_line ASC.
	anchorIdx := -1
	for i, s := range pool {
		if s.StartLine == anchorStart && s.Name == anchorName {
			anchorIdx = i
			break
		}
	}
	if anchorIdx == -1 {
		return nil
	}
	startBefore := anchorIdx - n
	if startBefore < 0 {
		startBefore = 0
	}
	endAfter := anchorIdx + n + 1
	if endAfter > len(pool) {
		endAfter = len(pool)
	}
	out := make([]symbolNearby, 0, endAfter-startBefore-1)
	for i := startBefore; i < endAfter; i++ {
		if i == anchorIdx {
			continue
		}
		out = append(out, symbolNearby{
			Name:      pool[i].Name,
			Kind:      pool[i].Kind,
			StartLine: pool[i].StartLine,
		})
	}
	return out
}

// attachDriftSignal pairs each codegraph match with its live regex
// counterpart (by name+kind) and surfaces IndexLines + LiveLines
// when they disagree. Matches without a live counterpart get just
// IndexLines; the agent reads this as "live file no longer has this
// symbol — likely renamed or deleted."
//
// V7-17 item 4: the agent sees the drift instead of trusting stale
// numbers. Pairs with the codegraph_stale warning emitted at the
// envelope level.
func attachDriftSignal(rel, abs string, idx []codeintel.SymbolMatch, live []livesym.Symbol) []symbolMatch {
	out := make([]symbolMatch, 0, len(idx))
	liveByName := map[string]livesym.Symbol{}
	for _, ls := range live {
		// Composite key (name, kind) — multiple methods can share a
		// name in Go (different receivers) but not within one file
		// at the same (name, kind), so this is safe enough for the
		// drift signal.
		liveByName[ls.Name+"|"+ls.Kind] = ls
	}
	for _, m := range idx {
		match := symbolMatch{
			Name:                m.Name,
			FQN:                 m.FQN,
			Kind:                m.Kind,
			File:                abs,
			ProjectRelativePath: rel,
			Language:            m.Language,
			StartLine:           m.StartLine,
			EndLine:             m.EndLine,
		}
		ls, ok := liveByName[m.Name+"|"+m.Kind]
		idxSpan := &lineSpan{Start: m.StartLine, End: m.EndLine}
		match.IndexLines = idxSpan
		if ok {
			match.LiveLines = &lineSpan{Start: ls.StartLine, End: ls.EndLine}
		}
		out = append(out, match)
	}
	return out
}

// matchLiveSymbols filters live regex symbols against the request's
// name/kind and converts them to symbolMatch records. The agent gets
// approximate positions; the degraded flag tells it the matches are
// regex-derived (no body, no end_line). Used by the V7-17 codegraph-
// unavailable fallback (commit 3) and the drift signal (commit 4).
//
// Discovery mode (empty name AND empty fqn) returns all symbols.
// FQN matching falls back to plain name match because the regex
// parser doesn't construct fully-qualified names.
func matchLiveSymbols(rel, abs string, syms []livesym.Symbol, req getSymbolsRequest) []symbolMatch {
	out := []symbolMatch{}
	discovery := req.Name == "" && req.FQN == ""
	for _, s := range syms {
		if !discovery {
			if req.Name != "" && s.Name != req.Name {
				continue
			}
			// FQN match: regex parser doesn't construct fqns, so we
			// match the trailing-dotted segment loosely.
			if req.FQN != "" && !strings.HasSuffix(req.FQN, "."+s.Name) && req.FQN != s.Name {
				continue
			}
		}
		if req.Kind != "" && s.Kind != req.Kind {
			continue
		}
		out = append(out, symbolMatch{
			Name:                s.Name,
			Kind:                s.Kind,
			File:                abs,
			ProjectRelativePath: rel,
			Language:            s.Language,
			StartLine:           s.StartLine,
			// EndLine stays at 0 — same as the existing
			// "codegraph didn't record an end" sentinel. Combined with
			// Degraded=true on the response, the agent sees this is
			// regex-derived without a wire-shape change.
		})
	}
	return out
}
