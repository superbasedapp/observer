package mcp

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/codeintel"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/mcp/audit"
	"github.com/marmutapp/superbased-observer/internal/stash"
)

// Tool is an MCP tool — a named callable with a JSON schema.
type Tool interface {
	Name() string
	Description() string
	InputSchema() map[string]any
	Invoke(ctx context.Context, args json.RawMessage) (any, error)
}

// Options configures a Server.
type Options struct {
	// DB is the observer's SQLite database (opened by internal/db.Open). The
	// built-in tools query it read-only for the most part.
	DB *sql.DB
	// Logger receives operational messages. stdout is reserved for the
	// JSON-RPC stream — the logger must write elsewhere (stderr by default).
	Logger *slog.Logger
	// ServerName, ServerVersion are echoed to clients during initialize.
	ServerName    string
	ServerVersion string
	// ToolCallTimeout bounds one tools/call invocation. Database-backed tools
	// receive the deadline through context, ensuring a stalled query cannot
	// pin a WAL read snapshot indefinitely. Zero disables the deadline.
	ToolCallTimeout time.Duration
	// ExtraTools lets callers add custom tools on top of the built-in set.
	ExtraTools []Tool
	// CostEngine optionally overrides the built-in cost engine (pricing table
	// with baked-in defaults only). Pass a config-aware engine from the CLI
	// so user-configured pricing overrides flow into get_cost_summary.
	CostEngine *cost.Engine
	// CacheWarm carries the [cachewarm] tunables so the cache_status tool
	// reports the operator's real thresholds + keep-warm mode. Zero value
	// (Enabled=false) makes cache_status report the disabled state.
	CacheWarm config.CacheWarmConfig
	// Tasks carries the [tasks] tunables for the get_session_tasks tool:
	// Enabled is checked inside Invoke, not at registration (the
	// cache_status rule), so the tool is always LISTED but reports
	// disabled=true/false honestly per current config; MatchMode/
	// ConcurrentAttribution/IncludeSidechains are threaded into an
	// explicit taskflow.Options on every call — NOT read off a fresh
	// store.New(db)'s Store.TasksOptions(), which would silently return
	// the zero value here (this server's db never had SetTasksOptions
	// called on it; see taskreport.LoadSessionTaskReport's doc comment).
	Tasks config.TasksConfig
	// CodeIntel is the code-intelligence provider for structural
	// enrichment (the strangler-fig seam — codeintel.Provider). When
	// non-nil and Available(), check_file_freshness and get_file_history
	// include a `structure` block with functions, callers, and imports,
	// and the get_symbols / get_relations retrieval tools are served from
	// it. Nil is treated as an unavailable provider.
	CodeIntel codeintel.Provider
	// Stash, when non-nil, registers the `retrieve_stashed` MCP tool.
	// Pairs with the v1.4.41 / Tier 1 / G31 (CCR) feature: the proxy
	// stashes large tool_result bodies and replaces them with a marker
	// referencing a sha; the model retrieves originals via this tool.
	Stash *stash.Stash
	// SignalRecorder, when non-nil, receives one row per retrieve_stashed
	// success and per search_past_outputs hit (K43 — Tier 3 self-
	// learning feedback loop). Optional — both tools work without it,
	// the absent recorder just means no aggregate retrieval-rate
	// reports get populated.
	SignalRecorder SignalRecorder
	// GetFile, when GetFileEnabled is true, configures the v1.7.8
	// get_file MCP tool (V7-12 retrieval surface, first of four).
	// Path-safety defenses (V7-13 Gap 4) draw their AllowExtensions /
	// DenyPaths / MaxResponseKB from this struct. Disabled when
	// GetFileEnabled is false — the tool is simply not registered.
	GetFile        GetFileOptions
	GetFileEnabled bool
	// GetSymbols, when GetSymbolsEnabled is true, configures the
	// v1.7.9 get_symbols MCP tool (V7-12 retrieval surface, second
	// of four). Path-safety fields (AllowExtensions, DenyPaths,
	// MaxResponseKB) are typically populated from the same
	// [intelligence.mcp.get_file] config block — keeps operators on
	// one set of allow/deny knobs across both tools.
	GetSymbols        GetSymbolsOptions
	GetSymbolsEnabled bool
	// GetRelations, when GetRelationsEnabled is true, configures the
	// v1.7.10 get_relations MCP tool (V7-12 retrieval surface,
	// third of four). Path-safety knobs are shared with GetFile /
	// GetSymbols. BFS bounds (MaxDepth / MaxResults) come from
	// [config.IntelligenceMCPGetRelationsConfig].
	GetRelations        GetRelationsOptions
	GetRelationsEnabled bool
	// AuditWriter, when non-nil, receives one row per V7-12 MCP call
	// (success or denial). Defaults to [audit.NewNoopWriter] when nil
	// so existing test wiring (which doesn't care about audit) still
	// works. Production `observer serve` wires
	// [audit.NewSQLWriter] when [intelligence.mcp.audit].enabled is
	// true. (V7-14.)
	AuditWriter audit.Writer
	// Features, when non-empty, restricts the V7-12 retrieval tools
	// (`get_file`, `get_symbols`, `get_relations`, `retrieve_stashed`)
	// to the listed subset. Built-in observability tools are NOT
	// affected — see [config.IntelligenceMCPConfig.Features]
	// doc-comment for the precedence rules (V7-16).
	//
	// Empty / nil = no filter applied (per-tool flags decide alone).
	Features []string
	// RetrieveStashedDisabled, when true, prevents registration of
	// the `retrieve_stashed` tool even when [Stash] is non-nil. Lets
	// operators keep proxy-side stash compression active while
	// denying the agent the retrieval surface (the V7-12 v1.7.11
	// per-tool kill switch).
	//
	// Default false preserves v1.7.10 behavior: `Stash != nil` is
	// sufficient to register the tool.
	RetrieveStashedDisabled bool
	// RetrieveStashedMaxShasPerCall caps the array-form sha input
	// per call. Zero defaults to 25 (matches get_symbols's batch
	// cap). Production `observer serve` reads this from
	// [intelligence.mcp.retrieve_stashed].max_shas_per_call.
	RetrieveStashedMaxShasPerCall int
	// BuildHandoff, when non-nil, backs the continue_session tool
	// (session handoff / docs/session-handoff.md) — the cmd-layer
	// handoffsvc runner closure, the same seam the dashboard uses.
	// Nil leaves the tool registered but degraded (honest error).
	BuildHandoff HandoffRunner
	// GetSessionMessage, when non-nil, backs the get_session_message tool
	// (the message-addressable handoff pull — re-reads one un-excerpted
	// message from a source session's own files). Same inject-a-closure
	// seam as BuildHandoff; nil leaves the tool registered but degraded.
	GetSessionMessage MessageReader
}

// SignalRecorder is the K43 retrieval-signal sink (v1.4.43+ / Tier 3).
// Production impl is (*learn.SignalRecorder); the interface lives in
// the mcp package so the contract stays import-cycle-free and tests
// can stub it.
//
// Errors from these methods are logged but do not propagate — losing a
// single signal row must never fail an MCP tool call.
type SignalRecorder interface {
	RecordRetrieveStashed(ctx context.Context, sha, sessionID string) error
	RecordSearchHit(ctx context.Context, actionID int64, query, sessionID string) error
}

// Server is the MCP stdio JSON-RPC server. Safe for concurrent use after
// Run; Run itself is single-threaded (reads stdio serially).
type Server struct {
	db              *sql.DB
	logger          *slog.Logger
	name            string
	version         string
	toolCallTimeout time.Duration

	mu    sync.RWMutex
	tools map[string]Tool
}

// New constructs a Server and registers the built-in tools. DB is required.
func New(opts Options) (*Server, error) {
	if opts.DB == nil {
		return nil, errors.New("mcp.New: DB is required")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s := &Server{
		db:              opts.DB,
		logger:          logger,
		name:            defaultIfEmpty(opts.ServerName, "observer"),
		version:         defaultIfEmpty(opts.ServerVersion, "dev"),
		toolCallTimeout: opts.ToolCallTimeout,
		tools:           map[string]Tool{},
	}
	engine := opts.CostEngine
	if engine == nil {
		engine = cost.NewEngine(config.IntelligenceConfig{})
	}
	cg := opts.CodeIntel
	if cg == nil {
		cg = codeintel.Unavailable()
	}
	for _, t := range builtinTools(opts.DB, cg, opts.SignalRecorder) {
		s.Register(t)
	}
	for _, t := range extraBuiltinTools(opts.DB, engine, opts.CacheWarm, opts.Tasks) {
		s.Register(t)
	}
	// continue_session (session handoff, P2): always registered so the
	// tool surface is deterministic; degrades at call time with an honest
	// error when the host wiring didn't inject a runner.
	s.Register(newContinueSessionTool(opts.DB, opts.BuildHandoff))
	// get_session_message (session handoff): always registered for a
	// deterministic tool surface; degrades honestly when unwired.
	s.Register(newGetSessionMessageTool(opts.GetSessionMessage))
	// get_project_guidance (agent-guidance inventory): always registered —
	// it reads node-local rows the daemon's scan loop already persisted and
	// answers honestly ("nothing scanned yet") on a fresh install, so there
	// is nothing to gate.
	s.Register(newGetProjectGuidanceTool(opts.DB))
	if opts.Stash != nil && !opts.RetrieveStashedDisabled && shouldRegisterV7_12Tool(opts.Features, "retrieve_stashed") {
		s.Register(newRetrieveStashedTool(opts.Stash, opts.SignalRecorder, opts.AuditWriter, opts.RetrieveStashedMaxShasPerCall))
	}
	if opts.GetFileEnabled && shouldRegisterV7_12Tool(opts.Features, "get_file") {
		s.Register(newGetFileTool(opts.GetFile, opts.AuditWriter))
	}
	if opts.GetSymbolsEnabled && shouldRegisterV7_12Tool(opts.Features, "get_symbols") {
		s.Register(newGetSymbolsTool(opts.GetSymbols, cg, opts.AuditWriter))
	}
	if opts.GetRelationsEnabled && shouldRegisterV7_12Tool(opts.Features, "get_relations") {
		s.Register(newGetRelationsTool(opts.GetRelations, cg, opts.AuditWriter))
	}
	for _, t := range opts.ExtraTools {
		s.Register(t)
	}
	return s, nil
}

// shouldRegisterV7_12Tool decides whether a V7-12 retrieval tool's
// registration survives the V7-16 features filter.
//
// Semantics (pinned by TestServer_FeaturesFilter_*):
//   - features empty / nil  → true (no filter, per-tool flags alone decide)
//   - features non-empty    → true iff toolName is in the list
//
// Per-tool `enabled = false` is checked at the call site BEFORE this
// helper — it always wins, the filter cannot re-enable a
// per-tool-disabled tool. This helper only refines the "yes" side.
func shouldRegisterV7_12Tool(features []string, toolName string) bool {
	if len(features) == 0 {
		return true
	}
	for _, f := range features {
		if f == toolName {
			return true
		}
	}
	return false
}

// Register adds a tool by name. A subsequent Register with the same name
// replaces the earlier entry.
func (s *Server) Register(t Tool) {
	s.mu.Lock()
	s.tools[t.Name()] = t
	s.mu.Unlock()
}

// Run reads newline-delimited JSON-RPC 2.0 messages from r and writes
// responses to w until r is closed or ctx is done. The bufio.Scanner buffer
// is extended so large tool/call requests don't trip MaxScanTokenSize.
func (s *Server) Run(ctx context.Context, r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)

	// Serialize writes — even though Run itself reads serially, a future
	// notification stream (e.g. tools/list_changed) would write from another
	// goroutine.
	var writeMu sync.Mutex
	writeResp := func(resp rpcResponse) {
		writeMu.Lock()
		defer writeMu.Unlock()
		if err := enc.Encode(resp); err != nil {
			s.logger.Warn("mcp: write response", "err", err)
		}
	}

	for scanner.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := scanner.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			writeResp(rpcResponse{
				JSONRPC: "2.0",
				Error:   &rpcError{Code: errParseError, Message: "parse error: " + err.Error()},
			})
			continue
		}
		if req.JSONRPC != "2.0" {
			writeResp(rpcResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &rpcError{Code: errInvalidRequest, Message: "jsonrpc must be '2.0'"},
			})
			continue
		}
		isNotification := len(req.ID) == 0

		result, rpcErr := s.dispatch(ctx, req)

		if isNotification {
			// JSON-RPC notifications get no response.
			continue
		}
		resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}
		if rpcErr != nil {
			resp.Error = rpcErr
		} else {
			resp.Result = result
		}
		writeResp(resp)
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("mcp.Run: scan: %w", err)
	}
	return nil
}

// dispatch routes a parsed request to its handler. Returns either a result
// or an rpcError (never both).
func (s *Server) dispatch(ctx context.Context, req rpcRequest) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		return s.handleInitialize(req.Params)
	case "notifications/initialized":
		return nil, nil // no-op, notification
	case "ping":
		return struct{}{}, nil
	case "tools/list":
		return s.handleToolsList()
	case "tools/call":
		return s.handleToolsCall(ctx, req.Params)
	default:
		return nil, &rpcError{Code: errMethodNotFound, Message: "method not found: " + req.Method}
	}
}

func (s *Server) handleInitialize(params json.RawMessage) (any, *rpcError) {
	var p initializeParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &rpcError{Code: errInvalidParams, Message: "invalid initialize params: " + err.Error()}
		}
	}
	return initializeResult{
		ProtocolVersion: protocolVersion,
		Capabilities: serverCapabilities{
			Tools: &toolsCapability{ListChanged: false},
		},
		ServerInfo: serverInfo{Name: s.name, Version: s.version},
	}, nil
}

func (s *Server) handleToolsList() (any, *rpcError) {
	s.mu.RLock()
	names := make([]string, 0, len(s.tools))
	for n := range s.tools {
		names = append(names, n)
	}
	s.mu.RUnlock()
	sort.Strings(names)

	out := make([]toolDescriptor, 0, len(names))
	s.mu.RLock()
	for _, n := range names {
		t := s.tools[n]
		out = append(out, toolDescriptor{
			Name:        t.Name(),
			Description: t.Description(),
			InputSchema: t.InputSchema(),
		})
	}
	s.mu.RUnlock()
	return toolsListResult{Tools: out}, nil
}

func (s *Server) handleToolsCall(ctx context.Context, params json.RawMessage) (any, *rpcError) {
	var p toolCallParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &rpcError{Code: errInvalidParams, Message: "invalid tools/call params: " + err.Error()}
	}
	s.mu.RLock()
	tool, ok := s.tools[p.Name]
	s.mu.RUnlock()
	if !ok {
		return nil, &rpcError{Code: errMethodNotFound, Message: "unknown tool: " + p.Name}
	}
	callCtx := ctx
	var cancel context.CancelFunc
	if s.toolCallTimeout > 0 {
		callCtx, cancel = context.WithTimeout(ctx, s.toolCallTimeout)
		defer cancel()
	}
	result, err := tool.Invoke(callCtx, p.Arguments)
	if errors.Is(callCtx.Err(), context.DeadlineExceeded) {
		s.logger.Warn("mcp: tool call exceeded read-transaction watchdog deadline",
			"tool", p.Name, "timeout", s.toolCallTimeout)
		err = fmt.Errorf("tool call timed out after %s: %w", s.toolCallTimeout, callCtx.Err())
	}
	if err != nil {
		// Tool errors are returned as in-band tool-result errors (isError=true),
		// not JSON-RPC transport errors — per MCP spec, so the model can see
		// the failure and recover.
		return toolCallResult{
			Content: []toolContent{{Type: "text", Text: err.Error()}},
			IsError: true,
		}, nil
	}
	body, mErr := json.MarshalIndent(result, "", "  ")
	if mErr != nil {
		return nil, &rpcError{Code: errInternalError, Message: "marshal tool result: " + mErr.Error()}
	}
	return toolCallResult{
		Content: []toolContent{{Type: "text", Text: string(body)}},
	}, nil
}

func defaultIfEmpty(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
