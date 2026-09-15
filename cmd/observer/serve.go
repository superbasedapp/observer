package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/intelligence/learn"
	"github.com/marmutapp/superbased-observer/internal/mcp"
	"github.com/marmutapp/superbased-observer/internal/mcp/audit"
	"github.com/marmutapp/superbased-observer/internal/stash"
	"github.com/marmutapp/superbased-observer/internal/stashalign"
)

// serveToolCallTimeout is the MCP-side read-transaction watchdog. MCP tools
// should be bounded queries; two minutes leaves headroom for large local
// databases while preventing a wedged client/query from pinning WAL forever.
const serveToolCallTimeout = 2 * time.Minute

// newServeCmd implements `observer serve` — the stdio MCP server
// entrypoint that AI tools spawn via their MCP configuration. Logs go to
// stderr; stdout is reserved for JSON-RPC.
func newServeCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the MCP server on stdio (spawned by AI tools)",
		Long: "Starts the Model Context Protocol server over stdio. Meant to be\n" +
			"launched by an AI tool per its MCP configuration, NOT run\n" +
			"interactively. Use `observer init` to register this command with\n" +
			"the tools you use.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			if err := os.MkdirAll(filepath.Dir(cfg.Observer.DBPath), 0o755); err != nil {
				return fmt.Errorf("ensure db dir: %w", err)
			}
			// No integrity probe here: the MCP server is a short-lived subprocess
			// the AI tool spawns per session against the daemon-owned DB — the
			// daemon already ran quick_check at its own startup. Re-running it
			// here just contends with the daemon's WAL holder AND, on a large
			// DB, can push the first `initialize` response past the MCP
			// client's startup timeout ("Couldn't start Observer MCP server").
			// Same rationale as the hook path (feedback_hook_db_open_no_timeout).
			database, err := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
			if err != nil {
				return fmt.Errorf("open db %s: %w", cfg.Observer.DBPath, err)
			}
			defer database.Close()
			// `observer serve` can live for days under an MCP client. Keep a
			// small idle pool (not zero — db.Open's ConnMaxIdleTime default
			// already reaps genuinely idle connections, and SetMaxIdleConns(0)
			// forces database/sql to close+reopen a connection after EVERY
			// call, defeating the DSN-level pragmas applied at open) so an
			// old process cannot retain a stale read snapshot and pin
			// observer.db-wal between requests, while still amortizing the
			// open cost across back-to-back tool calls.
			database.SetMaxIdleConns(2)

			// Stderr logger — stdout belongs to JSON-RPC.
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
				Level: logLevelFromString(cfg.Observer.LogLevel),
			}))
			mcpOpts := mcp.Options{
				DB:              database,
				Logger:          logger,
				ServerName:      "observer",
				ServerVersion:   version,
				ToolCallTimeout: serveToolCallTimeout,
				CostEngine:      acquireProcessCostEngine(cmd.Context(), cfg, database, logger),
				CacheWarm:       cfg.CacheWarm,
				Tasks:           cfg.Tasks,
				SignalRecorder:  learn.NewSignalRecorder(database),
				// Session handoff (docs/session-handoff.md P2): the shared
				// handoffsvc runner behind the continue_session tool.
				BuildHandoff: handoffRunner(cfg, database),
				// get_session_message: re-read one un-excerpted message of a
				// source session on demand (message-addressable handoff).
				GetSessionMessage: messageReader(cfg, database),
			}
			if cfg.Compression.Conversation.Stash.Enabled {
				st, err := stash.New(stash.Options{
					Dir:        cfg.Compression.Conversation.Stash.Dir,
					MaxTotalMB: cfg.Compression.Conversation.Stash.MaxTotalMB,
				})
				if err != nil {
					logger.Warn("mcp: stash init failed; retrieve_stashed will not be registered", "err", err)
				} else {
					mcpOpts.Stash = st
					// V7-8 transparency: log the active stash dir at
					// Info so operators can verify proxy ↔ MCP server
					// alignment by comparing startup logs.
					logger.Info("mcp: stash dir active",
						"dir", cfg.Compression.Conversation.Stash.Dir,
						"max_total_mb", cfg.Compression.Conversation.Stash.MaxTotalMB)
					// V7-8 cross-process detection (v1.7.13): if a
					// proxy on this host wrote a sidecar advertising
					// its stash dir, compare against ours. Mismatch
					// surfaces a loud warning naming both paths so
					// the operator can repoint one side. No sidecar
					// = no proxy ran yet (or it predates v1.7.13);
					// log an info note pointing at where to look.
					if home, herr := stashalign.DefaultObserverHome(); herr == nil {
						proxyDir, rerr := stashalign.ReadSidecar(home)
						switch {
						case rerr != nil:
							logger.Warn("mcp: stash-dir sidecar unreadable; skipping cross-process check",
								"err", rerr, "sidecar", stashalign.SidecarPath(home))
						case proxyDir == "":
							logger.Info("mcp: no proxy-side stash sidecar found (proxy may not have started yet, or runs an older observer)",
								"sidecar", stashalign.SidecarPath(home))
						default:
							ok, hint := stashalign.CompareDirs(cfg.Compression.Conversation.Stash.Dir, proxyDir)
							if !ok {
								logger.Warn("mcp: stash dir mismatch with proxy — retrieve_stashed will see misses",
									"hint", hint,
									"mcp_dir", cfg.Compression.Conversation.Stash.Dir,
									"proxy_dir", proxyDir,
									"sidecar", stashalign.SidecarPath(home))
							} else {
								logger.Info("mcp: stash dir aligned with proxy", "shared_dir", proxyDir)
							}
						}
					}
				}
			}
			// V7-16 features list — top-level allow-list for the four
			// V7-12 retrieval tools. Empty = no filter applied; per-
			// tool `enabled = false` always wins. See
			// docs/plans/v1.7.11-stash-retrieval-correctness-plan-2026-05-31.md
			// (D-3) for the V7-12-only scope decision rationale.
			mcpOpts.Features = cfg.Intelligence.MCP.Features
			// V7-12 retrieve_stashed (v1.7.11, fourth of four). Enabled
			// flag here gates registration independently of Options.Stash
			// — operators wanting "proxy compression yes, agent retrieval
			// no" set [intelligence.mcp.retrieve_stashed].enabled = false.
			if !cfg.Intelligence.MCP.RetrieveStashed.Enabled {
				mcpOpts.RetrieveStashedDisabled = true
				if cfg.Compression.Conversation.Stash.Enabled {
					logger.Info("mcp: retrieve_stashed disabled by config; stash compression still active on the proxy")
				}
			}
			mcpOpts.RetrieveStashedMaxShasPerCall = cfg.Intelligence.MCP.RetrieveStashed.MaxShasPerCall
			// V7-14 audit writer — wired before get_file so the tool's
			// AuditWriter is non-nil even when audit is disabled
			// (NoopWriter keeps the call signature uniform). Defer
			// Close so buffered rows flush at server shutdown.
			var auditCloser interface{ Close() error }
			if cfg.Intelligence.MCP.Audit.Enabled {
				w := audit.NewSQLWriter(database, logger, audit.SQLWriterOptions{})
				mcpOpts.AuditWriter = w
				auditCloser = w
			} else {
				mcpOpts.AuditWriter = audit.NewNoopWriter()
				logger.Info("mcp: audit log disabled — V7-12 tool calls will not be recorded")
			}
			defer func() {
				if auditCloser != nil {
					_ = auditCloser.Close()
				}
			}()
			// V7-12 get_file (v1.7.8, first of four retrieval-surface
			// tools). Defaults to ON; opt-out via
			// [intelligence.mcp.get_file].enabled = false.
			if cfg.Intelligence.MCP.GetFile.Enabled {
				mcpOpts.GetFileEnabled = true
				mcpOpts.GetFile = mcp.GetFileOptions{
					AllowExtensions: cfg.Intelligence.MCP.GetFile.AllowExtensions,
					DenyPaths:       cfg.Intelligence.MCP.GetFile.DenyPaths,
					MaxResponseKB:   cfg.Intelligence.MCP.GetFile.MaxResponseKB,
				}
				// Operator-visibility: warn once per silently-dead
				// deny pattern. Unsupported glob syntax is inert at
				// match time, which is the wrong default behavior
				// for a security control.
				for _, p := range cfg.Intelligence.MCP.GetFile.UnsupportedDenyPatterns() {
					logger.Warn("mcp.get_file: deny pattern uses unsupported glob syntax (inert; use * ? or <dir>/**)",
						"pattern", p)
				}
			}
			// Wire the code-intelligence provider into the MCP layer
			// (get_symbols / get_relations / check_file_freshness +
			// get_file_history structure enrichment). The NATIVE codeintel
			// engine is the only provider (Phase 4 decommissioned the
			// external code-graph dependency); it self-heals as projects
			// are indexed. Best-effort: an unavailable provider just
			// degrades enrichment.
			mcpOpts.CodeIntel = buildCodeIntelProvider(cfg, database, logger)
			// V7-12 get_symbols (v1.7.9, second of four). Shares
			// path-safety knobs with get_file; relations caps come
			// from its own block. Registration succeeds even when
			// the code index is unavailable — every per-request response
			// then carries `degraded: true` and the agent falls back
			// to get_file.
			if cfg.Intelligence.MCP.GetSymbols.Enabled {
				mcpOpts.GetSymbolsEnabled = true
				mcpOpts.GetSymbols = mcp.GetSymbolsOptions{
					AllowExtensions: cfg.Intelligence.MCP.GetFile.AllowExtensions,
					DenyPaths:       cfg.Intelligence.MCP.GetFile.DenyPaths,
					MaxResponseKB:   cfg.Intelligence.MCP.GetFile.MaxResponseKB,
					MaxCallers:      cfg.Intelligence.MCP.GetSymbols.MaxCallers,
					MaxCallees:      cfg.Intelligence.MCP.GetSymbols.MaxCallees,
				}
			}
			// V7-12 get_relations (v1.7.10, third of four). Shares
			// path-safety knobs with get_file; BFS bounds come from
			// its own block. Same registration semantics as
			// get_symbols — registers regardless of code-index
			// availability, degrades at call time.
			if cfg.Intelligence.MCP.GetRelations.Enabled {
				mcpOpts.GetRelationsEnabled = true
				mcpOpts.GetRelations = mcp.GetRelationsOptions{
					AllowExtensions: cfg.Intelligence.MCP.GetFile.AllowExtensions,
					DenyPaths:       cfg.Intelligence.MCP.GetFile.DenyPaths,
					MaxDepth:        cfg.Intelligence.MCP.GetRelations.MaxDepth,
					MaxResults:      cfg.Intelligence.MCP.GetRelations.MaxResults,
				}
			}
			s, err := mcp.New(mcpOpts)
			if err != nil {
				return err
			}
			if err := s.Run(ctx, os.Stdin, os.Stdout); err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	return cmd
}

func logLevelFromString(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
