package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/mcprelay"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/coverage"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/project"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/record"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// `observer mcp-relay` — the Agent Access P4 node relay operator surface
// (doc3 §12.1/§12.2/§12.7/§12.8): status (compiled table, record chain,
// pending loss, remote forwarding, what was projected, the client x
// transport x method coverage matrix), enable (config flag + the
// projection NOW), disable / restore (through the launch journal's rule
// table), and `wrap` — the TRUE stdio-wrapper entry the AI clients spawn in
// place of the original server.

const mcpRelayRestartNote = "The relay rides the daemon's :8820. Never stop/restart the daemon while an\n" +
	"MCP session or a proxied route is live: route OFF -> stop -> relaunch ->\n" +
	"route ON, as one atomic op (docs/daemon-restart-runbook.md)."

// mcpRelayRemoteProbeTimeout bounds the status / enable remote resolution
// (an idempotent registration against the org server).
const mcpRelayRemoteProbeTimeout = 10 * time.Second

func newMCPRelayCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp-relay",
		Short: "Node MCP relay: status, enable/disable, journal restore, stdio wrapper (older spelling of `observer mcp`)",
		Long: "Operate the node-side MCP relay that mediates this machine's AI clients'\n" +
			"MCP traffic against the organization's signed tools.mcp_access grant\n" +
			"(local PDP + hash-chained decision record), and inspect what the\n" +
			"best-effort node points (proxy tools[] filter, PreToolUse hook deny,\n" +
			"config projection) actually cover — the coverage-honesty matrix.\n\n" +
			mcpRelayRestartNote,
	}
	cmd.AddCommand(newMCPRelayStatusCmd())
	cmd.AddCommand(newMCPRelayEnableCmd())
	cmd.AddCommand(newMCPRelayDisableCmd())
	cmd.AddCommand(newMCPRelayRestoreCmd())
	cmd.AddCommand(newMCPRelayWrapCmd())
	return cmd
}

// mcpRelayStatus is the JSON shape `status --json` prints.
type mcpRelayStatus struct {
	Enabled          bool                      `json:"enabled"`
	Mode             string                    `json:"mode"`
	AuditMode        string                    `json:"audit_mode"`
	Listen           string                    `json:"listen,omitempty"`
	GatewayURL       string                    `json:"gateway_url,omitempty"`
	TableLoaded      bool                      `json:"table_loaded"`
	TableVersion     int64                     `json:"table_version,omitempty"`
	TableMode        string                    `json:"table_mode,omitempty"`
	TableRows        int                       `json:"table_rows,omitempty"`
	PolicyGen        int64                     `json:"policy_gen,omitempty"`
	CachePath        string                    `json:"cache_path"`
	EffectiveHash    string                    `json:"effective_hash,omitempty"`
	PointStatus      string                    `json:"point_status"`
	MissingCaps      []string                  `json:"missing_capabilities,omitempty"`
	ApprovedVServers []string                  `json:"approved_vservers,omitempty"`
	ChainHead        int64                     `json:"chain_head"`
	ChainOK          *bool                     `json:"chain_ok,omitempty"`
	PendingLoss      int64                     `json:"pending_loss"`
	LaunchSpecs      int                       `json:"launch_specs"`
	ProjectedClients []string                  `json:"projected_clients,omitempty"`
	RemoteForwarding mcpRelayRemote            `json:"remote_forwarding"`
	Coverage         map[coverage.Coverage]int `json:"coverage"`
}

func newMCPRelayStatusCmd() *cobra.Command {
	var (
		configPath string
		jsonOut    bool
		noMatrix   bool
		noRemote   bool
	)
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Print the relay's compiled table, record chain, remote forwarding, projection state and the coverage matrix",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)
			logger := slog.New(slog.DiscardHandler)
			h := newMCPRelayHandle(cfg, st, nil, logger)
			rs := record.NewSQLStore(database, mcpRelayNodeKey(cmd.Context(), cfg, st))
			// Remote forwarding: the SAME derivation the daemon runs at start
			// (an idempotent registration), so status tells the truth about
			// what the daemon would wire, with the honest reason when off.
			var remote mcpRelayRemote
			if noRemote {
				remote = mcpRelayRemote{Reason: "not probed (--no-remote)"}
			} else {
				pctx, pcancel := context.WithTimeout(cmd.Context(), mcpRelayRemoteProbeTimeout)
				_, _, remote = resolveMCPRelayRemote(pctx, cfg, st, h, defaultMCPRelayRemoteDeps(cfg, st, logger), logger)
				pcancel()
			}
			s, rows := buildMCPRelayStatus(cmd.Context(), cfg, h, rs, remote, true)
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(s)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "mcp-relay: enabled=%v mode=%s audit=%s listen=%q gateway=%q\n", s.Enabled, s.Mode, s.AuditMode, s.Listen, s.GatewayURL)
			if s.TableLoaded {
				fmt.Fprintf(out, "table: version=%d mode=%s rows=%d policy_gen=%d cache=%s\n", s.TableVersion, s.TableMode, s.TableRows, s.PolicyGen, s.CachePath)
				fmt.Fprintf(out, "approved vservers: %s\n", strings.Join(s.ApprovedVServers, ", "))
			} else {
				fmt.Fprintf(out, "table: none loaded (cache %s) — no tools.mcp_access resource accepted yet, or the relay is disabled\n", s.CachePath)
			}
			r := s.RemoteForwarding
			if r.Wired {
				fmt.Fprintf(out, "remote forwarding: ON credential_id=%s cred_gen=%d machine_fp=%s registered_at=%s issuer=%s\n", r.CredentialID, r.CredGen, r.MachineFP, r.RegisteredAt, r.Issuer)
			} else {
				fmt.Fprintf(out, "remote forwarding: OFF (%s)\n", r.Reason)
			}
			fmt.Fprintf(out, "projection: verified on disk for %d client(s) [%s]; launch_specs=%d\n", len(s.ProjectedClients), strings.Join(s.ProjectedClients, ", "), s.LaunchSpecs)
			fmt.Fprintf(out, "point: %s", s.PointStatus)
			if len(s.MissingCaps) > 0 {
				fmt.Fprintf(out, " (missing %s)", strings.Join(s.MissingCaps, ", "))
			}
			if s.EffectiveHash != "" {
				fmt.Fprintf(out, " effective_hash=%s", s.EffectiveHash)
			}
			fmt.Fprintln(out)
			chain := "unverified"
			if s.ChainOK != nil {
				chain = "ok"
				if !*s.ChainOK {
					chain = "TAMPER"
				}
			}
			fmt.Fprintf(out, "record chain: head=%d verify=%s pending_loss=%d\n", s.ChainHead, chain, s.PendingLoss)
			if !noMatrix {
				fmt.Fprintln(out)
				fmt.Fprint(out, coverage.Render(rows))
			}
			fmt.Fprintln(out)
			fmt.Fprintln(out, mcpRelayRestartNote)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml (default ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON")
	cmd.Flags().BoolVar(&noMatrix, "no-matrix", false, "omit the coverage matrix")
	cmd.Flags().BoolVar(&noRemote, "no-remote", false, "do not probe remote forwarding (no org-server registration call)")
	return cmd
}

// buildMCPRelayStatus is the ONE relay status derivation, shared by
// `observer mcp[-relay] status` and the node dashboard's GET
// /api/mcp-access/status (mcp_access_dashboard.go), so the two can never
// disagree. The caller resolves remote forwarding (the CLI probes the org
// server; the daemon reuses what its relay runtime resolved at start) and
// owns h: h must be a handle built for this read (newMCPRelayHandle), never
// the daemon's live one, because the verified-projection flag is set on it
// from the journal. verifyChain walks the whole record chain (the CLI always
// does; a polled read may skip it, leaving chain_ok absent = unverified).
// Returns the status and the coverage matrix rows it summarises.
func buildMCPRelayStatus(ctx context.Context, cfg config.Config, h *mcpRelayHandle, rs *record.SQLStore, remote mcpRelayRemote, verifyChain bool) (mcpRelayStatus, []coverage.Row) {
	s := mcpRelayStatus{
		Enabled: cfg.MCPRelay.Enabled, Mode: cfg.MCPRelay.Mode, AuditMode: cfg.MCPRelay.AuditMode,
		Listen: cfg.MCPRelay.Listen, GatewayURL: mcpRelayGatewayURL(cfg, h.Table()), CachePath: h.cache.Path,
		RemoteForwarding: remote,
	}
	if t := h.Table(); t != nil {
		s.TableLoaded = true
		s.TableVersion, s.TableMode, s.TableRows, s.PolicyGen = t.Meta.Version, string(t.Mode), len(t.Node.Rows), t.PolicyGen()
		for _, v := range t.Node.Registry.VServers {
			s.ApprovedVServers = append(s.ApprovedVServers, v.ID)
		}
	}
	s.ProjectedClients = projectedClients(ctx, rs)
	h.SetProjectionApplied(len(s.ProjectedClients) > 0)
	status, missing := coverage.Status(coverage.PointRelay, h.pointCapabilities())
	s.PointStatus, s.MissingCaps = string(status), missing
	if f, ok := h.Facts(); ok {
		s.EffectiveHash = f.EffectiveHash
	}
	if head, herr := rs.Head(ctx); herr == nil {
		s.ChainHead = head.Seq
	}
	if verifyChain && s.ChainHead > 0 {
		if vr, verr := rs.Verify(ctx); verr == nil {
			ok := vr.OK()
			s.ChainOK = &ok
		}
	}
	if pl, perr := rs.PendingLoss(ctx, record.DefaultFamily); perr == nil {
		s.PendingLoss = pl.Count
	}
	if specs, lerr := rs.ListLaunchSpecs(ctx); lerr == nil {
		s.LaunchSpecs = len(specs)
	}
	rows := coverage.Matrix(mcpRelayCoverageLive(ctx, cfg, rs, h, s.RemoteForwarding.Wired))
	s.Coverage = coverage.Summary(rows)
	return s, rows
}

// setMCPRelayEnabled patches [mcp_relay].enabled in the operator's config
// file (surgical patch, comments kept when possible).
func setMCPRelayEnabled(configPath string, enabled bool) (string, error) {
	path, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return "", err
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
	if err != nil {
		return "", err
	}
	rhs := "false"
	if enabled {
		rhs = "true"
	}
	if _, err := config.PatchFile(path, cfg, []config.Patch{{Dotted: "mcp_relay.enabled", RHS: rhs, Scalar: true}}); err != nil {
		return "", err
	}
	return path, nil
}

// printProjectionReport renders Apply receipts for the operator.
func printProjectionReport(out func(string, ...any), rep project.Report, remoteSkip string) (changed, failed int) {
	for _, r := range rep.Receipts {
		switch {
		case r.Err != "":
			failed++
			out("mcp-relay project: %s %s: %s", r.Client.Tool, r.Client.ConfigPath, r.Err)
		case r.Skipped != "":
			out("mcp-relay project: %s skipped (%s)", r.Client.Tool, r.Skipped)
		case r.Changed:
			changed++
			out("mcp-relay project: %s %s wrapped=[%s] remote=[%s] backup=%s", r.Client.Tool, r.Client.ConfigPath, strings.Join(r.Wrapped, ","), strings.Join(r.Remote, ","), r.BackupPath)
		default:
			out("mcp-relay project: %s %s already projected (no change)", r.Client.Tool, r.Client.ConfigPath)
		}
		for _, f := range r.Refused {
			out("mcp-relay project: %s entry %q NOT wrapped (%s): it runs direct, unmediated", r.Client.Tool, f.Key, f.Reason)
		}
		if r.Note != "" {
			out("mcp-relay project: %s note: %s", r.Client.Tool, r.Note)
		}
	}
	if remoteSkip != "" {
		out("mcp-relay project: remote entries not projected: %s", remoteSkip)
	}
	return changed, failed
}

func newMCPRelayEnableCmd() *cobra.Command {
	var (
		configPath string
		noRemote   bool
	)
	cmd := &cobra.Command{
		Use:   "enable",
		Short: "Set [mcp_relay].enabled = true and project every installed AI client's MCP config NOW",
		Long: "Writes [mcp_relay].enabled = true, then rewrites each installed AI\n" +
			"client's MCP entries: every stdio server is REPLACED by the relay's\n" +
			"stdio wrapper (`observer mcp-relay wrap --client <tool> --server <key>`)\n" +
			"and the approved vservers are projected as remote entries through the\n" +
			"relay's loopback listener. Every original is journaled in\n" +
			"mcp_relay_launch_spec with a verbatim backup BEFORE it is rewritten, so\n" +
			"`disable` and `restore` put it back. Idempotent. The relay listener\n" +
			"itself binds when the daemon starts.\n\n" + mcpRelayRestartNote,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := setMCPRelayEnabled(configPath, true)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "mcp-relay: enabled in %s\n", path)
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)
			logger := slog.New(slog.DiscardHandler)
			h := newMCPRelayHandle(cfg, st, nil, logger)
			rs := record.NewSQLStore(database, "")
			remote := mcpRelayRemote{Reason: "not probed (--no-remote)"}
			if !noRemote {
				pctx, pcancel := context.WithTimeout(cmd.Context(), mcpRelayRemoteProbeTimeout)
				_, _, remote = resolveMCPRelayRemote(pctx, cfg, st, h, defaultMCPRelayRemoteDeps(cfg, st, logger), logger)
				pcancel()
			}
			rep, remoteSkip, err := runMCPRelayProjection(cmd.Context(), cfg, configPath, rs, h, remote.Wired)
			if err != nil {
				return fmt.Errorf("mcp-relay enable: projection: %w", err)
			}
			out := func(f string, a ...any) { fmt.Fprintf(cmd.OutOrStdout(), f+"\n", a...) }
			changed, failed := printProjectionReport(out, rep, remoteSkip)
			if remote.Wired {
				out("mcp-relay: remote forwarding ON (credential %s gen %d)", remote.CredentialID, remote.CredGen)
			} else {
				out("mcp-relay: remote forwarding OFF (%s)", remote.Reason)
			}
			out("mcp-relay: projected %d client config(s), %d failed; restart the daemon (route OFF -> stop -> relaunch -> route ON) to bind the relay seams", changed, failed)
			if failed > 0 {
				return errors.New("mcp-relay enable: some client configs were not projected (see above)")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml (default ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&noRemote, "no-remote", false, "do not resolve remote forwarding (no org-server registration call; remote entries are not projected)")
	return cmd
}

// printRestoreReport renders Restore receipts for the operator and returns
// (restored, failed).
func printRestoreReport(out func(string, ...any), recs []project.RestoreReceipt) (restored, failed int) {
	for _, r := range recs {
		switch {
		case r.Err != "":
			failed++
			out("mcp-relay restore: %s %s: %s (journal + backup kept)", r.Client.Tool, r.Client.ConfigPath, r.Err)
		case r.Restored:
			restored++
			note := ""
			if r.Note != "" {
				note = " — " + r.Note
			}
			out("mcp-relay restore: %s %s restored (%s, rule %s, %d row(s))%s", r.Client.Tool, r.Client.ConfigPath, r.Mode, r.Rule, r.Rows, note)
		}
	}
	return restored, failed
}

// runMCPRelayRestore is the shared disable / restore body.
func runMCPRelayRestore(cmd *cobra.Command, configPath string) error {
	cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
	if err != nil {
		return err
	}
	defer cleanup()
	h := newMCPRelayHandle(cfg, store.New(database), nil, slog.New(slog.DiscardHandler))
	recs, rerr := restoreMCPRelayProjection(cmd.Context(), cfg, record.NewSQLStore(database, ""), h)
	out := func(f string, a ...any) { fmt.Fprintf(cmd.OutOrStdout(), f+"\n", a...) }
	restored, failed := printRestoreReport(out, recs)
	if rerr != nil && failed == 0 {
		return rerr
	}
	out("mcp-relay: restored %d client config(s), %d failed", restored, failed)
	if failed > 0 {
		return errors.New("mcp-relay restore: some client configs were not restored (see above; journal rows and backups are kept)")
	}
	return nil
}

func newMCPRelayDisableCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Set [mcp_relay].enabled = false and restore every journaled client config",
		Long: "Writes [mcp_relay].enabled = false, then restores each AI client's MCP\n" +
			"config from the launch journal: byte-identically from the hash-checked\n" +
			"backup when the file still holds exactly what the relay wrote, else by\n" +
			"reversing ONLY the relay-owned entries (a post-projection edit is\n" +
			"preserved, never clobbered). A config that cannot be restored keeps its\n" +
			"journal row and backup and is reported.\n\n" + mcpRelayRestartNote,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := setMCPRelayEnabled(configPath, false)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "mcp-relay: disabled in %s\n", path)
			if err := runMCPRelayRestore(cmd, configPath); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "mcp-relay: restart the daemon (route OFF first) to unbind the seams")
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml (default ~/.observer/config.toml)")
	return cmd
}

func newMCPRelayRestoreCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore every journaled client config without changing [mcp_relay].enabled",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMCPRelayRestore(cmd, configPath)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml (default ~/.observer/config.toml)")
	return cmd
}

func newMCPRelayWrapCmd() *cobra.Command {
	var (
		configPath string
		serverID   string
		client     string
		grace      time.Duration
	)
	cmd := &cobra.Command{
		Use:   "wrap --client <tool> --server <entry-key>",
		Short: "Stdio wrapper: spawn the journaled original MCP server and mediate every frame (spawned by the AI client)",
		Long: "The AI client's rewritten MCP entry runs this in place of the original\n" +
			"server. It resolves the ORIGINAL command from the launch journal,\n" +
			"spawns it with the client's cwd/environment (secret references resolved\n" +
			"from this process's own environment, never persisted), relays JSON-RPC\n" +
			"frames byte-exactly, and mediates each request through the local PDP\n" +
			"and the hash-chained decision record before the child sees it. A\n" +
			"SIGINT/SIGTERM/SIGHUP is forwarded to the original first; it gets\n" +
			"--grace to exit before it is killed; its exit code is propagated. Not\n" +
			"for interactive use.",
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if serverID == "" {
				return errors.New("mcp-relay wrap: --server is required")
			}
			// The wrapper's OWN working directory, recorded at spawn: the AI
			// client launched it inside the project, so this is the one
			// project the relay attests for the stream (P11 fold PF2). An
			// unreadable cwd is no project context, never a failure.
			projectDir, _ := os.Getwd()
			// No signal.NotifyContext here (Sol P3+P4 finding 6): the
			// child's lifetime is the wrapper's forward -> grace -> kill
			// ladder, never a context cancel. During the config/DB phase
			// the default signal disposition applies.
			ctx := cmd.Context()
			cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			if !cfg.MCPRelay.Enabled {
				return errors.New("mcp-relay wrap: [mcp_relay].enabled is false — run `observer mcp-relay restore` to put the original client config back")
			}
			logger := slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{Level: slog.LevelWarn}))
			st := store.New(database)
			h := newMCPRelayHandle(cfg, st, nil, logger)
			rt, err := buildMCPRelay(ctx, cfg, database, st, h, logger, nil, nil)
			if err != nil {
				return err
			}
			spec, err := launchSpecsFromJournal{st: rt.records}.Lookup(ctx, client, serverID)
			if err != nil {
				return err
			}
			sigs := make(chan os.Signal, 4)
			signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
			defer signal.Stop(sigs)
			err = rt.relay.ServeStdioWrapper(ctx, mcprelay.WrapperOptions{
				Spec:       spec,
				Stdin:      cmd.InOrStdin(),
				Stdout:     cmd.OutOrStdout(),
				Stderr:     cmd.ErrOrStderr(),
				Attestor:   mcprelay.DefaultAttestor(),
				Signals:    sigs,
				Grace:      grace,
				Corr:       mcpRelayWrapperCorr(),
				ProjectDir: projectDir,
			})
			var ce *mcprelay.ChildExitError
			if errors.As(err, &ce) {
				if ce.Code > 0 {
					return exitErr(ce.Code)
				}
				return exitErr(1)
			}
			return err
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml (default ~/.observer/config.toml)")
	cmd.Flags().StringVar(&serverID, "server", "", "launch-journal entry key of the original server")
	cmd.Flags().StringVar(&client, "client", "", "AI client tool id the entry belongs to (disambiguates the same key across clients)")
	cmd.Flags().DurationVar(&grace, "grace", mcprelay.DefaultGrace, "how long a forwarded SIGINT/SIGTERM/SIGHUP gives the original server before it is killed")
	return cmd
}
