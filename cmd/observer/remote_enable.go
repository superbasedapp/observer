//go:build !sbo_omit_remote

package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/remotecfg"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/tailnet"
)

// advanceRemoteSessionFence durably invalidates every persisted device session
// (persist-remote-sessions plan §5): it clears the node-local remote_sessions
// rows and advances the durable generation in the daemon DB, so that after the
// next restart no previously-paired cookie can re-validate. `enable`, `disable`,
// and `rotate` run in a SEPARATE process from the daemon and cannot touch its
// in-memory store, so this shared durable fence is how they invalidate sessions.
// Codex §7 ordering: callers advance the fence FIRST (durably invalidate), THEN
// mutate the secret/config. A missing DB path is created + migrated by db.Open;
// WAL + busy_timeout make the short cross-process write safe while the daemon
// holds the DB.
func advanceRemoteSessionFence(ctx context.Context, cfg config.Config) error {
	database, err := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		return fmt.Errorf("open db for remote-session fence: %w", err)
	}
	defer database.Close()
	if _, err := store.New(database).AdvanceRemoteSessionGeneration(ctx); err != nil {
		return err
	}
	return nil
}

// Phase 2 of the remote-dashboard-access plan (§6): `observer remote enable |
// disable | rotate` as an atomic create-validate-persist transaction over the
// pairing-secret file + [remote] config. v1 scope is tailnet-HTTPS-only
// (operator decision 2026-07-12): the operator runs `tailscale serve` and
// Observer serves plaintext on a dedicated loopback backend behind it. These
// verbs provision the credential + config; the backend listener binds on the
// next `observer start` (the daemon is NOT hot-restarted here — the running
// proxy IS the :8820 listener and a mid-flight restart breaks live sessions;
// see the daemon-restart-runbook. The verb prints the restart instruction).
//
// The arm/disarm/rotate TRANSACTION lives in internal/remotecfg (the ONE owner,
// shared byte-identically with the dashboard `/api/remote/*` handlers, plan
// §B). These commands are thin CLI shells: argument parsing + human-formatted
// output only.

// newRemoteEnableCmd arms tailnet remote access: mint a pairing secret, hash it
// at rest (argon2id, 0600), pin a loopback backend port + the tailnet Host
// allow-list, and persist [remote] atomically. Prints the QR/pairing URL + the
// `tailscale serve` command + the restart instruction.
func newRemoteEnableCmd(configPath *string) *cobra.Command {
	var (
		useTailscale  bool
		useLAN        bool
		allowTerminal bool
		host          string
	)
	cmd := &cobra.Command{
		Use:   "enable",
		Short: "Arm tailnet remote access (mint pairing secret + [remote] config)",
		Long: "Provisions remote dashboard access over Tailscale HTTPS (view tier).\n" +
			"Mints a 128-bit pairing secret (stored hashed, argon2id, 0600), pins a\n" +
			"dedicated loopback backend for `tailscale serve` to forward to, and adds\n" +
			"the tailnet host to the Host allow-list. Default OFF elsewhere - this is\n" +
			"the explicit opt-in. Execute-tier terminal stays off unless --allow-terminal\n" +
			"is ALSO passed (a separate knob; view access never turns it on).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if useLAN {
				return fmt.Errorf("`--lan` is deferred (Phase 3, operator decision 2026-07-12 - tailnet-HTTPS-only for v1). Use --tailscale")
			}
			_ = useTailscale // tailscale is the only supported mode in v1; the flag documents intent
			out := cmd.OutOrStdout()

			cfg, err := config.Load(config.LoadOptions{GlobalPath: *configPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			cfgPath, err := config.ResolveGlobalPath(*configPath)
			if err != nil {
				return fmt.Errorf("resolve config path: %w", err)
			}

			// (0) Resolve the tailnet host (the Host the browser sends). Prefer
			// --host; else best-effort `tailscale status`. It MUST be known —
			// the Host allow-list has no fallback (plan §4.5, never "allow any").
			if strings.TrimSpace(host) == "" {
				host = detectTailnetHost(cmd.Context())
			}
			host = strings.TrimSpace(strings.TrimSuffix(host, "."))
			if host == "" {
				return fmt.Errorf("could not determine the tailnet host - pass it explicitly, e.g. `observer remote enable --tailscale --host my-machine.tailnet-name.ts.net` (it is the HTTPS host `tailscale serve` exposes; run `tailscale status` to find it)")
			}

			// Durable-first (codex §7): invalidate any sessions from a prior
			// arming BEFORE minting the new secret, so a re-arm never leaves an
			// old device able to re-validate after the next restart.
			if err := advanceRemoteSessionFence(cmd.Context(), cfg); err != nil {
				return fmt.Errorf("invalidate prior remote sessions: %w", err)
			}

			info, err := remotecfg.Enable(cfg, cfgPath, remotecfg.EnableOptions{
				Host:          host,
				AllowTerminal: allowTerminal,
			})
			if err != nil {
				return err
			}

			// Print the pairing URL + operator steps.
			fmt.Fprintf(out, "remote access ARMED (tailnet-HTTPS, view tier)\n\n")
			fmt.Fprintf(out, "  tailnet host:    %s\n", info.Host)
			fmt.Fprintf(out, "  backend (local): %s   (loopback-only; tailscale serve forwards here)\n", info.BackendAddr)
			fmt.Fprintf(out, "  allow_terminal:  %v\n", info.AllowTerminal)
			fmt.Fprintf(out, "  secret hash:     %s (0600)\n\n", info.SecretPath)
			fmt.Fprintf(out, "NEXT STEPS:\n")
			fmt.Fprintf(out, "  1. Point Tailscale at the backend (run once, on this machine):\n")
			fmt.Fprintf(out, "       tailscale serve --bg %s\n", remotecfg.BackendPortOnly(info.BackendAddr))
			fmt.Fprintf(out, "     (this terminates HTTPS on the tailnet and forwards to %s)\n", info.BackendAddr)
			fmt.Fprintf(out, "  2. Restart the observer daemon so the backend listener binds:\n")
			fmt.Fprintf(out, "       observer service restart   (takes the proxy routes off first and puts them back)\n")
			fmt.Fprintf(out, "  3. On your phone/laptop (same tailnet), open the pairing URL and pair:\n\n")
			fmt.Fprintf(out, "     %s\n\n", info.PairingURL)
			fmt.Fprintf(out, "  The secret rides the URL FRAGMENT (after #) - it is never sent to or logged\n")
			fmt.Fprintf(out, "  by the server. Treat this URL like a password; `observer remote rotate`\n")
			fmt.Fprintf(out, "  invalidates it. (QR rendering is a follow-up - the URL above is scannable\n")
			fmt.Fprintf(out, "  via any QR generator, or copy it directly.)\n")
			return nil
		},
	}
	cmd.Flags().BoolVar(&useTailscale, "tailscale", false, "Arm tailnet-HTTPS remote access (the only supported mode in v1)")
	cmd.Flags().BoolVar(&useLAN, "lan", false, "Not available yet - refuses")
	cmd.Flags().BoolVar(&allowTerminal, "allow-terminal", false, "Also enable the execute-tier remote terminal (default off - separate opt-in)")
	cmd.Flags().StringVar(&host, "host", "", "The tailnet HTTPS host (e.g. my-machine.tailnet.ts.net); auto-detected via `tailscale status` when omitted")
	return cmd
}

// newRemoteDisableCmd closes remote access: flip [remote] back to loopback-only
// and REMOVE the pairing secret (true revocation). The running daemon's live
// device sessions are dropped on the next restart (a fresh process starts with
// an empty session store); this verb prints that instruction.
func newRemoteDisableCmd(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "disable",
		Short: "Close remote access - revert to loopback-only + revoke the pairing secret",
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			cfg, err := config.Load(config.LoadOptions{GlobalPath: *configPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			cfgPath, err := config.ResolveGlobalPath(*configPath)
			if err != nil {
				return fmt.Errorf("resolve config path: %w", err)
			}
			// Durable-first (codex §7): revoke every persisted device session in
			// the DB BEFORE removing the secret/config, so no cookie survives a
			// restart. disable advances the SAME fence as rotate.
			if err := advanceRemoteSessionFence(cmd.Context(), cfg); err != nil {
				return fmt.Errorf("revoke remote sessions: %w", err)
			}
			removed, err := remotecfg.Disable(cfg, cfgPath)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "remote access DISABLED - reverted to loopback-only.\n")
			fmt.Fprintf(out, "  pairing secret removed: %v\n", removed)
			fmt.Fprintf(out, "  Restart the observer daemon to close the backend listener + drop live sessions.\n")
			fmt.Fprintf(out, "  (You may also want to run `tailscale serve --https=443 off` to stop forwarding.)\n")
			return nil
		},
	}
}

// newRemoteRotateCmd mints a FRESH pairing secret, invalidating the old one.
// Every currently-paired device must re-pair. Takes effect on the next daemon
// restart (the running controller loaded the old hash at construction).
func newRemoteRotateCmd(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "rotate",
		Short: "Rotate the pairing secret (invalidates all paired devices)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			cfg, err := config.Load(config.LoadOptions{GlobalPath: *configPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			cfgPath, err := config.ResolveGlobalPath(*configPath)
			if err != nil {
				return fmt.Errorf("resolve config path: %w", err)
			}
			// Durable-first (codex §7): invalidate every persisted device
			// session in the DB BEFORE minting the new secret, so no
			// previously-paired cookie survives the next restart. Only when
			// enabled (rotate requires it; the error path below handles the
			// not-enabled case without having touched the fence).
			if cfg.Remote.Enabled {
				if err := advanceRemoteSessionFence(cmd.Context(), cfg); err != nil {
					return fmt.Errorf("invalidate remote sessions: %w", err)
				}
			}
			info, err := remotecfg.Rotate(cfg, cfgPath)
			if err != nil {
				if !cfg.Remote.Enabled {
					return fmt.Errorf("remote access is not enabled - run `observer remote enable --tailscale` first")
				}
				return err
			}
			fmt.Fprintf(out, "pairing secret ROTATED - all previously paired devices are invalidated.\n")
			if info.Host != "" {
				fmt.Fprintf(out, "\n  Re-pair with:\n\n     %s\n\n", info.PairingURL)
			} else {
				fmt.Fprintf(out, "\n  Re-pair with the new fragment credential (%s)\n\n", info.EncodedSecret)
			}
			fmt.Fprintf(out, "  Restart the observer daemon so the new secret takes effect (the running\n")
			fmt.Fprintf(out, "  process loaded the previous hash at startup) and open privileged sockets tear down.\n")
			return nil
		},
	}
}

// detectTailnetHost best-effort resolves the tailnet HTTPS host from
// `tailscale status --json` (Self.DNSName). Returns "" when tailscale is not
// installed / not up — the caller then requires --host. It delegates to
// internal/tailnet, the ONE owner of the tailscale exec (shared with the
// dashboard's GET /api/remote/tailscale/status), so the exec is never
// reimplemented (CLAUDE.md #4).
func detectTailnetHost(ctx context.Context) string {
	return tailnet.Host(ctx)
}
