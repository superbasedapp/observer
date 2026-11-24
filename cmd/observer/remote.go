//go:build !sbo_omit_remote

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/remoteauth"
	"github.com/marmutapp/superbased-observer/internal/remotecfg"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// remoteSecretPath is the 0600 file holding the argon2id hash of the pairing
// secret at rest (remote-dashboard-access plan §4.3). It delegates to
// remotecfg.SecretPath (the one owner) — kept as a thin cmd-local alias so the
// existing call sites (buildRemoteController, remote status) read unchanged.
func remoteSecretPath(cfg config.Config) string {
	return remotecfg.SecretPath(cfg)
}

// buildRemoteController constructs the dashboard RemoteController from [remote],
// or returns nil when remote access is disabled OR the pairing-secret file is
// absent/unreadable. A nil controller keeps the dashboard loopback-only: a
// non-loopback bind fails closed (plan §4.6). This wires the §4.6 predicate now
// so Phase 2 (exposure) satisfies it simply by minting the secret + setting an
// explicit bind; no non-loopback listener is opened here.
func buildRemoteController(cfg config.Config, database *sql.DB) dashapi.RemoteController {
	if !cfg.Remote.Enabled {
		return nil
	}
	hashBytes, err := os.ReadFile(remoteSecretPath(cfg))
	if err != nil {
		return nil // no secret provisioned yet → not ready (fail closed)
	}
	hash := strings.TrimSpace(string(hashBytes))
	if hash == "" {
		return nil
	}
	// Host allow-list: the explicit configured bind host + trusted_hosts. Never
	// "allow any" (plan §4.5).
	var hosts []string
	if h := strings.TrimSpace(cfg.Remote.BindAddr); h != "" {
		hosts = append(hosts, h)
	}
	hosts = append(hosts, cfg.Remote.TrustedHosts...)
	if len(hosts) == 0 {
		return nil // no allow-list → Ready() would be false anyway
	}
	// Standing terminal-control secret (opt-in §B): load its argon2id hash-at-
	// rest so the running controller can verify it. A read failure / absent file
	// leaves it empty (the standing path then denies) — never fatal.
	standingHash := ""
	standingPath := remotecfg.StandingTerminalSecretPath(cfg)
	if b, rerr := os.ReadFile(standingPath); rerr == nil {
		standingHash = strings.TrimSpace(string(b))
	}
	return newRemoteController(dashapi.RemoteOptions{
		HashedSecret:                hash,
		AllowedHosts:                hosts,
		RateLimitPerMin:             cfg.Remote.RateLimitPerMin,
		AllowTerminal:               cfg.Remote.AllowTerminal,
		AllowTerminalView:           cfg.Remote.AllowTerminalView,
		AllowRemoteTerminalTakeover: cfg.Remote.AllowRemoteTerminalTakeover,

		StandingTerminalSecretHash: standingHash,
		StandingTerminalEnabled:    cfg.Remote.AllowStandingTerminalControl,
		// The revoke-vs-disable discriminator (operator decision A2). The live
		// controller sees both as the same ("", false) reload, so it asks the
		// DISK: a genuine revoke unlinks this file, while allow_terminal→false,
		// remote-disable and a plain config toggle all leave it in place. Only
		// a definite "no such file" is reported as absent — any other stat
		// outcome answers "present", so an unreadable directory or a transient
		// I/O error can never make a device throw away a valid secret.
		StandingSecretAtRest: func() bool {
			_, serr := os.Stat(standingPath)
			return !errors.Is(serr, fs.ErrNotExist)
		},
		// Single-use execute-capability lifetime. 0 ⇒ remoteauth's default
		// (10m), sized for a human round-trip to a mail/chat app to fetch the
		// capability + confirm codes. Single-use semantics are unaffected.
		CapabilityTTL: time.Duration(cfg.Remote.CapabilityTTLMinutes) * time.Minute,
		// Audit is the SESSION-LIFECYCLE sink: session_paired, session_revoked,
		// and the six auth_failed reasons handlePair distinguishes
		// (rate_limited / bad_request / bad_secret / session_limit /
		// session_create). It is a DIFFERENT seam from Options.RemoteAudit,
		// which carries the per-request http_request rows from remote.go's
		// authorize path — and because only the latter was ever wired, the
		// former silently no-op'd (remoteController.auditSession returns early
		// on a nil audit func).
		//
		// The cost was not a missing log line, it was an unfalsifiable bug: a
		// paired phone losing authorization has SIX candidate causes and the
		// audit that discriminates them recorded nothing, so every
		// investigation had to reason backwards from `http_request … deny`
		// rows plus disk state. Measured on this install 2026-07-28: 17 rows
		// in remote_sessions covered by the audit window, and zero
		// session_paired rows to explain any of them.
		//
		// nil-safe: remoteAuditSink returns nil when database is nil (the
		// pure-in-memory path), which is exactly the no-op the controller
		// already tolerates.
		Audit: remoteAuditSink(database),
		Session: remoteauth.SessionParams{
			TTL:  time.Duration(cfg.Remote.SessionTTLMinutes) * time.Minute,
			Idle: time.Duration(cfg.Remote.SessionIdleMinutes) * time.Minute,
			Max:  cfg.Remote.MaxSessions,
			// Persist device sessions so a paired phone survives a daemon
			// restart (persist-remote-sessions plan). Nil when no DB is wired
			// ⇒ pure in-memory (the invariant still holds; devices just re-pair).
			Persister: remoteSessionPersister(database),
		},
	})
}

// remoteSessionPersister returns the SQLite-backed device-session persister, or
// a TRUE nil interface when no DB is available (so NewSessionStore's non-nil
// check does not see an interface wrapping a nil pointer).
func remoteSessionPersister(database *sql.DB) remoteauth.SessionPersister {
	if database == nil {
		return nil
	}
	return store.NewRemoteSessionPersister(database)
}

// remoteAuditSink lives in the core file remote_core.go (the remote_audit
// table is core: every Local + confirm route audits through it).

// newRemoteCmd wires `observer remote`. Phase 2 ships the tailnet-HTTPS view
// tier: `enable`/`disable`/`rotate` provision the pairing secret + [remote]
// config (the backend binds on the next `observer start`); `status` is
// read-only; `approve-execute` stays DEFERRED to Phase 4 (execute tier).
func newRemoteCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "remote",
		Short: "Remote dashboard access (LOCAL-ONLY; tailnet-HTTPS view tier)",
		Long: "Manage remote dashboard access ([remote] config). This release ships the\n" +
			"tailnet-HTTPS view tier: `enable --tailscale` mints a pairing secret and\n" +
			"arms the config; the backend listener binds on the next `observer start`.\n" +
			"Execute-tier terminal (`approve-execute`) is a separate opt-in.",
	}
	cmd.PersistentFlags().StringVar(&configPath, "config", "", "Path to config.toml")

	status := &cobra.Command{
		Use:   "status",
		Short: "Show remote-access configuration + recent access events (read-only)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			out := cmd.OutOrStdout()
			rc := buildRemoteController(cfg, database)
			ready := rc != nil && rc.Ready()
			_, secretErr := os.Stat(remoteSecretPath(cfg))
			fmt.Fprintf(out, "remote access:\n")
			fmt.Fprintf(out, "  enabled:        %v\n", cfg.Remote.Enabled)
			fmt.Fprintf(out, "  mode:           %s\n", cfg.Remote.Mode)
			fmt.Fprintf(out, "  bind_addr:      %s\n", cfg.Remote.BindAddr)
			fmt.Fprintf(out, "  backend (local):%s\n", cfg.Remote.TailscaleBackendAddr)
			fmt.Fprintf(out, "  trusted_hosts:  %s\n", strings.Join(cfg.Remote.TrustedHosts, ", "))
			fmt.Fprintf(out, "  require_tls:    %v\n", cfg.Remote.RequireTLS)
			fmt.Fprintf(out, "  allow_terminal: %v\n", cfg.Remote.AllowTerminal)
			fmt.Fprintf(out, "  pairing secret: %v\n", secretErr == nil)
			fmt.Fprintf(out, "  substrate ready (§4.6): %v\n", ready)
			fmt.Fprintf(out, "  notify: enabled=%v kind=%s\n", cfg.Remote.Notify.Enabled, cfg.Remote.Notify.Kind)
			events, err := store.New(database).RecentRemoteAudit(cmd.Context(), 20)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "recent access events (%d):\n", len(events))
			for _, e := range events {
				fmt.Fprintf(out, "  %s  %-16s %-8s %-8s %s %s\n",
					e.TS.Format(time.RFC3339), e.Kind, e.Principal, e.Decision, e.Route, e.Detail)
			}
			return nil
		},
	}

	cmd.AddCommand(status)
	cmd.AddCommand(newRemoteEnableCmd(&configPath))
	cmd.AddCommand(newRemoteDisableCmd(&configPath))
	cmd.AddCommand(newRemoteRotateCmd(&configPath))
	// approve-execute is the LOCAL approval step of the Phase-4 execute tier
	// (§4.γ/§6): it mints a single-use terminal-control capability + bound confirm
	// for a target (device, terminal handle) and surfaces them to the LOCAL
	// operator. The capability store is memory-only and owned by the RUNNING
	// daemon, so this verb drives the daemon's own loopback
	// `/api/remote/approve-execute` (CapabilityLocal) rather than minting into a
	// throwaway store — one owner of the state, fail-closed if the daemon is down.
	cmd.AddCommand(newRemoteApproveExecuteCmd())
	return cmd
}

// remoteConfirmCookieName / remoteConfirmHeaderName mirror the dashboard's
// double-submit confirm protocol constants (dashboard.remoteConfirmCookie /
// remoteConfirmHeader). Duplicated here (not imported — they are unexported) as
// stable wire-protocol names.
const (
	remoteConfirmCookieName = "sb_remote_confirm"
	remoteConfirmHeaderName = "X-Observer-Confirm" //nolint:gosec // header name, not a credential
)

// newRemoteApproveExecuteCmd builds `observer remote approve-execute`. It is a
// LOCAL loopback client of the running daemon's owner-only
// `/api/remote/approve-execute` endpoint: it fetches a fresh confirm token
// (GET /api/remote/config), then POSTs the approval, and prints the minted
// capability + confirm for the operator to hand to the remote device. Secrets
// appear only on stdout (never in argv/URLs).
func newRemoteApproveExecuteCmd() *cobra.Command {
	var (
		addr   string
		device string
		handle string
	)
	cmd := &cobra.Command{
		Use:   "approve-execute",
		Short: "Mint a single-use terminal-control capability for a remote device (LOCAL approval, §4.γ)",
		Long: "LOCAL approval step of the remote terminal execute tier. Mints a single-use,\n" +
			"short-lived terminal-control capability + a bound confirm for a specific paired\n" +
			"device (by fingerprint, from `observer remote status`) and terminal handle, by\n" +
			"driving the running daemon's owner-only loopback approval endpoint. Hand the\n" +
			"printed capability + confirm to the remote device to acquire the writer lease.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(device) == "" || strings.TrimSpace(handle) == "" {
				return fmt.Errorf("both --device (paired-device fingerprint) and --handle (terminal handle) are required")
			}
			if note := dashboardNotInBuildNote(); note != "" {
				// The approval endpoint is a dashboard route (MP-L1M, D-514).
				return errors.New("remote approve-execute needs the dashboard: " + note)
			}
			base := "http://" + strings.TrimSpace(addr)
			token, cookie, err := fetchRemoteConfirmToken(cmd.Context(), base)
			if err != nil {
				return fmt.Errorf("fetch confirm token from %s (is the daemon running with [remote] configured?): %w", base, err)
			}
			capTok, confirm, err := postApproveExecute(cmd.Context(), base, token, cookie, device, handle)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "approved terminal control for device %s on handle %s\n", device, handle)
			fmt.Fprintf(out, "  capability: %s\n", capTok)
			fmt.Fprintf(out, "  confirm:    %s\n", confirm)
			fmt.Fprintf(out, "\nHand these to the remote device; they are single-use and short-lived.\n")
			return nil
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8080", "Local dashboard address of the running daemon")
	cmd.Flags().StringVar(&device, "device", "", "Target paired-device fingerprint (from `observer remote status`)")
	cmd.Flags().StringVar(&handle, "handle", "", "Target terminal session handle")
	return cmd
}

// fetchRemoteConfirmToken performs GET /api/remote/config against the local
// daemon and returns the double-submit confirm token + its cookie.
func fetchRemoteConfirmToken(ctx context.Context, base string) (token string, cookie *http.Cookie, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/remote/config", nil)
	if err != nil {
		return "", nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("GET /api/remote/config: HTTP %d", resp.StatusCode)
	}
	var body struct {
		ConfirmToken string `json:"confirm_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", nil, err
	}
	for _, ck := range resp.Cookies() {
		if ck.Name == remoteConfirmCookieName {
			cookie = ck
		}
	}
	if body.ConfirmToken == "" || cookie == nil {
		return "", nil, fmt.Errorf("no confirm token returned")
	}
	return body.ConfirmToken, cookie, nil
}

// postApproveExecute POSTs the approval and returns the minted capability +
// confirm from the response body.
func postApproveExecute(ctx context.Context, base, token string, cookie *http.Cookie, device, handle string) (capTok, confirm string, err error) {
	reqBody, _ := json.Marshal(map[string]string{"device": device, "handle": handle})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/remote/approve-execute", bytes.NewReader(reqBody))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(remoteConfirmHeaderName, token)
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		return "", "", fmt.Errorf("POST /api/remote/approve-execute: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	var body struct {
		Capability string `json:"capability"`
		Confirm    string `json:"confirm"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", "", err
	}
	if body.Capability == "" || body.Confirm == "" {
		return "", "", fmt.Errorf("approval response missing capability/confirm")
	}
	return body.Capability, body.Confirm, nil
}

// isStandingCredential recognises a standing terminal-control credential by
// its shape (remoteauth.IsStandingSecret); remote_omit.go answers false.
func isStandingCredential(cred string) bool { return remoteauth.IsStandingSecret(cred) }
