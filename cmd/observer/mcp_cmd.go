package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/coverage"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/localpdp"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/record"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// `observer mcp` — the CANONICAL node tree of the Agent Access operator
// surface (doc3 §15.0, P10): {status|relay|wrap|unwrap|connect|doctor}.
// Every verb delegates to the SAME implementation `observer mcp-relay`
// runs (cmd/observer/mcprelay.go + mcprelay_wire.go): status IS the
// mcp-relay status body, relay IS the mcp-relay wrap stdio wrapper (the
// path the P11 fold PF2 cwd-attestation rides on), wrap / unwrap compose
// the one projector (runMCPRelayProjection / runMCPRelayRestore). Nothing
// here owns a table or a second write path.
//
// Kill switch ([mcp_relay].enabled = false): status reports the relay
// disabled without probing the org server, relay and wrap refuse BEFORE the
// database is opened (nothing is written), doctor runs no network probe.
// unwrap stays available because it is the recovery path for a client
// config left wrapped when the relay was switched off by hand; with no
// journal rows it writes nothing. connect only prints a URL.

// mcpNodeDisabledNote is the one-line enable hint every refusal carries.
const mcpNodeDisabledNote = "the node MCP relay is disabled ([mcp_relay].enabled = false); nothing was written. " +
	"Turn it on with `observer mcp-relay enable` (sets the flag and wraps every installed client), " +
	"or set [mcp_relay].enabled = true and run `observer mcp wrap`"

// errMCPNodeDisabled is the typed refusal of a verb that needs the relay on.
var errMCPNodeDisabled = errors.New(mcpNodeDisabledNote)

func newMCPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Agent Access node surface: relay status, stdio relay, wrap/unwrap client MCP configs, per-user connect, doctor",
		Long: "The node half of Agent Access (doc3 §15.0). The relay mediates this\n" +
			"machine's AI clients' MCP traffic against the organization's signed\n" +
			"tools.mcp_access grant: `wrap` rewrites every installed client's MCP\n" +
			"entries through the relay (originals journaled first), `unwrap` restores\n" +
			"them from the journal, `relay` is the stdio wrapper those entries spawn,\n" +
			"`status` and `doctor` report what is actually mediated, and `connect`\n" +
			"points you at the org dashboard to sign in to a per-user MCP server.\n\n" +
			"`observer mcp-relay` is the older spelling of the same surface (it also\n" +
			"carries enable / disable, which flip [mcp_relay].enabled).\n\n" +
			mcpRelayRestartNote,
	}
	cmd.AddCommand(newMCPStatusCmd())
	cmd.AddCommand(newMCPStdioRelayCmd())
	cmd.AddCommand(newMCPWrapCmd())
	cmd.AddCommand(newMCPUnwrapCmd())
	cmd.AddCommand(newMCPConnectCmd())
	cmd.AddCommand(newMCPDoctorCmd())
	return cmd
}

// loadMCPNodeConfig loads (and validates) the config WITHOUT opening the
// database: the kill-switch pre-check every verb runs before any write.
func loadMCPNodeConfig(configPath string) (config.Config, error) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return config.Config{}, fmt.Errorf("load config: %w", err)
	}
	return cfg, nil
}

// requireMCPRelayEnabled is the relay / wrap refusal: config only, no DB,
// no network, nothing written.
func requireMCPRelayEnabled(verb, configPath string) error {
	cfg, err := loadMCPNodeConfig(configPath)
	if err != nil {
		return err
	}
	if !cfg.MCPRelay.Enabled {
		return fmt.Errorf("observer mcp %s: %w", verb, errMCPNodeDisabled)
	}
	return nil
}

// dbFileExists reports whether the node database already exists: a
// disabled-relay read never CREATES one (the kill switch writes nothing).
func dbFileExists(cfg config.Config) bool {
	fi, err := os.Stat(cfg.Observer.DBPath)
	return err == nil && !fi.IsDir()
}

// newMCPStatusCmd is `observer mcp status`: the mcp-relay status body (one
// JSON shape for both spellings) behind the kill-switch pre-check.
func newMCPStatusCmd() *cobra.Command {
	c := newMCPRelayStatusCmd()
	inner := c.RunE
	c.Short = "Relay state, approved vservers, remote forwarding, effective state and the client x transport coverage matrix (--json)"
	c.Long = "Prints the node relay's state: the compiled tools.mcp_access table and\n" +
		"the vservers it approves, remote forwarding (an idempotent registration\n" +
		"against the org server unless --no-remote), which client configs are\n" +
		"VERIFIED projected, the relay point's effective state and hash, the\n" +
		"hash-chained decision record, and the coverage matrix.\n\n" +
		"With [mcp_relay].enabled = false it reports the relay disabled and makes\n" +
		"no org-server call; it still lists client configs the journal shows as\n" +
		"wrapped (switched off without `observer mcp unwrap`)."
	c.RunE = func(cmd *cobra.Command, args []string) error {
		configPath, _ := cmd.Flags().GetString("config")
		cfg, err := loadMCPNodeConfig(configPath)
		if err != nil {
			return err
		}
		if cfg.MCPRelay.Enabled {
			return inner(cmd, args)
		}
		jsonOut, _ := cmd.Flags().GetBool("json")
		return printMCPStatusDisabled(cmd, cfg, configPath, jsonOut)
	}
	return c
}

// mcpStatusDisabled builds the disabled status in the SAME shape the
// enabled status prints: nothing held, every required capability missing,
// no remote forwarding, an empty coverage summary.
func mcpStatusDisabled(cfg config.Config, specs int, projected []string) mcpRelayStatus {
	return mcpRelayStatus{
		Enabled: false, Mode: cfg.MCPRelay.Mode, AuditMode: cfg.MCPRelay.AuditMode,
		Listen: cfg.MCPRelay.Listen, GatewayURL: cfg.MCPRelay.GatewayURL,
		CachePath:        localpdp.SiblingPath(orgBundleCachePath(cfg), cfg.Observer.DBPath),
		PointStatus:      string(coverage.StatusIneffective),
		MissingCaps:      append([]string(nil), coverage.RequiredCapabilities[coverage.PointRelay]...),
		LaunchSpecs:      specs,
		ProjectedClients: projected,
		RemoteForwarding: mcpRelayRemote{Reason: "relay disabled ([mcp_relay].enabled = false)"},
		Coverage:         map[coverage.Coverage]int{},
	}
}

// mcpJournalLeftovers reads the launch journal of an EXISTING node DB (a
// disabled relay never creates one): row count + verified-projected tools.
func mcpJournalLeftovers(cmd *cobra.Command, cfg config.Config, configPath string) (int, []string, error) {
	if !dbFileExists(cfg) {
		return 0, nil, nil
	}
	_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
	if err != nil {
		return 0, nil, err
	}
	defer cleanup()
	rs := record.NewSQLStore(database, "")
	specs, err := rs.ListLaunchSpecs(cmd.Context())
	if err != nil {
		return 0, nil, fmt.Errorf("list launch journal: %w", err)
	}
	return len(specs), projectedClients(cmd.Context(), rs), nil
}

func printMCPStatusDisabled(cmd *cobra.Command, cfg config.Config, configPath string, jsonOut bool) error {
	specs, projected, err := mcpJournalLeftovers(cmd, cfg, configPath)
	if err != nil {
		return err
	}
	s := mcpStatusDisabled(cfg, specs, projected)
	if jsonOut {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(s)
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "mcp: relay DISABLED ([mcp_relay].enabled = false) mode=%s audit=%s - nothing is mediated, no relay listener binds, no org-server call was made\n", s.Mode, s.AuditMode)
	fmt.Fprintf(out, "point: %s (missing %s)\n", s.PointStatus, strings.Join(s.MissingCaps, ", "))
	if s.LaunchSpecs > 0 {
		fmt.Fprintf(out, "WARNING: the launch journal still holds %d row(s); verified wrapped client(s): [%s]. While disabled the relay wrapper refuses to start those servers - run `observer mcp unwrap` to restore the originals.\n", s.LaunchSpecs, strings.Join(s.ProjectedClients, ", "))
	} else {
		fmt.Fprintln(out, "projection: no client config is wrapped")
	}
	fmt.Fprintln(out, "enable: `observer mcp-relay enable` (sets the flag and wraps every installed client's MCP config)")
	return nil
}

// newMCPStdioRelayCmd is `observer mcp relay`: the stdio wrapper an AI
// client spawns in place of an original MCP server - the mcp-relay wrap
// command body (same flags, same journal lookup, same PF2 cwd attestation)
// behind the kill-switch pre-check.
func newMCPStdioRelayCmd() *cobra.Command {
	c := newMCPRelayWrapCmd()
	inner := c.RunE
	c.Use = "relay --server <entry-key> [--client <tool>]"
	c.Short = "Stdio relay: spawn the journaled original MCP server and mediate every frame (what a wrapped client entry runs)"
	c.Hidden = false
	c.RunE = func(cmd *cobra.Command, args []string) error {
		configPath, _ := cmd.Flags().GetString("config")
		if err := requireMCPRelayEnabled("relay", configPath); err != nil {
			return err
		}
		return inner(cmd, args)
	}
	return c
}

// newMCPWrapCmd is `observer mcp wrap`: run the ONE projector now (the
// mcp-relay enable body without touching [mcp_relay].enabled).
func newMCPWrapCmd() *cobra.Command {
	var (
		configPath string
		noRemote   bool
	)
	cmd := &cobra.Command{
		Use:   "wrap",
		Short: "Rewrite every installed AI client's MCP entries through the relay (originals journaled first; idempotent)",
		Long: "Projects the relay into every verified installed AI client's MCP\n" +
			"config: each stdio server bound to an approved vserver is REPLACED by\n" +
			"the stdio relay (`observer mcp-relay wrap --client <tool> --server\n" +
			"<key>`), and the approved vservers are added as remote entries through\n" +
			"the relay's loopback listener when one is configured and remote\n" +
			"forwarding is wired. Every original is journaled with a verbatim\n" +
			"backup BEFORE it is rewritten; `observer mcp unwrap` puts it back.\n" +
			"An entry with no approved binding is NOT wrapped and is reported.\n\n" +
			"Refuses (writing nothing) when [mcp_relay].enabled = false.\n\n" + mcpRelayRestartNote,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireMCPRelayEnabled("wrap", configPath); err != nil {
				return err
			}
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
				pctx, pcancel := contextWithMCPProbeTimeout(cmd)
				_, _, remote = resolveMCPRelayRemote(pctx, cfg, st, h, defaultMCPRelayRemoteDeps(cfg, st, logger), logger)
				pcancel()
			}
			rep, remoteSkip, err := runMCPRelayProjection(cmd.Context(), cfg, configPath, rs, h, remote.Wired)
			if err != nil {
				return fmt.Errorf("observer mcp wrap: projection: %w", err)
			}
			out := func(f string, a ...any) { fmt.Fprintf(cmd.OutOrStdout(), f+"\n", a...) }
			changed, failed := printProjectionReport(out, rep, remoteSkip)
			out("mcp wrap: projected %d client config(s), %d failed", changed, failed)
			if failed > 0 {
				return errors.New("observer mcp wrap: some client configs were not projected (see above)")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml (default ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&noRemote, "no-remote", false, "do not resolve remote forwarding (no org-server registration call; remote entries are not projected)")
	return cmd
}

// newMCPUnwrapCmd is `observer mcp unwrap`: restore every journaled client
// config through the projector's restore rule table (the mcp-relay restore
// body), leaving [mcp_relay].enabled untouched.
func newMCPUnwrapCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "unwrap",
		Short: "Restore every journaled client MCP config from the launch journal (byte-identical when untouched)",
		Long: "Restores each AI client's MCP config from the launch journal:\n" +
			"byte-identically from the hash-checked backup when the file still holds\n" +
			"exactly what the relay wrote, else by reversing ONLY the relay-owned\n" +
			"entries (a later edit is preserved, never clobbered). A config that\n" +
			"cannot be restored keeps its journal row and backup and is reported.\n\n" +
			"Works whether or not the relay is enabled (it is the recovery path for\n" +
			"a config left wrapped after the relay was switched off). It does not\n" +
			"change [mcp_relay].enabled: while the relay stays enabled the daemon\n" +
			"re-projects on its next start - `observer mcp-relay disable` keeps the\n" +
			"originals.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadMCPNodeConfig(configPath)
			if err != nil {
				return err
			}
			if !dbFileExists(cfg) {
				// No node DB = no launch journal = nothing was ever wrapped;
				// never create a database just to find that out.
				fmt.Fprintln(cmd.OutOrStdout(), "mcp unwrap: no node database, so no journaled client config - nothing to restore")
				return nil
			}
			if err := runMCPRelayRestore(cmd, configPath); err != nil {
				return err
			}
			if cfg.MCPRelay.Enabled {
				fmt.Fprintln(cmd.OutOrStdout(), "mcp unwrap: the relay is still enabled - the daemon re-projects every client on its next start; `observer mcp-relay disable` keeps the originals")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml (default ~/.observer/config.toml)")
	return cmd
}

// ConnectDonePath mirror: the org dashboard's My Connections route (web2
// /agent-access/connections, agentaccesswire.ConnectDonePath). Kept as a
// literal here so the node binary does not link the org-server package.
const mcpConnectPagePath = "/agent-access/connections"

// mcpVaultUserMode is the one credential mode (mcpaccess.CredentialModes)
// that takes a per-user connection.
const mcpVaultUserMode = "vault_user"

// mcpConnectOriginSource is one row of the ordered dashboard-origin
// resolution table: the first row yielding a non-empty value wins.
type mcpConnectOriginSource struct {
	name  string
	value func() string
}

// resolveMCPConnectOrigin walks the origin table top-down and returns the
// dashboard ORIGIN (scheme://host[:port], no path) and the row it came
// from. R-S3-1: the connect endpoints live on the org server's dashboard
// origin; the node never handles the OAuth callback.
func resolveMCPConnectOrigin(sources []mcpConnectOriginSource) (origin, source string, err error) {
	for _, s := range sources {
		raw := strings.TrimSpace(s.value())
		if raw == "" {
			continue
		}
		o, perr := mcpDashboardOrigin(raw)
		if perr != nil {
			return "", s.name, fmt.Errorf("%s %q: %w", s.name, raw, perr)
		}
		return o, s.name, nil
	}
	return "", "", errors.New("no org dashboard URL known: this node is not enrolled - pass --dashboard-url https://<your org dashboard>")
}

// mcpDashboardOrigin reduces an absolute http(s) URL to its origin.
func mcpDashboardOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("not a URL: %w", err)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", errors.New("must be an absolute http(s) URL")
	}
	return u.Scheme + "://" + u.Host, nil
}

// mcpConnectableServer is one registry server the node's accepted table
// marks as a per-user (vault_user) connection target.
type mcpConnectableServer struct {
	ServerID string   `json:"server_id"`
	VServers []string `json:"vservers"`
}

// mcpConnectableServers lists the table's vault_user servers, sorted.
func mcpConnectableServers(t *localpdp.Table) []mcpConnectableServer {
	if t == nil {
		return nil
	}
	by := map[string][]string{}
	for _, v := range t.Node.Registry.VServers {
		for _, s := range v.Servers {
			if s.CredentialMode == mcpVaultUserMode {
				by[s.ID] = append(by[s.ID], v.ID)
			}
		}
	}
	out := make([]mcpConnectableServer, 0, len(by))
	for id, vs := range by {
		sort.Strings(vs)
		out = append(out, mcpConnectableServer{ServerID: id, VServers: vs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ServerID < out[j].ServerID })
	return out
}

// mcpServerCredentialMode finds a server id in the table ("" = unknown).
func mcpServerCredentialMode(t *localpdp.Table, id string) (string, bool) {
	if t == nil || id == "" {
		return "", false
	}
	for _, v := range t.Node.Registry.VServers {
		for _, s := range v.Servers {
			if s.ID == id {
				return s.CredentialMode, true
			}
		}
	}
	return "", false
}

// mcpConnectResult is the JSON shape `observer mcp connect --json` prints.
type mcpConnectResult struct {
	URL                string                 `json:"url"`
	DashboardOrigin    string                 `json:"dashboard_origin"`
	OriginSource       string                 `json:"origin_source"`
	ServerID           string                 `json:"server_id,omitempty"`
	ServerKnown        bool                   `json:"server_known"`
	ServerCredential   string                 `json:"server_credential_mode,omitempty"`
	ConnectableServers []mcpConnectableServer `json:"connectable_servers"`
	Notes              []string               `json:"notes,omitempty"`
}

func newMCPConnectCmd() *cobra.Command {
	var (
		configPath   string
		serverID     string
		dashboardURL string
		openIt       bool
		jsonOut      bool
	)
	cmd := &cobra.Command{
		Use:   "connect [--server <id>]",
		Short: "Print (or --open) the org dashboard's My Connections URL to sign in to a per-user MCP server",
		Long: "Per-user OAuth connections are made in the ORGANIZATION DASHBOARD, in a\n" +
			"browser signed in to your org account: the dashboard starts the\n" +
			"attempt, the provider redirects back to the dashboard origin's\n" +
			"/connect/callback, and the connection is bound to the SAME signed-in\n" +
			"member. This node never handles the OAuth callback and never sees the\n" +
			"upstream token. `connect` prints that page's URL - on the dashboard\n" +
			"origin of the org this node is enrolled with (or --dashboard-url) - and\n" +
			"the per-user servers this node's accepted grant names. It makes no\n" +
			"network call; --open launches your browser on it.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadMCPNodeConfig(configPath)
			if err != nil {
				return err
			}
			var enrolled string
			if dbFileExists(cfg) {
				_, database, cleanup, derr := loadConfigAndDB(cmd.Context(), configPath)
				if derr != nil {
					return derr
				}
				if enr, lerr := store.New(database).LoadEnrolment(cmd.Context()); lerr == nil && enr != nil {
					enrolled = enr.OrgServerURL
				}
				cleanup()
			}
			origin, source, err := resolveMCPConnectOrigin([]mcpConnectOriginSource{
				{name: "--dashboard-url", value: func() string { return dashboardURL }},
				{name: "enrolment", value: func() string { return enrolled }},
				{name: "[org_client].org_server_url", value: func() string { return cfg.OrgClient.OrgServerURL }},
			})
			if err != nil {
				return fmt.Errorf("observer mcp connect: %w", err)
			}
			// The cached compiled table is read-only here (never written):
			// it names the servers the accepted grant marks per-user.
			h := newMCPRelayHandle(cfg, nil, nil, slog.New(slog.DiscardHandler))
			t := h.Table()
			res := mcpConnectResult{
				URL: origin + mcpConnectPagePath, DashboardOrigin: origin, OriginSource: source,
				ServerID: serverID, ConnectableServers: mcpConnectableServers(t),
			}
			if res.ConnectableServers == nil {
				res.ConnectableServers = []mcpConnectableServer{}
			}
			if serverID != "" {
				mode, known := mcpServerCredentialMode(t, serverID)
				res.ServerKnown, res.ServerCredential = known, mode
				switch {
				case !known:
					res.Notes = append(res.Notes, fmt.Sprintf("server %q is not in this node's accepted tools.mcp_access table; the dashboard resolves it (an admin may have given you the id)", serverID))
				case mode != mcpVaultUserMode:
					res.Notes = append(res.Notes, fmt.Sprintf("server %q uses credential_mode %q in this node's table - per-user connections apply only to vault_user servers (the dashboard answers connect_not_supported)", serverID, mode))
				}
			}
			if t == nil {
				res.Notes = append(res.Notes, "no tools.mcp_access table is cached on this node, so the per-user servers cannot be listed here; the dashboard lists them")
			}
			if openIt {
				openBrowser(res.URL)
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "Open the org dashboard's My Connections page in a browser signed in to your org account:")
			fmt.Fprintf(out, "  %s\n", res.URL)
			fmt.Fprintf(out, "(dashboard origin from %s)\n", res.OriginSource)
			if serverID != "" {
				fmt.Fprintf(out, "Then connect server id %q (\"Connect a server\"). The provider redirects back to the dashboard; this node never sees the token.\n", serverID)
			}
			if len(res.ConnectableServers) > 0 {
				fmt.Fprintln(out, "Per-user servers in this node's accepted grant:")
				for _, s := range res.ConnectableServers {
					fmt.Fprintf(out, "  %s (vservers: %s)\n", s.ServerID, strings.Join(s.VServers, ", "))
				}
			}
			for _, n := range res.Notes {
				fmt.Fprintf(out, "note: %s\n", n)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml (default ~/.observer/config.toml)")
	cmd.Flags().StringVar(&serverID, "server", "", "registry MCP server id to connect")
	cmd.Flags().StringVar(&dashboardURL, "dashboard-url", "", "org dashboard URL (default: the org server this node is enrolled with)")
	cmd.Flags().BoolVar(&openIt, "open", false, "open the URL in the default browser")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON")
	return cmd
}
