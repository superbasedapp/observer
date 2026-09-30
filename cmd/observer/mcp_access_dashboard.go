package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/localpdp"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/record"
	"github.com/marmutapp/superbased-observer/internal/policystate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// The node dashboard's MCP-access read (Agent Access P10, doc3 §15 "node
// dashboard" + "VS Code", §12.7 / §12.8): GET /api/mcp-access/status, the
// ONE payload behind the Security page's "MCP access" section and the VS
// Code "MCP access" status item. It is composed here, in the only package
// that owns the relay, and handed to the dashboard as a plain func
// (dashboard.Options.MCPAccessStatus) - the dashboard never imports the
// relay packages and there is no second relay derivation:
//
//   - status        = buildMCPRelayStatus, the SAME body `observer mcp
//                     status --json` prints (mcpStatusDisabled when the
//                     relay is off, exactly like the CLI);
//   - coverage_rows = the coverage matrix rows that status summarises;
//   - effective_state = policystate.Resolve over newMCPRelayPointReader on
//                     the daemon's LIVE handle - the same row the node ACKs
//                     to the org (minus the last-fetch reject facts, which
//                     only the policy-state reporter holds);
//   - connect       = resolveMCPConnectOrigin + mcpConnectableServers, the
//                     `observer mcp connect` URL builder (R-S3-1: the
//                     connect flow lives on the ORG dashboard origin).
//
// Remote forwarding is NOT probed per read (that is an org-server
// registration call): the daemon's relay runtime publishes what it resolved
// at start into processMCPRelayRemote, and the read reports that with its
// source. Kill switch: with [mcp_relay].enabled = false the read makes no
// network call, never creates the database and writes nothing.

// processMCPRelayRemote is the remote-forwarding resolution the daemon's
// relay runtime reached at start (startMCPRelayRuntime publishes it on
// success; nil = the runtime has not started in this process).
var processMCPRelayRemote atomic.Pointer[mcpRelayRemote]

// Remote-forwarding sources the read reports beside the resolution.
const (
	// mcpAccessRemoteDaemon: the resolution the running relay runtime holds.
	mcpAccessRemoteDaemon = "daemon"
	// mcpAccessRemoteNotStarted: no runtime in this process resolved one.
	mcpAccessRemoteNotStarted = "not_started"
	// mcpAccessRemoteDisabled: the relay is off in config.
	mcpAccessRemoteDisabled = "disabled"
)

// mcpAccessView is the GET /api/mcp-access/status body.
type mcpAccessView struct {
	// Available is always true on this body; the dashboard answers
	// {"available": false, "reason": ...} when no seam is wired.
	Available bool `json:"available"`
	// Status is the `observer mcp status --json` body, verbatim.
	Status mcpRelayStatus `json:"status"`
	// DaemonRelay is true when THIS daemon process bound the relay seams
	// (it was started with [mcp_relay].enabled = true). Status.Enabled is
	// the config file NOW; the two differ until the daemon is restarted.
	DaemonRelay bool `json:"daemon_relay"`
	// RemoteSource names where Status.RemoteForwarding came from.
	RemoteSource string `json:"remote_source"`
	// Enrolled / Managed describe the node's org enrolment.
	Enrolled bool `json:"enrolled"`
	Managed  bool `json:"managed"`
	// ChainVerified reports whether this read walked the record chain
	// (Status.ChainOK is absent = unverified when it did not).
	ChainVerified bool `json:"chain_verified"`
	// CoverageRows is the client x transport x method matrix Status.Coverage
	// summarises (empty when the relay is disabled - nothing is mediated).
	CoverageRows []mcpAccessCoverageRow `json:"coverage_rows"`
	// VServers is the approved registry the accepted grant carries.
	VServers []mcpAccessVServer `json:"vservers"`
	// EffectiveState is the node-mcp-relay effective-state row.
	EffectiveState mcpAccessEffective `json:"effective_state"`
	// Connect is the per-user connect target on the org dashboard.
	Connect mcpAccessConnect `json:"connect"`
}

// mcpAccessCoverageRow is one coverage.Row with wire names.
type mcpAccessCoverageRow struct {
	Client    string `json:"client"`
	Transport string `json:"transport"`
	Method    string `json:"method"`
	Coverage  string `json:"coverage"`
	Point     string `json:"point,omitempty"`
	Phase     string `json:"phase,omitempty"`
	Note      string `json:"note"`
}

// mcpAccessVServer is one approved virtual server and its member servers.
type mcpAccessVServer struct {
	ID               string            `json:"id"`
	Slug             string            `json:"slug"`
	SenderConstraint string            `json:"sender_constraint,omitempty"`
	Servers          []mcpAccessServer `json:"servers"`
}

// mcpAccessServer is one registry server inside an approved vserver.
type mcpAccessServer struct {
	ID             string `json:"id"`
	Target         string `json:"target"`
	CredentialMode string `json:"credential_mode,omitempty"`
	Pinned         bool   `json:"pinned"`
	// PerUserConnect is true for a vault_user server: each member signs in
	// to it on the org dashboard (the same predicate `observer mcp connect`
	// lists by).
	PerUserConnect bool `json:"per_user_connect"`
}

// mcpAccessEffective is the enum-only effective-state row (doc3 §12.8).
type mcpAccessEffective struct {
	Status          string `json:"status"`
	Reason          string `json:"reason"`
	Mode            string `json:"mode"`
	RunningVersion  int64  `json:"running_version"`
	EffectiveHash   string `json:"effective_hash,omitempty"`
	RestartRequired bool   `json:"restart_required"`
}

// mcpAccessConnect is the connect target; URL is empty when Unavailable
// says why.
type mcpAccessConnect struct {
	URL                string                 `json:"url,omitempty"`
	DashboardOrigin    string                 `json:"dashboard_origin,omitempty"`
	OriginSource       string                 `json:"origin_source,omitempty"`
	Unavailable        string                 `json:"unavailable,omitempty"`
	ConnectableServers []mcpConnectableServer `json:"connectable_servers"`
}

// mcpAccessStatusSeam builds the dashboard.Options.MCPAccessStatus func for
// the daemon: configPath is re-read on every call (like the CLI) so the page
// reflects the file, database is the daemon's own handle.
func mcpAccessStatusSeam(configPath string, database *sql.DB) func(ctx context.Context, verifyChain bool) (any, error) {
	return func(ctx context.Context, verifyChain bool) (any, error) {
		cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
		if err != nil {
			return nil, fmt.Errorf("mcpAccessStatus: load config: %w", err)
		}
		return buildMCPAccessView(ctx, cfg, database, processMCPRelay.Load() != nil, processMCPRelayRemote.Load(), verifyChain)
	}
}

// buildMCPAccessView composes the read. daemonRelay / daemonRemote are the
// process state (injected for tests).
func buildMCPAccessView(ctx context.Context, cfg config.Config, database *sql.DB, daemonRelay bool, daemonRemote *mcpRelayRemote, verifyChain bool) (mcpAccessView, error) {
	if database == nil {
		return mcpAccessView{}, errors.New("mcpAccessStatus: no database")
	}
	st := store.New(database)
	v := mcpAccessView{Available: true, DaemonRelay: daemonRelay, CoverageRows: []mcpAccessCoverageRow{}, VServers: []mcpAccessVServer{}}
	enr, eerr := st.LoadEnrolment(ctx)
	if eerr == nil && enr != nil {
		v.Enrolled, v.Managed = true, enr.IsManaged()
	}
	logger := slog.New(slog.DiscardHandler)
	// A handle built for this read (never the daemon's live one:
	// buildMCPRelayStatus sets its projection flag from the journal).
	h := newMCPRelayHandle(cfg, st, nil, logger)
	if cfg.MCPRelay.Enabled {
		rs := record.NewSQLStore(database, mcpRelayNodeKey(ctx, cfg, st))
		remote, source := mcpAccessRemote(daemonRelay, daemonRemote)
		s, rows := buildMCPRelayStatus(ctx, cfg, h, rs, remote, verifyChain)
		v.Status, v.RemoteSource, v.ChainVerified = s, source, verifyChain && s.ChainHead > 0
		for _, r := range rows {
			v.CoverageRows = append(v.CoverageRows, mcpAccessCoverageRow{
				Client: r.Client, Transport: string(r.Transport), Method: string(r.Method),
				Coverage: string(r.Coverage), Point: r.Point, Phase: r.Phase, Note: r.Note,
			})
		}
	} else {
		// The disabled `observer mcp status` shape, from the journal of the
		// daemon's own (already open) database - nothing is written.
		rs := record.NewSQLStore(database, "")
		specs, lerr := rs.ListLaunchSpecs(ctx)
		if lerr != nil {
			return mcpAccessView{}, fmt.Errorf("mcpAccessStatus: list launch journal: %w", lerr)
		}
		v.Status, v.RemoteSource = mcpStatusDisabled(cfg, len(specs), projectedClients(ctx, rs)), mcpAccessRemoteDisabled
	}
	// The approved registry is listed only while the relay is on (the
	// disabled CLI status lists none either); a cached table from before
	// the switch-off still names the connect targets below.
	t := h.Table()
	if t != nil && cfg.MCPRelay.Enabled {
		for _, vs := range t.Node.Registry.VServers {
			out := mcpAccessVServer{ID: vs.ID, Slug: vs.Slug, SenderConstraint: vs.SenderConstraint, Servers: []mcpAccessServer{}}
			for _, sv := range vs.Servers {
				out.Servers = append(out.Servers, mcpAccessServer{
					ID: sv.ID, Target: sv.Target, CredentialMode: sv.CredentialMode,
					Pinned: sv.Pinned(), PerUserConnect: sv.CredentialMode == mcpVaultUserMode,
				})
			}
			v.VServers = append(v.VServers, out)
		}
	}
	// Effective state: the SAME reader the policy-state reporter registers,
	// over the daemon's live handle (nil when the daemon did not bind the
	// relay -> the honest none/no_policy row the node ACKs too).
	facts, _ := newMCPRelayPointReader(processMCPRelayIfWired(daemonRelay), nil, time.Now)(ctx)
	row := policystate.Resolve(policystate.PointNodeMCPRelay, policystate.FamilyToolsMCPAccess, facts)
	v.EffectiveState = mcpAccessEffective{
		Status: row.Status, Reason: row.Reason, Mode: row.Mode, RunningVersion: row.RunningVersion,
		EffectiveHash: row.EffectiveHash, RestartRequired: row.RestartRequired,
	}
	v.Connect = mcpAccessConnectTarget(cfg, enr, t)
	return v, nil
}

// processMCPRelayIfWired returns the live handle only when the daemon bound
// the relay (the injected flag keeps tests off the process global).
func processMCPRelayIfWired(daemonRelay bool) *mcpRelayHandle {
	if !daemonRelay {
		return nil
	}
	return processMCPRelay.Load()
}

// mcpAccessRemote is the remote-forwarding source rule table, first match
// wins: the runtime's resolution, else the honest reason none exists.
func mcpAccessRemote(daemonRelay bool, daemonRemote *mcpRelayRemote) (mcpRelayRemote, string) {
	switch {
	case daemonRemote != nil:
		return *daemonRemote, mcpAccessRemoteDaemon
	case !daemonRelay:
		return mcpRelayRemote{Reason: "the daemon was started with the relay disabled; restart it to bind the relay (route OFF -> stop -> relaunch -> route ON)"}, mcpAccessRemoteNotStarted
	default:
		return mcpRelayRemote{Reason: "the daemon's relay runtime has not started (still starting, or it failed - see the daemon log)"}, mcpAccessRemoteNotStarted
	}
}

// mcpAccessConnectTarget resolves the org-dashboard connect URL through the
// `observer mcp connect` origin table (enrolment, then
// [org_client].org_server_url; there is no --dashboard-url on a read).
func mcpAccessConnectTarget(cfg config.Config, enr *store.Enrolment, t *localpdp.Table) mcpAccessConnect {
	c := mcpAccessConnect{ConnectableServers: mcpConnectableServers(t)}
	if c.ConnectableServers == nil {
		c.ConnectableServers = []mcpConnectableServer{}
	}
	enrolled := ""
	if enr != nil {
		enrolled = enr.OrgServerURL
	}
	if strings.TrimSpace(enrolled) == "" && strings.TrimSpace(cfg.OrgClient.OrgServerURL) == "" {
		c.Unavailable = "this node is not enrolled with an organization, so there is no org dashboard to connect a server in"
		return c
	}
	origin, source, err := resolveMCPConnectOrigin([]mcpConnectOriginSource{
		{name: "enrolment", value: func() string { return enrolled }},
		{name: "[org_client].org_server_url", value: func() string { return cfg.OrgClient.OrgServerURL }},
	})
	if err != nil {
		c.Unavailable = err.Error()
		return c
	}
	c.URL, c.DashboardOrigin, c.OriginSource = origin+mcpConnectPagePath, origin, source
	return c
}
