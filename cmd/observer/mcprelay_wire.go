package main

// Agent Access P4 W4d (doc3 §12.5-§12.8): the ONE daemon composition point
// for the node MCP relay's node-side enforcement seams. Everything here is
// gated on [mcp_relay].enabled: with it false, wireMCPRelay returns nil,
// binds NOTHING (no proxy tools[] seam, no guard MCP-access lookup, no
// policy-state point facts beyond none/no_policy) and the binary is
// byte-identical to a build without the relay.
//
// Seams bound here (each a plain func / plain result, never a type threaded
// through the hot path):
//
//   - proxy.Options.ToolsAllowlist (internal/proxy/mcptools.go): the tools[]
//     strip (R-306) + hosted-connector refusal (R-307) decided against the
//     compiled node table; the proxy never imports the relay.
//   - guard.SetMCPAccessLookup (internal/guard/mcpaccess.go): the SAME table
//     answers the hook PreToolUse deny / watcher flag / proxy inspection.
//   - policystate.PointNodeMCPRelay reader: the enum-only effective-state
//     ACK row (Family=tools.mcp_access, EnforcementPoint=node-mcp-relay).
//   - the policy-resource publisher for tools.mcp_access (compile → swap →
//     cache beside the guard org-bundle cache, so a hook process reads the
//     SAME compiled table without recompiling).
//
// The reverse-import boundary holds by construction: internal/proxy,
// internal/guard, internal/policy and internal/hook never import
// internal/mcprelay; only this cmd file does (tests/invariant/
// agentaccess_boundary_test.go).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/mcp"
	"github.com/marmutapp/superbased-observer/internal/mcpaccess"
	"github.com/marmutapp/superbased-observer/internal/mcpegress"
	"github.com/marmutapp/superbased-observer/internal/mcprelay"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/coverage"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/localpdp"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/project"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/record"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/policyfam"
	famcp "github.com/marmutapp/superbased-observer/internal/policyfam/mcpaccess"
	"github.com/marmutapp/superbased-observer/internal/policystate"
	"github.com/marmutapp/superbased-observer/internal/proxy"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// mcpRelayState is the handle's frozen snapshot of the accepted resource.
type mcpRelayState struct {
	HasOrgRail     bool
	OrgKey         string
	Generation     int64
	Version        int64
	BodyHash       string
	InertReason    string
	EnforceAllowed bool
	AppliedAt      time.Time
	LastApplyErr   string
	// TableLoaded is true once a compiled table is in the holder (from the
	// cache at start or from an accepted resource).
	TableLoaded bool
}

// mcpRelayHandle is the daemon-lifetime owner of the compiled node table
// (localpdp.Holder) and its on-disk cache. ONE owner (CLAUDE.md #4): the
// resource publisher writes it; the proxy seam, the guard lookup, the
// point reader and `observer mcp-relay status` read it.
type mcpRelayHandle struct {
	cfg    config.MCPRelayConfig
	tables *localpdp.Holder
	engine *localpdp.Engine
	cache  localpdp.Cache
	logger *slog.Logger

	// identity is the node principal source for every local decision.
	identity localpdp.NodeIdentity
	// managed reports Enterprise-Managed Tenancy (managedTenancyLookup);
	// nil = unresolved → individual posture.
	managed func() bool
	// orgAuthoritative reports whether the org holds enforce.mcp_access on
	// a managed node (gateway posture: unknown servers are refused). nil =
	// individual posture (local-stricter-wins; unknown servers ungoverned).
	orgAuthoritative func() bool

	mu    sync.Mutex
	state mcpRelayState

	// projectionApplied is true once at least one client config on this
	// node carries launch-journal rows (the projection actually ran): the
	// relay point's "projection.applied" capability (coverage honesty, Sol
	// P3+P4 finding 2). Set by the runtime / the CLI after a projection or
	// from the journal at start.
	projectionApplied atomic.Bool
	// projectionProbe, when set (the daemon runtime), re-derives the
	// verified applied state on every capability read so the ACK follows
	// the SAME predicate as the matrix (mcpRelayAppliedState) - a config
	// edited or restored after start stops claiming it (Sol P3+P4 fold
	// finding 3). nil = the last SetProjectionApplied value.
	projectionProbe atomic.Pointer[func() bool]
}

// SetProjectionApplied records whether the relay projection is VERIFIED
// applied on this node (mcpRelayAppliedState(...).Any()).
func (h *mcpRelayHandle) SetProjectionApplied(applied bool) {
	if h == nil {
		return
	}
	h.projectionApplied.Store(applied)
}

// SetProjectionProbe binds the live verified-applied probe (nil clears).
func (h *mcpRelayHandle) SetProjectionProbe(fn func() bool) {
	if h == nil {
		return
	}
	if fn == nil {
		h.projectionProbe.Store(nil)
		return
	}
	h.projectionProbe.Store(&fn)
}

// projectionIsApplied is the `projection.applied` capability read.
func (h *mcpRelayHandle) projectionIsApplied() bool {
	if p := h.projectionProbe.Load(); p != nil {
		return (*p)()
	}
	return h.projectionApplied.Load()
}

// processMCPRelay is the process-wide handle the policy-resource publisher
// dispatches to (nil when [mcp_relay].enabled is false or before wiring).
var processMCPRelay atomic.Pointer[mcpRelayHandle]

// newMCPRelayHandle builds the handle and loads any cached compiled table so
// the seams answer before the first org fetch of this process.
func newMCPRelayHandle(cfg config.Config, st *store.Store, ngov *nodeGovernanceHandle, logger *slog.Logger) *mcpRelayHandle {
	if logger == nil {
		logger = slog.Default()
	}
	h := &mcpRelayHandle{
		cfg:    cfg.MCPRelay,
		tables: &localpdp.Holder{},
		cache:  localpdp.Cache{Path: localpdp.SiblingPath(orgBundleCachePath(cfg), cfg.Observer.DBPath)},
		logger: logger,
	}
	h.engine = &localpdp.Engine{Tables: h.tables}
	if st != nil {
		h.managed = managedTenancyLookup(st)
		h.identity = mcpRelayNodeIdentity(context.Background(), st)
	}
	if ngov != nil {
		h.orgAuthoritative = func() bool {
			eff := ngov.Effective(context.Background())
			return mcpRelayOrgAuthoritative(eff)
		}
	}
	if t, err := h.cache.Load(); err == nil && t != nil {
		h.tables.Swap(t)
		h.mu.Lock()
		h.state.TableLoaded = true
		h.state.Version, h.state.BodyHash = t.Meta.Version, t.Meta.BodyHash
		h.state.OrgKey, h.state.Generation = t.Meta.OrgKey, t.Meta.Generation
		h.state.EnforceAllowed = t.Meta.EnforceAllowed
		h.state.HasOrgRail = t.Meta.Version > 0
		h.mu.Unlock()
		logger.Info("mcp-relay: compiled node table loaded from cache", "version", t.Meta.Version, "mode", t.Mode, "path", h.cache.Path)
	} else if err != nil && !errors.Is(err, localpdp.ErrCacheAbsent) {
		logger.Warn("mcp-relay: cached node table unreadable; waiting for the org fetch", "err", err)
	}
	return h
}

// mcpRelayOrgAuthoritative is the managed-vs-individual rule (doc3 §12.8):
// the org mode is authoritative only on a MANAGED node whose grant carries
// enforce.mcp_access; every other node is local-stricter-wins.
func mcpRelayOrgAuthoritative(eff govern.Effective) bool {
	if !eff.Managed || eff.GrantRefused() {
		return false
	}
	for _, a := range eff.Authority {
		if a == govern.AuthorityEnforceMCPAccess {
			return true
		}
	}
	return false
}

// mcpRelayNodeIdentity resolves the node principal from the enrolment row
// (member id + subject); credential assurance is node_enrolled by
// construction (the P1 per-device key). Absent enrolment → empty identity,
// which the table's subject rules treat as an unmatched subject.
func mcpRelayNodeIdentity(ctx context.Context, st *store.Store) localpdp.NodeIdentity {
	enr, err := st.LoadEnrolment(ctx)
	if err != nil || enr == nil {
		return localpdp.NodeIdentity{}
	}
	return localpdp.NodeIdentity{
		Subject:       enr.UserID,
		MemberID:      enr.UserID,
		CredAssurance: "node_enrolled",
	}
}

// Apply is the tools.mcp_access resource publisher (the applyNodeFeatures
// twin): compile the accepted spec into the node table, swap it into the
// holder and persist it beside the org-bundle cache. PRAppliedInert keeps
// the table but in observe mode (Compile reads EnforceAllowed).
func (h *mcpRelayHandle) Apply(res orgclient.PolicyResourceResult) {
	if h == nil {
		return
	}
	spec, ok := res.Spec.(famcp.PolicySpec)
	if !ok {
		h.recordApplyErr(res, "spec is not a tools.mcp_access PolicySpec")
		return
	}
	meta := localpdp.Meta{Version: res.Version, BodyHash: res.BodyHash, OrgKey: res.OrgKey, Generation: res.Generation, EnforceAllowed: res.EnforceAllowed}
	t, err := localpdp.Compile(spec, meta, time.Now().Unix())
	if err != nil {
		h.recordApplyErr(res, err.Error())
		return
	}
	if h.cfg.AuditMode == config.MCPRelayAuditStrict {
		// The effective posture is strict when THIS is strict OR the policy
		// marks the vserver (the table already carries the latter).
		if t.AuditStrict == nil {
			t.AuditStrict = map[string]bool{}
		}
		for _, v := range t.Node.Registry.VServers {
			t.AuditStrict[v.ID] = true
		}
	}
	h.tables.Swap(t)
	if err := h.cache.Save(t); err != nil {
		h.logger.Warn("mcp-relay: node table cache write failed (in-memory table still live; hook processes keep the previous cache)", "err", err)
	}
	h.mu.Lock()
	h.state = mcpRelayState{
		HasOrgRail: true, OrgKey: res.OrgKey, Generation: res.Generation,
		Version: res.Version, BodyHash: res.BodyHash, InertReason: res.InertReason,
		EnforceAllowed: res.EnforceAllowed, AppliedAt: time.Now().UTC(), TableLoaded: true,
	}
	h.mu.Unlock()
	h.logger.Info("mcp-relay: node table applied", "version", res.Version, "mode", t.Mode, "rows", len(t.Node.Rows), "inert_reason", res.InertReason)
}

func (h *mcpRelayHandle) recordApplyErr(res orgclient.PolicyResourceResult, msg string) {
	h.mu.Lock()
	h.state.LastApplyErr = msg
	h.state.HasOrgRail = true
	h.state.Version = res.Version
	h.mu.Unlock()
	h.logger.Warn("mcp-relay: node table apply failed; previous table stays live", "version", res.Version, "err", msg)
}

// Clear drops the org layer (ErrNotEnrolled / identity change): the table
// holder and the cache are emptied so no stale grant decides anything.
func (h *mcpRelayHandle) Clear() {
	if h == nil {
		return
	}
	h.tables.Swap(nil)
	if err := h.cache.Remove(); err != nil {
		h.logger.Warn("mcp-relay: node table cache remove failed", "err", err)
	}
	h.mu.Lock()
	h.state = mcpRelayState{}
	h.mu.Unlock()
}

// SetGovernance binds the node-governance handle after the daemon builds it
// (start.go builds ngov AFTER buildProxy binds the seams): from then on the
// managed-vs-individual rule reads the live effective grant.
func (h *mcpRelayHandle) SetGovernance(ngov *nodeGovernanceHandle) {
	if h == nil || ngov == nil {
		return
	}
	h.mu.Lock()
	h.orgAuthoritative = func() bool { return mcpRelayOrgAuthoritative(ngov.Effective(context.Background())) }
	h.mu.Unlock()
}

// State returns the frozen snapshot.
func (h *mcpRelayHandle) State() mcpRelayState {
	if h == nil {
		return mcpRelayState{}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.state
}

// Table returns the live compiled table (nil = none loaded).
func (h *mcpRelayHandle) Table() *localpdp.Table {
	if h == nil {
		return nil
	}
	return h.tables.Current()
}

// resolveVServer maps a client-side MCP server name (the `mcp__<server>__`
// segment) onto a registry vserver: by id, then by slug, then by a server
// id/target inside a vserver. serverRef is the registry server ref ONLY
// when the name matched a server (the evaluator treats a non-empty Server
// as a registry ref, never a client label); ok=false = the org table does
// not know the name.
func resolveVServer(reg mcpaccess.Registry, server string) (vserver, serverRef string, ok bool) {
	if v, found := reg.VServerByID(server); found {
		return v.ID, "", true
	}
	for _, v := range reg.VServers {
		if v.Slug == server {
			return v.ID, "", true
		}
		for _, s := range v.Servers {
			if s.ID == server || s.Target == server {
				return v.ID, s.ID, true
			}
		}
	}
	return "", "", false
}

// accessRule is one ordered row of the MCP-access decision table the guard
// lookup and the proxy seam share; first match wins.
type accessRule struct {
	match func(known bool, orgAuth bool, observe bool, d localpdp.Decision) bool
	out   func(d localpdp.Decision) guard.MCPAccessVerdict
}

var accessRules = []accessRule{
	// 0. unknown server, org authoritative, table in OBSERVE: a would-deny,
	//    reported allowed (observe never strips / denies — R8.27.h).
	{
		match: func(known, orgAuth, observe bool, _ localpdp.Decision) bool { return !known && orgAuth && observe },
		out: func(localpdp.Decision) guard.MCPAccessVerdict {
			return guard.MCPAccessVerdict{Known: true, Allowed: true, Reason: "observe: would-deny (server not in the org registry)"}
		},
	},
	// 1. unknown server, org authoritative (managed + enforce.mcp_access):
	//    gateway posture — every remote MCP goes through the org gateway.
	{
		match: func(known, orgAuth, _ bool, _ localpdp.Decision) bool { return !known && orgAuth },
		out: func(localpdp.Decision) guard.MCPAccessVerdict {
			return guard.MCPAccessVerdict{Known: true, Reason: "server not in the org tools.mcp_access registry (managed node: org gateway posture)"}
		},
	},
	// 2. unknown server, individual node: ungoverned → inert (no finding).
	{
		match: func(known, _, _ bool, _ localpdp.Decision) bool { return !known },
		out:   func(localpdp.Decision) guard.MCPAccessVerdict { return guard.MCPAccessVerdict{} },
	},
	// 3. pass (allow, or observe-mode would-deny): allowed.
	{
		match: func(_, _, _ bool, d localpdp.Decision) bool { return d.Forwardable() },
		out: func(d localpdp.Decision) guard.MCPAccessVerdict {
			return guard.MCPAccessVerdict{Known: true, Allowed: true, Reason: d.Reason}
		},
	},
	// 4. PDP error (no table / unknown vserver / bad params): inert — the
	//    relay's own error path handles it; never a fabricated deny.
	{
		match: func(_, _, _ bool, d localpdp.Decision) bool { return d.Verdict == localpdp.VerdictError },
		out:   func(localpdp.Decision) guard.MCPAccessVerdict { return guard.MCPAccessVerdict{} },
	},
	// 5. explicit deny / ask on a channel that cannot ask: org grant denied.
	{
		match: func(_, _, _ bool, _ localpdp.Decision) bool { return true },
		out: func(d localpdp.Decision) guard.MCPAccessVerdict {
			return guard.MCPAccessVerdict{Known: true, OrgDenied: true, Reason: d.Reason}
		},
	},
}

// orgAuth reads the (possibly re-bound) authority resolver.
func (h *mcpRelayHandle) orgAuth() bool {
	h.mu.Lock()
	fn := h.orgAuthoritative
	h.mu.Unlock()
	return fn != nil && fn()
}

// decide answers one (server, tool) pair for the capability-reduced points
// (hook / proxy): transport unknown → attestation `claimed`, so
// product-scoped grants are NOT honoured here (the honest posture: neither
// point can attest the client).
func (h *mcpRelayHandle) decide(server, tool string) guard.MCPAccessVerdict {
	t := h.Table()
	if t == nil {
		return guard.MCPAccessVerdict{}
	}
	orgAuth := h.orgAuth()
	vs, serverRef, known := resolveVServer(t.Node.Registry, server)
	var d localpdp.Decision
	if known {
		p, ok := t.NodePrincipal(h.identity, vs, localpdp.TransportUnknown)
		if !ok {
			known = false
		} else {
			d = h.engine.CheckRequest(context.Background(), localpdp.Request{
				VServerID: vs, Method: "tools/call", Tool: tool, Server: serverRef, Principal: p,
			})
		}
	}
	observe := t.Mode == localpdp.ModeObserve
	for _, r := range accessRules {
		if r.match(known, orgAuth, observe, d) {
			return r.out(d)
		}
	}
	return guard.MCPAccessVerdict{}
}

// AccessLookup is the guard seam.
func (h *mcpRelayHandle) AccessLookup() guard.MCPAccessLookup {
	return func(server, tool string) guard.MCPAccessVerdict { return h.decide(server, tool) }
}

// connectorApproved reports whether a provider-hosted connector URL is one
// the org table names (a vserver audience or a server target).
func connectorApproved(reg mcpaccess.Registry, c proxy.HostedMCPConnector) bool {
	if c.URL == "" {
		return false
	}
	u := strings.TrimRight(c.URL, "/")
	for _, v := range reg.VServers {
		if strings.TrimRight(reg.AudienceOf(v), "/") == u {
			return true
		}
		for _, s := range v.Servers {
			if strings.TrimRight(s.Target, "/") == u {
				return true
			}
		}
	}
	return false
}

// ToolsSeam is the proxy seam: strip every `mcp__*` declaration the table
// does not allow (R-306); refuse the request for a hosted connector the org
// does not approve (R-307, org-authoritative nodes only — an individual
// node's unknown connector is ungoverned).
func (h *mcpRelayHandle) ToolsSeam() proxy.ToolsAllowlistSeam {
	return func(in proxy.ToolsAllowlistInput) proxy.ToolsAllowlistResult {
		t := h.Table()
		if t == nil {
			return proxy.ToolsAllowlistResult{Keep: in.Decls}
		}
		orgAuth := h.orgAuth()
		for _, c := range in.Connectors {
			if connectorApproved(t.Node.Registry, c) {
				continue
			}
			if !orgAuth {
				continue
			}
			if t.Mode == localpdp.ModeObserve {
				h.logger.Info("mcp-relay: observe would-deny hosted MCP connector", "connector", c.Name, "url", c.URL, "session_id", in.SessionID)
				continue
			}
			name := c.Name
			if name == "" {
				name = c.ConnectorID
			}
			return proxy.ToolsAllowlistResult{
				DenyRuleID: "R-307",
				DenyReason: "hosted MCP connector " + name + " is not approved by the organization's tools.mcp_access grant; remote MCP must route through the org gateway",
			}
		}
		keep := make([]proxy.MCPToolDecl, 0, len(in.Decls))
		for _, d := range in.Decls {
			v := h.decide(d.Server, d.Tool)
			if !v.Known || v.Allowed {
				keep = append(keep, d)
				continue
			}
			h.logger.Info("mcp-relay: stripping disallowed MCP tool declaration", "tool", d.Name, "reason", v.Reason, "session_id", in.SessionID)
		}
		return proxy.ToolsAllowlistResult{Keep: keep}
	}
}

// pointCapabilities lists the capabilities the relay point actually holds in
// this process — the `point_capability_set` the effective hash and status
// are computed from. Missing ANY required one reports ineffective.
func (h *mcpRelayHandle) pointCapabilities() []string {
	caps := []string{"stdio.wrapper", "record.store"}
	if h.Table() != nil {
		caps = append(caps, "table.loaded")
	}
	if h.projectionIsApplied() {
		caps = append(caps, "projection.applied")
	}
	return caps
}

// Facts resolves the point facts for the effective-state reader.
func (h *mcpRelayHandle) Facts() (policystate.PointFacts, bool) {
	if h == nil {
		return policystate.PointFacts{EnforceMode: "off"}, false
	}
	st := h.State()
	t := h.Table()
	f := policystate.PointFacts{HasOrgRail: st.HasOrgRail, InertReason: st.InertReason}
	if !st.HasOrgRail || t == nil {
		f.EnforceMode = "off"
		return f, false
	}
	// The LIVE table's identity, never st.Version: recordApplyErr stamps the
	// REFUSED version there, and reporting it as running would ACK a config
	// the relay refused (last-known-good stays live; Lane HA defect D3).
	f.CachedAcceptedVersion = t.Meta.Version
	f.RunningVersion = t.Meta.Version
	status, _ := coverage.Status(coverage.PointRelay, h.pointCapabilities())
	f.EffectiveHash = coverage.EffectiveHash(coverage.EffectiveInput{
		PolicyVersion: t.Meta.Version, CompiledSubsetHash: t.Meta.BodyHash,
		PointCapabilitySet: h.pointCapabilities(), ClientID: "observer", ClientVersion: version,
		ClientConfigState: string(status),
	})
	switch {
	case t.Mode == localpdp.ModeEnforce && status == coverage.StatusEffective:
		f.EnforceMode = "enforce"
	default:
		f.EnforceMode = "observe"
		// Either an observe table, or an enforce table on a point missing a
		// required capability (coverage.StatusIneffective - e.g. the
		// client-config projection never applied): the point only observes,
		// so the ACK row must be accepted_inert, never effective (doc3
		// §12.7; Lane SURF F1). mode_observe is the closed-enum reason the
		// org server pairs with accepted_inert for "runs, does not enforce".
		if f.InertReason == "" {
			f.InertReason = "mode_observe" // orgcontract.ReasonModeObserve
		}
	}
	return f, true
}

// newMCPRelayPointReader is the node-mcp-relay PointReader (the
// newNodeFeaturesPointReader twin). Registered UNCONDITIONALLY: an omitted
// row is indistinguishable from an older agent, an explicit none/no_policy
// row is the honest "no relay / no table on this node".
func newMCPRelayPointReader(h *mcpRelayHandle, lastFetch func() orgclient.PolicyResourceFetchOutcome, now func() time.Time) policystate.PointReader {
	return func(context.Context) (policystate.PointFacts, error) {
		f, _ := h.Facts()
		f.LastSeen = now()
		if lastFetch != nil {
			o := lastFetch()
			reject := wirePolicyResourceRejectReason(o.RejectCode)
			f.LatestFetchRejected = reject != ""
			f.RejectCode = reject
			f.RejectedVersion = o.Version
			f.Unreachable = o.Unreachable
		}
		return f, nil
	}
}

// mcpRelayPublish is the tools.mcp_access hook publishPolicyResourceResult
// calls; nil handle (relay disabled) = no-op, byte-identical.
func mcpRelayPublish(res orgclient.PolicyResourceResult) {
	if h := processMCPRelay.Load(); h != nil {
		h.Apply(res)
	}
}

// mcpRelayClear is the tools.mcp_access hook clearOrgLayer calls.
func mcpRelayClear() {
	if h := processMCPRelay.Load(); h != nil {
		h.Clear()
	}
}

// wireMCPRelay binds the node-side seams under [mcp_relay].enabled and
// returns the handle (nil when disabled: NOTHING is bound).
func wireMCPRelay(cfg config.Config, st *store.Store, ngov *nodeGovernanceHandle, opts *proxy.Options, g *guard.Guard, logger *slog.Logger) *mcpRelayHandle {
	if !cfg.MCPRelay.Enabled {
		return nil
	}
	h := newMCPRelayHandle(cfg, st, ngov, logger)
	processMCPRelay.Store(h)
	if opts != nil {
		opts.ToolsAllowlist = h.ToolsSeam()
	}
	if g != nil {
		g.SetMCPAccessLookup(h.AccessLookup())
	}
	h.logger.Info("mcp-relay: node-side seams wired",
		"mode", cfg.MCPRelay.Mode, "audit_mode", cfg.MCPRelay.AuditMode,
		"proxy_tools_filter", opts != nil, "guard_access_lookup", g != nil,
		"table_loaded", h.Table() != nil, "family", policyfam.FamilyMCPAccess)
	return h
}

// hookMCPAccessLookup is the HOOK-process binding: a short-lived process
// that must not pay an org fetch reads the compiled table the daemon cached
// beside the org-bundle cache (localpdp.Cache) and answers from it. Absent
// cache / relay disabled → nil (no finding; fail-open, memory
// feedback_hook_fail_open_on_timeout).
func hookMCPAccessLookup(cfg config.Config) guard.MCPAccessLookup {
	if !cfg.MCPRelay.Enabled {
		return nil
	}
	h := newMCPRelayHandle(cfg, nil, nil, slog.New(slog.DiscardHandler))
	if h.Table() == nil {
		return nil
	}
	return h.AccessLookup()
}

// serveMCPRelayLoopback binds the dedicated loopback listener when
// [mcp_relay].listen is set. The address MUST be loopback — the relay is
// never exposed beyond this machine. Returns the bound address.
func serveMCPRelayLoopback(ctx context.Context, listen string, handler http.Handler, logger *slog.Logger) (string, error) {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("mcp-relay listen %q: %w", listen, err)
	}
	if !isLoopbackHost(host) {
		return "", fmt.Errorf("mcp-relay listen %q is not a loopback address (127.0.0.1 / localhost / ::1)", listen)
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return "", fmt.Errorf("mcp-relay listen: %w", err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	go func() {
		if serr := srv.Serve(ln); serr != nil && !errors.Is(serr, http.ErrServerClosed) {
			logger.Warn("mcp-relay: loopback listener stopped", "err", serr)
		}
	}()
	return ln.Addr().String(), nil
}

// mcpRelayRuntime is what startMCPRelayRuntime built: the relay, its record
// store, the loopback address (empty when no dedicated listener), the
// remote-forwarding resolution and the projection report.
type mcpRelayRuntime struct {
	relay    *mcprelay.Relay
	records  *record.SQLStore
	loopback string
	// remoteForwarding is TRUE exactly when the STS token client was built
	// (remote.Wired): node-local stdio servers are always mediated; a
	// remote vserver call is refused by the relay's own no-token path when
	// this is false, never silently forwarded.
	remoteForwarding bool
	remote           mcpRelayRemote
	// projection is the receipt of the projection this start ran
	// (idempotent: a re-run of an applied node changes nothing).
	projection project.Report
	// remoteSkip explains why no remote entry was projected ("" = they were).
	remoteSkip string
}

// mcpRelayNodeKey is the record chain's genesis identity: the enrolment
// member id (stable per node enrolment) — never empty on an enrolled node.
// An unenrolled node gets a DB-path-scoped key so the chain still opens.
func mcpRelayNodeKey(ctx context.Context, cfg config.Config, st *store.Store) string {
	if st != nil {
		if enr, err := st.LoadEnrolment(ctx); err == nil && enr != nil && enr.UserID != "" {
			return "member:" + enr.UserID
		}
	}
	return "node:" + cfg.Observer.DBPath
}

// launchSpecStore is the launch-journal subset of record.Store the relay
// composition uses (the record.SQLStore in production, a fake in tests).
type launchSpecStore interface {
	PutLaunchSpec(ctx context.Context, spec record.LaunchSpec, expectedGeneration int64) error
	GetLaunchSpec(ctx context.Context, client, configPath, entryKey string) (record.LaunchSpec, error)
	ListLaunchSpecs(ctx context.Context) ([]record.LaunchSpec, error)
	DeleteLaunchSpec(ctx context.Context, client, configPath, entryKey string) error
}

// errMCPRelayUnbound is the typed refusal for a stdio journal row that
// carries no approved vserver binding (a pre-133 row): the wrapper never
// guesses a vserver - the local PDP could not authorize a single call.
var errMCPRelayUnbound = errors.New("mcp-relay launch spec has no approved vserver binding (projected before node migration 133); run `observer mcp-relay disable` then `observer mcp-relay enable` to re-project it")

// launchSpecsFromJournal adapts N-M's launch journal to the wrapper's
// LaunchSpecs seam: the stdio wrapper is spawned with
// `--client <tool> --server <entry key>` and resolves the ORIGINAL command
// AND the approved (vserver, registry server) binding the entry was
// projected under from the journaled row (Sol P3+P4 fold finding 2): the
// wrapper hands the local PDP exactly the vserver the projection bound. The child's environment starts from the
// wrapper's OWN os.Environ() (the client's - PATH/HOME/locale and whatever
// the client set on the entry) with the journaled secret-reference KEYS
// overlaid from that same environment; a value is never persisted and a
// one-variable environment is never passed (Sol P3+P4 finding 6).
type launchSpecsFromJournal struct {
	st        launchSpecStore
	environ   func() []string
	lookupEnv func(string) (string, bool)
}

// Lookup implements mcprelay.LaunchSpecs.
func (l launchSpecsFromJournal) Lookup(ctx context.Context, client, serverID string) (mcprelay.LaunchSpec, error) {
	rows, err := l.st.ListLaunchSpecs(ctx)
	if err != nil {
		return mcprelay.LaunchSpec{}, fmt.Errorf("mcp-relay launch spec: %w", err)
	}
	environ, lookup := l.environ, l.lookupEnv
	if environ == nil {
		environ = os.Environ
	}
	if lookup == nil {
		lookup = os.LookupEnv
	}
	for _, r := range rows {
		if r.EntryKey != serverID || (client != "" && r.Client != client) || r.OrigCommand == project.RemoteOrigCommand {
			continue
		}
		if r.VServer == "" {
			return mcprelay.LaunchSpec{}, fmt.Errorf("mcp-relay launch spec %s/%q: %w", r.Client, serverID, errMCPRelayUnbound)
		}
		spec := mcprelay.LaunchSpec{ServerID: r.RegistryServerID, VServer: r.VServer, Command: r.OrigCommand, Args: append([]string(nil), r.OrigArgs...), Cwd: r.OrigCwd}
		spec.Env = overlayEnv(environ(), r.OrigEnvRefs, lookup)
		return spec, nil
	}
	return mcprelay.LaunchSpec{}, fmt.Errorf("mcp-relay launch spec %s/%q: %w", client, serverID, record.ErrNotFound)
}

// overlayEnv returns base with every ref that resolves through lookup set
// (replacing an existing KEY= entry, else appended); refs that do not
// resolve are left as base has them.
func overlayEnv(base, refs []string, lookup func(string) (string, bool)) []string {
	out := append([]string(nil), base...)
	for _, ref := range refs {
		v, ok := lookup(ref)
		if !ok {
			continue
		}
		replaced := false
		for i, kv := range out {
			if strings.HasPrefix(kv, ref+"=") {
				out[i] = ref + "=" + v
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, ref+"="+v)
		}
	}
	return out
}

// mcpRelayBackupDir is where the verbatim pre-relay config backups live:
// <db dir>/mcp-relay/backups (doc3 §12.1 R8.28.i: ~/.observer/mcp-relay/
// backups on a default install), owner-only.
func mcpRelayBackupDir(cfg config.Config) string {
	return filepath.Join(filepath.Dir(cfg.Observer.DBPath), "mcp-relay", "backups")
}

// mcpRelayJournal is the ONE project.Journal owner on the node: the
// mcp_relay_launch_spec rows through N-M's store + the backup FILE half
// (internal/mcprelay/journal.go). It is a pure adapter - the SEQUENCE is
// the projector's (parking decision B5).
type mcpRelayJournal struct {
	st        launchSpecStore
	backupDir string
}

func newMCPRelayJournal(cfg config.Config, st launchSpecStore) mcpRelayJournal {
	return mcpRelayJournal{st: st, backupDir: mcpRelayBackupDir(cfg)}
}

func journalRowOf(l record.LaunchSpec) project.JournalRow {
	return project.JournalRow{
		Tool: l.Client, ConfigPath: l.ConfigPath, EntryKey: l.EntryKey,
		OrigCommand: l.OrigCommand, OrigArgs: l.OrigArgs, OrigCwd: l.OrigCwd, OrigEnvRefs: l.OrigEnvRefs,
		ConfigGeneration: l.ConfigGeneration, BackupPath: l.BackupPath, BackupSHA256: l.BackupSHA256,
		AppliedSHA256: l.AppliedSHA256, AppliedAt: time.Unix(l.AppliedAt, 0).UTC(),
		VServer: l.VServer, RegistryServerID: l.RegistryServerID,
	}
}

// List implements project.Journal.
func (j mcpRelayJournal) List(ctx context.Context) ([]project.JournalRow, error) {
	rows, err := j.st.ListLaunchSpecs(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]project.JournalRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, journalRowOf(r))
	}
	return out, nil
}

// Put implements project.Journal (the store's generation CAS).
func (j mcpRelayJournal) Put(ctx context.Context, row project.JournalRow, expected int64) error {
	return j.st.PutLaunchSpec(ctx, record.LaunchSpec{
		Client: row.Tool, ConfigPath: row.ConfigPath, EntryKey: row.EntryKey,
		OrigCommand: row.OrigCommand, OrigArgs: row.OrigArgs, OrigCwd: row.OrigCwd, OrigEnvRefs: row.OrigEnvRefs,
		ConfigGeneration: row.ConfigGeneration, BackupPath: row.BackupPath, BackupSHA256: row.BackupSHA256,
		AppliedAt: row.AppliedAt.Unix(), AppliedSHA256: row.AppliedSHA256,
		VServer: row.VServer, RegistryServerID: row.RegistryServerID,
	}, expected)
}

// Delete implements project.Journal; the backup file is removed once no
// row references it (a backup of a client config may hold secrets).
func (j mcpRelayJournal) Delete(ctx context.Context, tool, configPath, entryKey string) error {
	old, err := j.st.GetLaunchSpec(ctx, tool, configPath, entryKey)
	if errors.Is(err, record.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := j.st.DeleteLaunchSpec(ctx, tool, configPath, entryKey); err != nil {
		return err
	}
	if old.BackupPath == "" {
		return nil
	}
	rows, err := j.st.ListLaunchSpecs(ctx)
	if err != nil {
		return nil // best-effort cleanup; the row is gone
	}
	for _, r := range rows {
		if r.BackupPath == old.BackupPath {
			return nil
		}
	}
	_ = os.Remove(old.BackupPath)
	return nil
}

// Backup implements project.Journal (doc3 §12.1 step 1: verbatim, owner-
// only, fsynced).
func (j mcpRelayJournal) Backup(_ context.Context, c project.Client, original []byte) (string, string, error) {
	return mcprelay.BackupConfigBytes(c.ConfigPath, j.backupDir, original, original == nil)
}

// RestoreWhole implements project.Journal through the ONE whole-file
// restore primitive (mcprelay.RestoreConfigCAS): backup digest verified,
// CAS on the row's applied digest; refusals are mapped onto the
// projector's sentinels so its rule table can fall back to the reversal.
func (j mcpRelayJournal) RestoreWhole(_ context.Context, _ project.Client, row project.JournalRow) error {
	err := mcprelay.RestoreConfigCAS(mcprelay.LaunchJournalEntry{
		Client: row.Tool, ConfigPath: row.ConfigPath, EntryKey: row.EntryKey,
		OrigCommand: row.OrigCommand, OrigArgs: row.OrigArgs, OrigCwd: row.OrigCwd, OrigEnvRefs: row.OrigEnvRefs,
		ConfigGeneration: row.ConfigGeneration, BackupPath: row.BackupPath, BackupSHA256: row.BackupSHA256,
		AppliedAt: row.AppliedAt, AppliedSHA256: row.AppliedSHA256,
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, mcprelay.ErrConfigChanged):
		return fmt.Errorf("%w: %v", project.ErrConfigChanged, err) //nolint:errorlint // single-sentinel classification; cause deliberately not in the chain
	case errors.Is(err, mcprelay.ErrNoAppliedDigest):
		return fmt.Errorf("%w: %v", project.ErrNoAppliedDigest, err) //nolint:errorlint // single-sentinel classification; cause deliberately not in the chain
	}
	return err
}

// mcpRelayHomeOverride pins the registrar's home directory (tests only:
// a projection must never touch the developer's real client configs from
// a test). Empty = the real $HOME.
var mcpRelayHomeOverride string

// mcpRelayRegistrar builds the per-format writer over the running binary
// (the command every wrapped entry spawns).
func mcpRelayRegistrar() (*mcp.Registrar, string, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, "", fmt.Errorf("mcp-relay: resolve observer binary: %w", err)
	}
	if abs, aerr := filepath.EvalSymlinks(exe); aerr == nil {
		exe = abs
	}
	r, err := mcp.NewRegistrar(mcp.RegisterOptions{BinaryPath: exe, HomeDir: mcpRelayHomeOverride})
	if err != nil {
		return nil, "", err
	}
	return r, exe, nil
}

// mcpRelayLoopbackURL is the relay's own loopback base URL when
// [mcp_relay].listen names a dedicated listener ("" otherwise: nothing
// serves /mcp/<slug> on this node, so no remote entry can be projected).
func mcpRelayLoopbackURL(cfg config.Config) string {
	if cfg.MCPRelay.Listen == "" {
		return ""
	}
	return "http://" + cfg.MCPRelay.Listen
}

// mcpRelayDesired composes the desired state for every client: the stdio
// wrap (always, under enable) and the approved vservers as remote entries
// through the relay loopback - only when a loopback listener is configured
// AND the token client is wired, else the remote entries are skipped with
// the honest reason (a projected entry the relay cannot forward would break
// the client's server for nothing).
func mcpRelayDesired(cfg config.Config, h *mcpRelayHandle, binary, configPath string, remoteWired bool) (project.Desired, string) {
	t := h.Table()
	d := project.Desired{Wrap: &project.WrapSpec{Command: binary, ConfigPath: configPath}, Approved: mcpRelayApproved(t)}
	loop := mcpRelayLoopbackURL(cfg)
	switch {
	case loop == "":
		return d, "no [mcp_relay].listen loopback listener configured"
	case !remoteWired:
		return d, "remote forwarding is not wired (no STS token client)"
	case t == nil:
		return d, "no tools.mcp_access table loaded (no approved vservers)"
	}
	for _, v := range t.Node.Registry.VServers {
		d.Remote = append(d.Remote, project.RemoteEntry{Name: mcpRelayEntryPrefix + v.Slug, URL: loop + "/mcp/" + v.Slug, Transport: "http"})
	}
	if len(d.Remote) == 0 {
		return d, "the tools.mcp_access table names no vserver"
	}
	return d, ""
}

// mcpRelayApproved flattens the accepted table's registry into the binding
// rows a stdio entry key is resolved against at projection time (Sol P3+P4
// fold finding 2): one row per (vserver, member), a vserver with no member
// as one member-less row. nil table = nil (every stdio entry is refused
// project.RefuseNoApprovedServers - never wrapped unbound).
func mcpRelayApproved(t *localpdp.Table) []project.ApprovedServer {
	if t == nil {
		return nil
	}
	var out []project.ApprovedServer
	for _, v := range t.Node.Registry.VServers {
		if len(v.Servers) == 0 {
			out = append(out, project.ApprovedServer{VServer: v.ID, VServerSlug: v.Slug})
			continue
		}
		for _, sv := range v.Servers {
			out = append(out, project.ApprovedServer{VServer: v.ID, VServerSlug: v.Slug, ServerID: sv.ID, Target: sv.Target})
		}
	}
	return out
}

// mcpRelayEntryPrefix prefixes every relay-owned remote entry key
// ("superbased-<slug>"), distinct from mcp.ServerName ("observer").
const mcpRelayEntryPrefix = "superbased-"

// runMCPRelayProjection is THE installation path (Sol P3+P4 finding 2):
// every verified installed client's stdio entries are wrapped and the
// approved remote entries projected, each write journaled first, through
// the ONE projector. Idempotent. Runs from the daemon runtime and from
// `observer mcp-relay enable`.
func runMCPRelayProjection(ctx context.Context, cfg config.Config, configPath string, st launchSpecStore, h *mcpRelayHandle, remoteWired bool) (project.Report, string, error) {
	registrar, exe, err := mcpRelayRegistrar()
	if err != nil {
		return project.Report{}, "", err
	}
	desired, remoteSkip := mcpRelayDesired(cfg, h, exe, configPath, remoteWired)
	p := &project.Projector{Writer: registrar, Journal: newMCPRelayJournal(cfg, st)}
	rep, err := p.Apply(ctx, registrar.RelayClients(), desired)
	if err != nil {
		return rep, remoteSkip, err
	}
	h.SetProjectionApplied(mcpRelayAppliedState(ctx, st).Any())
	return rep, remoteSkip, nil
}

// restoreMCPRelayProjection puts every journaled client config back through
// the projector's restore rule table (whole-file byte-identical under the
// applied-digest CAS, else the format-aware reversal), never bypassing it.
func restoreMCPRelayProjection(ctx context.Context, cfg config.Config, st launchSpecStore, h *mcpRelayHandle) ([]project.RestoreReceipt, error) {
	registrar, _, err := mcpRelayRegistrar()
	if err != nil {
		return nil, err
	}
	p := &project.Projector{Writer: registrar, Journal: newMCPRelayJournal(cfg, st)}
	recs, rerr := p.Restore(ctx)
	h.SetProjectionApplied(mcpRelayAppliedState(ctx, st).Any())
	return recs, rerr
}

// mcpRelayConfigDigest is the VerifyApplied current-bytes seam: the
// lowercase hex SHA-256 of a client config's bytes on disk (ok=false when
// it cannot be read - an absent or unreadable config verifies nothing).
func mcpRelayConfigDigest(path string) (string, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return mcprelay.HashBytes(raw), true
}

// mcpRelayAppliedState is THE applied predicate on this node (Sol P3+P4
// fold finding 3), per client AND per transport: a journal row counts only
// when its config's CURRENT bytes hash to the row's applied digest - a row
// left behind by a failed commit, or a config edited since, is NOT
// applied. The coverage matrix, the effective-state ACK's
// `projection.applied` capability and `observer mcp-relay status` all read
// this one derivation.
func mcpRelayAppliedState(ctx context.Context, st launchSpecStore) project.AppliedState {
	if st == nil {
		return project.VerifyApplied(nil, nil)
	}
	specs, err := st.ListLaunchSpecs(ctx)
	if err != nil {
		return project.VerifyApplied(nil, nil)
	}
	rows := make([]project.JournalRow, 0, len(specs))
	for _, l := range specs {
		rows = append(rows, journalRowOf(l))
	}
	return project.VerifyApplied(rows, mcpRelayConfigDigest)
}

// mcpRelayUnmediatedStdio previews (Stage only - nothing is journaled or
// written) what a projection would do NOW for every verified client and
// counts, per client, the stdio entries that are not the wrapper: refused
// for want of an approved binding, or bound but not yet wrapped. A client
// whose preview fails counts one (its stdio is not claimed). nil when the
// writer cannot be built (the matrix then claims no partial mediation
// beyond the verified rows - and a verified row requires the file the
// relay wrote, so this only ever lowers a claim).
func mcpRelayUnmediatedStdio(ctx context.Context, cfg config.Config, h *mcpRelayHandle, remoteWired bool) map[string]int {
	registrar, exe, err := mcpRelayRegistrar()
	if err != nil {
		return nil
	}
	desired, _ := mcpRelayDesired(cfg, h, exe, "", remoteWired)
	desired.Remote = nil
	rep, err := (&project.Projector{Writer: registrar}).Preview(ctx, registrar.RelayClients(), desired)
	if err != nil {
		return nil
	}
	out := map[string]int{}
	for _, r := range rep.Receipts {
		switch {
		case r.Skipped != "":
		case r.Err != "":
			out[r.Client.Tool]++
		default:
			if n := len(r.Wrapped) + len(r.Refused); n > 0 {
				out[r.Client.Tool] += n
			}
		}
	}
	return out
}

// mcpRelayCoverageLive derives the coverage matrix's live inputs from what
// exists on THIS node: the writer table (internal/mcp), the VERIFIED
// applied state per transport (mcpRelayAppliedState), the stdio entries a
// preview shows are not wrapped, and the remote-forwarding resolution.
func mcpRelayCoverageLive(ctx context.Context, cfg config.Config, st launchSpecStore, h *mcpRelayHandle, remoteWired bool) coverage.Live {
	applied := mcpRelayAppliedState(ctx, st)
	unmediated := mcpRelayUnmediatedStdio(ctx, cfg, h, remoteWired)
	return coverage.Live{
		WrapWriter:      mcp.WrapWriterImplemented,
		AppliedStdio:    applied.StdioApplied,
		AppliedRemote:   applied.RemoteApplied,
		StdioUnmediated: func(tool string) int { return unmediated[tool] },
		RemoteWired:     remoteWired,
	}
}

// projectedClients lists the tools with at least one VERIFIED applied row
// (either transport), sorted.
func projectedClients(ctx context.Context, st launchSpecStore) []string {
	return mcpRelayAppliedState(ctx, st).Clients()
}

// mcpRelayRemote is the remote-forwarding resolution `observer mcp-relay
// status` reports (parking decision B9, node half): the registration is
// re-derived on every start and held in memory only - the key store (keychain,
// or the hardened 0600 file on a host without one) is the durable secret, the org server the durable record.
type mcpRelayRemote struct {
	// Wired is TRUE exactly when the STS token client was built.
	Wired bool `json:"wired"`
	// Reason is the honest reason forwarding is off ("" when wired).
	Reason       string `json:"reason,omitempty"`
	CredentialID string `json:"credential_id,omitempty"`
	CredGen      int64  `json:"cred_gen,omitempty"`
	MachineFP    string `json:"machine_fp,omitempty"`
	RegisteredAt string `json:"registered_at,omitempty"`
	// Created reports this resolution registered a NEW credential (false on
	// the idempotent re-registration every start performs).
	Created    bool   `json:"created,omitempty"`
	Issuer     string `json:"issuer,omitempty"`
	GatewayURL string `json:"gateway_url,omitempty"`
}

// mcpRelayRemoteDeps are the I/O seams resolveMCPRelayRemote composes; the
// production set is defaultMCPRelayRemoteDeps, tests inject fakes.
type mcpRelayRemoteDeps struct {
	// keys opens the agent-access-key slot (orgclient.OpenAgentAccessKeyStore).
	keys func() (orgclient.AgentAccessKeyStore, error)
	// register performs the idempotent P1 registration.
	register func(ctx context.Context, keys orgclient.AgentAccessKeyStore) (orgclient.AgentAccessRegistration, error)
	// bearer loads the enrolment bearer (the subject token).
	bearer func() (string, error)
	// egress builds the policy-guarded HTTP client for a target URL.
	egress func(target string, enr *store.Enrolment) *http.Client
}

func defaultMCPRelayRemoteDeps(cfg config.Config, st *store.Store, logger *slog.Logger) mcpRelayRemoteDeps {
	bs := orgclient.OpenBearerStore(cfg.OrgClient.KeychainID, filepath.Dir(cfg.Observer.DBPath), logger)
	return mcpRelayRemoteDeps{
		keys: func() (orgclient.AgentAccessKeyStore, error) {
			return orgclient.OpenAgentAccessKeyStoreIn(cfg.OrgClient.KeychainID, filepath.Dir(cfg.Observer.DBPath), logger)
		},
		register: func(ctx context.Context, keys orgclient.AgentAccessKeyStore) (orgclient.AgentAccessRegistration, error) {
			client := orgclient.New(cfg.OrgClient, st, bs, version, nil, logger)
			return client.RegisterAgentAccessKey(ctx, keys)
		},
		bearer: bs.LoadBearer,
		egress: mcpRelayEgressClient,
	}
}

// mcpRelayEgressClient is the internal/mcpegress-guarded client every
// upstream dial (STS exchange, gateway forward) goes through. Loopback /
// private ranges are admitted ONLY when the target is the very org server
// this node is enrolled with (the operator trusted that host at enrolment).
func mcpRelayEgressClient(target string, enr *store.Enrolment) *http.Client {
	allowPrivate := enr != nil && sameHost(target, enr.OrgServerURL)
	policy := mcpegress.DialPolicyFor(mcpegress.Options{Transport: mcpegress.TransportStreamableHTTP, AllowPrivateNetwork: allowPrivate})
	// Decision (Sol fold 5 finding 1): mcpegress ignores ambient proxies by default, but this relay reaches org-APPROVED URLs from the developer's own machine, where corporate proxies are common, so it passes the environment proxy EXPLICITLY (the dial to that proxy is still policy-checked).
	return mcpegress.NewClient(policy, mcpegress.ClientConfig{UserAgent: "superbased-observer-mcp-relay/" + version, Proxy: http.ProxyFromEnvironment})
}

func sameHost(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	return errA == nil && errB == nil && ua.Hostname() != "" && strings.EqualFold(ua.Hostname(), ub.Hostname())
}

// mcpRelayGatewayURL resolves the org gateway base: [mcp_relay].gateway_url
// when set (an individual node dialling a gateway directly), else the
// accepted table's gateway_base_uri (a managed node's grant).
func mcpRelayGatewayURL(cfg config.Config, t *localpdp.Table) string {
	if cfg.MCPRelay.GatewayURL != "" {
		return cfg.MCPRelay.GatewayURL
	}
	if t != nil {
		return t.Node.Registry.GatewayBaseURI
	}
	return ""
}

// buildMCPRelayTokenClient builds the DPoP-bound STS exchange client from a
// registration (never from nothing: an empty CredentialID / MachineFP is
// refused by mcprelay.NewTokenClient). The relay ALWAYS mints DPoP-bound
// tokens (R9.1).
func buildMCPRelayTokenClient(reg orgclient.AgentAccessRegistration, memberID, issuer string, keys mcprelay.KeyStore, bearer func() (string, error), httpc *http.Client, logger *slog.Logger) (*mcprelay.TokenClient, error) {
	if strings.TrimSpace(issuer) == "" {
		return nil, errors.New("mcp-relay: STS issuer is empty")
	}
	if memberID == "" {
		return nil, errors.New("mcp-relay: enrolment member id is empty")
	}
	return mcprelay.NewTokenClient(mcprelay.TokenClientConfig{
		TokenEndpoint: strings.TrimRight(issuer, "/") + "/oauth2/token",
		Keys:          keys,
		SubjectToken:  func(context.Context) (string, error) { return bearer() },
		Actor: mcprelay.ActorSpec{
			NodeID: reg.MachineFP, CredentialID: reg.CredentialID, MemberID: memberID,
			MachineFP: reg.MachineFP, CredGen: reg.CredGen,
		},
		HTTP: httpc,
		Log:  logger,
	})
}

// remoteRefusal classifies a registration error into the status reason.
var remoteRefusal = []struct {
	is     error
	reason string
}{
	{orgclient.ErrNotEnrolled, "not enrolled"},
	{orgclient.ErrAgentAccessKeychainUnavailable, "no agent-access key store: OS keychain unavailable and the hardened 0600 file fallback is unusable here (unsupported platform, or the org-bearer directory is not an owner-only 0700 directory)"},
	{orgclient.ErrAgentAccessUnsupported, "registration refused: the org server does not serve agent-access registration"},
	{orgclient.ErrAgentAccessDeviceRevoked, "registration refused: this device's agent-access credential was revoked by an admin"},
	{orgclient.ErrAgentAccessDeviceLimit, "registration refused: the member is at the agent-access device limit"},
	{orgclient.ErrAgentAccessRejected, "registration refused: the org server rejected the registration"},
	{orgclient.ErrAuthFailed, "registration refused: enrolment bearer rejected (401/403)"},
}

func classifyRemoteErr(err error) string {
	for _, r := range remoteRefusal {
		if errors.Is(err, r.is) {
			return r.reason
		}
	}
	return "org server / STS unreachable: " + err.Error()
}

// resolveMCPRelayRemote derives remote forwarding for this start: enrolled
// -> the idempotent P1 registration (which mints the agent-access key on
// first use) -> the DPoP token client over the accepted table's STS
// issuer through an egress-guarded client. Every refusal is a plain
// reason, never a fabricated client. Returns the token client (nil when
// off), the gateway HTTP client and the resolution.
func resolveMCPRelayRemote(ctx context.Context, cfg config.Config, st *store.Store, h *mcpRelayHandle, deps mcpRelayRemoteDeps, logger *slog.Logger) (*mcprelay.TokenClient, *http.Client, mcpRelayRemote) {
	if st == nil {
		return nil, nil, mcpRelayRemote{Reason: "no node store"}
	}
	enr, err := st.LoadEnrolment(ctx)
	if err != nil || enr == nil {
		return nil, nil, mcpRelayRemote{Reason: "not enrolled"}
	}
	keys, err := deps.keys()
	if err != nil {
		return nil, nil, mcpRelayRemote{Reason: classifyRemoteErr(err)}
	}
	// No key yet is the normal first-start state, not a refusal: the
	// registration below (RegisterAgentAccessKey -> EnsureAgentAccessKey)
	// mints the device key into the store and registers its public half.
	// Nothing else in production generates it, so refusing here left remote
	// forwarding off on every fresh node. Any OTHER load error still refuses.
	if _, err := keys.LoadAgentAccessKey(); err != nil && !errors.Is(err, orgclient.ErrNoSecret) {
		return nil, nil, mcpRelayRemote{Reason: "agent-access key unreadable: " + err.Error()}
	}
	t := h.Table()
	if t == nil {
		return nil, nil, mcpRelayRemote{Reason: "no tools.mcp_access table loaded: STS issuer unknown (forwarding is wired on the first start after the resource is accepted)"}
	}
	issuer := t.Node.Registry.Issuer
	gateway := mcpRelayGatewayURL(cfg, t)
	reg, err := deps.register(ctx, keys)
	if err != nil {
		return nil, nil, mcpRelayRemote{Reason: classifyRemoteErr(err), Issuer: issuer, GatewayURL: gateway}
	}
	res := mcpRelayRemote{CredentialID: reg.CredentialID, CredGen: reg.CredGen, MachineFP: reg.MachineFP, RegisteredAt: reg.CreatedAt, Created: reg.Created, Issuer: issuer, GatewayURL: gateway}
	tc, err := buildMCPRelayTokenClient(reg, enr.UserID, issuer, keys, deps.bearer, deps.egress(issuer, enr), logger)
	if err != nil {
		res.Reason = "token client not built: " + err.Error()
		return nil, nil, res
	}
	res.Wired = true
	return tc, deps.egress(gateway, enr), res
}

// buildMCPRelay constructs the relay over the node record store and the
// handle's local PDP. Shared by the daemon runtime (tokens + gateway client
// wired when remote forwarding resolved) and the stdio-wrapper subcommand
// (node-local mediation only: nil tokens). Each process owns its own relay
// instance; the chain store is the one shared owner, SQLite-serialised.
func buildMCPRelay(ctx context.Context, cfg config.Config, db *sql.DB, st *store.Store, h *mcpRelayHandle, logger *slog.Logger, tokens *mcprelay.TokenClient, httpc *http.Client) (*mcpRelayRuntime, error) {
	records := record.NewSQLStore(db, mcpRelayNodeKey(ctx, cfg, st))
	captureLevel := string(record.CaptureL0)
	if cfg.OrgClient.Share.FullContent || cfg.OrgClient.Share.AdminManaged {
		captureLevel = string(record.CaptureL2)
	}
	gateway := ""
	if tokens != nil {
		gateway = mcpRelayGatewayURL(cfg, h.Table())
	}
	relay, err := mcprelay.New(mcprelay.Options{
		GatewayURL:   gateway,
		Tokens:       tokens,
		HTTP:         httpc,
		Records:      records,
		SidecarPath:  filepath.Join(filepath.Dir(cfg.Observer.DBPath), "mcp-relay-loss.json"),
		AuditMode:    cfg.MCPRelay.AuditMode,
		Local:        h.engine,
		CaptureLevel: captureLevel,
		Log:          logger,
		LocalPrincipal: func(vserver string, transport localpdp.Transport) (localpdp.Principal, bool) {
			t := h.Table()
			if t == nil {
				return localpdp.Principal{}, false
			}
			return t.NodePrincipal(h.identity, vserver, transport)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("mcp-relay: %w", err)
	}
	return &mcpRelayRuntime{relay: relay, records: records, remoteForwarding: tokens != nil}, nil
}

// startMCPRelayRuntime starts the daemon-side relay under [mcp_relay].enabled:
// remote forwarding resolved (registration + token client, or the honest
// reason), the relay + record store, the dedicated loopback listener when
// [mcp_relay].listen is set, and THEN the projection - every verified
// client's stdio entries wrapped and the approved remote entries projected
// through the launch journal (idempotent on every start). The stdio wrapper
// is NOT a daemon goroutine — the AI client spawns `observer mcp-relay wrap
// --client <tool> --server <id>` per server (process-attested by
// construction), so "supervising" it means keeping the launch journal and
// the compiled table cache current, which this process does through the
// handle.
func startMCPRelayRuntime(ctx context.Context, cfg config.Config, db *sql.DB, st *store.Store, h *mcpRelayHandle, logger *slog.Logger) (*mcpRelayRuntime, error) {
	if h == nil || !cfg.MCPRelay.Enabled {
		return nil, nil
	}
	tokens, httpc, remote := resolveMCPRelayRemote(ctx, cfg, st, h, defaultMCPRelayRemoteDeps(cfg, st, logger), logger)
	rt, err := buildMCPRelay(ctx, cfg, db, st, h, logger, tokens, httpc)
	if err != nil {
		return nil, err
	}
	rt.remote = remote
	if cfg.MCPRelay.Listen != "" {
		addr, lerr := serveMCPRelayLoopback(ctx, cfg.MCPRelay.Listen, rt.relay.ServeLoopbackHTTP(), logger)
		if lerr != nil {
			return nil, lerr
		}
		rt.loopback = addr
	}
	rep, remoteSkip, perr := runMCPRelayProjection(ctx, cfg, daemonConfigPath(), rt.records, h, rt.remoteForwarding)
	rt.projection, rt.remoteSkip = rep, remoteSkip
	records := rt.records
	h.SetProjectionProbe(func() bool { return mcpRelayAppliedState(context.Background(), records).Any() })
	if perr != nil {
		logger.Warn("mcp-relay: client-config projection failed; the relay serves what was journaled before", "err", perr)
	}
	for _, r := range rep.Receipts {
		switch {
		case r.Err != "":
			logger.Warn("mcp-relay: projection receipt", "client", r.Client.Tool, "config", r.Client.ConfigPath, "err", r.Err)
		case r.Skipped != "":
			logger.Info("mcp-relay: projection skipped", "client", r.Client.Tool, "reason", r.Skipped)
		case r.Changed:
			logger.Info("mcp-relay: client config projected", "client", r.Client.Tool, "config", r.Client.ConfigPath, "wrapped", r.Wrapped, "remote", r.Remote, "backup", r.BackupPath)
		}
		for _, f := range r.Refused {
			logger.Info("mcp-relay: stdio entry not wrapped (left direct)", "client", r.Client.Tool, "entry", f.Key, "reason", f.Reason)
		}
		if r.Note != "" {
			logger.Warn("mcp-relay: projection note", "client", r.Client.Tool, "note", r.Note)
		}
	}
	loss := rt.relay.PendingLoss()
	logger.Info("mcp-relay: runtime started",
		"mode", cfg.MCPRelay.Mode, "audit_mode", cfg.MCPRelay.AuditMode,
		"loopback", rt.loopback, "gateway_url", remote.GatewayURL,
		"remote_forwarding", rt.remoteForwarding, "remote_reason", remote.Reason,
		"credential_id", remote.CredentialID, "cred_gen", remote.CredGen,
		"projected_clients", projectedClients(ctx, rt.records), "remote_entries_skipped", remoteSkip,
		"pending_loss", loss.Count,
		"restart_note", "the relay rides the daemon: route OFF -> stop -> relaunch -> route ON (docs/daemon-restart-runbook.md)")
	processMCPRelayRemote.Store(&remote)
	return rt, nil
}
