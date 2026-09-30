package coverage

import (
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// Point identifiers: the node-side enforcement points the matrix reports on.
const (
	// PointRelay is the node MCP relay proper (stdio wrapper / ipc / loopback
	// serving modes) - the only MEDIATING point.
	PointRelay = "node-mcp-relay"
	// PointProxyTools is the proxy tools[] filter (internal/proxy/mcptools.go):
	// sees ONLY inference routed through :8820 - best-effort.
	PointProxyTools = "proxy-tools-filter"
	// PointHook is the PreToolUse hook deny of an unapproved `mcp__*` call -
	// parses known tool shapes only, best-effort.
	PointHook = "hook-pretooluse"
	// PointConfigProjection is the per-client MCP registry rewrite (approved
	// remote entries + relay-wrapped stdio entries) - advisory: a client that
	// ignores its registry, or a raw client with its own, bypasses it.
	PointConfigProjection = "config-projection"
)

// Coverage is the closed honesty label a row carries.
type Coverage string

const (
	// Mediated: every call on this row passes through the relay's local
	// PDP + decision/completion record BEFORE the server sees it.
	Mediated Coverage = "mediated"
	// HookOnly: not relay-mediated; the pre-execution hook deny is the
	// only lever, and it parses known tool shapes only.
	HookOnly Coverage = "hook-only"
	// BestEffort: a post-hoc / advisory control exists (proxy tools[]
	// filter, config projection) but nothing blocks the call itself.
	BestEffort Coverage = "best-effort"
	// Uncovered: no node-side control sees this combination (the Note says
	// why - including "the writer exists but the projection has not been
	// applied on this node", which is uncovered, never mediated).
	Uncovered Coverage = "uncovered"
	// Planned: a writer does not exist TODAY; Phase names when (R8.23.o).
	Planned Coverage = "planned"
)

// Transport is the closed MCP transport vocabulary a client uses to reach a
// server.
type Transport string

const (
	// TransportStdio: the client spawns the server process (the relay's
	// stdio wrapper replaces the spawn, PRIMARY mediation).
	TransportStdio Transport = "stdio"
	// TransportRemoteHTTP: streamable-HTTP / SSE remote entry (the relay's
	// loopback listener or the org gateway URL is projected in).
	TransportRemoteHTTP Transport = "remote-http"
	// TransportHostedConnector: a provider-hosted connector the LLM vendor
	// dials itself (Anthropic mcp_servers, OpenAI Responses mcp tool) - the
	// node never sees the MCP traffic, only the inference request.
	TransportHostedConnector Transport = "hosted-connector"
)

// Method is the canonical partition name a row covers (R8.26.b): the
// governed set (sync chained decision before Pass) or the catalogue set
// (policy sync, audit async), never a re-authored per-method list.
type Method string

const (
	// MethodGoverned: tools/call, resources/read, prompts/get,
	// completion/complete, tasks/* (STRIPPED on the node, R8.27.b),
	// subscriptions/listen and any MRTR retry.
	MethodGoverned Method = "governed"
	// MethodCatalogue: tools/list, resources/list, resources/templates/list,
	// prompts/list, server/discover, ping.
	MethodCatalogue Method = "catalogue"
)

// GovernedMethods is the canonical governed set (R8.26.b), the data the
// MethodGoverned row stands for.
var GovernedMethods = []string{
	"tools/call", "resources/read", "prompts/get", "completion/complete",
	"tasks/get", "tasks/update", "tasks/cancel", "subscriptions/listen",
}

// CatalogueMethods is the canonical catalogue set (R8.26.b).
var CatalogueMethods = []string{
	"tools/list", "resources/list", "resources/templates/list", "prompts/list",
	"server/discover", "ping",
}

// Row is one client x transport x method cell.
type Row struct {
	// Client is the integration registry tool id.
	Client string
	// Transport is the MCP transport the row covers.
	Transport Transport
	// Method is the canonical partition the row covers.
	Method Method
	// Coverage is the honesty label.
	Coverage Coverage
	// Point is the enforcement point that provides the coverage ("" for
	// Uncovered / Planned).
	Point string
	// Phase names when a Planned row's writer lands ("" otherwise).
	Phase string
	// Note is the bounded human-readable reason.
	Note string
}

// Live is what the matrix cannot read off the integration registry: the
// capabilities that exist in THIS process on THIS node (Sol P3+P4 finding
// 2, doc3 §12.7 coverage honesty). The composition root fills it from
// internal/mcp (the writer table), the launch journal (what was actually
// applied) and the relay runtime (whether the DPoP token client was built).
// The zero value reports nothing live: no writer, nothing applied, no
// remote forwarding - so a matrix built from it never claims mediation.
type Live struct {
	// WrapWriter reports whether a stdio-wrap writer exists TODAY for a
	// registry MCP config format (internal/mcp.WrapWriterImplemented).
	WrapWriter func(integration.MCPFormat) bool
	// Applied is the legacy any-transport, UNVERIFIED flag (journal rows
	// exist for the client). Deprecated (Sol P3+P4 fold finding 3): it
	// feeds only the informational ClientShape.ProjectionApplied and NO
	// transport rule - a row of the other transport, or a row whose commit
	// failed, must never make a cell mediated. Use AppliedStdio /
	// AppliedRemote.
	Applied func(client string) bool
	// AppliedStdio reports a stdio_wrap journal row of the client whose
	// config's CURRENT bytes hash to the row's applied digest (the wrap is
	// what is on disk). Only the stdio rules consume it.
	AppliedStdio func(client string) bool
	// AppliedRemote is the same verified predicate for a relay-added
	// remote row. Only the remote-http rules consume it.
	AppliedRemote func(client string) bool
	// StdioUnmediated returns how many of the client's CURRENT stdio
	// entries are not the wrapper (refused for want of an approved binding,
	// or added after the projection): a client with any is never
	// stdio-mediated. nil = none known.
	StdioUnmediated func(client string) int
	// RemoteWired reports the relay's STS token client was built (remote
	// forwarding on): a projected remote entry is mediated only then.
	RemoteWired bool
}

// ClientShape is the capability shape one client row is derived from -
// resolved from internal/integration + Live at the boundary so the rules
// below never name a tool.
type ClientShape struct {
	// Client is the registry tool id.
	Client string
	// HasMCPRegistry: the client keeps an MCP server registry the relay
	// can project into (stdio entries wrapped, remote entries rewritten).
	HasMCPRegistry bool
	// RegistryWriterImplemented: the stdio-wrap writer for the client's
	// config format exists TODAY.
	RegistryWriterImplemented bool
	// SupportsRemote: the registry format grounds a remote entry AND a
	// remote writer projects it (MCPTarget.Remote != nil && Implemented).
	SupportsRemote bool
	// ProjectionApplied: informational - a verified row of either
	// transport (or the legacy unverified Live.Applied). No rule reads it.
	ProjectionApplied bool
	// StdioApplied: a verified stdio_wrap row (Live.AppliedStdio).
	StdioApplied bool
	// RemoteApplied: a verified relay remote row (Live.AppliedRemote).
	RemoteApplied bool
	// StdioUnmediated: the client's current stdio entries that are NOT the
	// wrapper (unbound / added after the projection).
	StdioUnmediated int
	// RemoteWired: the relay's token client is built (remote forwarding).
	RemoteWired bool
	// HookBlocks: the client's hook mechanism honours a pre-execution deny.
	HookBlocks bool
	// ProxyRoutable: observer drives an inference route through :8820 today.
	ProxyRoutable bool
}

// ShapeOf resolves a registry capability + the live node capabilities into
// a ClientShape.
func ShapeOf(c integration.Capability, live Live) ClientShape {
	s := ClientShape{Client: c.Tool, RemoteWired: live.RemoteWired}
	if c.MCP != nil {
		s.HasMCPRegistry = true
		s.RegistryWriterImplemented = c.MCP.Implemented && live.WrapWriter != nil && live.WrapWriter(c.MCP.Format)
		s.SupportsRemote = c.MCP.Remote != nil && c.MCP.Remote.Implemented
		s.StdioApplied = live.AppliedStdio != nil && live.AppliedStdio(c.Tool)
		s.RemoteApplied = live.AppliedRemote != nil && live.AppliedRemote(c.Tool)
		if live.StdioUnmediated != nil {
			s.StdioUnmediated = live.StdioUnmediated(c.Tool)
		}
		s.ProjectionApplied = s.StdioApplied || s.RemoteApplied || (live.Applied != nil && live.Applied(c.Tool))
	}
	s.HookBlocks = c.EnforcementChannel() == integration.EnforceHookBlock
	s.ProxyRoutable = c.Proxy != nil
	return s
}

// coverageRule is one ordered row of the derivation table: the first rule
// whose match accepts (shape, transport, method) decides the cell.
type coverageRule struct {
	match    func(s ClientShape, t Transport, m Method) bool
	coverage Coverage
	point    string
	phase    string
	note     string
}

// rules is the ordered derivation table, walked top-down, first match wins.
// A cell that matches no row is Uncovered (the honest default).
var rules = []coverageRule{
	// 0. stdio PARTIALLY projected: a wrap is verified on disk but some
	//    CURRENT entry is not the wrapper (it binds to no approved server,
	//    or was added after the projection) - that server runs direct, so
	//    the client's stdio is never mediated; a governed call's only lever
	//    is the hook where it blocks. (Nothing verified at all is rule 8.)
	{
		match: func(s ClientShape, t Transport, m Method) bool {
			return t == TransportStdio && s.HasMCPRegistry && s.RegistryWriterImplemented && s.StdioApplied && s.StdioUnmediated > 0 && s.HookBlocks && m == MethodGoverned
		},
		coverage: HookOnly, point: PointHook,
		note: "one or more stdio entries are not wrapped (no approved tools.mcp_access binding, or added after the projection) and run direct; PreToolUse deny is the only pre-execution lever for them",
	},
	{
		match: func(s ClientShape, t Transport, _ Method) bool {
			return t == TransportStdio && s.HasMCPRegistry && s.RegistryWriterImplemented && s.StdioApplied && s.StdioUnmediated > 0
		},
		coverage: Uncovered,
		note:     "one or more stdio entries are not wrapped (no approved tools.mcp_access binding, or added after the projection) and run direct",
	},
	// 1. stdio through a projected registry whose wrap is VERIFIED on disk
	//    (a stdio_wrap row whose config still hashes to what the relay
	//    wrote): the wrapper mediates EVERY method (governed sync-chained,
	//    catalogue filtered).
	{
		match: func(s ClientShape, t Transport, _ Method) bool {
			return t == TransportStdio && s.HasMCPRegistry && s.RegistryWriterImplemented && s.StdioApplied
		},
		coverage: Mediated, point: PointRelay,
		note: "stdio wrapper replaces the spawn (process_attested); local PDP + decision record before the child sees the call",
	},
	// 2. stdio with a registry but no writer TODAY: planned, phase named.
	{
		match: func(s ClientShape, t Transport, _ Method) bool {
			return t == TransportStdio && s.HasMCPRegistry && !s.RegistryWriterImplemented
		},
		coverage: Planned, phase: "P4 W4a (per-format writer)",
		note: "registry format known, no projection writer yet; until then hook/proxy best-effort only",
	},
	// 3. remote-http through a projected registry that grounds a remote
	//    entry, applied on this node, with the DPoP token client built: the
	//    entry is rewritten to the relay loopback and forwarded.
	{
		match: func(s ClientShape, t Transport, _ Method) bool {
			return t == TransportRemoteHTTP && s.HasMCPRegistry && s.RegistryWriterImplemented && s.SupportsRemote && s.RemoteApplied && s.RemoteWired
		},
		coverage: Mediated, point: PointRelay,
		note: "remote entry projected to the relay loopback (configured); DPoP-bound token minted by the relay",
	},
	// 4. remote-http where the relay does not mediate: the hook is the only
	//    lever for governed calls.
	{
		match: func(s ClientShape, t Transport, m Method) bool {
			return t == TransportRemoteHTTP && s.HookBlocks && m == MethodGoverned
		},
		coverage: HookOnly, point: PointHook,
		note: "no relay-mediated remote entry; PreToolUse deny of an unapproved mcp__* call is the only pre-execution lever (known tool shapes only)",
	},
	// 5. hosted connector on a proxy-routed client: the proxy sees the
	//    connector declaration on the inference request and can refuse it
	//    (R-307) or strip mcp__* decls (R-306) - it never sees MCP traffic.
	{
		match: func(s ClientShape, t Transport, _ Method) bool {
			return t == TransportHostedConnector && s.ProxyRoutable
		},
		coverage: BestEffort, point: PointProxyTools,
		note: "provider dials the connector itself; the proxy refuses a non-approved connector on the inference request and strips disallowed mcp__* decls - only for traffic routed through :8820",
	},
	// 6. any governed call on a client whose hook blocks: hook-only.
	{
		match:    func(s ClientShape, _ Transport, m Method) bool { return s.HookBlocks && m == MethodGoverned },
		coverage: HookOnly, point: PointHook,
		note: "PreToolUse deny of an unapproved mcp__* call; parses known tool shapes only",
	},
	// 7. catalogue on a proxy-routed client: the tools[] strip narrows what
	//    the model can see - best-effort, never a block.
	{
		match:    func(s ClientShape, _ Transport, m Method) bool { return s.ProxyRoutable && m == MethodCatalogue },
		coverage: BestEffort, point: PointProxyTools,
		note: "disallowed mcp__* declarations stripped from tools[] on proxied inference; the client's own tools/list is not seen",
	},
	// 8. stdio: the writer exists but nothing was projected on this node -
	//    uncovered, with the reason (never mediated on a writer's existence).
	{
		match: func(s ClientShape, t Transport, _ Method) bool {
			return t == TransportStdio && s.HasMCPRegistry && s.RegistryWriterImplemented && !s.StdioApplied
		},
		coverage: Uncovered,
		note:     "wrap writer exists but no stdio wrap is verified on disk on this node (not applied, the config write failed or was edited since: observer mcp-relay enable)",
	},
	// 9. remote-http: projectable, but not applied / no token client.
	{
		match: func(s ClientShape, t Transport, _ Method) bool {
			return t == TransportRemoteHTTP && s.HasMCPRegistry && s.RegistryWriterImplemented && s.SupportsRemote && !s.RemoteApplied
		},
		coverage: Uncovered,
		note:     "remote entry projectable but no relay remote entry is verified on disk on this node (not applied, the config write failed or was edited since: observer mcp-relay enable)",
	},
	{
		match: func(s ClientShape, t Transport, _ Method) bool {
			return t == TransportRemoteHTTP && s.HasMCPRegistry && s.RegistryWriterImplemented && s.SupportsRemote && !s.RemoteWired
		},
		coverage: Uncovered,
		note:     "remote entry projected but the relay's STS token client is not wired (not enrolled / no agent-access key / registration refused) - remote forwarding off",
	},
}

// Transports is the ordered transport set every client is evaluated over.
var Transports = []Transport{TransportStdio, TransportRemoteHTTP, TransportHostedConnector}

// Methods is the ordered method partition every client is evaluated over.
var Methods = []Method{MethodGoverned, MethodCatalogue}

// CellFor derives one cell from a client shape.
func CellFor(s ClientShape, t Transport, m Method) Row {
	row := Row{
		Client: s.Client, Transport: t, Method: m, Coverage: Uncovered,
		Note: "no node-side control sees this combination; only MDM/EDR + network egress enforcement closes it",
	}
	for _, r := range rules {
		if r.match(s, t, m) {
			row.Coverage, row.Point, row.Phase, row.Note = r.coverage, r.point, r.phase, r.note
			return row
		}
	}
	return row
}

// RowsFor derives every cell for one client shape, in Transports x Methods
// order.
func RowsFor(s ClientShape) []Row {
	out := make([]Row, 0, len(Transports)*len(Methods))
	for _, t := range Transports {
		for _, m := range Methods {
			out = append(out, CellFor(s, t, m))
		}
	}
	return out
}

// VerifiedClients returns the registry tool ids the matrix covers: every
// client that keeps an MCP registry (the relay can project into it) OR whose
// hook can block (the hook deny applies) OR that observer proxies (the
// tools[] filter applies). Sorted for stable output.
func VerifiedClients() []string {
	var out []string
	for _, c := range integration.Capabilities() {
		s := ShapeOf(c, Live{})
		if s.HasMCPRegistry || s.HookBlocks || s.ProxyRoutable {
			out = append(out, c.Tool)
		}
	}
	sort.Strings(out)
	return out
}

// Matrix derives the full client x transport x method matrix from the
// integration registry and the live node capabilities.
func Matrix(live Live) []Row {
	var out []Row
	byTool := map[string]integration.Capability{}
	for _, c := range integration.Capabilities() {
		byTool[c.Tool] = c
	}
	for _, tool := range VerifiedClients() {
		out = append(out, RowsFor(ShapeOf(byTool[tool], live))...)
	}
	return out
}

// Summary counts rows per coverage label.
func Summary(rows []Row) map[Coverage]int {
	m := map[Coverage]int{}
	for _, r := range rows {
		m[r.Coverage]++
	}
	return m
}

// Render prints the matrix as a fixed-width table (one line per row) with
// a summary line - the `observer mcp-relay status` body.
func Render(rows []Row) string {
	var b strings.Builder
	b.WriteString("CLIENT               TRANSPORT         METHOD     COVERAGE     POINT\n")
	for _, r := range rows {
		b.WriteString(pad(r.Client, 21))
		b.WriteString(pad(string(r.Transport), 18))
		b.WriteString(pad(string(r.Method), 11))
		b.WriteString(pad(string(r.Coverage), 13))
		point := r.Point
		if r.Coverage == Planned && r.Phase != "" {
			point = "planned: " + r.Phase
		}
		b.WriteString(point)
		b.WriteByte('\n')
	}
	s := Summary(rows)
	b.WriteString("summary: ")
	labels := []Coverage{Mediated, HookOnly, BestEffort, Uncovered, Planned}
	for i, l := range labels {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(string(l))
		b.WriteByte('=')
		b.WriteString(itoa(s[l]))
	}
	b.WriteString("\nnode-side points other than the relay are BEST-EFFORT controls unless backed by MDM/EDR + network egress enforcement (doc3 §12.7).\n")
	return b.String()
}

func pad(s string, w int) string {
	if len(s) >= w {
		return s + " "
	}
	return s + strings.Repeat(" ", w-len(s))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
