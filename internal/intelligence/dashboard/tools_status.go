package dashboard

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/clientwire"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/mcpregister"
)

// Connected-tools panel (usability arc P4.1 / review row B1): one
// status row per supported tool — detected / capturing / hooks / MCP /
// proxied — generalizing the per-tool /api/setup/* probes into a
// single matrix. Every probe is read-only (registry DryRun or plain
// file stat); the panel never writes AI-client config.

// toolProbe is one integration's read-only state for a tool. A nil
// probe on the row means the integration doesn't exist for that tool
// (honest n/a, not false).
type toolProbe struct {
	// Registered: the integration currently points at the observer.
	Registered bool `json:"registered"`
	// Partial: some but not all managed entries are registered
	// (hooks only — a subset of events point at the observer).
	Partial bool `json:"partial,omitempty"`
	// ViaPlugin: the integration is wired through the AI tool's OWN
	// plugin surface (the SuperBased Observer Claude Code plugin), not
	// through a config file `observer init` wrote. This is a THIRD state,
	// distinct both from unregistered and from init-registered: the
	// wiring is live, so Registered is true, but re-running init would
	// deliberately write nothing.
	ViaPlugin bool `json:"via_plugin,omitempty"`
	// NoHooks: the tool has no hook surface Observer registers (hooks
	// only). Detail carries the reason from the integration registry.
	NoHooks bool `json:"no_hooks,omitempty"`
	// Unprobed: the tool has a hook surface, but this panel does not dry-run
	// it (hooks only): it is written outside the hook registry, by hand, or
	// no longer at all. Detail says which.
	Unprobed bool `json:"unprobed,omitempty"`
	// Detail is a one-line human explanation (counts, conflict text,
	// or the setup status word).
	Detail string `json:"detail,omitempty"`
}

// toolStatusRow is one tool's full status line.
type toolStatusRow struct {
	Tool         string     `json:"tool"`
	Detected     bool       `json:"detected"`
	DetectedPath string     `json:"detected_path,omitempty"`
	Enabled      bool       `json:"enabled"`
	ActionCount  int64      `json:"action_count"`
	LastSeenAt   string     `json:"last_seen_at,omitempty"`
	Hooks        *toolProbe `json:"hooks,omitempty"`
	MCP          *toolProbe `json:"mcp,omitempty"`
	Proxy        *toolProbe `json:"proxy,omitempty"`
	// Wiring is the set of setup / removal actions the dashboard offers for
	// this tool (nil: none).
	Wiring *toolWiring `json:"wiring,omitempty"`
}

// handleToolsStatus serves GET /api/tools/status — the Connected-tools
// matrix. Rows are the union of the injected adapter catalog and any
// tool with rows in the actions table (so foreign/legacy capture still
// shows). Sorted by tool name for a stable render.
func (s *Server) handleToolsStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	out, _ := s.toolStatusRows(r.Context())

	missingDefaults, missingNote := s.missingDefaultAdapters()
	resp := map[string]any{
		"tools":        out,
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		// missing_default_adapters/_remediation/_note are the Invariant
		// #51 diagnostic (a default adapter absent from this operator's
		// explicit enabled_adapters list — grokbot's 2026-09-22 capture
		// gap was exactly this). Every row above ALREADY carries the
		// per-tool fact via Enabled==false; these three top-level fields
		// add the SAME fact pre-filtered to "missing from the compiled-in
		// defaults" (as opposed to a non-default tool, or a default the
		// operator deliberately turned off) plus the one-command fix, so
		// the Connected-tools panel can render a single actionable
		// banner instead of making the operator infer it row by row.
		"missing_default_adapters": missingDefaults,
	}
	if len(missingDefaults) > 0 {
		resp["missing_default_remediation"] = config.AdoptDefaultsRemediationCmd
	}
	if missingNote != "" {
		resp["missing_default_note"] = missingNote
	}
	writeJSON(w, resp)
}

// toolStatusRows builds the Connected-tools rows: the union of the injected
// adapter catalog and any tool with rows in the actions table, sorted by
// tool name. configLoaded reports whether config.toml was readable (when it
// was not, every row's Enabled is false because nothing says otherwise). It
// is the one builder /api/tools/status and the first-run view
// (/api/firstrun, T-922) share, so the two never disagree about a tool.
func (s *Server) toolStatusRows(ctx context.Context) (out []toolStatusRow, configLoaded bool) {
	type activity struct {
		lastSeen string
		count    int64
	}
	seen := map[string]activity{}
	// s.opts.DB, not s.db(): the connected-tools matrix describes THIS
	// machine's real capture activity even while demo mode is active.
	if s.opts.DB != nil {
		rows, err := s.opts.DB.QueryContext(ctx,
			`SELECT tool, MAX(timestamp), COUNT(*) FROM actions GROUP BY tool`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var tool, last string
				var n int64
				if rows.Scan(&tool, &last, &n) == nil {
					seen[tool] = activity{lastSeen: last, count: n}
				}
			}
			_ = rows.Err()
		}
	}

	enabled := map[string]bool{}
	if cfg, err := loadConfigForDashboard(s.opts.ConfigPath); err == nil {
		configLoaded = true
		for _, name := range cfg.Observer.Watch.EnabledAdapters {
			enabled[name] = true
		}
	}

	out = make([]toolStatusRow, 0, len(s.opts.ToolCatalog)+4)
	covered := map[string]bool{}
	hooks := s.hookProber()
	wanted := s.hookWantedFunc()
	for _, entry := range s.opts.ToolCatalog {
		row := toolStatusRow{Tool: entry.Tool, Enabled: enabled[entry.Tool]}
		for _, p := range entry.WatchPaths {
			if fi, err := os.Stat(p); err == nil && fi.IsDir() {
				row.Detected = true
				row.DetectedPath = p
				break
			}
		}
		if a, ok := seen[entry.Tool]; ok {
			row.ActionCount = a.count
			row.LastSeenAt = a.lastSeen
		}
		s.attachIntegrationProbes(&row, hooks, wanted)
		covered[entry.Tool] = true
		out = append(out, row)
	}
	// Tools with DB activity but no catalog entry (legacy adapters,
	// foreign rows) still get a row — capture history never hides.
	for tool, a := range seen {
		if covered[tool] {
			continue
		}
		out = append(out, toolStatusRow{
			Tool:        tool,
			Enabled:     enabled[tool],
			ActionCount: a.count,
			LastSeenAt:  a.lastSeen,
		})
	}
	slices.SortFunc(out, func(a, b toolStatusRow) int {
		return strings.Compare(a.Tool, b.Tool)
	})
	return out, configLoaded
}

// missingDefaultAdapters reports which compiled-in default adapters
// (s.opts.ToolCatalog — the same adapterdefaults.Adapters() names
// cmd/observer/main.go's warnMissingDefaultsFromAllowList and `observer
// config adopt-defaults` both use) are absent from this operator's
// EXPLICIT [observer.watch] enabled_adapters array in config.toml.
//
// Deliberately reuses config.AdoptEnabledAdapters — the one pure,
// I/O-free diff this whole diagnostic already has ONE owner for — in its
// read-only mode (the returned newBody is discarded; this handler never
// writes config.toml). That keeps this endpoint's report byte-for-byte
// consistent with the daemon startup WARN and the CLI's own preview,
// rather than a second, independently-drifting implementation of "is
// this adapter missing."
//
// note is non-empty only when config.toml has an enabled_adapters array
// AdoptEnabledAdapters could not safely parse (AdoptResult.Skipped) — in
// that case names is nil, which must NOT be read as "nothing missing";
// callers surface note instead. A missing/unreadable config.toml, or one
// with no explicit enabled_adapters key at all, honestly reports zero
// missing (config.Default() already covers every adapter in both cases).
func (s *Server) missingDefaultAdapters() (names []string, note string) {
	body, err := os.ReadFile(s.opts.ConfigPath) //nolint:gosec // operator's own config.toml
	if err != nil {
		return nil, ""
	}
	defaults := make([]string, len(s.opts.ToolCatalog))
	for i, entry := range s.opts.ToolCatalog {
		defaults[i] = entry.Tool
	}
	_, res, err := config.AdoptEnabledAdapters(string(body), defaults)
	if err != nil {
		return nil, ""
	}
	if res.Skipped {
		return nil, res.SkipReason
	}
	return res.Missing, ""
}

// attachIntegrationProbes fills the hooks / MCP / proxy probes for
// tools that have those integrations. All probes are DryRun /
// read-only. Tools without an integration keep a nil probe (n/a).
// The hooks and MCP cells are driven by the integration registry for
// EVERY tool (hookProber; clientwire.MCPSupported, the MCP formats the
// registrar writes); the proxy cell reads the per-tool route snapshot of
// the tools whose persisted route the dashboard can write (routeSetups).
func (s *Server) attachIntegrationProbes(row *toolStatusRow, hooks func(tool string) *toolProbe, wanted func(tool string) bool) {
	row.Hooks = hooks(row.Tool)
	if clientwire.MCPSupported(row.Tool) {
		row.MCP = s.mcpProbe(row.Tool)
	}
	if rs, ok := routeSetups[row.Tool]; ok && clientwire.RouteSupported(row.Tool) {
		row.Proxy = rs.probe(s)
	}
	row.Wiring = wiringFor(row.Tool, wanted)
}

// routeSetup is one tool's persisted-route setup: the dashboard route that
// writes (and, with undo, removes) it, and its read-only state probe.
type routeSetup struct {
	endpoint string
	probe    func(s *Server) *toolProbe
}

// routeSetups is the closed table of tools whose persisted proxy route the
// dashboard writes, one row per per-tool route handler registered in
// registerRoutes (the route writers differ per config file and schema, so
// this cannot be a capability switch; clientwire.RouteSupported still gates
// every row).
var routeSetups = map[string]routeSetup{
	"claude-code": {endpoint: "/api/setup/claude", probe: func(s *Server) *toolProbe {
		snap := s.claudeSetupSnapshot()
		detail := snap.Status
		if snap.RoutedBaseURL != "" {
			detail = snap.RoutedBaseURL
		}
		return &toolProbe{Registered: snap.RoutedToObserver, Detail: detail}
	}},
	"codex": {endpoint: "/api/setup/codex", probe: func(s *Server) *toolProbe {
		snap := s.codexSetupSnapshot()
		return &toolProbe{Registered: snap.Status == "routed_to_observer", Detail: snap.Status}
	}},
}

// wiringPart is one integration's available actions for a tool: whether
// the dashboard can register it, and whether it can remove it. Note says
// why a register is not offered when the registry knows the reason.
type wiringPart struct {
	Register bool   `json:"register"`
	Remove   bool   `json:"remove"`
	Note     string `json:"note,omitempty"`
	// Tradeoff is what the tool switches off while the route is in force
	// (integration.RouteTradeoff, the CC-11 sentence), shown in the route
	// consent before the write (surface-gap FU-24). Additive; older web
	// builds ignore it.
	Tradeoff string `json:"tradeoff,omitempty"`
}

// toolWiring is the per-row action set the Connected tools Set up wizard
// renders (T-421 item 2). It is computed from clientwire's predicates, the
// ones `observer init` and `observer uninstall` use, so the dashboard offers
// a write exactly where the CLI makes it.
type toolWiring struct {
	Hooks         wiringPart `json:"hooks"`
	MCP           wiringPart `json:"mcp"`
	Route         wiringPart `json:"route"`
	RouteEndpoint string     `json:"route_endpoint,omitempty"`
	// Telemetry is the opt-in exporter wiring (T-537): point the tool's own
	// OpenTelemetry export at this node. Additive; older web builds ignore it.
	Telemetry *wiringPart `json:"telemetry,omitempty"`
}

// wiringFor returns tool's action set, or nil when nothing is offered.
// wanted reports whether a hook registration has anything to write right
// now (clientwire.HookRegistrationWanted under the daemon's own filter).
func wiringFor(tool string, wanted func(tool string) bool) *toolWiring {
	w := &toolWiring{
		Hooks: wiringPart{Register: clientwire.HookSupported(tool), Remove: clientwire.HookRemovable(tool)},
		MCP:   wiringPart{Register: clientwire.MCPSupported(tool), Remove: clientwire.MCPSupported(tool)},
	}
	if w.Hooks.Register && wanted != nil && !wanted(tool) {
		w.Hooks.Register = false
		w.Hooks.Note = "nothing to register right now: this tool's hooks serve only gates that are off (the prompt-submit hook lane) or still owe a live test"
	}
	if rs, ok := routeSetups[tool]; ok && clientwire.RouteSupported(tool) {
		w.Route = wiringPart{Register: true, Remove: clientwire.RouteRemovable(tool), Tradeoff: integration.RouteTradeoff(tool)}
		w.RouteEndpoint = rs.endpoint
	}
	if clientwire.TelemetrySupported(tool) {
		w.Telemetry = &wiringPart{Register: true, Remove: true}
	}
	if !w.Hooks.Register && !w.Hooks.Remove && !w.MCP.Register && !w.Route.Register && !w.Route.Remove && w.Telemetry == nil {
		return nil
	}
	return w
}

// hookWantedFunc returns the per-request "is a hook registration wanted"
// predicate: the prompt-lane state and the daemon's owes-live filter,
// resolved once.
func (s *Server) hookWantedFunc() func(tool string) bool {
	promptLane := s.promptLaneEnabled()
	var skip func(tool, event string) bool
	if opts, err := s.hookProbeOptions(); err == nil {
		skip = opts.SkipEvent
	}
	return func(tool string) bool { return clientwire.HookRegistrationWanted(tool, promptLane, skip) }
}

// hookCellKind is what the Connected-tools hooks cell does for one tool.
type hookCellKind int

const (
	// hookCellProbe: dry-run the hook registry and report its state.
	hookCellProbe hookCellKind = iota
	// hookCellNone: no hook surface Observer registers ("no hooks").
	hookCellNone
	// hookCellUnprobed: a hook surface this panel does not dry-run.
	hookCellUnprobed
)

// hookCellRules is the ordered decision table for the hooks cell (T-400,
// CLAUDE.md #3 and #5): it reads only the tool's integration registry row
// (its hook mechanism, lifecycle and auto-wiring) and the hook registry's
// own writer table, never a tool name, so every adapter with a registered
// binding shows its real state and a hookless one says why. The first row
// whose `when` holds decides. The rows mirror `observer init`'s
// hookSupported, so the cell probes exactly the tools init would wire.
var hookCellRules = []struct {
	name   string
	when   func(c integration.Capability) bool
	kind   hookCellKind
	detail func(c integration.Capability) string
}{
	{
		name: "no hook mechanism",
		when: func(c integration.Capability) bool { return c.Hook.Mechanism == integration.HookNone },
		kind: hookCellNone,
		detail: func(c integration.Capability) string {
			if c.Hook.Note != "" {
				return c.Hook.Note
			}
			return "no hook surface Observer registers; sessions are captured from the tool's own files"
		},
	},
	{
		name: "not advertised",
		when: func(c integration.Capability) bool { return !c.Advertised() },
		kind: hookCellUnprobed,
		detail: func(c integration.Capability) string {
			return "Observer no longer registers hooks for this " + string(c.Lifecycle) + " product"
		},
	},
	{
		name: "written outside the hook registry",
		when: func(c integration.Capability) bool { return !hook.RegistryWrites(c.Hook.Mechanism) },
		kind: hookCellUnprobed,
		detail: func(c integration.Capability) string {
			return "wired through " + string(c.Hook.Mechanism) + ", outside the hook registry; not probed here"
		},
	},
	{
		name: "not auto-wired",
		when: func(c integration.Capability) bool { return !c.Hook.AutoWired },
		kind: hookCellUnprobed,
		detail: func(c integration.Capability) string {
			d := "hook registration for this tool is manual; Observer does not write it"
			if c.Hook.Note != "" {
				d += " (" + c.Hook.Note + ")"
			}
			return d
		},
	},
	{
		// DEC-12: a writer built but switched off until a live check
		// passes; the dashboard never runs it (not even as a dry run).
		name: "waiting on a live check",
		when: func(c integration.Capability) bool { return c.Hook.LiveGate.Waiting() },
		kind: hookCellUnprobed,
		detail: func(c integration.Capability) string {
			return "hook writer " + c.Hook.LiveGate.Text() + "; Observer does not write it yet"
		},
	},
	{
		name: "registry writes it",
		when: func(integration.Capability) bool { return true },
		kind: hookCellProbe,
	},
}

// hookCellFor walks hookCellRules for c and returns the decided kind and
// detail ("" for a probe, whose detail comes from the dry run).
func hookCellFor(c integration.Capability) (hookCellKind, string) {
	for _, r := range hookCellRules {
		if !r.when(c) {
			continue
		}
		if r.detail == nil {
			return r.kind, ""
		}
		return r.kind, r.detail(c)
	}
	return hookCellProbe, ""
}

// hookProber returns the hooks-cell function for one /api/tools/status
// request: a tool with no integration registry row stays n/a (nil), every
// other tool is decided by hookCellRules. The dry-run registry is built at
// most once per request, and only if some tool needs a probe.
func (s *Server) hookProber() func(tool string) *toolProbe {
	var (
		reg    *hook.Registry
		regErr error
		built  bool
	)
	return func(tool string) *toolProbe {
		c, ok := integration.For(tool)
		if !ok {
			return nil
		}
		switch kind, detail := hookCellFor(c); kind {
		case hookCellNone:
			return &toolProbe{NoHooks: true, Detail: detail}
		case hookCellUnprobed:
			return &toolProbe{Unprobed: true, Detail: detail}
		}
		if !built {
			built = true
			reg, regErr = s.hookProbeRegistry()
		}
		if regErr != nil {
			return &toolProbe{Detail: "probe failed: " + regErr.Error()}
		}
		return hookProbeFromResult(reg.Register(tool))
	}
}

// hookProbeRegistry builds the dry-run hook registry the probe uses. The
// registrars count an event as AlreadySet only when the observer entry's
// command matches the one they would write EXACTLY (binary and --config
// included); an observer entry with drifted arguments is refreshed, so it
// lands in HooksAdded. The probe therefore has to build the command the
// daemon built, which is what hookProbeOptions returns (T-376).
func (s *Server) hookProbeRegistry() (*hook.Registry, error) {
	opts, err := s.hookProbeOptions()
	if err != nil {
		return nil, err
	}
	return hook.NewRegistry(opts)
}

// hookProbeOptions returns the registry options the hooks probe dry-runs
// with: the daemon's own auto-registration options when cmd injected
// them (Options.HookRegistryOptions), otherwise this binary plus the
// dashboard's config path. DryRun is forced on either way, so the probe
// can never write.
func (s *Server) hookProbeOptions() (hook.Options, error) {
	if s.opts.HookRegistryOptions != nil {
		opts, err := s.opts.HookRegistryOptions()
		if err != nil {
			return hook.Options{}, err
		}
		opts.DryRun = true
		return opts, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return hook.Options{}, err
	}
	return hook.Options{BinaryPath: exe, ConfigPath: s.opts.ConfigPath, DryRun: true}, nil
}

// hookProbeFromResult is the pure result→status mapping, split out so
// the states can be exercised without a registry and a real home dir.
func hookProbeFromResult(res hook.RegistrationResult) *toolProbe {
	if res.Error != nil {
		return &toolProbe{Detail: res.Error.Error()}
	}
	// The registrar declined to write because the tool's own plugin
	// already declares these hooks. That is WIRED, not unregistered —
	// falling through would render "registered=false / would register 0
	// events", telling the user to fix something already working.
	if res.Skipped {
		return &toolProbe{
			Registered: true,
			ViaPlugin:  true,
			Detail:     "wired via the Claude Code plugin - " + res.SkipReason,
		}
	}
	p := &toolProbe{
		Registered: len(res.AlreadySet) > 0 && len(res.HooksAdded) == 0,
		Partial:    len(res.AlreadySet) > 0 && len(res.HooksAdded) > 0,
	}
	switch {
	case p.Registered:
		p.Detail = fmt.Sprintf("%d events registered", len(res.AlreadySet))
	case p.Partial:
		p.Detail = fmt.Sprintf("%d registered, %d missing", len(res.AlreadySet), len(res.HooksAdded))
	default:
		p.Detail = fmt.Sprintf("would register %d events", len(res.HooksAdded))
	}
	return p
}

// mcpProbe dry-runs the MCP registrar for one tool. A conflict error
// (an `observer` entry pointing elsewhere) reads as registered=false
// with the conflict in detail — honest about stale registrations.
func (s *Server) mcpProbe(tool string) *toolProbe {
	exe, err := os.Executable()
	if err != nil {
		return &toolProbe{Detail: "probe failed: " + err.Error()}
	}
	reg, err := mcpregister.NewRegistrar(mcpregister.RegisterOptions{BinaryPath: exe, DryRun: true})
	if err != nil {
		return &toolProbe{Detail: "probe failed: " + err.Error()}
	}
	return mcpProbeFromResult(reg.Register(tool))
}

// mcpProbeFromResult is the pure result→status mapping, split out for
// the same reason as hookProbeFromResult.
func mcpProbeFromResult(res mcpregister.RegistrationResult) *toolProbe {
	if res.Error != nil {
		return &toolProbe{Detail: res.Error.Error()}
	}
	// Same third state as hookProbeFromResult: the plugin's own .mcp.json
	// already declares this server, so the registrar wrote nothing on
	// purpose. Rendering "not registered" here would be false.
	if res.Skipped {
		return &toolProbe{
			Registered: true,
			ViaPlugin:  true,
			Detail:     "wired via the Claude Code plugin - " + res.SkipReason,
		}
	}
	p := &toolProbe{Registered: res.AlreadySet}
	if res.AlreadySet {
		p.Detail = "observer MCP server registered"
	} else {
		p.Detail = "not registered"
	}
	return p
}
