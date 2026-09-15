package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// newAdaptersCmd renders the adapter Integration Capability Registry as a
// support matrix — the agnostic asset that replaces a hand-maintained audit
// grid (adapter-coverage-parity plan §7). Every cell is read from
// internal/integration so the matrix can never drift from the code that
// init/register/doctor actually dispatch on.
func newAdaptersCmd() *cobra.Command {
	var (
		jsonOut    bool
		configPath string
	)
	cmd := &cobra.Command{
		Use:   "adapters",
		Short: "Show the adapter capability matrix (proxy / hook / MCP / native / token)",
		Long: "Renders the Integration Capability Registry (internal/integration) as\n" +
			"a support matrix: for every adapter, how it can be proxy-routed, how\n" +
			"hooks register, where MCP config is written, which native-console\n" +
			"rails the vendor exposes, and its token/cost capture tier + any known\n" +
			"gap. This is the same data init/register/doctor dispatch on, so the\n" +
			"matrix is generated, never hand-maintained.\n\n" +
			"When a local observer DB is reachable, a trailing 'surface split'\n" +
			"section reports how many sessions each adapter actually captured per\n" +
			"CAPTURE SURFACE (cli / ide / desktop / sdk / web + host token,\n" +
			"migration 107) and the metered spend behind them — the observed\n" +
			"counterpart to the declared capability grid above. The section is\n" +
			"skipped silently when no DB is reachable; --json emits the registry\n" +
			"alone, unchanged.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			caps := integration.Capabilities()
			sort.Slice(caps, func(i, j int) bool { return caps[i].Tool < caps[j].Tool })
			if jsonOut {
				// The JSON payload is the REGISTRY contract (a
				// []integration.Capability array); the observed surface
				// split is a local-DB addendum for the human table and
				// deliberately does not reshape it.
				body, _ := json.MarshalIndent(caps, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(body))
				return nil
			}
			// P6 item 5: annotate the live node.features tools.disallow state,
			// read from the node-local LKG sidecar (best-effort — an ungoverned
			// node resolves an always-false lookup, so the matrix is unchanged).
			cfg, _ := config.Load(config.LoadOptions{})
			disallowed, _ := featuresDisallowSet(cfg)
			renderAdapterMatrix(cmd.OutOrStdout(), caps, disallowed)
			if counts, ok := loadSurfaceSplit(cmd.Context(), configPath); ok {
				renderSurfaceSplit(cmd.OutOrStdout(), counts)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit the registry as JSON instead of a table")
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (used only to locate the DB for the surface split)")
	return cmd
}

// loadSurfaceSplit reads the per-(tool, surface, host) session rollup
// from the local DB. FAIL-OPEN by design: `observer adapters` renders a
// static registry and must keep working with no config, no DB and no
// daemon, so any failure to reach the DB reports ok=false and the
// caller simply omits the section. Never returns an error.
func loadSurfaceSplit(ctx context.Context, configPath string) ([]store.SurfaceCount, bool) {
	_, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return nil, false
	}
	defer cleanup()
	counts, err := store.New(database).LoadSurfaceCounts(ctx, "")
	if err != nil {
		return nil, false
	}
	return counts, true
}

// renderSurfaceSplit writes the observed capture-surface rollup: per
// adapter, how many sessions came from each surface kind + host and the
// metered spend behind them.
//
// Sessions no adapter stamped roll up under an explicit "(unstamped)"
// row rather than being hidden — surface capture is per-adapter and
// retroactive only on a rescan, so a large unstamped share is normal on
// an existing DB and pretending otherwise would misreport coverage.
func renderSurfaceSplit(w io.Writer, counts []store.SurfaceCount) {
	fmt.Fprintln(w)
	if len(counts) == 0 {
		fmt.Fprintln(w, "surface split: no sessions in the local DB yet.")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ADAPTER\tSURFACE-KIND\tHOST\tSESSIONS\tCOST USD")
	stamped := 0
	for _, c := range counts {
		kind, host := c.Surface, c.SurfaceHost
		if kind == "" {
			kind = "(unstamped)"
		} else {
			stamped++
		}
		if host == "" {
			host = "—"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%.2f\n", c.Tool, kind, host, c.Sessions, c.CostUSD)
	}
	fmt.Fprintln(tw)
	fmt.Fprintln(tw, "legend\tobserved capture surface per session (sessions.surface /")
	fmt.Fprintln(tw, "\tsurface_host, migration 107), node-local and never pushed to an")
	fmt.Fprintln(tw, "\torg server. (unstamped) = no adapter found a grounded")
	fmt.Fprintln(tw, "\tdiscriminator on disk for that session — the honest unknown,")
	fmt.Fprintln(tw, "\tnever guessed. Sessions ingested before the adapter learned to")
	fmt.Fprintln(tw, "\tstamp stay unstamped until their transcript is re-read")
	fmt.Fprintln(tw, "\t(`observer scan --force`).")
	_ = tw.Flush()
	if stamped == 0 {
		fmt.Fprintln(w, "note: no session carries a capture surface yet.")
	}
}

// renderAdapterMatrix writes the capability matrix as an aligned table. When
// disallowed is non-nil, a tool it reports true for has its ENFORCE cell
// annotated with a live "!disallowed" marker (P6 item 5 — the node.features
// tools.disallow state read from the LKG sidecar). A nil lookup (tests, no
// governed node) renders the static matrix unchanged.
func renderAdapterMatrix(w io.Writer, caps []integration.Capability, disallowed func(tool string) bool) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ADAPTER\tPROXY\tSURFACE\tHOOK\tMCP\tNATIVE\tTOKEN\tVOCAB\tHANDOFF\tATTACH\tRESUME\tPROMPT\tENFORCE\tLIFECYCLE")
	anyDisallowed := false
	for _, c := range caps {
		enforce := enforcementCell(c.EnforcementChannel())
		if disallowed != nil && disallowed(c.Tool) {
			enforce += " !disallowed"
			anyDisallowed = true
		}
		fmt.Fprintf(
			tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			c.Tool,
			proxyCell(c.Proxy),
			routabilityCell(c.Routability),
			hookCell(c.Hook),
			mcpCell(c.MCP),
			nativeCell(c.Native),
			tokenCell(c.TokenTier),
			vocabCell(c.Vocabulary),
			handoffCell(c.Handoff),
			attachCell(c.Attach),
			resumeCell(c),
			promptCell(c.PromptLane, c.Hook.AutoWired),
			enforce,
			lifecycleCell(c.Lifecycle),
		)
	}
	fmt.Fprintln(tw)
	if anyDisallowed {
		fmt.Fprintln(tw, "note\t\"!disallowed\" = the org has disallowed this tool fleet-wide right now")
		fmt.Fprintln(tw, "\t(node.features tools.disallow); a bare `observer <tool>` launch is refused.")
	}
	fmt.Fprintln(tw, "legend\tPROXY = route observer applies today (or dash). SURFACE = the")
	fmt.Fprintln(tw, "\tsurface-specific routability bucket (routable / after-upstream /")
	fmt.Fprintln(tw, "\tafter-bridge / probe / native-exempt). TOKEN shows the capture")
	fmt.Fprintln(tw, "\ttier, with (gap) flagging a known hole. VOCAB = the adapter's")
	fmt.Fprintln(tw, "\tnative tool names are carried by the canonical taxonomy")
	fmt.Fprintln(tw, "\t(internal/tooltax), so its tool calls resolve to canonical")
	fmt.Fprintln(tw, "\taction types; a dash means the capture has no native tool")
	fmt.Fprintln(tw, "\tvocabulary at all (`observer doctor <tool>` prints the grounded")
	fmt.Fprintln(tw, "\treason). HANDOFF shows the session-handoff transcript tier +")
	fmt.Fprintln(tw, "\tlaunch mode (seeded / doc-assisted); a dash is the")
	fmt.Fprintln(tw, "\tactions-only carry floor (file lane only, not launchable in")
	fmt.Fprintln(tw, "\tthe embedded terminal). ATTACH = can hand the PTY to the")
	fmt.Fprintln(tw, "\tdaemon for dashboard jump-in (`observer <x> --attach`).")
	fmt.Fprintln(tw, "\tRESUME = how a closed session reopens: native (the tool's own")
	fmt.Fprintln(tw, "\tresume) / handoff (a --continue-from fork) / dash (neither).")
	fmt.Fprintln(tw, "\tENFORCE = the guard-policy enforcement bucket (P7): hook-block")
	fmt.Fprintln(tw, "\t(a wired, genuinely blocking hook mechanism can deny the call) /")
	fmt.Fprintln(tw, "\tsandbox (no blocking hook, but the launcher can require a bwrap")
	fmt.Fprintln(tw, "\tsandboxed launch — Linux/WSL2 only; this is the STATIC bucket,")
	fmt.Fprintln(tw, "\tnot degraded for the current host) / org-disallow (neither hook")
	fmt.Fprintln(tw, "\tnor sandbox — a signed org policy naming the tool disallowed is")
	fmt.Fprintln(tw, "\tthe only lever) / recorded (no grounded lever at all — an")
	fmt.Fprintln(tw, "\tacknowledgment, not a block).")
	fmt.Fprintln(tw, "\tLIFECYCLE = the vendor-support status under the harness")
	fmt.Fprintln(tw, "\tlifecycle policy: active (advertised for install / launch /")
	fmt.Fprintln(tw, "\tinit) vs DEPRECATED / DEAD (never advertised — but ALWAYS")
	fmt.Fprintln(tw, "\tstill captured; rows are never deleted). `observer doctor")
	fmt.Fprintln(tw, "\t<tool>` prints the grounded reason verbatim. PROMPT = the")
	fmt.Fprintln(tw, "\tprompt-submit intervention lane (docs/guard-prompt.md):")
	fmt.Fprintln(tw, "\thook (a verified, wired dialect) / proxy-only (no hook, the")
	fmt.Fprintln(tw, "\tproxy lane is the only path) / probe (a documented mechanism")
	fmt.Fprintln(tw, "\twhose exact wire shape is unverified — `observer doctor")
	fmt.Fprintln(tw, "\t--probe-hook <tool>` decides) / dash (no grounded capability).")
	_ = tw.Flush()
	renderProductLifecycles(w, integration.ProductLifecycles())
}

// lifecycleCell renders a row's harness-lifecycle status for the matrix.
// Non-active statuses are SHOUTED so a sunset or dead product cannot be
// skimmed past; the grounded reason (LifecycleNote) is deliberately not in
// the grid — the matrix is one token per cell and the note belongs where it
// fits verbatim, `observer doctor <tool>`. Dispatches on the closed
// vocabulary, never a tool name.
func lifecycleCell(l integration.Lifecycle) string {
	switch l {
	case integration.LifecycleDeprecated:
		return "DEPRECATED"
	case integration.LifecycleDead:
		return "DEAD"
	default:
		return "active"
	}
}

// renderProductLifecycles writes the trailing "product lifecycle" block:
// the products Observer categorises that have NO registry row of their own
// (a retag identity like roo-code, a renamed alias like windsurf, a dead
// sibling line that shares a command name). Without it those products are
// silently absent from the matrix, which reads as "Observer never heard of
// it" rather than the truth ("dead, still captured, serviced by <adapter>").
// The block is omitted entirely when the table is empty — an empty section
// header would be noise, not honesty.
func renderProductLifecycles(w io.Writer, products []integration.ProductLifecycle) {
	if len(products) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "product lifecycle (products with no adapter row of their own):")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSTATUS\tSERVICED-BY\tNOTE")
	for _, pl := range products {
		servicedBy := pl.Adapter
		if servicedBy == "" {
			servicedBy = "—"
		}
		// The Note is the grounded evidence (reason + date + vendor URL)
		// and is printed VERBATIM, wrapped into continuation rows rather
		// than truncated: a lifecycle claim without its evidence is
		// exactly the unsourced assertion the policy exists to prevent.
		lines := wrapNote(pl.Note, productLifecycleNoteWidth)
		first := ""
		if len(lines) > 0 {
			first = lines[0]
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", pl.ID, lifecycleCell(pl.Lifecycle), servicedBy, first)
		for _, cont := range lines[1:] {
			fmt.Fprintf(tw, "\t\t\t%s\n", cont)
		}
	}
	_ = tw.Flush()
}

// productLifecycleNoteWidth is the column width the product-lifecycle NOTE
// wraps at — narrow enough that the four-column block stays readable in an
// 80-column terminal once the id/status/adapter columns are accounted for.
const productLifecycleNoteWidth = 64

// wrapNote greedily wraps s into lines of at most width runes, breaking on
// spaces only (a token longer than width is emitted whole rather than cut —
// never split a URL). Returns a single empty line for an empty note so the
// caller always has a first cell to print.
func wrapNote(s string, width int) []string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return []string{""}
	}
	var (
		out  []string
		line string
	)
	for _, f := range fields {
		switch {
		case line == "":
			line = f
		case len(line)+1+len(f) <= width:
			line += " " + f
		default:
			out = append(out, line)
			line = f
		}
	}
	return append(out, line)
}

// routabilityCell renders the surface-specific routability bucket — the
// honest "is this routable at all?" status, distinct from the PROXY cell
// (which shows only what observer drives today). A row can read PROXY="—"
// yet SURFACE="routable" (knob exists, writer pending) or SURFACE="probe"
// (BYOK path documented, unconfirmed live).
func routabilityCell(s integration.RouteStatus) string {
	switch s {
	case integration.RouteStatusRoutableNow:
		return "routable"
	case integration.RouteStatusAfterUpstream:
		return "after-upstream"
	case integration.RouteStatusAfterBridge:
		return "after-bridge"
	case integration.RouteStatusProbeRequired:
		return "probe"
	case integration.RouteStatusNativeExempt:
		return "native-exempt"
	default:
		return "—"
	}
}

func proxyCell(p *integration.ProxyRoute) string {
	if p == nil {
		return "—"
	}
	switch p.Kind {
	case integration.RouteEnvSettings:
		return "env:" + p.EnvVar
	case integration.RouteConfigFile:
		return "config-file"
	case integration.RouteLauncher:
		return "launcher"
	default:
		return string(p.Kind)
	}
}

func hookCell(h integration.HookSpec) string {
	if h.Mechanism == integration.HookNone {
		return "—"
	}
	s := string(h.Mechanism)
	if h.CrossOSBridge {
		s += "+bridge"
	}
	if !h.AutoWired {
		s += "+manual"
	}
	return s
}

// promptCell renders a row's prompt-submit intervention lane
// (Capability.PromptLane) for the matrix. Dispatches on the closed
// PromptLane vocabulary, never a tool name. autoWired mirrors
// hookCell's own "+manual" convention for the same underlying concept
// (Capability.Hook.AutoWired): a PromptLaneHook row with a built,
// tested dialect but no registration writer in the auto-register loop
// (today only zcode, pending its zai-org/feedback#32 liveness probe)
// would otherwise render identically to a fully auto-wired tool like
// Claude Code — misleading, since nothing actually registers zcode's
// hook for the operator. Rendered as "hook (manual)" instead.
func promptCell(p integration.PromptLane, autoWired bool) string {
	switch p {
	case integration.PromptLaneHook:
		if !autoWired {
			return "hook (manual)"
		}
		return "hook"
	case integration.PromptLaneProxyOnly:
		return "proxy-only"
	case integration.PromptLaneProbeRequired:
		return "probe"
	default:
		return "—"
	}
}

func mcpCell(m *integration.MCPTarget) string {
	if m == nil {
		return "—"
	}
	if !m.Implemented {
		return string(m.Format) + " (candidate)"
	}
	return string(m.Format)
}

func nativeCell(n integration.NativeRails) string {
	if !n.Any() {
		return "—"
	}
	var r []string
	if n.A {
		r = append(r, "A")
	}
	if n.B {
		r = append(r, "B")
	}
	if n.C {
		r = append(r, "C")
	}
	return strings.Join(r, "/")
}

func tokenCell(t integration.TokenTier) string {
	tier := t.Best
	if tier == "" {
		tier = "unknown"
	}
	if t.Gap != "" {
		return tier + " (gap)"
	}
	return tier
}

// vocabCell renders the adapter's NATIVE TOOL VOCABULARY coverage: "yes"
// when the canonical taxonomy (internal/tooltax) carries rows for this
// adapter's native tool names, else the honest-zero dash used by every
// other empty cell in this table. There is deliberately no third rendering
// for the honest-zero rows' Note — the matrix is a one-token-per-cell grid,
// and the grounded reason belongs where it fits verbatim: `observer doctor
// <tool>`. Dispatches on the declared capability, never on tool name.
func vocabCell(v integration.Vocabulary) string {
	if v.InTaxonomy {
		return "yes"
	}
	return "—"
}

// handoffCell renders the session-handoff capability compactly: the
// transcript tier the handoff re-reads (full / partial), joined with the
// launch mode when the tool is startable in the dashboard's embedded web
// terminal (seeded prompt injection vs a doc-assisted TUI open). A
// zero-value HandoffCapability — actions-only transcript, not launchable —
// renders as a dash: the honest floor is a metadata-carry handoff over the
// universal file lane, not a grounded transcript or launcher (matching the
// nativeCell/tokenCell zero-value convention; never a fabricated cell).
func handoffCell(h integration.HandoffCapability) string {
	var parts []string
	switch h.Transcript {
	case integration.TranscriptFull:
		parts = append(parts, "full")
	case integration.TranscriptPartial:
		parts = append(parts, "partial")
	}
	if h.Launchable() {
		switch h.Launch.Mode {
		case integration.LaunchDocAssisted:
			parts = append(parts, "doc-assisted")
		default:
			parts = append(parts, "seeded")
		}
	}
	if len(parts) == 0 {
		return "—"
	}
	return strings.Join(parts, "+")
}

// attachCell renders the session-attach capability: "yes (--attach)" when
// the tool can hand its PTY to the daemon for dashboard jump-in (a non-nil
// AttachSpec), else a dash (the honest floor — bare launch only, not
// retrofittable). Dispatches on the capability SHAPE, never tool name.
func attachCell(a *integration.AttachSpec) string {
	if a == nil {
		return "—"
	}
	return "yes (--attach)"
}

// resumeCell renders how a closed session reopens, dispatching on capability
// shape: "native" when a grounded ResumeNative contract exists; otherwise
// "handoff" when the tool is launchable (the shipped `--continue-from` fork
// runs in a dashboard terminal via the launcher); otherwise a dash (neither
// native resume nor a launcher to fork into). Phase 0 grounds no
// ResumeNative row, so today this reads "handoff" for launchable tools and a
// dash for file-lane-only ones — honest, never fabricated.
func resumeCell(c integration.Capability) string {
	switch {
	case c.Resume.Kind == integration.ResumeNative:
		return "native"
	case c.Handoff.Launchable():
		return "handoff"
	default:
		return "—"
	}
}

// enforcementCell renders the P7 guard-enforcement bucket (docs/plans/
// plane-b-gateway-implementation-tracker-2026-08-29.md "Phase P7"):
// which channel an org guard policy in enforce mode actually has to stop a
// dangerous call for this adapter. This is the STATIC classification from
// Capability.EnforcementChannel() — the per-host degrade (EnforceSandbox ->
// EnforceRecordedAcceptance when bwrap isn't available, see
// Capability.EffectiveEnforcement) is a runtime-only view the CLI's launch
// path applies at launch time, not shown here, so a Linux/WSL2 "sandbox" row
// reads the same on every platform. EnforcementChannel() is a computed,
// total function (never the registry's zero-value dash) — the switch's
// default only guards a future bucket this binary doesn't know about yet.
func enforcementCell(ch integration.EnforcementChannel) string {
	switch ch {
	case integration.EnforceHookBlock:
		return "hook-block"
	case integration.EnforceSandbox:
		return "sandbox"
	case integration.EnforceOrgDisallow:
		return "org-disallow"
	case integration.EnforceRecordedAcceptance:
		return "recorded"
	default:
		return string(ch)
	}
}
