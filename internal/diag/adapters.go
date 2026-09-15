package diag

import (
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	adapterdefaults "github.com/marmutapp/superbased-observer/internal/adapter/defaults"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
	"github.com/marmutapp/superbased-observer/internal/toolresolve/host"
)

// resolveEnvOnce builds the production toolresolve.Env exactly once per
// process (one login-shell PATH capture + crossmount walk for the whole
// `observer doctor` run, no matter how many adapters get a launch-resolution
// note).
var resolveEnvOnce = sync.OnceValue(func() toolresolve.Env { return host.NewEnv(host.Options{}) })

// launchResolve is the injectable seam over toolresolve.Resolve — tests swap
// it to exercise every verdict without touching the filesystem or a login
// shell.
var launchResolve = func(spec integration.BinaryResolveSpec) toolresolve.Resolution {
	return toolresolve.Resolve(spec, resolveEnvOnce())
}

// checkAdapters is the registry-driven, all-adapter capture-health
// summary (replaces the old two-tool checkAdapterPaths). For every
// REGISTERED adapter it reports whether it's detected on this host (any
// WatchPaths dir exists), idle (enabled but no local data yet), or
// disabled via the enabled_adapters allow-list. Iterating the registry
// means every adapter — including any future one — is covered uniformly
// without touching this function.
func checkAdapters(cfg config.Config) Check {
	enabled := enabledSet(cfg)
	var detected, idle, foreignOnly, disabled []string
	for _, a := range adapterdefaults.Adapters() {
		name := a.Name()
		if enabled != nil && !enabled[name] {
			disabled = append(disabled, name)
			continue
		}
		if adapterDetected(a) {
			detected = append(detected, name)
			continue
		}
		// Not detected locally — before filing it as merely idle, check
		// whether it's actually installed on Windows only (a WSL daemon
		// can't launch it). Resolution only runs for this branch (idle/
		// undetected tools), and shares the one memoized login-PATH env.
		if ic, _ := integration.For(name); ic.Binary != nil {
			if res := launchResolve(*ic.Binary); res.Verdict == toolresolve.VerdictForeignOnly {
				foreignOnly = append(foreignOnly, name)
				continue
			}
		}
		idle = append(idle, name)
	}
	sort.Strings(detected)
	sort.Strings(idle)
	sort.Strings(foreignOnly)
	sort.Strings(disabled)

	var details []string
	if len(detected) > 0 {
		details = append(details, "detected (local data dir present): "+strings.Join(detected, ", "))
	}
	if len(idle) > 0 {
		details = append(details, "enabled, no data yet: "+strings.Join(idle, ", "))
	}
	if len(foreignOnly) > 0 {
		details = append(details, "installed on Windows only (not launchable from WSL): "+strings.Join(foreignOnly, ", "))
	}
	if len(disabled) > 0 {
		details = append(details, "disabled (enabled_adapters): "+strings.Join(disabled, ", "))
	}

	// DI-07: name the same allowed-but-unwatched gap the `observer start`
	// WARN prints (cmd/observer/start.go), so `observer doctor` agrees with
	// it rather than each surface having its own opinion. Downgrades the
	// check to warn — this is a real, silent capture hole, not informational.
	status := StatusOK
	if unwatched := AllowedToolsNotWatched(cfg); len(unwatched) > 0 {
		status = StatusWarn
		details = append(details, "launchable but NOT watched (in [terminal.launch].allowed_tools, "+
			"missing from an explicit [observer.watch].enabled_adapters): "+strings.Join(unwatched, ", ")+
			" — add them to enabled_adapters or delete the key to watch the default set")
	}

	details = append(details, "run `observer doctor <tool>` for a per-adapter capture check")

	msg := strconv.Itoa(len(detected)) + " adapter(s) with local data, " + strconv.Itoa(len(idle)) + " idle"
	if len(detected) == 0 {
		msg = "no adapter data directories detected yet"
	}
	return Check{Name: "adapters", Status: status, Message: msg, Details: details}
}

// CheckAdapter runs a focused, per-adapter capture-health check (the
// `observer doctor <tool>` surface). It returns ok=false when tool is
// not a registered adapter (so the caller can fall back to a substring
// filter over the other checks). For proxy-routable tools it adds the
// routing pre-flight (proxy reachable + base-URL pointed at the proxy +
// Azure bypass warning); for everything else it confirms the
// watcher/hook capture path. Works for ALL adapters, not just opencode.
func CheckAdapter(tool string, cfg config.Config) (Check, bool) {
	var found adapter.Adapter
	for _, a := range adapterdefaults.Adapters() {
		if a.Name() == tool {
			found = a
			break
		}
	}
	if found == nil {
		// Not an adapter — but it may still be a PRODUCT Observer
		// categorises under the harness lifecycle policy with no registry
		// row of its own (a retag identity like roo-code, a renamed alias,
		// a dead sibling product line). Answering those honestly beats the
		// substring-filter fallback telling the operator we never heard of
		// a tool whose data we are actively parsing. Dispatch is on the
		// lifecycle table, never a name list (CLAUDE.md #3/#5).
		if c, ok := productLifecycleCheck(tool); ok {
			return c, true
		}
		return Check{}, false
	}

	var details []string
	worst := StatusOK
	note := func(s Status, m string) {
		details = append(details, m)
		if s > worst {
			worst = s
		}
	}

	if enabled := enabledSet(cfg); enabled != nil && !enabled[tool] {
		note(StatusWarn, "disabled in [observer.watch] enabled_adapters — the watcher will skip it (add \""+tool+"\" to re-enable)")
	}

	ic, _ := integration.For(tool)

	// The 5 *-web browser-capture adapters have no filesystem store at all
	// (capture arrives over the extension's native-messaging bridge), so
	// WatchPaths() is unconditionally nil for them and the generic
	// watch-path check below would file an unconditional, misleading WARN
	// on every install (docs/plans/adapter-parity-audit-2026-08-25.md
	// §2.10). Dispatch on the capability SHAPE (CLAUDE.md #3), never tool
	// name: HookBrowserExtension gets a probe of the signals that actually
	// exist for this topology instead.
	if ic.Hook.Mechanism == integration.HookBrowserExtension {
		browserExtensionHealthNote(tool, cfg, note)
	} else {
		var present []string
		for _, p := range found.WatchPaths() {
			if dirExists(p) {
				present = append(present, p)
			}
		}
		if len(present) > 0 {
			note(StatusOK, "watch path present: "+strings.Join(present, ", "))
		} else {
			hint := strings.Join(found.WatchPaths(), ", ")
			if hint == "" {
				hint = "(no canonical path on this OS)"
			}
			note(StatusWarn, "no watch path found ("+hint+") — is "+tool+" installed, and has it created a session yet?")
		}
	}

	if ic.Proxy != nil {
		ri := ic.Proxy
		port := cfg.Proxy.Port
		if port <= 0 {
			port = 8820
		}
		portStr := strconv.Itoa(port)
		addr := "127.0.0.1:" + portStr
		if dialable(addr) {
			note(StatusOK, "observer proxy reachable at "+addr)
		} else {
			note(StatusWarn, "observer proxy NOT reachable at "+addr+" — start `observer start` for proxy-level api_turn capture")
		}

		switch {
		case ri.Note != "":
			note(StatusOK, ri.Note+" — launch with `"+ri.Launcher+"`")
		case ri.EnvVar != "":
			v := strings.TrimSpace(os.Getenv(ri.EnvVar))
			switch {
			case v == "":
				note(StatusWarn, ri.EnvVar+" not set — launch via `"+ri.Launcher+"` (or export "+ri.EnvVar+"=http://127.0.0.1:"+portStr+ri.Suffix+") for proxy capture")
			case strings.Contains(v, "127.0.0.1:"+portStr) || strings.Contains(v, "localhost:"+portStr):
				note(StatusOK, ri.EnvVar+" points at the observer proxy ("+v+")")
			default:
				note(StatusWarn, ri.EnvVar+"="+v+" is NOT the observer proxy — proxy-level api_turns won't be captured for "+tool)
			}
		}

		// OpenAI-compatible routable tools can be diverted by an
		// Azure-direct provider that ignores the base-URL env var.
		if ri.Suffix == "/v1" && azureProviderConfigured() {
			note(StatusWarn, "Azure provider detected (AZURE_* env) — Azure-direct calls may bypass "+ri.EnvVar+"; route the provider base URL through the observer proxy for api_turn capture")
		}
	} else {
		note(StatusOK, "captured via the watcher/hooks (no proxy launcher needed for this adapter)")
	}

	// Launch-binary resolution (registry-sourced BinaryResolveSpec). Only
	// tools the daemon can actually spawn (`observer <tool>`) carry a spec;
	// a nil Binary means no grounded resolution row for this adapter.
	if ic.Binary != nil {
		status, msg := launchResolutionNote(tool, launchResolve(*ic.Binary))
		note(status, msg)
	}

	// Native-console ledger (Phase 4, registry-sourced). Informational:
	// whether the VENDOR exposes managed-config / usage-export / org-
	// analytics rails. Most adapters are enrollment-only — that is the
	// honest ceiling, not a fault, so it stays StatusOK.
	note(StatusOK, "native console: "+nativeRailsSummary(ic.Native))

	// Token/cost coverage gauge (Phase 5, registry-sourced). Names the best
	// available capture tier and any honest known gap so coverage is
	// measured uniformly across adapters and we can watch the gaps shrink.
	// Stays StatusOK even when gapped: the gaps are inherent to the tool's
	// source data, not user-fixable misconfiguration — surfacing them as a
	// WARN would be alarm fatigue, not signal.
	note(StatusOK, "token/cost: "+tokenTierSummary(ic.TokenTier))

	// Native tool VOCABULARY coverage (WP-T7, registry-sourced): whether
	// the canonical taxonomy (internal/tooltax) carries this adapter's
	// native tool names, so its raw tool calls resolve to a canonical
	// action type instead of falling into `unknown`. An honest-zero row
	// prints its registry Note VERBATIM — the Note is the grounded reason
	// (e.g. a browser-capture lane that records chat turns, never tool
	// calls), and paraphrasing it would re-introduce exactly the
	// heuristic-lie class WP-T3 removed. Stays StatusOK either way: a
	// capture with no tool vocabulary is the honest ceiling of that
	// source, not user-fixable misconfiguration.
	note(StatusOK, "vocabulary: "+vocabularySummary(ic.Vocabulary))

	// Session attach/resume (registry-sourced, session-attach design §2.3).
	// Informational: whether the tool can hand its PTY to the daemon for
	// dashboard jump-in (`observer <sub> --attach`) and how a closed session
	// reopens (native resume vs the shipped handoff-fork). Stays StatusOK —
	// a non-attachable tool is the honest floor, not a fault.
	note(StatusOK, "session: "+attachResumeSummary(ic))

	// Harness lifecycle (registry-sourced, docs/harness-lifecycle-policy.md).
	// Active is informational; deprecated/dead is a WARN and NEVER a FAIL —
	// capture keeps running for a sunset product (rows are never deleted),
	// only ADVERTISING stops, so the operator's install is not broken, it is
	// merely no longer offered. The grounded note prints VERBATIM.
	note(lifecycleNote(ic.Lifecycle, ic.LifecycleNote))

	msg := tool + " capture path looks good"
	if worst != StatusOK {
		msg = tool + " — see notes below"
	}
	return Check{Name: tool, Status: worst, Message: msg, Details: details}, true
}

// lifecycleNote renders a harness-lifecycle status as a doctor note: the
// status it should be reported at, and the line. Active is StatusOK; both
// non-active statuses are StatusWarn and never StatusFail — a deprecated or
// dead product still captures, so it is never a broken check. The grounded
// LifecycleNote is appended VERBATIM (paraphrasing vendor evidence in the
// rendering layer is the exact class of unsourced claim the policy forbids);
// an active row with no note prints the bare status. Dispatches on the closed
// vocabulary, never a tool name.
func lifecycleNote(l integration.Lifecycle, note string) (Status, string) {
	line := "lifecycle: " + l.String()
	if l != integration.LifecycleActive {
		line = "lifecycle: " + strings.ToUpper(l.String())
	}
	if note = strings.TrimSpace(note); note != "" {
		line += " — " + note
	}
	if l.Advertised() {
		return StatusOK, line
	}
	return StatusWarn, line
}

// productLifecycleCheck answers `observer doctor <id>` for a PRODUCT that has
// no registry row and no registered adapter, but that the harness lifecycle
// policy knows about (integration.LifecycleFor resolves it) — roo-code being
// the shipped case. The single Warn note carries the lifecycle + the grounded
// note verbatim; the message names which adapter, if any, still services the
// product's local data. ok is false for an id the policy has never heard of,
// leaving the caller's substring-filter fallback untouched.
func productLifecycleCheck(id string) (Check, bool) {
	lifecycle, note, ok := integration.LifecycleFor(id)
	if !ok {
		return Check{}, false
	}
	status, line := lifecycleNote(lifecycle, note)
	serviced := "no adapter"
	for _, pl := range integration.ProductLifecycles() {
		if pl.ID == id && pl.Adapter != "" {
			serviced = "serviced by " + pl.Adapter
			break
		}
	}
	return Check{
		Name:    id,
		Status:  status,
		Message: id + " is " + lifecycle.String() + " — " + serviced,
		Details: []string{line},
	}, true
}

// launchResolutionNote renders one tool's toolresolve.Resolution as a doctor
// note: the status (OK for a clean resolve, Warn for anything the operator
// should act on) and the one-line honest message. It shares the same verdict
// vocabulary as toolresolve.FormatVerdict but stays doctor-note-shaped (one
// line, no leading "tool:" — CheckAdapter already scopes notes to tool).
func launchResolutionNote(tool string, r toolresolve.Resolution) (Status, string) {
	switch r.Verdict {
	case toolresolve.VerdictOK:
		return StatusOK, "launcher binary: " + r.Bin

	case toolresolve.VerdictOKOffPath:
		hygiene := ""
		if len(r.Notes) > 0 {
			hygiene = r.Notes[0]
		}
		msg := "launcher binary found off PATH: " + r.Bin
		if hygiene != "" {
			msg += " — " + hygiene
		}
		return StatusWarn, msg

	case toolresolve.VerdictShadowed:
		var shims []string
		for _, s := range r.Shadowing {
			shims = append(shims, s.Path)
		}
		return StatusWarn, "launcher binary shadowed by a Windows interop shim on PATH (" + strings.Join(shims, ", ") +
			") — using the native binary at " + r.Bin + " instead"

	case toolresolve.VerdictForeignOnly:
		msg := "installed on Windows, not in WSL — only a Windows interop install was found"
		if fc := firstForeignCandidatePath(r.Considered); fc != "" {
			msg += " (" + fc + ")"
		}
		msg += "; the daemon cannot launch it. Install natively: " + firstInstallDisplay(r.Installs) +
			"; cross-OS launch is a planned follow-up"
		return StatusWarn, msg

	case toolresolve.VerdictNotFound:
		return StatusWarn, "launcher binary not found — install: " + firstInstallDisplay(r.Installs)

	default:
		return StatusWarn, tool + " launcher resolution: " + string(r.Verdict)
	}
}

// firstInstallDisplay returns the first grounded install hint's Display, or
// the honest vendor-docs fallback when none are grounded.
func firstInstallDisplay(installs []integration.InstallHint) string {
	for _, h := range installs {
		if h.Display != "" {
			return h.Display
		}
	}
	return toolresolve.NoGroundedInstallMsg
}

// firstForeignCandidatePath returns the first foreign (Windows-only)
// candidate's path from a resolution's evidence trail, or "" when none was
// recorded.
func firstForeignCandidatePath(considered []toolresolve.Candidate) string {
	for _, c := range considered {
		if c.Foreign {
			return c.Path
		}
	}
	return ""
}

// tokenTierSummary renders an adapter's token/cost capture coverage (the
// registry ledger) for the doctor: the best available tier plus any honest
// known gap. The cost engine is already agnostic; this gauge tracks the
// per-adapter CAPTURE holes the coverage-parity Phase 5 fixes shrink.
func tokenTierSummary(t integration.TokenTier) string {
	best := t.Best
	if best == "" {
		best = "unknown"
	}
	if t.Gap == "" {
		return "best tier=" + best + " (no known gap)"
	}
	return "best tier=" + best + " — known gap: " + t.Gap
}

// vocabularySummary renders an adapter's native tool VOCABULARY coverage
// (the registry ledger) for the doctor.
//
// Three shapes, dispatched on the declared capability (never tool name):
//
//   - InTaxonomy — states the coverage plainly; any Note is a
//     partial-coverage caveat and is appended VERBATIM.
//   - honest zero (InTaxonomy false, Note set) — prints the Note VERBATIM.
//     The Note is the grounded reason this capture has no tool vocabulary;
//     summarizing it here would put a rendering-layer guess in front of the
//     registry's evidence.
//   - undeclared (the zero value) — says exactly that. registry_coverage_
//     test.go rejects this state, so it should be unreachable in a shipped
//     build; rendering still refuses to invent a claim for it.
func vocabularySummary(v integration.Vocabulary) string {
	if v.InTaxonomy {
		s := "in taxonomy (native tool names classified via internal/tooltax)"
		if v.Note != "" {
			s += " — " + v.Note
		}
		return s
	}
	if v.Note != "" {
		return v.Note
	}
	return "not declared in the integration registry"
}

// attachResumeSummary renders an adapter's session attach/resume capability
// (the registry ledger) for the doctor: whether `observer <sub> --attach`
// can hand the tool's PTY to the daemon for dashboard jump-in, and how a
// closed session reopens. It dispatches on capability SHAPE (Attach non-nil,
// Resume.Kind, Handoff.Launchable), never on tool name. The zero value is
// the honest floor: "not attachable" + the handoff-fork resume when a
// launcher exists, else no resume.
func attachResumeSummary(ic integration.Capability) string {
	attach := "not attachable (bare launch only)"
	if ic.Attach != nil {
		attach = "attachable via `observer " + ic.Attach.Subcommand + " --attach`"
	}
	var resume string
	switch {
	case ic.Resume.Kind == integration.ResumeNative:
		resume = "native resume via `observer " + ic.Resume.Subcommand + " --resume <id>`"
	case ic.Handoff.Launchable():
		resume = "handoff-fork resume (--continue-from)"
	default:
		resume = "no resume (file-lane carry only)"
	}
	return attach + "; " + resume
}

// nativeRailsSummary renders an adapter's native-console rails (the
// registry ledger) as a one-line human summary for the doctor. A vendor
// with no rails is enrollment-only — correct for most adapters, not a gap.
func nativeRailsSummary(n integration.NativeRails) string {
	if !n.Any() {
		return "enrollment-only (no vendor telemetry rails)"
	}
	var rails []string
	if n.A {
		rails = append(rails, "A:node-telemetry")
	}
	if n.B {
		rails = append(rails, "B:managed-config")
	}
	if n.C {
		rails = append(rails, "C:org-analytics")
	}
	s := "rails " + strings.Join(rails, " ")
	if n.Note != "" {
		s += " (" + n.Note + ")"
	}
	return s
}

// adapterDetected reports whether any of an adapter's watch directories
// exists on this host (a proxy for "this tool is installed + has run"). A
// package-level var (like launchResolve) so tests can force a deterministic
// detected/undetected split without depending on the real host filesystem.
var adapterDetected = func(a adapter.Adapter) bool {
	for _, p := range a.WatchPaths() {
		if dirExists(p) {
			return true
		}
	}
	return false
}

// enabledSet returns the enabled-adapters allow-list as a set, or nil
// when no explicit list is configured (nil == every adapter enabled).
func enabledSet(cfg config.Config) map[string]bool {
	list := cfg.Observer.Watch.EnabledAdapters
	if len(list) == 0 {
		return nil
	}
	m := make(map[string]bool, len(list))
	for _, n := range list {
		m[n] = true
	}
	return m
}

// AdapterWatched reports whether the watcher would capture the named
// adapter under this config's [observer.watch].enabled_adapters list.
//
// It is THE one owner of that list's nil-vs-empty rule for every read-side
// surface (CLAUDE.md #4). The rule mirrors adapter.Registry.Detected
// (internal/adapter/registry.go): a NIL list is "no restriction — every
// adapter is watched", while a NON-NIL EMPTY list is the explicit
// `enabled_adapters = []` intent "watch nothing". enabledSet deliberately
// collapses those two cases (it answers a different question — "is there a
// restriction to apply") and must NOT be reused here.
//
// Pure: no filesystem, no config load, no registry probe.
func AdapterWatched(cfg config.Config, name string) bool {
	list := cfg.Observer.Watch.EnabledAdapters
	if list == nil {
		return true
	}
	for _, n := range list {
		if n == name {
			return true
		}
	}
	return false
}

// GUILaunchWatched reports whether a GUI launch row's capture is covered by
// this config's [observer.watch].enabled_adapters list. It is THE one owner of
// that question for every GUI surface (CLAUDE.md #4) — the dashboard picker's
// per-row `watched` flag and the `observer start` capture-gap WARN both read
// it, so the two can never disagree.
//
// The rule is shaped by the row's CARRIER, never by a product name:
//
//   - A pure editor HOST (Adapter == "") has no adapter of its own — the
//     sessions come from whatever extension runs inside it — so there is
//     nothing for enabled_adapters to omit and nothing to warn about. It is
//     watched by definition; reporting a gap would invent one.
//   - An adapter-carried row (cursor-ide → cursor, kiro-ide → kiro-cli, …)
//     defers to that ADAPTER's membership: launching the IDE records nothing
//     if the watcher is not watching the adapter behind it.
//
// Pure: no filesystem, no config load, no registry probe.
func GUILaunchWatched(cfg config.Config, row integration.GUILaunchable) bool {
	if row.Adapter == "" {
		return true
	}
	return AdapterWatched(cfg, row.Adapter)
}

// AllowedToolsNotWatched returns the [terminal.launch].allowed_tools entries
// that the watcher would NOT capture, because an explicit
// [observer.watch].enabled_adapters list omits them (audit DI-07). These are
// the tools a fresh dashboard launch will start happily and then record
// nothing for — the two allow-lists are independent by design, so the only
// honest fix is to name the gap.
//
// allowed_tools is ONE list keyed by launch id, and a launch id is not always
// an adapter name: since the GUI launch arc it also holds IDE / desktop-app
// ids (vscode, cursor-ide, claude-desktop, …). Each entry is therefore
// resolved through a lookup ladder that dispatches on which registry OWNS the
// id, never on the id's spelling (CLAUDE.md #3):
//
//  1. a registry ADAPTER row → its own enabled_adapters membership (the
//     original DI-07 rule, unchanged);
//  2. a GUI LAUNCH row → GUILaunchWatched, so a host is never flagged and an
//     adapter-carried IDE is judged by the adapter behind it;
//  3. an unknown id → its own membership, exactly as before. An id nothing
//     recognises is most likely a typo'd adapter name, and the original
//     behaviour (name it) is the more useful answer.
//
// Before rung 2 existed, every GUI id in allowed_tools was measured against
// enabled_adapters as if it were an adapter, so a correctly configured node
// warned "lists 10 tool(s) that your explicit enabled_adapters does not watch:
// vscode, cursor-ide, …" at every start (2026-09-03 live verification).
//
// The result preserves allowed_tools order (the operator's own spelling) and
// is nil when nothing is missing — including the nil-enabled_adapters case,
// where every adapter is watched. A non-nil EMPTY enabled_adapters list means
// "watch nothing", so every allowed tool comes back (a GUI host still does
// not: it has no adapter to switch off).
//
// Pure: no filesystem, no config load. Callers: the `observer start` WARN,
// diag.checkAdapters, and the dashboard's /api/terminal/policy GET.
func AllowedToolsNotWatched(cfg config.Config) []string {
	if cfg.Observer.Watch.EnabledAdapters == nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, raw := range cfg.Terminal.Launch.AllowedTools {
		tool := strings.TrimSpace(raw)
		if tool == "" || seen[tool] {
			continue
		}
		seen[tool] = true
		if tool == termsvc.ShellTool {
			// The plain-shell pseudo-tool has no adapter and is never
			// watched by construction; reporting it would be noise.
			continue
		}
		if !allowedIDWatched(cfg, tool) {
			out = append(out, tool)
		}
	}
	return out
}

// allowedIDWatched runs the allowed_tools lookup ladder for ONE id (see
// AllowedToolsNotWatched). It is the single place that decides which registry
// owns a launch id, so the WARN and the dashboard policy key can never drift.
func allowedIDWatched(cfg config.Config, id string) bool {
	if _, ok := integration.For(id); ok {
		return AdapterWatched(cfg, id)
	}
	if row, ok := integration.GUILaunchFor(id); ok {
		return GUILaunchWatched(cfg, row)
	}
	return AdapterWatched(cfg, id)
}

// azureProviderConfigured reports whether the environment carries a
// signal that an Azure OpenAI / AI Foundry provider is in use — the
// case where an OpenAI-compatible tool may bypass its base-URL env var.
func azureProviderConfigured() bool {
	for _, k := range []string{"AZURE_RESOURCE_NAME", "AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_API_KEY", "AZURE_API_KEY"} {
		if strings.TrimSpace(os.Getenv(k)) != "" {
			return true
		}
	}
	return strings.EqualFold(strings.TrimSpace(os.Getenv("OPENAI_API_TYPE")), "azure")
}
