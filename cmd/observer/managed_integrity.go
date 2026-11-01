package main

import (
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
)

// managed_integrity.go — the cmd/observer boundary seam for the Arc 4 P6b
// managed-integrity probe (plan §9). collectManagedIntegritySignals is the ONE
// place that gathers the host tamper-evidence (sibling observers via diag,
// AI-tool route drift via proxyroute) and returns coarse labels; the orgclient
// consults it inside PushLoop (managed nodes only) so the client never imports
// diag/proxyroute. EVIDENCE, not prevention — see the §5 gate.

// hookIntegrityInputs are the T-847 hook inputs of the probe: the hook
// targets this node's own auto-registration owns (with a dry run's drift,
// probeExpectedHooks) and the repair tracker the auto-registration passes
// share. The zero value reproduces the pre-T-847 probe.
type hookIntegrityInputs struct {
	Expected []diag.ExpectedHook
	Tracker  hookRegistryLossSource
	Now      time.Time
	// RealBinary is the running binary with symlinks resolved, when the
	// binaryPath argument is the registration command (T-874: the daemon
	// passes what `observer doctor` passes, so a registration naming the
	// npm launcher is not a hook_binary_mismatch).
	RealBinary string
}

// hookRegistryLossSource is the slice of hook.RepairTracker the probe reads.
type hookRegistryLossSource interface {
	RegistryLostSince(now time.Time, window time.Duration) (time.Time, bool)
}

// routeDriftModes maps the live route posture to how the integrity probe
// reads the host's AI tool routes (T-900, RETEST5 F4). One row per posture,
// one test per posture rule (TestRouteDriftPolicyFollowsPosture):
//
//   - maintain (the admin pinned it ON, or it is unset and the org governs an
//     enforcement point in the API proxy): routes are required and kept, so
//     every installed tool whose route does not reach this proxy is drift;
//   - release (the admin pinned it OFF): no route is required; the daemon
//     removed the organization's routes and a tool on its own provider is the
//     setup the admin chose, so nothing is drift;
//   - none (unset without such an authority, or not a managed grant): nothing
//     is maintained and the routes the organization wrote earlier are left in
//     place (D-738), so only such a route that is gone or no longer reaches
//     this proxy is drift; a route the organization never wrote is the
//     developer's own setup.
var routeDriftModes = map[govern.RoutePosture]proxyroute.DriftMode{
	govern.RoutePostureMaintain: proxyroute.DriftModeMaintained,
	govern.RoutePostureRelease:  proxyroute.DriftModeOff,
	govern.RoutePostureNone:     proxyroute.DriftModeOrgRoutes,
}

// routeDriftPolicy resolves the probe's drift reading from the live route
// posture and the daemon's own proxy listener port (T-901: a loopback route
// at another port does not reach this proxy). A posture the table does not
// name reads as maintained, the loud side. sel is the node's component
// selection, routeSelection, the same one route maintenance acts on, so a
// tool maintenance never routes is never drift (T-915, D-770, D-771); the
// zero value selects routing and every tool.
func routeDriftPolicy(v govern.RoutePostureVerdict, proxyPort int, sel proxyroute.Selection) proxyroute.DriftPolicy {
	mode, ok := routeDriftModes[v.Posture]
	if !ok {
		mode = proxyroute.DriftModeMaintained
	}
	return proxyroute.DriftPolicy{Mode: mode, ProxyPort: proxyPort, Selection: sel}
}

// collectManagedIntegritySignals returns the coarse tamper-evidence labels for
// this host: a sibling-observer origin label per second/parallel observer.db
// (never a filesystem path), and the adapter tool name of every AI-tool proxy
// route that has drifted off this daemon's proxy. The counts the wire carries
// are the label lengths; only these labels cross (the §9 content-floor). It
// reads the live crossmount homes; the pure inner collectIntegritySignalsFrom
// takes them injected so the assembly is testable without the host
// environment.
func collectManagedIntegritySignals(dbPath, homeDir, binaryPath string, routeDrift proxyroute.DriftPolicy, hooks hookIntegrityInputs) orgcontract.ManagedIntegrityReport {
	return collectIntegritySignalsWith(dbPath, homeDir, binaryPath, crossmount.AllHomes(), routeDrift, hooks)
}

// collectIntegritySignalsFrom is the injected-homes core of
// collectManagedIntegritySignals, without the T-847 hook inputs.
//
// routeDrift is resolved by the caller from the live governance posture
// (routeDriftPolicy over govern.Effective.RoutePosture), never a tenancy or
// tool name (CLAUDE.md #3). See proxyroute.DriftedTools for what each mode
// reads as drift and why.
//
// Even the strictest mode only counts an absent route when the tool's own
// config artifact is actually on the host (RouteStatus.ArtifactPresent). A
// tool the developer never installed leaves nothing behind and is never
// reported as drift, otherwise a Claude-Code-only developer on a managed node
// would report four drifted tools and open a fleet-wide integrity_risk
// finding for having a plain single-tool install.
func collectIntegritySignalsFrom(dbPath, homeDir, binaryPath string, homes []crossmount.HomeRoot, routeDrift proxyroute.DriftPolicy) orgcontract.ManagedIntegrityReport {
	return collectIntegritySignalsWith(dbPath, homeDir, binaryPath, homes, routeDrift, hookIntegrityInputs{})
}

// collectIntegritySignalsWith is collectIntegritySignalsFrom plus the T-847
// hook inputs: every capture risk is also reported as a located item naming
// the registration target and a home-relative file label, a missing
// hook_checksums.json is a risk on a node that registers hooks (audit c3), a
// dry-run drift of the node's own registration is a risk, and a recorded
// repair (or a registry deletion the repair tracker saw) is reported for a
// day.
func collectIntegritySignalsWith(dbPath, homeDir, binaryPath string, homes []crossmount.HomeRoot, routeDrift proxyroute.DriftPolicy, hooks hookIntegrityInputs) orgcontract.ManagedIntegrityReport {
	report := orgcontract.ManagedIntegrityReport{CaptureCheckVersion: orgcontract.ManagedCaptureCheckVersion}
	for _, s := range diag.DetectSiblingObservers(dbPath, homes) {
		report.SiblingDetail = append(report.SiblingDetail, coarseSiblingLabel(s.Origin, s.OS))
	}
	// DEC-7 (lane w4-wire): a route that is in the file while the tool's
	// active provider is another one reads RouteInactiveProvider, its own
	// drift-table row: never drift, reported as inactive_provider_tools.
	routes := proxyroute.ApplyActiveProvider(proxyroute.InspectRoutes(homeDir))
	report.DriftedTools = proxyroute.DriftedTools(routes, routeDrift)
	report.InactiveProviderTools = proxyroute.InactiveProviderTools(routes, routeDrift)
	// Lane P1: an installed tool Observer cannot route here and never
	// routed is coverage, never drift.
	report.UnroutableTools = proxyroute.UnroutableTools(routes, routeDrift)
	// T-915 (D-770): an installed tool the policy did not select is never
	// routed by maintenance, so it is never drift; the organization sees it
	// as "installed, not selected by policy".
	report.UnselectedTools = proxyroute.UnselectedTools(routes, routeDrift)
	// D-771: the route writer component is not active, so the daemon keeps
	// no routes and nothing is drift; the admin sees "routing switched off
	// by policy" naming the installed tools.
	report.RoutingOff = proxyroute.RoutingSwitchedOff(routeDrift)
	report.RoutingOffTools = proxyroute.RoutingOffTools(routes, routeDrift)
	// Lane P1: routes are maintained, so a daemon that is not restarted
	// after a crash, a failed update or a reboot leaves every routed tool on
	// ConnectionRefused. Say so when no supervisor was found (a warning on
	// the admin view, never a refusal). With routing switched off the daemon
	// keeps no routes, so there is nothing to warn about.
	report.SupervisorMissing = routeDrift.Mode == proxyroute.DriftModeMaintained && !report.RoutingOff && !detectSupervisor().Detected
	checks := diag.InspectCaptureIntegrityWith(homeDir, diag.CaptureIntegrityOptions{
		BinaryPath:     binaryPath,
		RealBinaryPath: hooks.RealBinary,
		Expected:       hooks.Expected,
		Now:            hooks.Now,
	})
	report.CaptureRisks = checks.Risks
	if len(report.InactiveProviderTools) > 0 {
		report.CaptureRisks = appendLabel(report.CaptureRisks, orgcontract.CaptureRiskRouteInactiveProvider)
	}
	report.UnknownChecks = checks.Unknown
	report.CaptureRiskItems = checks.Items
	report.CaptureRiskItemsOmitted = checks.ItemsOmitted
	if hooks.Tracker != nil && !hooks.Now.IsZero() {
		if _, lost := hooks.Tracker.RegistryLostSince(hooks.Now, diag.DefaultRepairWindow); lost {
			report.CaptureRisks = appendLabel(report.CaptureRisks, orgcontract.CaptureRiskHookRegistryMissing)
			items, more := orgcontract.NormalizeCaptureRiskItemsCounted(append(report.CaptureRiskItems, orgcontract.CaptureRiskItem{
				Risk: orgcontract.CaptureRiskHookRegistryMissing,
				Tool: diag.HookRegistryTool,
				File: "~/.observer/hook_checksums.json",
			}))
			report.CaptureRiskItems = items
			report.CaptureRiskItemsOmitted = orgcontract.AddCaptureRiskItemsOmitted(report.CaptureRiskItemsOmitted, more)
		}
	}
	if !hooks.Now.IsZero() {
		addRouteActs(&report, homeDir, proxyroute.RecentRouteActs(homeDir, hooks.Now, diag.DefaultRepairWindow))
	}
	report.SiblingObservers = len(report.SiblingDetail)
	report.RouteDrift = len(report.DriftedTools)
	return report
}

// addRouteActs reports the recent route acts of Observer's enrolment (lane
// P1), the way hook repairs are reported: a route put back after removal is
// the route_repaired capture risk, located on the tool and a home-relative
// label of its config file and stamped with the repair time; a first write is
// the informational routes_written label, never a risk.
func addRouteActs(report *orgcontract.ManagedIntegrityReport, homeDir string, acts []proxyroute.RouteAct) {
	var items []orgcontract.CaptureRiskItem
	for _, act := range acts {
		if act.Kind != proxyroute.RouteActRepaired {
			report.RoutesWritten = appendLabel(report.RoutesWritten, act.Tool)
			continue
		}
		report.CaptureRisks = appendLabel(report.CaptureRisks, orgcontract.CaptureRiskRouteRepaired)
		items = append(items, orgcontract.CaptureRiskItem{
			Risk: orgcontract.CaptureRiskRouteRepaired,
			Tool: act.Tool,
			File: diag.RiskFileLabel(homeDir, act.ConfigPath),
			At:   act.At.UTC().Format(time.RFC3339),
		})
	}
	if len(items) == 0 {
		return
	}
	merged, more := orgcontract.NormalizeCaptureRiskItemsCounted(append(report.CaptureRiskItems, items...))
	report.CaptureRiskItems = merged
	report.CaptureRiskItemsOmitted = orgcontract.AddCaptureRiskItemsOmitted(report.CaptureRiskItemsOmitted, more)
}

// vendorPolicyRiskLabels maps a cached vendor policy finding (S-15, D17) to
// its closed capture-risk label. A kind with no row (a route veto where
// Observer writes no route) stays on the doctor row and never crosses.
var vendorPolicyRiskLabels = map[diag.VendorPolicyKind]string{
	diag.VendorPolicyBlocksMCP: orgcontract.CaptureRiskVendorPolicyBlocksMCP,
	diag.VendorPolicyPinsRoute: orgcontract.CaptureRiskVendorPolicyPinsRoute,
}

// addVendorPolicyRisks reports the cached vendor org policies that block
// Observer's MCP server or pin a tool's route (S-15, D17), as standing
// capture risks located on the tool and a home-relative label of the cache
// DIRECTORY (Cline's cache file name carries the vendor org id, which never
// crosses). Nothing read from a cache crosses.
func addVendorPolicyRisks(homeDir string, getenv func(string) string, report *orgcontract.ManagedIntegrityReport) {
	var items []orgcontract.CaptureRiskItem
	for _, f := range diag.VendorPolicyFindings(homeDir, getenv) {
		label, ok := vendorPolicyRiskLabels[f.Kind]
		if !ok || !f.Warn {
			continue
		}
		report.CaptureRisks = appendLabel(report.CaptureRisks, label)
		items = append(items, orgcontract.CaptureRiskItem{Risk: label, Tool: f.Tool, File: diag.RiskFileLabel(homeDir, f.Dir)})
	}
	if len(items) == 0 {
		return
	}
	merged, more := orgcontract.NormalizeCaptureRiskItemsCounted(append(report.CaptureRiskItems, items...))
	report.CaptureRiskItems = merged
	report.CaptureRiskItemsOmitted = orgcontract.AddCaptureRiskItemsOmitted(report.CaptureRiskItemsOmitted, more)
}

// appendLabel adds label to labels unless it is already there.
func appendLabel(labels []string, label string) []string {
	for _, l := range labels {
		if l == label {
			return labels
		}
	}
	return append(labels, label)
}

// coarseSiblingLabel removes the username/distro suffix carried by the local
// crossmount diagnostic before the signal crosses the org wire.
func coarseSiblingLabel(origin, osName string) string {
	switch {
	case origin == "native-alt":
		origin = "native-alt"
	case strings.HasPrefix(origin, "wsl-mnt:"):
		origin = "wsl-mnt"
	case strings.HasPrefix(origin, "wslhost:"):
		origin = "wslhost"
	default:
		origin = "other"
	}
	switch osName {
	case crossmount.OSWindows, crossmount.OSLinux, crossmount.OSDarwin:
	default:
		osName = "other"
	}
	return origin + "/" + osName
}
