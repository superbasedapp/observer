package main

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/diag"
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

// collectManagedIntegritySignals returns the coarse tamper-evidence labels for
// this host: a sibling-observer origin label per second/parallel observer.db
// (never a filesystem path), and the adapter tool name of every AI-tool proxy
// route that has drifted off an observer proxy. The counts the wire carries are
// the label lengths; only these labels cross (the §9 content-floor). It reads
// the live crossmount homes; the pure inner collectIntegritySignalsFrom takes
// them injected so the assembly is testable without the host environment.
func collectManagedIntegritySignals(dbPath, homeDir, binaryPath string, absentRouteIsDrift bool) orgcontract.ManagedIntegrityReport {
	return collectIntegritySignalsFrom(dbPath, homeDir, binaryPath, crossmount.AllHomes(), absentRouteIsDrift)
}

// collectIntegritySignalsFrom is the injected-homes core of
// collectManagedIntegritySignals.
//
// absentRouteIsDrift is a CAPABILITY flag resolved by the caller from the
// live governance posture (govern.Effective.GrantsAnyEnforcement), never a
// tenancy or tool name (CLAUDE.md #3). See proxyroute.DriftedTools for what
// it changes and why.
//
// It is a PERMISSION to read an absent route strictly, not an instruction to:
// proxyroute only counts an absent route when the tool's own config artifact
// is actually on the host (RouteStatus.ArtifactPresent). A tool the developer
// never installed leaves nothing behind and is never reported as drift under
// any tenancy — otherwise a Claude-Code-only developer on a managed node
// would report four drifted tools and open a fleet-wide integrity_risk
// finding for having a plain single-tool install.
func collectIntegritySignalsFrom(dbPath, homeDir, binaryPath string, homes []crossmount.HomeRoot, absentRouteIsDrift bool) orgcontract.ManagedIntegrityReport {
	report := orgcontract.ManagedIntegrityReport{CaptureCheckVersion: orgcontract.ManagedCaptureCheckVersion}
	for _, s := range diag.DetectSiblingObservers(dbPath, homes) {
		report.SiblingDetail = append(report.SiblingDetail, coarseSiblingLabel(s.Origin, s.OS))
	}
	report.DriftedTools = proxyroute.DriftedTools(proxyroute.InspectRoutes(homeDir), absentRouteIsDrift)
	checks := diag.InspectCaptureIntegrity(homeDir, binaryPath)
	report.CaptureRisks = checks.Risks
	report.UnknownChecks = checks.Unknown
	report.SiblingObservers = len(report.SiblingDetail)
	report.RouteDrift = len(report.DriftedTools)
	return report
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
