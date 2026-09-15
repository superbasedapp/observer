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
func collectManagedIntegritySignals(dbPath, homeDir, binaryPath string) orgcontract.ManagedIntegrityReport {
	return collectIntegritySignalsFrom(dbPath, homeDir, binaryPath, crossmount.AllHomes())
}

// collectIntegritySignalsFrom is the injected-homes core of
// collectManagedIntegritySignals.
func collectIntegritySignalsFrom(dbPath, homeDir, binaryPath string, homes []crossmount.HomeRoot) orgcontract.ManagedIntegrityReport {
	report := orgcontract.ManagedIntegrityReport{CaptureCheckVersion: orgcontract.ManagedCaptureCheckVersion}
	for _, s := range diag.DetectSiblingObservers(dbPath, homes) {
		report.SiblingDetail = append(report.SiblingDetail, coarseSiblingLabel(s.Origin, s.OS))
	}
	for _, rs := range proxyroute.InspectRoutes(homeDir) {
		if rs.State == proxyroute.RouteDrifted {
			report.DriftedTools = append(report.DriftedTools, rs.Tool)
		}
	}
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
