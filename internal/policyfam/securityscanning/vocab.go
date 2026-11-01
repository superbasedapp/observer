package securityscanning

import (
	"github.com/marmutapp/superbased-observer/internal/postureop"
)

// Family is the policy-resource family name (policyfam.FamilySecurityScanning).
const Family = "security.scanning"

// BodyVersion is the only body version this build reads.
const BodyVersion = 1

// DefaultMaxBytes bounds a body when the caller passes no cap.
const DefaultMaxBytes int64 = 64 << 10

// Child is one security child component a body may name, in a section or in
// require.components. The id is the part after "security." in the catalog.
type Child struct {
	// ID is the section key, for example "deps" or "scan.osv".
	ID string
	// Component is the catalog id, "security." + ID.
	Component string
	// StartsProcess: switching the child on starts a program outside the
	// observer process (a scanner engine, a custom driver).
	StartsProcess bool
	// MakesEgress: switching the child on makes the node reach the network
	// on its own (a database or index download).
	MakesEgress bool
}

// Children is the closed child vocabulary. security.githooks is not here on
// purpose: the org never installs git hooks, on managed nodes too (PR11), so
// no floor may require them. A child added to the catalog joins this table
// with its process and egress columns reviewed.
var Children = []Child{
	{ID: "trust", Component: "security.trust"},
	{ID: "secrets", Component: "security.secrets"},
	{ID: "code", Component: "security.code"},
	{ID: "deps", Component: "security.deps", MakesEgress: true},
	{ID: "scan.custom", Component: "security.scan.custom", StartsProcess: true},
	{ID: "scan.scalibr", Component: "security.scan.scalibr", StartsProcess: true, MakesEgress: true},
	{ID: "scan.osv", Component: "security.scan.osv", StartsProcess: true, MakesEgress: true},
	// Opengrep (lane SEC-G1): a separately installed program, no download
	// of its own (the rule pack ships in the binary or is imported).
	{ID: "scan.opengrep", Component: "security.scan.opengrep", StartsProcess: true},
	// SARIF import and the linked actionlint (lane SEC-G5): drivers like
	// the rows above, so a floor may require them; neither starts a program
	// (sarif-import reads one file the developer names, actionlint is linked
	// in process) and neither reaches the network.
	{ID: "scan.sarif-import", Component: "security.scan.sarif-import"},
	{ID: "scan.actionlint", Component: "security.scan.actionlint"},
	// The IaC process drivers (lane GATES-SEC): separately installed
	// programs; Trivy's guided install downloads only on the developer's
	// consent (like Opengrep's, no download of its own otherwise), KICS has
	// no download at all.
	{ID: "scan.trivy", Component: "security.scan.trivy", StartsProcess: true},
	{ID: "scan.kics", Component: "security.scan.kics", StartsProcess: true},
}

// LookupChild returns the vocabulary row for a section key.
func LookupChild(id string) (Child, bool) {
	for _, c := range Children {
		if c.ID == id {
			return c, true
		}
	}
	return Child{}, false
}

// LookupChildComponent returns the vocabulary row for a catalog component id.
func LookupChildComponent(component string) (Child, bool) {
	for _, c := range Children {
		if c.Component == component {
			return c, true
		}
	}
	return Child{}, false
}

// CapabilityToken is a child's section capability token.
func CapabilityToken(childID string) string { return "security." + childID + ".v1" }

// Driver is one scanner driver an allow-set may name.
type Driver struct {
	// ID is the driver id the scanner registry uses.
	ID string
	// Component is the catalog component that owns it, "" when no
	// component does (the driver then switches no component on).
	Component string
	// StartsProcess: the driver runs as a separate program (every
	// non-native driver does today).
	StartsProcess bool
}

// Drivers is the closed driver vocabulary for allow.drivers (security plan
// 4.4). Native detectors are not drivers an allow-set names.
var Drivers = []Driver{
	{ID: "scalibr", Component: "security.scan.scalibr", StartsProcess: true},
	{ID: "osv", Component: "security.scan.osv", StartsProcess: true},
	{ID: "opengrep", Component: "security.scan.opengrep", StartsProcess: true},
	// actionlint: owned by security.scan.actionlint (lane SEC-G5). It is
	// linked in process, but the row keeps StartsProcess so allowing it
	// still asks for the super admin, as before that component existed.
	{ID: "actionlint", Component: "security.scan.actionlint", StartsProcess: true},
	{ID: "trivy", Component: "security.scan.trivy", StartsProcess: true},
	{ID: "kics", Component: "security.scan.kics", StartsProcess: true},
}

// LookupDriver returns the vocabulary row for a driver id.
func LookupDriver(id string) (Driver, bool) {
	for _, d := range Drivers {
		if d.ID == id {
			return d, true
		}
	}
	return Driver{}, false
}

// ScannerSources is the closed vocabulary of allow.scanner_sources.
var ScannerSources = []string{"vendor_release", "org_mirror", "user_installed"}

// Enum values, each axis listed weaker first.
var (
	PrelaunchTrustValues       = []string{"warn", "ask", "refuse"}
	CommitGateValues           = []string{"ask", "quick_scan"}
	SeverityValues             = []string{"critical", "high", "medium", "low"}
	InstallUnknownValues       = []string{"flag", "ask"}
	OnlineChecksRequireValues  = []string{"leave", "required"}
	InstallOnlineUnknownValues = []string{"flag", "ask", "deny"}
	OnlineChecksAllowValues    = []string{"allowed", "forbidden"}
	BoolValues                 = []string{"false", "true"}
	QuickScanBudgetValues      = []int64{5, 10, 30}
	RetentionDaysValues        = []int64{0, 90, 180, 365, 730}
)

// Axis names. Each is the dotted body key, so a posture_loosened refusal
// names the key the admin wrote.
const (
	AxisComponents           = "require.components"
	AxisPrelaunchTrust       = "require.prelaunch_trust"
	AxisCommitGate           = "require.commit_gate"
	AxisQuickScanBudget      = "require.quick_scan_budget_s"
	AxisMaxScanStaleness     = "require.max_scan_staleness_min"
	AxisMaxAdvisoryDBAge     = "require.max_advisory_db_age_h"
	AxisMinBlockingSeverity  = "require.min_blocking_severity"
	AxisInstallUnknown       = "require.install_unknown"
	AxisOnlineChecks         = "require.online_checks"
	AxisInstallOnlineUnknown = "require.install_online_unknown"
	AxisHistoryScanOnEnrol   = "require.history_scan_on_enrol"
	AxisFindingRetention     = "require.finding_retention_days"
	AxisAllowDrivers         = "allow.drivers"
	AxisAllowCustomManifests = "allow.custom_manifests"
	AxisAllowScannerSources  = "allow.scanner_sources"
	AxisAllowOnlineChecks    = "allow.online_checks"
	AxisRulePackMinVersion   = "rule_pack.min_version"
)

// Axes is the family's posture axis table (security plan 4.9), weaker to
// stronger, as data. postureop.Compare walks it in this order.
var Axes = []postureop.Axis{
	{Name: AxisComponents, Kind: postureop.AxisSupersetStronger},
	{Name: AxisPrelaunchTrust, Kind: postureop.AxisEnum, Order: PrelaunchTrustValues},
	{Name: AxisCommitGate, Kind: postureop.AxisEnum, Order: CommitGateValues},
	{Name: AxisQuickScanBudget, Kind: postureop.AxisHigherStronger},
	{Name: AxisMaxScanStaleness, Kind: postureop.AxisLowerStronger},
	{Name: AxisMaxAdvisoryDBAge, Kind: postureop.AxisLowerStronger},
	{Name: AxisMinBlockingSeverity, Kind: postureop.AxisEnum, Order: SeverityValues},
	{Name: AxisInstallUnknown, Kind: postureop.AxisEnum, Order: InstallUnknownValues},
	{Name: AxisOnlineChecks, Kind: postureop.AxisEnum, Order: OnlineChecksRequireValues},
	{Name: AxisInstallOnlineUnknown, Kind: postureop.AxisEnum, Order: InstallOnlineUnknownValues},
	{Name: AxisHistoryScanOnEnrol, Kind: postureop.AxisEnum, Order: BoolValues},
	{Name: AxisFindingRetention, Kind: postureop.AxisRetention},
	{Name: AxisAllowDrivers, Kind: postureop.AxisSubsetStronger},
	{Name: AxisAllowCustomManifests, Kind: postureop.AxisSubsetStronger},
	{Name: AxisAllowScannerSources, Kind: postureop.AxisSubsetStronger},
	{Name: AxisAllowOnlineChecks, Kind: postureop.AxisEnum, Order: OnlineChecksAllowValues},
	{Name: AxisRulePackMinVersion, Kind: postureop.AxisVersion},
}

// LookupAxis returns the axis row by name.
func LookupAxis(name string) (postureop.Axis, bool) {
	for _, a := range Axes {
		if a.Name == name {
			return a, true
		}
	}
	return postureop.Axis{}, false
}

// EnumKeys lists every enum-valued body key with the values the decoder
// accepts, for postureop.ReviewEnums: a value accepted here with no place on
// its axis fails the tests (unknown fails closed).
var EnumKeys = []postureop.EnumKey{
	{Key: AxisPrelaunchTrust, Axis: AxisPrelaunchTrust, Values: PrelaunchTrustValues},
	{Key: AxisCommitGate, Axis: AxisCommitGate, Values: CommitGateValues},
	{Key: AxisMinBlockingSeverity, Axis: AxisMinBlockingSeverity, Values: SeverityValues},
	{Key: AxisInstallUnknown, Axis: AxisInstallUnknown, Values: InstallUnknownValues},
	{Key: AxisOnlineChecks, Axis: AxisOnlineChecks, Values: OnlineChecksRequireValues},
	{Key: AxisInstallOnlineUnknown, Axis: AxisInstallOnlineUnknown, Values: InstallOnlineUnknownValues},
	{Key: AxisHistoryScanOnEnrol, Axis: AxisHistoryScanOnEnrol, Values: BoolValues},
	{Key: AxisAllowOnlineChecks, Axis: AxisAllowOnlineChecks, Values: OnlineChecksAllowValues},
}

// keyRule is one row of the key table: which axis a body key sits on, the
// child component it only means something under ("" for every node), and
// whether only a managed node honours it (security plan 4.9 and 7.3: on an
// individual node the developer's own switch decides).
type keyRule struct {
	Axis        string
	Component   string
	ManagedOnly bool
}

// keyRules is the key table, in axis order. A key with a Component is
// not_applicable: component_absent on an individual node where that
// component is not active.
var keyRules = []keyRule{
	{Axis: AxisComponents},
	// Managed only like the commit gate (orchestrator ruling P-125, audit
	// SEC-P4 F4): an org floor never raises an individual node's own trust
	// step, whatever components it runs.
	{Axis: AxisPrelaunchTrust, Component: "security.trust", ManagedOnly: true},
	{Axis: AxisCommitGate, ManagedOnly: true},
	{Axis: AxisQuickScanBudget},
	{Axis: AxisMaxScanStaleness},
	{Axis: AxisMaxAdvisoryDBAge, Component: "security.deps"},
	{Axis: AxisMinBlockingSeverity},
	{Axis: AxisInstallUnknown, Component: "security.deps"},
	{Axis: AxisOnlineChecks, Component: "security.deps", ManagedOnly: true},
	{Axis: AxisInstallOnlineUnknown, Component: "security.deps", ManagedOnly: true},
	{Axis: AxisHistoryScanOnEnrol},
	{Axis: AxisFindingRetention},
	{Axis: AxisAllowDrivers},
	{Axis: AxisAllowCustomManifests, Component: "security.scan.custom", ManagedOnly: true},
	{Axis: AxisAllowScannerSources},
	{Axis: AxisAllowOnlineChecks, Component: "security.deps"},
	{Axis: AxisRulePackMinVersion},
}
