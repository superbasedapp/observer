package secscan

import (
	"context"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

// Kind is a driver's kind (section 4.4).
type Kind string

// The Kind values (section 4.4).
const (
	// KindNative is Observer's own pure Go detectors, in process; some run
	// on the hook path (bounded) and in the commit quick scan.
	KindNative Kind = "native"
	// KindLinked is an imported Go module behind a facade package and its
	// driver's omit tag; background only; permissive licences only.
	KindLinked Kind = "linked"
	// KindProcess is a subprocess engine, background only, never in a
	// hook; never bundled.
	KindProcess Kind = "process"
	// KindSARIFImport reads a SARIF file the user's own tool produced;
	// Observer never runs the tool.
	KindSARIFImport Kind = "sarif-import"
	// KindCustom is a program the user configured through a structured
	// manifest (section 8.6); flag-only by default.
	KindCustom Kind = "custom"
)

// Kinds returns the closed Kind vocabulary.
func Kinds() []Kind {
	return []Kind{KindNative, KindLinked, KindProcess, KindSARIFImport, KindCustom}
}

// Support is a platform cell of the registry row.
type Support string

// The Support values. Unsupported coverage renders "not scanned"
// (principle PR12), never clean.
const (
	SupportSupported   Support = "supported"
	SupportUnsupported Support = "unsupported"
	SupportUntested    Support = "untested"
)

// Platform is one OS and architecture pair, in GOOS/GOARCH spelling.
type Platform struct {
	OS   string
	Arch string
}

// PlatformRow is one platform cell, per extractor where the engine has
// several (the SCALIBR Windows matrix, section 8.4).
type PlatformRow struct {
	Platform Platform
	// Extractor is "" for the whole engine.
	Extractor string
	Support   Support
}

// Offline says whether a driver runs with no network and where its
// database comes from.
type Offline struct {
	// NoNetwork reports the engine runs with no network.
	NoNetwork bool
	// Database names the advisory database source, "" when none.
	Database string
}

// ProcessDecl names a binary a driver may start and the companion files
// whose digests must also match (section 4.4: an Opengrep bundle unpacks
// companion files under its cache directory [JSP-8]).
type ProcessDecl struct {
	Binary     string
	Companions []string
}

// EgressDecl is one host a driver may contact (database download only),
// with its trigger.
type EgressDecl struct {
	Host    string
	Trigger string
}

// ExitMeaning is how a driver reads one exit code (revision 2.4 [JSP-8]).
// Findings are read from the output, never from the exit code.
type ExitMeaning string

// The ExitMeaning values.
const (
	// ExitOK: the run completed; read findings from the output.
	ExitOK ExitMeaning = "ok"
	// ExitFindings: the run completed and reported findings (osv-scanner
	// exit 1), a result, not a failure.
	ExitFindings ExitMeaning = "findings"
	// ExitNothingToScan: the engine found nothing to scan (osv-scanner
	// exit 128); coverage is not_scanned, never clean.
	ExitNothingToScan ExitMeaning = "nothing_to_scan"
	// ExitConfigError: a missing or invalid rule or config file.
	ExitConfigError ExitMeaning = "config_error"
	// ExitCrash: the engine crashed or failed.
	ExitCrash ExitMeaning = "crash"
)

// ExitCode maps one exit code to its meaning.
type ExitCode struct {
	Code    int
	Meaning ExitMeaning
}

// FlagRule is the driver's flag table (revision 2.4 [JSP-8]): defaults are
// never trusted.
type FlagRule struct {
	// Always are flags every run passes (for example --offline,
	// --disable-version-check).
	Always []string
	// Never are flags a run refuses (for example --config auto, which
	// reaches a registry).
	Never []string
}

// DriverRow is the registry data row, one per driver (section 4.4). A
// coverage test checks registry against catalog against config against
// the settings inventory.
type DriverRow struct {
	// ID is the driver id; the component id is "security.scan." + ID for
	// every driver but the native ones.
	ID   string
	Kind Kind
	// ComponentID is the catalog row that owns the driver.
	ComponentID string
	// Categories are the finding categories it can emit.
	Categories []secfinding.Category
	// Triggers are the scopes it supports; pre_write and staged only for
	// native drivers with a measured budget.
	Triggers []secfinding.Scope
	// DiffAware: it can limit itself to changed lines, not only changed
	// files.
	DiffAware bool
	Platforms []PlatformRow
	Offline   Offline
	Processes []ProcessDecl
	Egress    []EgressDecl
	// MinVersion refuses older engines; outside TestedRange is labelled
	// beta; a PinnedDigests mismatch is refused (driver_unverified).
	MinVersion    string
	TestedRange   string
	PinnedDigests []string
	// SemanticAdapter names the per-driver SARIF-to-finding adapter
	// (section 4.5.3).
	SemanticAdapter string
	// ConfigInputs is the explicit config Observer passes; repository-local
	// scanner configs are ignored unless allowed.
	ConfigInputs []string
	Flags        FlagRule
	ExitCodes    []ExitCode
	// Licence is the licence matrix verdict (section 8.7).
	Licence string
}

// Budget caps one run (section 4.4).
type Budget struct {
	Wall time.Duration
	// Nice is the CPU niceness, 0 for the default.
	Nice           int
	MemoryBytes    int64
	MaxFindings    int
	MaxOutputBytes int64
	MaxChildren    int
}

// Target is what one run scans (section 4.4).
type Target struct {
	// ProjectRoot is absolute, resolved by internal/git.
	ProjectRoot string
	// CheckoutRoot is the directory the run reads when it is not
	// ProjectRoot: a linked worktree's own top level (git.FindCheckoutRoot),
	// while findings stay keyed on ProjectRoot, the main repository. Empty
	// means ProjectRoot. A run that reads another checkout than the project
	// proves nothing gone in the project, so it closes nothing.
	CheckoutRoot string
	Scope        secfinding.Scope
	// Paths is a bounded list, diff-scoped where the driver supports it.
	Paths   []string
	BaseRev string
	HeadRev string
	Budget  Budget
}

// Outcome is a run's coverage outcome (revision 2.4 [JSP-12]: "scanned"
// is not "clean").
type Outcome string

// The Outcome values.
const (
	// OutcomeClean: the driver's self-test passed for its current digests
	// and versions, it ran to completion and reported nothing.
	OutcomeClean Outcome = "clean"
	// OutcomeFindings: it ran to completion and reported findings.
	OutcomeFindings Outcome = "findings"
	// OutcomeUnknown: it ran, but the result cannot be trusted as clean
	// (exit 0 with an empty SARIF and no passed self-test, an
	// unknown-marking stderr pattern, a cap reached).
	OutcomeUnknown Outcome = "unknown"
	// OutcomeNotScanned: nothing ran (not installed, unsupported platform,
	// nothing to scan, inactive). Never clean.
	OutcomeNotScanned Outcome = "not_scanned"
	// OutcomeFailed: the engine failed or was refused (driver_unverified).
	OutcomeFailed Outcome = "failed"
)

// Skip records one part of the target that was not scanned and why.
type Skip struct {
	Path   string
	Reason string
}

// Coverage is what was scanned, what was skipped and why (section 4.4).
type Coverage struct {
	Outcome Outcome
	// Reason is a closed reason code when Outcome is not clean or findings
	// (for example "not_installed", "unsupported_platform",
	// "driver_unverified", "budget_exceeded").
	Reason       string
	FilesScanned int
	Skipped      []Skip
	// Scanned names the parts the run checked in full (a dependency
	// driver: the ecosystems). Only a part named here may close an older
	// finding; a part missing from it proves nothing, whatever Skipped says.
	// Empty for a driver that does not report parts.
	Scanned []string `json:",omitempty"`
	// Notes are plain sentences, written by Observer's own code (never
	// engine text), about how the run was made: an engine version outside
	// the tested range, a run that was not isolated and why.
	Notes []string `json:",omitempty"`
	// Truncated reports that MaxFindings or MaxOutputBytes was reached.
	Truncated bool
	// Passes are the extra passes a run made beside its core pass (the
	// Opengrep driver's intrafile taint pass on a full scan), each with its
	// own status. Empty for a driver that makes none.
	Passes []PassStatus `json:",omitempty"`
}

// PassStatus is one extra pass of a run: its name, its status (a closed
// vocabulary the driver owns, for example completed, timed_out, failed or
// skipped) and a closed reason, and counts only: no path, no engine text.
// A pass never changes the core pass's outcome; what it merged is already
// in the run's findings.
type PassStatus struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
	// Batches is how many target batches the pass planned, Merged how many
	// finished with their canary reported and were merged.
	Batches int `json:"batches,omitempty"`
	Merged  int `json:"merged,omitempty"`
	// Targets are the files the pass applies to; Covered those whose
	// results it merged (Cached of them from its cache), Partial those the
	// engine did not read in full.
	Targets int `json:"targets,omitempty"`
	Covered int `json:"covered,omitempty"`
	Cached  int `json:"cached,omitempty"`
	Partial int `json:"partial,omitempty"`
	// BudgetMS is the pass's wall budget and TookMS its time, in ms.
	BudgetMS int64 `json:"budget_ms,omitempty"`
	TookMS   int64 `json:"took_ms,omitempty"`
}

// EngineIdentity names the engine that ran (section 4.4).
type EngineIdentity struct {
	Name    string
	Version string
	// Digest is the sha256 of the binary or module.
	Digest          string
	RulePackVersion string
	DatabaseEpoch   string
}

// Result is one run's answer. Findings are normalized by the driver's
// semantic adapter; never engine types.
type Result struct {
	Findings []secfinding.Finding
	Coverage Coverage
	Engine   EngineIdentity
}

// Probe is a driver's probe ladder answer (section 4.4, 4.11): installed,
// version, verified digest, database age, platform support.
type Probe struct {
	Installed bool
	Version   string
	// Verified reports the binary and companion digests matched.
	Verified bool
	// Beta reports a version outside the tested range.
	Beta     bool
	Platform Support
	// DatabaseAge is the advisory database age; 0 when none.
	DatabaseAge time.Duration
	// Reason is a closed reason code when the driver cannot run.
	Reason string
}

// Driver is one detection engine. Implementations never decide outcomes.
type Driver interface {
	// Row is the registry data row.
	Row() DriverRow
	// Probe answers the probe ladder without scanning.
	Probe(ctx context.Context) Probe
	// Scan runs one bounded scan of t.
	Scan(ctx context.Context, t Target) (Result, error)
}
