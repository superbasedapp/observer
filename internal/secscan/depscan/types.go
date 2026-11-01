package depscan

// ProtocolVersion is the child protocol's version. A response with another
// version is refused (the daemon and its child are the same binary, so a
// mismatch means a half-applied update).
const ProtocolVersion = 1

// Package is one inventory row, relative to the scanned root.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	// Path is the dependency file the package came from, relative to the
	// project root, forward slashes.
	Path      string `json:"path"`
	Extractor string `json:"extractor,omitempty"`
	// Local: an npm workspace member or a file: dependency.
	Local bool `json:"local,omitempty"`
	// Restored: the npm lockfile rule passed the entry on as a registry
	// package (scalibrfacade/npmlock.go).
	Restored bool `json:"restored,omitempty"`
	// Unpinned: a requirements line with a range, not one exact version
	// (`requests>=2.0`); the extractor's lowest bound is not what installs.
	Unpinned bool `json:"unpinned,omitempty"`
	// LockfileTooLarge: a LOCAL entry of a package-lock.json over the npm
	// lockfile rule's size cap, so the rule could not tell a hoisted
	// registry package from a workspace member.
	LockfileTooLarge bool `json:"lockfile_too_large,omitempty"`
}

// Manifest is a dependency manifest the run found with no lockfile beside
// it or above it (a Cargo.toml or a pyproject.toml that declares
// dependencies): its resolved versions are unknown, so it is not scanned.
type Manifest struct {
	Ecosystem string `json:"ecosystem"`
	// Path is relative to the project root, forward slashes.
	Path string `json:"path"`
}

// Advisory is one advisory id for one package, before alias grouping.
type Advisory struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases,omitempty"`
	// Severity is the advisory's own severity label ("" when none).
	Severity string `json:"severity,omitempty"`
	// Index is the ChildResponse.Packages index of the affected package.
	Index int `json:"index"`
}

// EcoOutcome is one ecosystem's outcome.
type EcoOutcome string

// The EcoOutcome values.
const (
	// EcoScanned: the ecosystem's packages were matched against a database
	// that passed its self-test.
	EcoScanned EcoOutcome = "scanned"
	// EcoNotScanned: nothing trustworthy was matched; never clean.
	EcoNotScanned EcoOutcome = "not_scanned"
)

// The closed EcoResult.Reason vocabulary.
const (
	ReasonNoDatabase     = "database_missing"
	ReasonMatchFailed    = "match_failed"
	ReasonSelfTestFailed = "self_test_failed"
	ReasonNoCanary       = "no_self_test_for_ecosystem"
	ReasonUnsupported    = "unsupported_platform"
	ReasonNotCompiled    = "not_compiled"
	ReasonNotInstalled   = "not_installed"
	ReasonEngineFailed   = "engine_failed"
	// ReasonIsolationRefused: an isolation provider exists on this host but
	// refused the run (a path that overlaps ~/.observer, a provider that
	// could not be built), so the scan child did not start (lane SEC-DEPS3
	// item 5): a refused isolation never falls back to an unisolated run.
	ReasonIsolationRefused = "isolation_refused"
	// ReasonDBNotAccepted: no OSV database is installed and the developer
	// has not given the one-time accept of its download (operator ruling
	// PT-19 (2)), so nothing ran and nothing is claimed clean.
	ReasonDBNotAccepted = "database_not_accepted"
	// The gap reasons (Gap.Reason): a part of the project the run could
	// not check, so the run is partial, never clean.
	ReasonExtractorFailed  = "extractor_failed"
	ReasonUnpinned         = "unpinned_version"
	ReasonLockfileTooLarge = "lockfile_too_large"
	ReasonNoLockfile       = "no_lockfile"
)

// EcoResult is one ecosystem's answer.
type EcoResult struct {
	Ecosystem string     `json:"ecosystem"`
	Outcome   EcoOutcome `json:"outcome"`
	Reason    string     `json:"reason,omitempty"`
	// Packages is how many packages of the ecosystem were matched.
	Packages int `json:"packages"`
	// Epoch is the database epoch the match used ("" online or when not
	// scanned).
	Epoch string `json:"epoch,omitempty"`
	// Withheld counts packages of the ecosystem that were not matched
	// because their names may be private (online matching never sends
	// them); a run with withheld packages is never clean.
	Withheld int `json:"withheld,omitempty"`
	// Gaps counts the parts of the ecosystem the run could not check (Gap
	// rows: a failed dependency file, unpinned or unchecked packages, a
	// manifest with no lockfile); an ecosystem with gaps is never counted
	// as scanned in full. Finalize sets it.
	Gaps       int        `json:"gaps,omitempty"`
	Advisories []Advisory `json:"advisories,omitempty"`
}

// ExtractorStatus is one extractor's run status.
type ExtractorStatus struct {
	Extractor string `json:"extractor"`
	OK        bool   `json:"ok"`
	// Platform is the registry's support cell for this OS ("supported",
	// "untested", "unsupported").
	Platform string `json:"platform,omitempty"`
	// Ecosystem is the ecosystem the extractor feeds ("" when unknown).
	Ecosystem string `json:"ecosystem,omitempty"`
	// Files are the dependency files it failed on, relative to the root,
	// forward slashes (at most MaxFailedFiles).
	Files []string `json:"files,omitempty"`
}

// MaxFailedFiles caps ExtractorStatus.Files.
const MaxFailedFiles = 50

// ChildRequest is what the daemon hands the scan child on stdin.
type ChildRequest struct {
	Version int `json:"version"`
	// Root is the absolute project root.
	Root string `json:"root"`
	// DBDir is the local database directory (osvdb.Store.Dir).
	DBDir string `json:"db_dir"`
	// Epochs are the ecosystems whose database is installed, with the
	// epoch to record; an ecosystem missing here is not matched.
	Epochs map[string]string `json:"epochs"`
	// SkipDirs are absolute directories the walk skips.
	SkipDirs []string `json:"skip_dirs,omitempty"`
	// MaxInodes caps the walk.
	MaxInodes int `json:"max_inodes,omitempty"`
	// GOOS is the platform the Platforms column is read for.
	GOOS string `json:"goos"`
}

// ChildResponse is what the scan child writes on stdout.
type ChildResponse struct {
	Version int `json:"version"`
	// Compiled is false in a build without SCALIBR.
	Compiled bool `json:"compiled"`
	// Error is a plain sentence when the extraction itself failed.
	Error      string            `json:"error,omitempty"`
	Packages   []Package         `json:"packages,omitempty"`
	Extractors []ExtractorStatus `json:"extractors,omitempty"`
	Ecosystems []EcoResult       `json:"ecosystems,omitempty"`
	// Dropped counts the packages each drop rule removed, by rule name.
	Dropped map[string]int `json:"dropped,omitempty"`
	// Unlocked are the manifests found with no lockfile (Manifest).
	Unlocked []Manifest `json:"unlocked,omitempty"`
}
