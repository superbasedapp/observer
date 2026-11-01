package scalibrfacade

import (
	"errors"
	"net/http"
	"time"
)

// ErrNotCompiled is what every call answers in a build without SCALIBR
// (sbo_omit_security_scan_scalibr). The driver turns it into "not
// scanned", never clean.
var ErrNotCompiled = errors.New("scalibrfacade: OSV-SCALIBR is not compiled into this build")

// ErrNoDatabase is what Match answers when the ecosystem's local database is
// not on disk. The driver turns it into "not scanned" for that ecosystem
// only.
var ErrNoDatabase = errors.New("scalibrfacade: no local OSV database for this ecosystem")

// ExtractorInfo is one row of the facade's closed extractor table, with the
// requirements the extractor itself declares (for the Platforms matrix).
type ExtractorInfo struct {
	// Name is SCALIBR's plugin name.
	Name string
	// Kind is "lockfile" or "manifest".
	Kind string
	// Ecosystem is the OSV ecosystem the extractor feeds.
	Ecosystem string
	// Files lists the file names it claims, for display.
	Files string
	// RequiresOS is the OS the extractor declares ("any" for all of them at
	// v0.5.3).
	RequiresOS string
}

// Package is one inventory row. Path is relative to the scanned root, so no
// local absolute path leaves the facade.
type Package struct {
	Ecosystem string
	Name      string
	Version   string
	Path      string
	Extractor string
	// Local reports that the package is marked as locally developed (an npm
	// workspace member or a file: dependency); osvlocal never matches those.
	Local bool
	// Restored reports that the npm lockfile rule (npmlock.go) passed the
	// entry on as a registry package.
	Restored bool
	// Unpinned reports a requirements line with a range, not one exact
	// version (the extractor's version is the range's lowest bound).
	Unpinned bool
	// LockfileTooLarge reports a LOCAL entry of a package-lock.json the
	// npm lockfile rule could not read (over its size cap).
	LockfileTooLarge bool
}

// Manifest is a dependency manifest found with no lockfile beside or above
// it (Inventory.Unlocked). Path is relative to the scanned root.
type Manifest struct {
	Ecosystem string
	Path      string
}

// Status is one extractor's run status.
type Status struct {
	Extractor string
	OK        bool
	// Detail is SCALIBR's failure reason, "" when OK.
	Detail          string
	FilesWithErrors int
	// Files are the files it failed on, relative to the root, forward
	// slashes, sorted.
	Files []string
}

// Inventory is the result of one extraction pass.
type Inventory struct {
	Packages []Package
	Statuses []Status
	// Unlocked are the manifests found with no lockfile that declare
	// dependencies (a Cargo.toml or a pyproject.toml): not scanned.
	Unlocked []Manifest
	// impl holds SCALIBR's own package values in the linked build, for
	// Match; nil in the omitted build.
	impl any
}

// Canary is the self-test package Match adds to one ecosystem's request: a
// public package with a well-known advisory. A database that does not flag
// it did not load, so the ecosystem is not "clean".
type Canary struct {
	Name    string
	Version string
}

// MatchRequest is one ecosystem's match.
type MatchRequest struct {
	// Ecosystem is the OSV ecosystem name (Package.Ecosystem).
	Ecosystem string
	// Indices are the Inventory.Packages to match; packages of another
	// ecosystem are ignored.
	Indices []int
	// Canary, when set, is matched with the packages; its result is
	// reported in MatchResult.CanaryHit and never as a Vuln.
	Canary *Canary
}

// MatchOptions selects the OSV data source.
type MatchOptions struct {
	// DBDir is the directory that holds osv-scalibr/<Ecosystem>/all.zip
	// (internal/secscan/osvdb owns it). Used when Online is false.
	DBDir string
	// Online asks api.osv.dev instead of the local database.
	Online bool
	// HTTPClient is the egress lane's client for the online path; it is the
	// only client SCALIBR is handed. gRPC and Google clients are refused.
	HTTPClient *http.Client
	// OnlineTimeout bounds the online call (SCALIBR's own retry loop adds
	// about 20 s before it gives up, JSP-9b); 0 means 30 s.
	OnlineTimeout time.Duration
}

// Vuln is one advisory for one package, as SCALIBR's matcher returned it.
// Aliases are not folded here; internal/secscan/depscan groups them.
type Vuln struct {
	ID      string
	Aliases []string
	// Severity is the advisory's database_specific severity label when it
	// carries one (GHSA: LOW, MODERATE, HIGH, CRITICAL), else "".
	Severity string
	// Index is the Inventory.Packages index of the affected package.
	Index int
}

// MatchResult is one ecosystem's answer.
type MatchResult struct {
	Vulns []Vuln
	// CanaryHit reports that the request's canary matched at least one
	// advisory.
	CanaryHit bool
	// Matcher is SCALIBR's enricher name.
	Matcher string
}
