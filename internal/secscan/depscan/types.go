package depscan

import "github.com/marmutapp/superbased-observer/internal/secreach"

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
	// Unpinned: a declared version that is not one exact version: a
	// requirements line with a range (`requests>=2.0`; the extractor's
	// lowest bound is not what installs), or a NuGet or Gradle version
	// catalog range, floating version or MSBuild property
	// (scalibrfacade/versionshape.go).
	Unpinned bool `json:"unpinned,omitempty"`
	// LockfileTooLarge: a LOCAL entry of a package-lock.json over the npm
	// lockfile rule's size cap, so the rule could not tell a hoisted
	// registry package from a workspace member.
	LockfileTooLarge bool `json:"lockfile_too_large,omitempty"`
	// Line is the 1-based line the package is named on (a workflow's
	// uses: line); 0 when the extractor names no line.
	Line int `json:"line,omitempty"`
	// PinnedBySHA: a GitHub Actions uses: pinned by a full commit SHA with
	// no version comment, so there is no version to match without
	// resolving the SHA (a gap, never clean).
	PinnedBySHA bool `json:"pinned_by_sha,omitempty"`
	// NotAVersion: the ref names a branch or another name, not a version
	// (`@main`); it is not pinned, so it is a gap, never matched.
	NotAVersion bool `json:"not_a_version,omitempty"`
	// MovingTag: the version is a tag with fewer than three numeric
	// components (`@v4`, `@v4.1`), which its owner moves to each release;
	// it is matched as its lowest member, so the version that runs may
	// differ (the finding says so, at medium confidence).
	MovingTag bool `json:"moving_tag,omitempty"`
	// VersionFromComment: the version came from the trailing comment of a
	// SHA pin (`@<sha> # v4.1.0`), which is not verified against the SHA.
	VersionFromComment bool `json:"version_from_comment,omitempty"`
	// Binary is an OS package's binary name when Name is the source (dpkg
	// Source:) or origin (apk o:) name the matcher uses; "" when they are
	// the same (osimage.go).
	Binary string `json:"binary,omitempty"`
	// OtherRelease: an OS package whose distribution release differs from
	// the image's os-release, so the release's database cannot answer for
	// it (a gap, never matched).
	OtherRelease bool `json:"other_release,omitempty"`
	// Artifact: the package was read out of a build artifact (an
	// executable's Go build info or cargo auditable section, a Java
	// archive, a Python wheel or egg; artifacts.go), not a dependency file.
	Artifact bool `json:"artifact,omitempty"`
	// VersionUnknown: an artifact's Go toolchain version that could not be
	// read as a release (a development build, an unparseable string;
	// NormalizeGoVersion). Version is then empty and the package is a gap
	// (ReasonGoVersionUnknown), never matched and never clean.
	VersionUnknown bool `json:"version_unknown,omitempty"`
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
	// The package lookup posture's reasons (OS and CI scanning plan
	// sections 13.9 and 13.10, lane RM-2):
	//
	// ReasonLookupNotChosen: a fresh install where the developer has chosen
	// neither the database download nor the SuperBased lookup (ruling Q8
	// (a)), so nothing ran and nothing is claimed clean.
	ReasonLookupNotChosen = "lookup_not_chosen"
	// ReasonRemoteNotAccepted: the lookup mode is remote (or both, with no
	// local database for the ecosystem) and the developer's remote-lookup
	// consent is not recorded.
	ReasonRemoteNotAccepted = "remote_not_accepted"
	// ReasonRemoteUnavailable: the remote shards could not serve this run
	// (the host unreachable, the signed shard manifest unverifiable, past
	// its age floor, or naming no set for the ecosystem).
	ReasonRemoteUnavailable = "remote_unavailable"
	// ReasonRemoteLookupFailed is a gap reason: the packages whose shard
	// or index file failed to fetch or verify were not matched.
	ReasonRemoteLookupFailed = "remote_lookup_failed"
	// The gap reasons (Gap.Reason): a part of the project the run could
	// not check, so the run is partial, never clean.
	ReasonExtractorFailed  = "extractor_failed"
	ReasonUnpinned         = "unpinned_version"
	ReasonLockfileTooLarge = "lockfile_too_large"
	ReasonNoLockfile       = "no_lockfile"
	// ReasonPinnedBySHA: a GitHub Actions uses: pinned by a commit SHA with
	// no version comment; Observer resolves no SHA (no network lookup).
	ReasonPinnedBySHA = "pinned_by_sha_no_version"
	// ReasonGoVersionUnknown: a Go binary whose toolchain version is a
	// development build or could not be read as a release (goversion.go):
	// its standard library was not matched, so the run is partial.
	ReasonGoVersionUnknown = "go_version_unknown"
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
	// LookupGaps counts packages of the ecosystem a remote lookup could not
	// match because their shard failed to fetch or verify (lane RM-2); the
	// driver turns them into ReasonRemoteLookupFailed gaps
	// (depdriver.ApplyOnline), so the run is partial, never clean.
	LookupGaps int `json:"lookup_gaps,omitempty"`
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
	// Kind is "" for a project scan and KindOSImage for an image's OS
	// packages (osimage.go); Root is then the extracted image root and OS
	// names its release. Additive: the version stays 1.
	Kind string          `json:"kind,omitempty"`
	OS   *OSImageRequest `json:"os,omitempty"`
	// ArtifactDirs are the artifact folders the developer turned on or
	// named for this scan (`observer security scan artifacts enable`,
	// `--artifacts`), relative to Root, forward slashes: an executable is
	// read only under one (artifacts.go). The child adds none. Additive:
	// the version stays 1.
	ArtifactDirs []string `json:"artifact_dirs,omitempty"`
	// ArtifactOff are the discovered candidate folders that are NOT turned
	// on, relative to Root, forward slashes: nothing under one is read,
	// not even a Java archive or a wheel found by name.
	ArtifactOff []string `json:"artifact_off,omitempty"`
	// ReachGo asks the child for the Go symbol check (plan section 14.5
	// item 3b, component security.reach.go): govulncheck's binary mode over
	// each Go binary the artifact extractors read, against the matched
	// records. Additive: the version stays 1; a child built without x/vuln
	// answers nothing for it.
	ReachGo bool `json:"reach_go,omitempty"`
	// Packages are the rows a KindSBOM request matches (security coverage
	// gaps plan item 2): the child extracts nothing and matches these, read
	// by the caller from an SBOM file. Additive: the version stays 1.
	Packages []Package `json:"packages,omitempty"`
	// ScratchDir is a writable directory the daemon prepared for this run
	// (absolute, as the child sees it): the symbol check writes its flat
	// record directory there. Empty: the child uses the system temporary
	// directory.
	ScratchDir string `json:"scratch_dir,omitempty"`
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
	// Kind echoes the request's Kind, so a child that did not understand
	// an image request is refused rather than read as a project scan.
	Kind string `json:"kind,omitempty"`
	// Gaps are gaps the caller already knows (an image entry the layer
	// reader refused); Finalize adds them to the ones it derives.
	Gaps []Gap `json:"gaps,omitempty"`
	// Reach are the Go symbol checks (ChildRequest.ReachGo), one per Go
	// binary, in path order. They rank and label findings only; nothing
	// here changes a finding, the coverage or the outcome. Additive.
	Reach []secreach.SymbolRun `json:"reach,omitempty"`
	// ReachRan reports that the child ran the symbol check step (the
	// request asked and x/vuln is compiled in), so an empty Reach means "no
	// Go binary", not "not checked".
	ReachRan bool `json:"reach_ran,omitempty"`
}
