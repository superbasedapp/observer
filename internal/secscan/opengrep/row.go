package opengrep

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secengine"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// The driver's ids.
const (
	// DriverID is the registry id and the findings' driver name.
	DriverID = "opengrep"
	// ComponentID is the catalog row that owns the driver.
	ComponentID = "security.scan.opengrep"
)

// Spec is how Opengrep is found: a separately installed binary, never a
// shim (the runner's resolver excludes the command-wrapping shims), never a
// bare PATH lookup by the runner.
var Spec = integration.BinaryResolveSpec{
	Names: integration.BinaryNames{Unix: []string{"opengrep"}, Windows: []string{"opengrep.exe"}},
}

// GitSpec is the git Opengrep runs (git ls-files in a full scan, the
// baseline in a diff scope); its directory is the only one on Opengrep's
// PATH.
var GitSpec = integration.BinaryResolveSpec{
	Names: integration.BinaryNames{Unix: []string{"git"}, Windows: []string{"git.exe"}},
}

// Jobs bounds -j. The children cap scales with it (JSP-8: 33 opengrep-core
// processes plus the git calls at -j 4).
const (
	DefaultJobs = 4
	MaxJobs     = 8
)

// ClampJobs returns jobs within 1 and MaxJobs; 0 is DefaultJobs.
func ClampJobs(jobs int) int {
	switch {
	case jobs <= 0:
		return DefaultJobs
	case jobs > MaxJobs:
		return MaxJobs
	}
	return jobs
}

// Mode is how much of the project a run reads.
type Mode string

// The Mode values.
const (
	// ModeFull scans every file under the project root but the excluded
	// directories, with the canary as a second target.
	ModeFull Mode = "full"
	// ModeDiff scans only what changed since a base commit
	// (--baseline-commit): results present at the base are not reported.
	ModeDiff Mode = "diff"
	// ModeSelfTest scans only the canary.
	ModeSelfTest Mode = "self_test"
	// ModeFiles scans a bounded list of project files (the post-write
	// trigger, lane SEC-G2) with the canary as one more target, so the
	// files it read in full can close findings like a full scan's.
	ModeFiles Mode = "files"
)

// MaxFiles bounds a files-mode run's targets.
const MaxFiles = 200

// The reasons a target is refused before anything runs.
const (
	// ReasonBadPaths: a files-mode target named no file, too many, or a
	// path that is absolute, has a ".." element or reads as a flag.
	ReasonBadPaths = "bad_target_paths"
)

// modeRows is the ordered table that turns a target into a mode (CLAUDE.md
// module rule 5): a diff-capable scope with a base is a diff run, a
// post-write target with paths a files run, anything else a full scan.
var modeRows = []struct {
	when func(secscan.Target) bool
	mode Mode
}{
	{func(t secscan.Target) bool { return t.Scope == policy.FindingScopeDiff }, ModeDiff},
	{func(t secscan.Target) bool { return t.Scope == policy.FindingScopeCommit && t.BaseRev != "" }, ModeDiff},
	{func(t secscan.Target) bool { return t.Scope == policy.FindingScopePostWrite }, ModeFiles},
}

// ModeFor returns a target's mode, or a refusal reason when the target
// cannot run in it (a bad diff base, bad or missing paths).
func ModeFor(t secscan.Target) (Mode, string) {
	mode := ModeFull
	for _, r := range modeRows {
		if r.when(t) {
			mode = r.mode
			break
		}
	}
	switch {
	case mode == ModeDiff && !ValidBase(t.BaseRev):
		return mode, ReasonBadBase
	case mode == ModeFiles && !ValidPaths(t.Paths):
		return mode, ReasonBadPaths
	}
	return mode, ""
}

// ValidPaths reports whether a files-mode path list is usable: one to
// MaxFiles relative, forward-slash paths with no "." or ".." element, none
// starting with "-".
func ValidPaths(paths []string) bool {
	if len(paths) == 0 || len(paths) > MaxFiles {
		return false
	}
	for _, p := range paths {
		if !secengine.ValidTreePath(p) || strings.HasPrefix(p, "-") || strings.ContainsAny(p, "\x00\n") {
			return false
		}
	}
	return true
}

// carriesCanary reports whether a mode's run carries the canary itself.
func carriesCanary(m Mode) bool { return m == ModeFull || m == ModeFiles }

// LimitsFor returns the caps of a run (JSP-8: 1.3 GB and 305 s measured for
// a full scan of this repository, 13 s and 79 s for one and twenty commit
// diffs; 13.7 MB of SARIF).
func LimitsFor(mode Mode, jobs int) extrun.Limits {
	jobs = ClampJobs(jobs)
	wall := 600 * time.Second
	switch mode {
	case ModeFiles:
		wall = 120 * time.Second
	case ModeDiff, ModeSelfTest:
		wall = 60 * time.Second
	}
	children := 16 * jobs
	if children < 64 {
		children = 64
	}
	return extrun.Limits{
		Wall:        wall,
		StdoutBytes: 32 << 20,
		StderrBytes: 4 << 20,
		MemoryBytes: 2 << 30,
		Children:    children,
	}
}

// FlagsAlways are passed on every run; FlagsNever are refused (section 4.4
// flag table).
var (
	FlagsAlways = []string{
		"--disable-version-check", "--sarif", "--no-rewrite-rule-ids", "--disable-nosem",
		"--x-ignore-semgrepignore-files", "--timeout", "10", "--max-target-bytes", "1000000",
	}
	FlagsNever = []string{"--config auto", "--enable-version-check", "--error", "--test"}
)

// FullExcludes are the directories a full scan skips (dependency trees,
// virtual environments, git itself). --exclude-minified-files is listed by
// `opengrep scan --help` at v1.30.1 but refused as "No such option", so it
// is not passed.
var FullExcludes = []string{
	"--exclude", ".git", "--exclude", "node_modules", "--exclude", ".venv", "--exclude", "venv",
	"--exclude", "__pycache__",
}

// exitCodes is the driver's exit table (JSP-8, at v1.30.1): 0 a result with
// or without findings, 2 a crash, 7 a missing or invalid rule file. 1 comes
// only with --error, which the driver never passes.
var exitCodes = []secscan.ExitCode{
	{Code: 0, Meaning: secscan.ExitOK},
	{Code: 2, Meaning: secscan.ExitCrash},
	{Code: 7, Meaning: secscan.ExitConfigError},
}

// Row is the registry row.
func Row() secscan.DriverRow {
	return secscan.DriverRow{
		ID: DriverID, Kind: secscan.KindProcess, ComponentID: ComponentID,
		Categories: []secfinding.Category{policy.FindingCodeVuln},
		Triggers:   []secfinding.Scope{policy.FindingScopeManual, policy.FindingScopeScheduled, policy.FindingScopeCommit, policy.FindingScopeDiff},
		DiffAware:  true,
		Platforms: []secscan.PlatformRow{
			{Platform: secscan.Platform{OS: "linux", Arch: "amd64"}, Support: secscan.SupportSupported},
			{Platform: secscan.Platform{OS: "linux", Arch: "arm64"}, Support: secscan.SupportUntested},
			{Platform: secscan.Platform{OS: "darwin", Arch: "arm64"}, Support: secscan.SupportUntested},
			{Platform: secscan.Platform{OS: "darwin", Arch: "amd64"}, Support: secscan.SupportUntested},
			{Platform: secscan.Platform{OS: "windows", Arch: "amd64"}, Support: secscan.SupportUntested},
		},
		Offline: secscan.Offline{NoNetwork: true},
		Processes: []secscan.ProcessDecl{
			{Binary: "opengrep", Companions: []string{"the files its self-extracting bundle unpacks into <engine cache>/xdg-cache/opengrep/v<version>"}},
			{Binary: "git"},
		},
		MinVersion: secengine.MinVersion, TestedRange: "=" + secengine.TestedVersion,
		PinnedDigests:   pinnedDigests(),
		SemanticAdapter: "opengrep",
		ConfigInputs: []string{
			"the observer-code rule pack's rules directory (--config, the only one)",
			"Observer's own targets and excludes; a repository's .semgrepignore and nosem comments are ignored",
		},
		Flags:     secscan.FlagRule{Always: FlagsAlways, Never: FlagsNever},
		ExitCodes: exitCodes,
		Licence:   "LGPL-2.1 (engine), run only as a separately installed process; never bundled or linked",
	}
}

func pinnedDigests() []string {
	var out []string
	for _, p := range secengine.CompiledPins() {
		if p.SHA256 != "" {
			out = append(out, p.SHA256)
		}
	}
	return out
}

// versionPattern reads `1.30.1` from `opengrep --version`.
var versionPattern = regexp.MustCompile(`(?m)^\s*v?(\d+\.\d+\.\d+)\s*$`)

// baseCommit is what a diff base must look like: a commit id (the CLI
// resolves a ref to one first), so it can never read as a flag.
var baseCommit = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

// ValidBase reports whether base is a usable commit id.
func ValidBase(base string) bool { return baseCommit.MatchString(base) }

// Args returns the argument list of a run. rulesDir and canary are
// absolute; jsonOut is the JSON copy's absolute path; base is the diff
// base (ModeDiff only).
func Args(mode Mode, rulesDir, canary, jsonOut, base string, jobs int) []string {
	return ArgsFor(mode, rulesDir, canary, jsonOut, base, nil, jobs)
}

// ArgsFor is Args with a files-mode target list (each passed as "./path",
// so none can read as a flag, followed by the canary).
func ArgsFor(mode Mode, rulesDir, canary, jsonOut, base string, paths []string, jobs int) []string {
	args := append([]string{"scan"}, FlagsAlways...)
	args = append(args, "-j", strconv.Itoa(ClampJobs(jobs)), "--config", rulesDir, "--json-output="+jsonOut)
	switch mode {
	case ModeDiff:
		return append(args, "--baseline-commit", base, ".")
	case ModeSelfTest:
		return append(append(args, "--no-git-ignore"), canary)
	case ModeFiles:
		args = append(append(args, "--no-git-ignore"), FullExcludes...)
		for _, p := range paths {
			args = append(args, "./"+p)
		}
		return append(args, canary)
	}
	args = append(append(args, "--no-git-ignore"), FullExcludes...)
	return append(args, ".", canary)
}

// notRunReasons are the closed reasons of a failed run that stopped before
// the engine scanned anything: no engine or git, no pack, a bad target, a
// refused engine, an isolation or runner refusal before the start, a
// repository whose git config names a filter driver. A crash, a budget
// cut, a rule config error, unreadable output or a cancel came after the
// engine started, so those runs did execute (lane SEC-G2 audit finding 4).
var notRunReasons = map[string]bool{
	ReasonNotInstalled:         true,
	ReasonNoGit:                true,
	ReasonNoPack:               true,
	ReasonBadBase:              true,
	ReasonBadPaths:             true,
	ReasonIsolation:            true,
	ReasonRunner:               true,
	ReasonGitFilter:            true,
	ReasonGitConfig:            true,
	secengine.ReasonUnverified: true,
}

// EngineRan reports whether a run's coverage is a scan: not when nothing
// ran (not_scanned) or when it failed for one of notRunReasons. A run that
// did not run is still recorded (its time keeps a schedule), but it is not
// a scan (store.SecRunReasonNotRun).
func EngineRan(c secscan.Coverage) bool {
	switch c.Outcome {
	case secscan.OutcomeNotScanned:
		return false
	case secscan.OutcomeFailed:
		return !notRunReasons[c.Reason]
	}
	return true
}
