package extrun

import "strings"

// Engine is a per-engine run profile (roadmap F0-2 follow-ups, JSP-8 "what
// the runner must provide"): how its environment is hardened, where its
// home and cache live, and what its exit codes mean. A consumer (a scanner
// driver) owns its engine rows as data; the runner applies them and never
// branches on an engine name.
type Engine struct {
	// Name is recorded on the run; it selects nothing.
	Name string
	// GitHardening sets the git hardening environment (GitHardeningEnv),
	// for an engine that runs git inside an untrusted repository (Opengrep
	// runs git ls-files): no system or global config, no fsmonitor command,
	// no hooks, no prompts.
	GitHardening bool
	// OwnHome gives the engine its own HOME and XDG_CACHE_HOME inside the
	// request's CacheDir (which is then required), so it never reads the
	// user's dotfiles or writes into the user's cache (Opengrep unpacks
	// 246 MB into $XDG_CACHE_HOME and logs under ~/.opengrep).
	OwnHome bool
	// Locale, when set, becomes LC_ALL (Opengrep exits 2 on a non-UTF-8
	// locale; JSP-8 sets C.UTF-8).
	Locale string
	// ExitCodes says what each exit status means. A status the table does
	// not name is a failure.
	ExitCodes []ExitCodeRow
}

// ExitMeaning is what an engine's exit status says about its output. It is a
// closed vocabulary.
type ExitMeaning string

// The closed exit-meaning vocabulary.
const (
	// ExitUnclassified: the run had no engine, or never exited on its own
	// (refused, not started, killed).
	ExitUnclassified ExitMeaning = ""
	// ExitResult: the engine finished; its findings are in its output (for
	// Opengrep, 0 with or without findings: read the SARIF, never the code).
	ExitResult ExitMeaning = "result"
	// ExitClean: the engine finished and found nothing.
	ExitClean ExitMeaning = "clean"
	// ExitFindings: the engine finished and found something (osv-scanner's
	// 1 is a result, not a failure).
	ExitFindings ExitMeaning = "findings"
	// ExitNoInput: the engine found nothing to scan (osv-scanner's 128).
	// Never "clean": nothing was scanned.
	ExitNoInput ExitMeaning = "no_input"
	// ExitFailure: the engine failed; its output is not a result.
	ExitFailure ExitMeaning = "failure"
)

// ExitCodeRow is one row of an engine's exit-code table.
type ExitCodeRow struct {
	Code    int
	Meaning ExitMeaning
}

// ClassifyExit says what a run's exit status means for engine e. Only a run
// that exited on its own (OutcomeOK or OutcomeExitNonZero) is classified;
// a status the table does not name is a failure.
func ClassifyExit(e *Engine, outcome Outcome, code int) ExitMeaning {
	if e == nil || (outcome != OutcomeOK && outcome != OutcomeExitNonZero) {
		return ExitUnclassified
	}
	for _, row := range e.ExitCodes {
		if row.Code == code {
			return row.Meaning
		}
	}
	return ExitFailure
}

// GitHardeningEnv is the git hardening environment for goos (JSP-8: with a
// repository's core.fsmonitor set, the fsmonitor command RAN through
// Opengrep's git ls-files; these settings stopped it). The null device is
// /dev/null, or NUL on Windows.
func GitHardeningEnv(goos string) []string {
	null := "/dev/null"
	if goos == "windows" {
		null = "NUL"
	}
	return []string{
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + null,
		"GIT_CONFIG_PARAMETERS='core.fsmonitor=false' 'core.hooksPath=" + null + "'",
		"GIT_TERMINAL_PROMPT=0",
		// A repository's git-lfs filter never fetches during a checkout
		// the engine starts (lane SEC-G1 audit finding 3).
		"GIT_LFS_SKIP_SMUDGE=1",
	}
}

// The directories an engine with OwnHome gets inside CacheDir.
const (
	engineHomeDir  = "home"
	engineCacheDir = "xdg-cache"
)

// joinPath joins dir and name with goos's separator.
func joinPath(goos, dir, name string) string {
	sep := "/"
	if goos == "windows" {
		sep = `\`
	}
	return strings.TrimRight(dir, `/\`) + sep + name
}

// dirOf returns the directory of an absolute path, split on both
// separators on Windows.
func dirOf(goos, p string) string {
	cut := "/"
	if goos == "windows" {
		cut = `/\`
	}
	i := strings.LastIndexAny(p, cut)
	switch {
	case i < 0:
		return ""
	case i == 0:
		return p[:1]
	case goos == "windows" && i == 2 && p[1] == ':':
		return p[:3]
	}
	return p[:i]
}

// engineEnv is what an engine adds to the caller's environment: the git
// hardening, the locale and, with OwnHome, HOME and XDG_CACHE_HOME inside
// cacheDir, plus the directories the executor must create first.
func engineEnv(goos string, e *Engine, cacheDir string) (set, mkdirs []string) {
	if e == nil {
		return nil, nil
	}
	if e.GitHardening {
		set = append(set, GitHardeningEnv(goos)...)
	}
	if e.Locale != "" {
		set = append(set, "LC_ALL="+e.Locale)
	}
	if e.OwnHome && cacheDir != "" {
		home := joinPath(goos, cacheDir, engineHomeDir)
		cache := joinPath(goos, cacheDir, engineCacheDir)
		set = append(set, "HOME="+home, "XDG_CACHE_HOME="+cache)
		mkdirs = append(mkdirs, home, cache)
	}
	return set, mkdirs
}

// OpengrepEngine is the measured Opengrep profile (JSP-8): it runs git
// inside the repository, needs a UTF-8 locale, unpacks into its cache; 0
// means "read the SARIF" with or without findings (1 only with --error),
// 2 is a crash and 7 a missing or invalid rule file.
var OpengrepEngine = Engine{
	Name:         "opengrep",
	GitHardening: true,
	OwnHome:      true,
	Locale:       "C.UTF-8",
	ExitCodes: []ExitCodeRow{
		{0, ExitResult},
		{1, ExitFindings},
		{2, ExitFailure},
		{7, ExitFailure},
	},
}

// OSVScannerEngine is the measured osv-scanner profile (JSP-8): 0 clean,
// 1 vulnerabilities found (a result, not a failure), 128 no packages found,
// 127 every error.
var OSVScannerEngine = Engine{
	Name:    "osv-scanner",
	OwnHome: true,
	ExitCodes: []ExitCodeRow{
		{0, ExitClean},
		{1, ExitFindings},
		{128, ExitNoInput},
		{127, ExitFailure},
	},
}
