package osvscanner

import (
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
)

// source.go is the runner request of the Go source check, 3b-src (OS and CI
// vulnerability scanning plan section 14.5 item 3b, spike RG-0 "Answer" item
// 2): osv-scanner with Go call analysis over ONE go.mod (-L), offline,
// which runs govulncheck in process and, through `go list`, the project's
// own Go toolchain (and cgo and the C compiler for a cgo package). The
// request is all data; the cmd layer resolves the paths, prepares the run
// directories, wraps it in the isolation component's no-network run and
// reads the result (internal/secreachgo). The scan driver's flag table
// (OSVScannerFlags, --no-call-analysis=all) is untouched: only this request
// uses depscan.OSVScannerSourceFlags.

// SourceComponent owns the source check's runs (the process belongs to the
// Go reachability component, not to the osv-scanner scan driver).
const SourceComponent = "security.reach.go"

// SourceChildren caps the run's tasks: go list runs the compiler, cgo and
// the C compiler in parallel, each a Go or C process with threads.
const SourceChildren = 512

// sourceEngine is osv-scanner's run profile for the source check: its own
// HOME (and with it the go command's telemetry directory), a UTF-8 locale
// and the exit-code table. With call analysis on, 1 is "a called
// vulnerability" and 0 "nothing called"; both are results.
var sourceEngine = extrun.Engine{
	Name: "osv-scanner (Go call analysis)", OwnHome: true, Locale: "C.UTF-8",
	ExitCodes: []extrun.ExitCodeRow{
		{Code: 0, Meaning: extrun.ExitClean},
		{Code: 1, Meaning: extrun.ExitFindings},
		{Code: 128, Meaning: extrun.ExitNoInput},
		{Code: 127, Meaning: extrun.ExitFailure},
	},
}

// SourceInput is one go.mod run.
type SourceInput struct {
	// Bin is the resolved osv-scanner, GoBin the Go toolchain's go and
	// GoRoot its GOROOT (all absolute, resolved through links).
	Bin, GoBin, GoRoot string
	// Root is the project (the run's directory) and GoMod the absolute
	// path of the go.mod under it.
	Root, GoMod string
	// DBDir holds the Go export as <DBDir>/osv-scalibr/Go/all.zip, what
	// osv-scanner v2.6 reads under OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY;
	// ConfigFile is Observer's empty
	// osv-scanner config, so a repository's osv-scanner.toml is ignored.
	DBDir, ConfigFile string
	// CacheDir is the run's own writable directory: HOME, GOCACHE, GOPATH,
	// the telemetry directory (XDG_CONFIG_HOME) and TMPDIR live in it. The
	// caller creates its subdirectories (SourceCacheDirs).
	CacheDir string
	// ModCache is the developer's module cache, read only (GOMODCACHE).
	ModCache string
	// PathDirs follow GoRoot/bin on PATH (the C compiler's directories).
	PathDirs []string
	// MemoryBytes and Wall are the developer's caps.
	MemoryBytes int64
	Wall        time.Duration
	// Sep is the path separator of the target OS.
	Sep string
}

// SourceCacheDirs are the subdirectories of CacheDir the caller creates
// before the run.
var SourceCacheDirs = []string{"gocache", "gopath", "config", "tmp"}

// SourceArgs is the argument list of one go.mod run.
func SourceArgs(gomod, configFile string) []string {
	args := append([]string(nil), depscan.OSVScannerSourceFlags.Always...)
	return append(args, "--config", configFile, "-L", gomod)
}

// GoMemLimit is the GOMEMLIMIT of a run capped at memoryBytes: 90 % of the
// cap (RG-0 G3: most of the peak is collector headroom; the limit let a
// 9.8 GiB run fit where 12 GiB without it was killed), in MiB.
func GoMemLimit(memoryBytes int64) string {
	return fmt.Sprintf("%dMiB", (memoryBytes/10*9)>>20)
}

// SourceEnv is the run's environment beyond the engine's own HOME and
// locale: the plan's environment (GOTOOLCHAIN=local, GOPROXY=off,
// GOFLAGS=-mod=readonly, GOWORK=off), the user's go env file and the
// checksum database off, the run's own caches and telemetry directory, and
// GOMEMLIMIT.
func SourceEnv(in SourceInput) []string {
	sep := in.Sep
	if sep == "" {
		sep = "/"
	}
	c := in.CacheDir + sep
	return []string{
		"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=" + in.DBDir,
		"GOTOOLCHAIN=local",
		"GOPROXY=off",
		"GOFLAGS=-mod=readonly",
		"GOWORK=off",
		"GOENV=off",
		"GOSUMDB=off",
		"GOROOT=" + in.GoRoot,
		"GOMODCACHE=" + in.ModCache,
		"GOCACHE=" + c + "gocache",
		"GOPATH=" + c + "gopath",
		"XDG_CONFIG_HOME=" + c + "config",
		"TMPDIR=" + c + "tmp",
		"GOMEMLIMIT=" + GoMemLimit(in.MemoryBytes),
	}
}

// SourceRequest is the runner request of one go.mod run.
func SourceRequest(in SourceInput) extrun.Request {
	e := sourceEngine
	sep := in.Sep
	if sep == "" {
		sep = "/"
	}
	return extrun.Request{
		Component: SourceComponent,
		Program: extrun.Program{
			Path:           in.Bin,
			CompanionExecs: []extrun.CompanionExec{{Path: in.GoBin}},
		},
		Args: SourceArgs(in.GoMod, in.ConfigFile),
		Env: extrun.EnvSpec{
			Set:      SourceEnv(in),
			PathDirs: append([]string{in.GoRoot + sep + "bin"}, in.PathDirs...),
		},
		Dir: in.Root,
		Limits: extrun.Limits{
			Wall:        in.Wall,
			StdoutBytes: 64 << 20,
			StderrBytes: 4 << 20,
			MemoryBytes: in.MemoryBytes,
			Children:    SourceChildren,
		},
		CacheDir: in.CacheDir,
		Engine:   &e,
	}
}
