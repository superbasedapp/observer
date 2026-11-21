package osvscanner

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
)

func sourceInput() SourceInput {
	return SourceInput{
		Bin: "/opt/osv/osv-scanner", GoBin: "/opt/go/bin/go", GoRoot: "/opt/go",
		Root: "/src/app", GoMod: "/src/app/tools/go.mod",
		DBDir: "/run/r1/db", ConfigFile: "/run/r1/etc/observer-osv-scanner.toml",
		CacheDir: "/run/r1/cache", ModCache: "/opt/gomod",
		PathDirs:    []string{"/usr/bin", "/bin"},
		MemoryBytes: 12288 << 20, Wall: 20 * time.Minute,
	}
}

// TestSourceRequest: one go.mod per run with Go call analysis, offline,
// the plan's environment, the run's own caches and the developer's caps.
func TestSourceRequest(t *testing.T) {
	req := SourceRequest(sourceInput())
	for _, f := range []string{"--offline", "--call-analysis=go", "-L", "/src/app/tools/go.mod", "--config", "/run/r1/etc/observer-osv-scanner.toml"} {
		if !slices.Contains(req.Args, f) {
			t.Errorf("args %v lack %q", req.Args, f)
		}
	}
	for _, never := range depscan.OSVScannerSourceFlags.Never {
		if slices.Contains(req.Args, never) {
			t.Errorf("args carry %q", never)
		}
	}
	// The scan driver's flag table keeps call analysis off.
	if !slices.Contains(depscan.OSVScannerFlags.Always, "--no-call-analysis=all") || slices.Contains(depscan.OSVScannerFlags.Always, "--call-analysis=go") {
		t.Errorf("the scan driver's flags changed: %v", depscan.OSVScannerFlags.Always)
	}
	env := strings.Join(req.Env.Set, "\n") + "\n"
	for _, want := range []string{
		"GOTOOLCHAIN=local\n", "GOPROXY=off\n", "GOFLAGS=-mod=readonly\n", "GOWORK=off\n", "GOENV=off\n", "GOSUMDB=off\n",
		"GOROOT=/opt/go\n", "GOMODCACHE=/opt/gomod\n", "GOCACHE=/run/r1/cache/gocache\n", "GOPATH=/run/r1/cache/gopath\n",
		"XDG_CONFIG_HOME=/run/r1/cache/config\n", "TMPDIR=/run/r1/cache/tmp\n", "GOMEMLIMIT=11059MiB\n",
		"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/run/r1/db\n",
	} {
		if !strings.Contains(env, want) {
			t.Errorf("environment lacks %q:\n%s", want, env)
		}
	}
	if want := []string{"/opt/go/bin", "/usr/bin", "/bin"}; !slices.Equal(req.Env.PathDirs, want) {
		t.Errorf("PATH dirs %v, want %v", req.Env.PathDirs, want)
	}
	if req.Component != SourceComponent || req.Dir != "/src/app" || req.CacheDir != "/run/r1/cache" || !req.Engine.OwnHome {
		t.Errorf("request %+v", req)
	}
	if req.Limits.MemoryBytes != 12288<<20 || req.Limits.Wall != 20*time.Minute || req.Limits.Children != SourceChildren {
		t.Errorf("limits %+v", req.Limits)
	}
	if len(req.Program.CompanionExecs) != 1 || req.Program.CompanionExecs[0].Path != "/opt/go/bin/go" {
		t.Errorf("the toolchain is not a hashed companion: %+v", req.Program)
	}
	if got := extrun.ClassifyExit(req.Engine, extrun.OutcomeExitNonZero, 1); got != extrun.ExitFindings {
		t.Errorf("exit 1 = %q", got)
	}
}

func TestGoMemLimit(t *testing.T) {
	for _, tc := range []struct {
		cap  int64
		want string
	}{{12288 << 20, "11059MiB"}, {10240 << 20, "9216MiB"}, {512 << 20, "460MiB"}} {
		if got := GoMemLimit(tc.cap); got != tc.want {
			t.Errorf("GoMemLimit(%d) = %q, want %q", tc.cap, got, tc.want)
		}
	}
}
