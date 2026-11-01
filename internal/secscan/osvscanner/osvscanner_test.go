package osvscanner

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/extrun/extruntest"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

const (
	root   = "/home/u/src/p"
	canary = "/home/u/.observer/security/osv-canary"
	bin    = "/usr/local/bin/osv-scanner"
)

func allEpochs() map[string]string {
	m := map[string]string{}
	for _, e := range depscan.Ecosystems() {
		m[e] = "epoch-" + e
	}
	return m
}

func fixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "osv-scanner-2.6.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestParseRealOutput reads an osv-scanner v2.6.0 run over the facade's
// fixture project plus the canary project (captured 2026-10-21, paths
// rewritten, advisory bodies trimmed to ids).
func TestParseRealOutput(t *testing.T) {
	resp, err := Parse(fixture(t), root, canary, allEpochs())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]depscan.EcoResult{}
	for _, e := range resp.Ecosystems {
		got[e.Ecosystem] = e
	}
	for _, eco := range []string{"npm", "PyPI", "Go"} {
		if got[eco].Outcome != depscan.EcoScanned || got[eco].Epoch != "epoch-"+eco {
			t.Errorf("%s %+v: its canary came back flagged, so it is scanned", eco, got[eco])
		}
	}
	for _, p := range resp.Packages {
		if strings.HasPrefix(p.Path, "/") || strings.Contains(p.Path, "osv-canary") || p.Path == "" {
			t.Fatalf("package path %q: only project-relative paths, never the canary or another root", p.Path)
		}
	}
	names := map[string]bool{}
	for _, e := range resp.Ecosystems {
		for _, a := range e.Advisories {
			names[resp.Packages[a.Index].Name] = true
		}
	}
	for _, want := range []string{"lodash", "@babel/core", "requests", "golang.org/x/text"} {
		if !names[want] {
			t.Errorf("%s not flagged: %v", want, names)
		}
	}
}

func TestParseMissingCanaryIsNotScanned(t *testing.T) {
	out := []byte(`{"results":[{"source":{"path":"` + root + `/requirements.txt"},"packages":[{"package":{"name":"requests","version":"2.19.0","ecosystem":"PyPI"},"groups":[{"ids":["PYSEC-2018-28"],"max_severity":"7.5"}]}]}]}`)
	resp, err := Parse(out, root, canary, allEpochs())
	if err != nil {
		t.Fatal(err)
	}
	if e := resp.Ecosystems[0]; e.Outcome != depscan.EcoNotScanned || e.Reason != depscan.ReasonSelfTestFailed || len(e.Advisories) != 0 {
		t.Fatalf("%+v: no canary result means the database is not trusted", e)
	}
}

func TestSeverityBand(t *testing.T) {
	for in, want := range map[string]string{"9.8": "critical", "7.5": "high", "5.3": "medium", "3.2": "low", "": "", "x": "", "0": ""} {
		if got := severityBand(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func runnerWith(ex *extruntest.Executor, found bool) *extrun.Runner {
	files := extruntest.Files{}
	if found {
		files[bin] = extruntest.File{}
	}
	r := extruntest.NewRunner("linux", files, ex, map[string]string{"PATH": "/usr/bin", "HOME": "/home/u"})
	r.Resolve = func(integration.BinaryResolveSpec) toolresolve.Resolution {
		if !found {
			return toolresolve.Resolution{Verdict: toolresolve.VerdictNotFound}
		}
		return toolresolve.Resolution{Verdict: toolresolve.VerdictOK, Bin: bin}
	}
	return r
}

func newDriver(r *extrun.Runner, epochs map[string]string) *Driver {
	return New(Env{Runner: r, DBDir: "/home/u/.observer/security/osv", Epochs: epochs, CanaryDir: canary, HomeDir: "/home/u/.observer/security/osv-scanner-home", GOOS: "linux", GOARCH: "amd64"})
}

// TestNotInstalledStartsNothing: no osv-scanner, no process, "not
// scanned", never clean (D-766, PR12).
func TestNotInstalledStartsNothing(t *testing.T) {
	ex := &extruntest.Executor{}
	d := newDriver(runnerWith(ex, false), allEpochs())
	res, err := d.Scan(context.Background(), secscan.Target{ProjectRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(ex.Calls()) != 0 {
		t.Fatalf("started %d processes with no osv-scanner installed", len(ex.Calls()))
	}
	if res.Coverage.Outcome != secscan.OutcomeNotScanned || res.Coverage.Reason != depscan.ReasonNotInstalled {
		t.Fatalf("coverage %+v", res.Coverage)
	}
	if p := d.Probe(context.Background()); p.Installed || p.Reason != depscan.ReasonNotInstalled {
		t.Fatalf("probe %+v", p)
	}
}

func TestMissingDatabaseStartsNothing(t *testing.T) {
	ex := &extruntest.Executor{}
	eps := allEpochs()
	delete(eps, "PyPI")
	res, _ := newDriver(runnerWith(ex, true), eps).Scan(context.Background(), secscan.Target{ProjectRoot: root})
	if len(ex.Calls()) != 0 || res.Coverage.Reason != depscan.ReasonNoDatabase || res.Coverage.Outcome != secscan.OutcomeNotScanned {
		t.Fatalf("calls %d coverage %+v: osv-scanner fails the whole run on a missing database, so it must not start", len(ex.Calls()), res.Coverage)
	}
}

// TestExitCodes maps JSP-8's exit-code table.
func TestExitCodes(t *testing.T) {
	out := fixture(t)
	cases := []struct {
		code    int
		outcome secscan.Outcome
		reason  string
	}{
		{1, secscan.OutcomeFindings, ""},
		{0, secscan.OutcomeFindings, ""}, // the output, never the code, says what was found
		{128, secscan.OutcomeNotScanned, "no_packages"},
		{127, secscan.OutcomeFailed, depscan.ReasonEngineFailed},
		{2, secscan.OutcomeFailed, depscan.ReasonEngineFailed},
	}
	for _, c := range cases {
		ex := &extruntest.Executor{Facts: func(p extrun.Plan) extrun.ExecFacts {
			if slices.Contains(p.Args, "--version") {
				return extrun.ExecFacts{Stdout: []byte("osv-scanner version: 2.6.0\nosv-scalibr version: 0.5.2\n"), PeakChildren: -1}
			}
			return extrun.ExecFacts{ExitCode: c.code, Stdout: out, PeakChildren: -1}
		}}
		res, err := newDriver(runnerWith(ex, true), allEpochs()).Scan(context.Background(), secscan.Target{ProjectRoot: root})
		if err != nil {
			t.Fatal(err)
		}
		if res.Coverage.Outcome != c.outcome || res.Coverage.Reason != c.reason {
			t.Errorf("exit %d: coverage %+v, want %s/%s", c.code, res.Coverage, c.outcome, c.reason)
		}
	}
}

// TestRunFlagsAndEnvironment pins the flags (offline, no call analysis,
// Observer's own config), the minimal environment and the caps.
func TestRunFlagsAndEnvironment(t *testing.T) {
	ex := &extruntest.Executor{Facts: func(p extrun.Plan) extrun.ExecFacts {
		if slices.Contains(p.Args, "--version") {
			return extrun.ExecFacts{Stdout: []byte("osv-scanner version: 2.6.0\n"), PeakChildren: -1}
		}
		return extrun.ExecFacts{ExitCode: 0, Stdout: []byte(`{"results":[]}`), PeakChildren: -1}
	}}
	_, _ = newDriver(runnerWith(ex, true), allEpochs()).Scan(context.Background(), secscan.Target{ProjectRoot: root})
	calls := ex.Calls()
	if len(calls) != 2 {
		t.Fatalf("want the version probe and the scan, got %d plans", len(calls))
	}
	p := calls[1]
	for _, f := range []string{"--offline", "--no-call-analysis=all", "--format", "json", "--all-packages", "--config", canary + "/" + ConfigFile, root, canary} {
		if !slices.Contains(p.Args, f) {
			t.Errorf("args %v lack %q", p.Args, f)
		}
	}
	for _, never := range depscan.OSVScannerFlags.Never {
		if slices.Contains(p.Args, never) {
			t.Errorf("args carry %q", never)
		}
	}
	env := strings.Join(p.Env, "\n")
	for _, bad := range []string{"PATH=", "HOME=/home/u\n"} {
		if strings.Contains(env+"\n", bad) {
			t.Errorf("environment %v carries %q", p.Env, bad)
		}
	}
	if !strings.Contains(env, "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/home/u/.observer/security/osv") || !strings.Contains(env, "LC_ALL=C.UTF-8") {
		t.Errorf("environment %v", p.Env)
	}
	if p.Component != depscan.OSVComponent || p.Limits.MemoryBytes != Limits.MemoryBytes {
		t.Errorf("plan %+v", p)
	}
}

func TestTooOldVersionIsRefused(t *testing.T) {
	ex := &extruntest.Executor{Facts: func(p extrun.Plan) extrun.ExecFacts {
		return extrun.ExecFacts{Stdout: []byte("osv-scanner version: 1.9.2\n"), PeakChildren: -1}
	}}
	res, _ := newDriver(runnerWith(ex, true), allEpochs()).Scan(context.Background(), secscan.Target{ProjectRoot: root})
	if res.Coverage.Outcome != secscan.OutcomeFailed || res.Coverage.Reason != "driver_unverified" || len(ex.Calls()) != 1 {
		t.Fatalf("coverage %+v calls %d: below the minimum version only the version probe runs", res.Coverage, len(ex.Calls()))
	}
}

// TestVersionVerdict pins milestone 2b of lane SEC-D2B: the tested range
// is enforced at its floor and labelled above its ceiling.
func TestVersionVerdict(t *testing.T) {
	cases := []struct {
		v    string
		want VersionVerdict
	}{
		{"", VersionRefused},
		{"garbage", VersionRefused},
		{"2.6", VersionRefused},
		{"1.9.2", VersionRefused},
		{"2.5.99", VersionRefused},
		{"2.6.0", VersionTested},
		{"v2.6.3", VersionTested},
		{"2.6.10", VersionTested},
		{"2.7.0", VersionUntested},
		{"3.0.0", VersionUntested},
	}
	for _, c := range cases {
		if got := Verdict(c.v); got != c.want {
			t.Errorf("Verdict(%q) = %s, want %s", c.v, got, c.want)
		}
	}
}

// TestUntestedVersionRunsLabelled: a newer osv-scanner runs, and the run
// carries the untested-version note.
func TestUntestedVersionRunsLabelled(t *testing.T) {
	ex := &extruntest.Executor{Facts: func(p extrun.Plan) extrun.ExecFacts {
		if slices.Contains(p.Args, "--version") {
			return extrun.ExecFacts{Stdout: []byte("osv-scanner version: 2.8.1\n"), PeakChildren: -1}
		}
		return extrun.ExecFacts{ExitCode: 0, Stdout: []byte(`{"results":[]}`), PeakChildren: -1}
	}}
	res, _ := newDriver(runnerWith(ex, true), allEpochs()).Scan(context.Background(), secscan.Target{ProjectRoot: root})
	if len(ex.Calls()) != 2 {
		t.Fatalf("an untested newer version still runs: %d plans", len(ex.Calls()))
	}
	if len(res.Coverage.Notes) != 1 || !strings.HasPrefix(res.Coverage.Notes[0], depscan.UntestedVersionPrefix) {
		t.Fatalf("notes %v", res.Coverage.Notes)
	}
	if strings.Contains(res.Coverage.Notes[0], "2.8.1") {
		t.Errorf("note %q: notes are fixed sentences, never engine text (SEC-DEPS3 item 6)", res.Coverage.Notes[0])
	}
	if res.Engine.Version != "2.8.1" {
		t.Fatalf("engine %+v", res.Engine)
	}
}

// TestExtractionFailuresAreGaps is lane SEC-DEPS3 item 4 (P-030, the
// P-027 rule on the second driver): a lockfile osv-scanner reports it could
// not read is an extractor failure of its ecosystem; an error it names no
// placeable file for fails every ecosystem; a canary file is left to the
// canary rule.
func TestExtractionFailuresAreGaps(t *testing.T) {
	cases := []struct {
		name      string
		stderr    string
		truncated bool
		want      map[string][]string // ecosystem -> files; nil files = no file named
		every     bool
	}{
		{"clean", "", false, map[string][]string{}, false},
		{
			"one lockfile", "Error during extraction: (extracting as javascript/packagelockjson) could not extract from " + root + "/web/package-lock.json: unexpected end of JSON input\n",
			false,
			map[string][]string{"npm": {"web/package-lock.json"}},
			false,
		},
		{
			"quoted windows-style", `failed to parse "` + strings.ReplaceAll(root, "/", `\`) + `\Cargo.lock": bad toml` + "\n",
			false,
			map[string][]string{"crates.io": {"Cargo.lock"}},
			false,
		},
		{"canary only", "could not extract from " + canary + "/package-lock.json: x\n", false, map[string][]string{}, false},
		{"unplaced", "Error: something went wrong\n", false, nil, true},
		{"unknown file", "could not extract from " + root + "/weird.lock: x\n", false, nil, true},
		{"truncated", "", true, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ExtractionFailures([]byte(c.stderr), c.truncated, root, canary)
			if c.every {
				if len(got) != len(depscan.Ecosystems()) {
					t.Fatalf("an unplaced error must fail every ecosystem: %+v", got)
				}
				return
			}
			if len(got) != len(c.want) {
				t.Fatalf("got %+v want %v", got, c.want)
			}
			for _, x := range got {
				if x.OK || !slices.Equal(x.Files, c.want[x.Ecosystem]) {
					t.Errorf("%+v want files %v", x, c.want[x.Ecosystem])
				}
			}
		})
	}
	// Lane sec-deps4 (P-036): a project whose path holds the canary path
	// (inside the canary directory, or with the canary path as an inner
	// part of its own) still counts its unreadable lockfile as a gap; a
	// canary file under a project that contains the canary directory (a
	// scan of the home directory) is still the canary's.
	for _, c := range []struct {
		name, root, line string
		want             map[string][]string
	}{
		{"project inside the canary directory", canary + "/inner", "could not extract from " + canary + "/inner/web/package-lock.json: x", map[string][]string{"npm": {"web/package-lock.json"}}},
		{"canary path inside the project path", "/srv" + canary + "/repo", "could not extract from /srv" + canary + "/repo/Cargo.lock: x", map[string][]string{"crates.io": {"Cargo.lock"}}},
		{"canary inside the project", "/home/u", "could not extract from " + canary + "/package-lock.json: x", map[string][]string{}},
		{"a base inside a longer path is not that base", root, "could not extract from /x" + root + "/package-lock.json: x", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := ExtractionFailures([]byte(c.line+"\n"), false, c.root, canary)
			if c.want == nil {
				if len(got) != len(depscan.Ecosystems()) {
					t.Fatalf("a line naming no file under the root must fail every ecosystem: %+v", got)
				}
				return
			}
			if len(got) != len(c.want) {
				t.Fatalf("got %+v want %v", got, c.want)
			}
			for _, x := range got {
				if x.OK || !slices.Equal(x.Files, c.want[x.Ecosystem]) {
					t.Errorf("%+v want files %v", x, c.want[x.Ecosystem])
				}
			}
		})
	}
	// Through the driver: a run whose stderr names an unreadable lockfile
	// scans no ecosystem in full, so StaleFindings can close nothing.
	ex := &extruntest.Executor{Facts: func(p extrun.Plan) extrun.ExecFacts {
		if slices.Contains(p.Args, "--version") {
			return extrun.ExecFacts{Stdout: []byte("osv-scanner version: 2.6.0\n"), PeakChildren: -1}
		}
		return extrun.ExecFacts{ExitCode: 1, Stdout: fixture(t), Stderr: []byte("could not extract from " + root + "/web/package-lock.json: truncated\n"), PeakChildren: -1}
	}}
	res, err := newDriver(runnerWith(ex, true), allEpochs()).Scan(context.Background(), secscan.Target{ProjectRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Coverage.Scanned) != 0 {
		t.Fatalf("scanned %v: a failed lockfile must keep every ecosystem from closing findings", res.Coverage.Scanned)
	}
	found := false
	for _, s := range res.Coverage.Skipped {
		if s.Path == "web/package-lock.json" && s.Reason == depscan.ReasonExtractorFailed {
			found = true
		}
	}
	if !found {
		t.Errorf("skipped %+v lacks the failed lockfile", res.Coverage.Skipped)
	}
	if res.Coverage.Outcome == secscan.OutcomeClean {
		t.Errorf("coverage %+v: never clean with a gap", res.Coverage)
	}
}
