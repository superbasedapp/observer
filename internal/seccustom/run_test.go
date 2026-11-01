package seccustom

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secfinding/sarif"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

func TestCheckExecutable(t *testing.T) {
	t.Parallel()
	file := PathElem{Path: "/opt/x/bin/gosec", Exists: true, Regular: true, Perm: 0o755}
	dir := func(p string) PathElem { return PathElem{Path: p, Exists: true, Dir: true, Perm: 0o755} }
	chain := func(first PathElem, rest ...PathElem) []PathElem { return append([]PathElem{first}, rest...) }
	ok := chain(file, dir("/opt/x/bin"), dir("/opt/x"), dir("/opt"), dir("/"))
	cases := []struct {
		name   string
		goos   string
		elems  []PathElem
		accept bool
	}{
		{"a clean install", "linux", ok, true},
		{"the file is a symlink", "linux", chain(PathElem{Path: file.Path, Exists: true, Symlink: true}, ok[1:]...), false},
		{"a parent is a symlink", "linux", append([]PathElem{file, {Path: "/opt/x/bin", Exists: true, Symlink: true}}, ok[2:]...), false},
		{"writable by others", "linux", chain(PathElem{Path: file.Path, Exists: true, Regular: true, Perm: 0o757}, ok[1:]...), false},
		{"writable by group", "linux", chain(PathElem{Path: file.Path, Exists: true, Regular: true, Perm: 0o775}, ok[1:]...), false},
		{"a parent writable by group", "linux", append([]PathElem{file, {Path: "/opt/x/bin", Exists: true, Dir: true, Perm: 0o775}}, ok[2:]...), false},
		{"under the shared sticky /tmp", "linux", chain(file, PathElem{Path: "/tmp", Exists: true, Dir: true, Perm: 0o777, Sticky: true}, dir("/")), false},
		{"not executable", "linux", chain(PathElem{Path: file.Path, Exists: true, Regular: true, Perm: 0o644}, ok[1:]...), false},
		{"a directory, not a file", "linux", chain(dir(file.Path), ok[1:]...), false},
		{"missing", "linux", chain(PathElem{Path: file.Path}, ok[1:]...), false},
		{"windows: mode bits do not apply, a symlink still refuses", "windows", chain(PathElem{Path: `C:\x\g.exe`, Exists: true, Symlink: true}), false},
		{"windows: accepted with the ACL note", "windows", chain(PathElem{Path: `C:\x\g.exe`, Exists: true, Regular: true, Perm: 0o777}, PathElem{Path: `C:\x`, Exists: true, Dir: true, Perm: 0o777}), true},
	}
	for _, c := range cases {
		got := CheckExecutable(c.goos, c.elems)
		if got.OK != c.accept {
			t.Errorf("%s: ok=%v (%s)", c.name, got.OK, got.Reason)
		}
		if c.goos == "windows" && got.OK && !strings.Contains(got.Note, "ACL") {
			t.Errorf("%s: no ACL note", c.name)
		}
	}
}

func TestShebangAndPin(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"#!/usr/bin/python3\nimport x": "/usr/bin/python3",
		"#! /opt/v/bin/python -E\n":    "/opt/v/bin/python",
		"#!python\n":                   "",
		"\x7fELF":                      "",
	} {
		if got := Shebang([]byte(in)); got != want {
			t.Errorf("Shebang(%q) = %q, want %q", in, got, want)
		}
	}
	bandit, _ := TemplateByID("bandit")
	gosec, _ := TemplateByID("gosec")
	if PinScopeFor(&bandit, false) != PinPartial || PinScopeFor(&gosec, false) != PinFull || PinScopeFor(nil, true) != PinPartial {
		t.Fatal("pin labels")
	}
}

// TestCheckInterpreterTable: a "#!" executable's interpreter must be
// absolute, not env, and a declared companion (by its named or resolved
// path); an executable with no "#!" has nothing to check.
func TestCheckInterpreterTable(t *testing.T) {
	t.Parallel()
	resolve := func(p string) string {
		switch p {
		case "/usr/bin/python3":
			return "/usr/bin/python3.12"
		case "/usr/bin/runpy":
			return "/usr/bin/env"
		case "/usr/bin/env", "/opt/bb/py":
			return "/bin/busybox"
		case "/opt/cu/launch":
			return "/usr/bin/coreutils"
		case "/usr/bin/RunPy":
			return "/usr/bin/ENV.EXE"
		}
		return p
	}
	py := []Companion{{Path: "/usr/bin/python3.12"}}
	// The interpreters' own first bytes: /opt/wrap/python is a "#!" script.
	heads := map[string]string{
		"/usr/bin/python3.12": "\x7fELF",
		"/opt/wrap/python":    "#!/usr/bin/python3.12\n",
	}
	readHead := func(p string) []byte { return []byte(heads[p]) }
	cases := []struct {
		name       string
		head       string
		companions []Companion
		refused    string
	}{
		{"no shebang", "\x7fELF", nil, ""},
		{"interpreter pinned by its resolved path", "#!/usr/bin/python3\n", py, ""},
		{"interpreter pinned by its named path", "#!/bin/sh\n", []Companion{{Path: "/bin/sh"}}, ""},
		{"interpreter not a companion", "#!/usr/bin/python3\n", nil, "not one of its declared"},
		{"a different companion", "#!/bin/sh\n", py, "not one of its declared"},
		{"relative interpreter", "#!python\n", py, "names no absolute interpreter"},
		{"empty shebang", "#!\n", py, "names no absolute interpreter"},
		{"env", "#!/usr/bin/env python3\n", []Companion{{Path: "/usr/bin/env"}}, "through env"},
		{"env at another path", "#!/usr/local/bin/env python3\n", []Companion{{Path: "/usr/local/bin/env"}}, "through env"},
		{"env under a busybox prefix", "#!/opt/tools/bin/env -S python3\n", []Companion{{Path: "/opt/tools/bin/env"}}, "through env"},
		{"a link that resolves to env", "#!/usr/bin/runpy\n", []Companion{{Path: "/usr/bin/runpy"}}, "through env"},
		{"an interpreter that is itself a #! script", "#!/opt/wrap/python\n", []Companion{{Path: "/opt/wrap/python"}}, "itself a \"#!\" script"},
		{"envoy is not env", "#!/usr/bin/envoy\n", []Companion{{Path: "/usr/bin/envoy"}}, ""},
		// PT-32: the env check is case-insensitive, drops ".exe" and names a
		// multi-call launcher by its applet, after the link is resolved.
		{"ENV in upper case", "#!/usr/bin/ENV python3\n", []Companion{{Path: "/usr/bin/ENV"}}, "through env"},
		{"Env in mixed case", "#!/usr/bin/Env python3\n", []Companion{{Path: "/usr/bin/Env"}}, "through env"},
		{"env.exe", "#!/c/tools/env.exe python3\n", []Companion{{Path: "/c/tools/env.exe"}}, "through env"},
		{"ENV.EXE", "#!/c/tools/ENV.EXE python3\n", []Companion{{Path: "/c/tools/ENV.EXE"}}, "through env"},
		{"a link that resolves to ENV.EXE", "#!/usr/bin/RunPy\n", []Companion{{Path: "/usr/bin/RunPy"}}, "through env"},
		{"busybox env", "#!/bin/busybox env python3\n", []Companion{{Path: "/bin/busybox"}}, "through env"},
		{"BusyBox.exe ENV", "#!/c/bin/BusyBox.exe ENV python3\n", []Companion{{Path: "/c/bin/BusyBox.exe"}}, "through env"},
		// BusyBox runs as itself for any name that starts with "busybox".
		{"busybox-x86_64 env python3", "#!/opt/busybox-x86_64 env python3\n", []Companion{{Path: "/opt/busybox-x86_64"}}, "through env"},
		{"busybox64.exe env", "#!/c/bin/busybox64.exe env\n", []Companion{{Path: "/c/bin/busybox64.exe"}}, "through env"},
		{"busybox-x86_64 with no applet", "#!/opt/busybox-x86_64\n", []Companion{{Path: "/opt/busybox-x86_64"}}, "names no applet"},
		{"toybox env", "#!/bin/toybox env python3\n", []Companion{{Path: "/bin/toybox"}}, "through env"},
		{"coreutils env", "#!/usr/bin/coreutils env python3\n", []Companion{{Path: "/usr/bin/coreutils"}}, "through env"},
		{"coreutils --coreutils-prog=env", "#!/usr/bin/coreutils --coreutils-prog=env python3\n", []Companion{{Path: "/usr/bin/coreutils"}}, "through env"},
		{"coreutils --coreutils-prog-shebang=env", "#!/usr/bin/coreutils --coreutils-prog-shebang=env\n", []Companion{{Path: "/usr/bin/coreutils"}}, "through env"},
		{"Alpine's env, a busybox link named env", "#!/usr/bin/env\n", []Companion{{Path: "/bin/busybox"}}, "through env"},
		{"busybox sh is not env", "#!/bin/busybox sh\n", []Companion{{Path: "/bin/busybox"}}, ""},
		{"a link to busybox named for its applet", "#!/opt/bb/py\n", []Companion{{Path: "/bin/busybox"}}, ""},
		{"coreutils by a link runs the link's name", "#!/opt/cu/launch\n", []Companion{{Path: "/usr/bin/coreutils"}}, ""},
		{"busybox with no applet", "#!/bin/busybox\n", []Companion{{Path: "/bin/busybox"}}, "names no applet"},
		{"coreutils with an empty applet flag", "#!/usr/bin/coreutils --coreutils-prog=\n", []Companion{{Path: "/usr/bin/coreutils"}}, "names no applet"},
	}
	for _, tc := range cases {
		got := CheckInterpreter([]byte(tc.head), resolve, readHead, tc.companions)
		if (tc.refused == "") != (got.Reason == "") || !strings.Contains(got.Reason, tc.refused) {
			t.Errorf("%s: %+v, want refused %q", tc.name, got, tc.refused)
		}
	}
}

func TestApplyChoicesStayInTheirSets(t *testing.T) {
	t.Parallel()
	tpl, _ := TemplateByID("gosec")
	m := FromTemplate(tpl, "/opt/a/gosec", []string{"/usr/local/go/bin/go"})
	cand := Candidates{Executable: []string{"/opt/a/gosec", "/opt/b/gosec"}, Companions: [][]string{{"/usr/local/go/bin/go"}}}
	got, err := Apply(m, Choices{Executable: "/opt/b/gosec", Limits: Limits{MemoryMiB: 4096}, Severity: map[string]secfinding.Severity{"LOW": policy.FindingSeverityInfo}}, cand, Options{})
	if err != nil || got.Executable != "/opt/b/gosec" || got.Limits.MemoryMiB != 4096 || got.Limits.WallSeconds != 600 || got.Severity.Levels["LOW"] != policy.FindingSeverityInfo {
		t.Fatalf("apply: %+v %v", got, err)
	}
	if m.Severity.Levels["LOW"] != policy.FindingSeverityLow {
		t.Fatal("Apply changed the template's own map")
	}
	for name, c := range map[string]Choices{
		"an executable nobody discovered": {Executable: "/tmp/evil"},
		"an off-step limit":               {Limits: Limits{WallSeconds: 7}},
		"a severity for an unknown level": {Severity: map[string]secfinding.Severity{"BOGUS": policy.FindingSeverityHigh}},
		"a companion nobody discovered":   {Companions: []string{"/tmp/go"}},
		"a category Observer owns":        {Category: string(policy.FindingAgentConfig)},
	} {
		if _, err := Apply(m, c, cand, Options{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Apply(m, Choices{}, Candidates{}, Options{}); err == nil {
		t.Error("a file executable that discovery did not find was accepted")
	}
}

func testRecord(t *testing.T, id string) Record {
	t.Helper()
	tpl, _ := TemplateByID(id)
	var comps []string
	for range tpl.Companions {
		comps = append(comps, "/usr/lib/"+id+"/bin/helper")
	}
	m := FromTemplate(tpl, "/opt/"+id+"/bin/"+id, comps)
	m.ExecutableSHA256 = testSum
	for i := range m.Companions {
		m.Companions[i].SHA256 = strings.Repeat("b", 64)
	}
	return Record{ID: id, Manifest: m, ManifestSHA256: m.Digest()}
}

func TestBuildRun(t *testing.T) {
	t.Parallel()
	dirs := RunDirs{Project: "/home/u/src/p", Output: "/home/u/.cache/sbo/run1/out", Cache: "/home/u/.cache/sbo/gosec"}
	spec, err := BuildRun("linux", testRecord(t, "gosec"), dirs, []string{"/home/u/src/p/a.go", "/home/u/src/p/evil\nname.go", "/etc/passwd"})
	if err != nil {
		t.Fatal(err)
	}
	r := spec.Request
	if r.Component != ComponentID || r.Program.Path != "/opt/gosec/bin/gosec" || r.Expect.Binary != testSum || r.Dir != dirs.Project {
		t.Fatalf("request %+v", r)
	}
	if want := []string{"-fmt", "sarif", "-out", spec.OutputFile, "-no-fail", "-quiet", "./..."}; !slices.Equal(r.Args, want) {
		t.Fatalf("args %q", r.Args)
	}
	if string(r.Stdin) != "/home/u/src/p/a.go\n" || spec.SkippedTargets != 2 {
		t.Fatalf("targets %q skipped %d", r.Stdin, spec.SkippedTargets)
	}
	if len(r.Program.CompanionExecs) != 1 || !r.Program.CompanionExecs[0].OnPath || r.Program.CompanionExecs[0].Version == nil {
		t.Fatalf("companions %+v", r.Program.CompanionExecs)
	}
	if !r.Engine.OwnHome || r.CacheDir != dirs.Cache || r.Limits.Children != 64 || r.Limits.MemoryBytes != 2048<<20 {
		t.Fatalf("engine %+v limits %+v", r.Engine, r.Limits)
	}
	if !spec.Isolable || spec.OneShot.Project != dirs.Project || !slices.Contains(spec.OneShot.ProgramDirs, "/usr/lib/gosec/bin") {
		t.Fatalf("one-shot %+v", spec.OneShot)
	}
	// Bandit: {project_root} and {output_file} substituted whole, HOME in
	// the run's own directory, the launcher's tree bound.
	bspec, err := BuildRun("linux", testRecord(t, "bandit"), dirs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bspec.Request.Args[1] != dirs.Project || !slices.Contains(bspec.Request.Env.Set, "HOME="+HomeDir("linux", dirs)) || !slices.Contains(bspec.OneShot.ProgramDirs, "/opt/bandit") {
		t.Fatalf("bandit %+v %+v", bspec.Request, bspec.OneShot)
	}
	// Semgrep needs the network: not isolable.
	sspec, _ := BuildRun("linux", testRecord(t, "semgrep"), dirs, nil)
	if sspec.Isolable {
		t.Fatal("semgrep with network hosts cannot be isolated")
	}
	noDigest := testRecord(t, "gosec")
	noDigest.Manifest.ExecutableSHA256 = ""
	if _, err := BuildRun("linux", noDigest, dirs, nil); err == nil {
		t.Fatal("a record with no pinned digest built a run")
	}
}

func TestClassifyTable(t *testing.T) {
	t.Parallel()
	ok := RunFacts{Runner: extrun.OutcomeOK, Exit: extrun.ExitResult, SelfTestCurrent: true}
	with := func(f func(*RunFacts)) RunFacts { c := ok; f(&c); return c }
	cases := []struct {
		name string
		f    RunFacts
		want Verdict
	}{
		{"clean: result exit, empty SARIF, self-test current", ok, Verdict{secscan.OutcomeClean, ""}},
		{"exit 0 empty SARIF without a self-test is unknown (gosec with no go)", with(func(f *RunFacts) { f.SelfTestCurrent = false }), Verdict{secscan.OutcomeUnknown, "no_self_test"}},
		{"unknown stderr pattern", with(func(f *RunFacts) { f.UnknownMarker = true }), Verdict{secscan.OutcomeUnknown, "unknown_marker"}},
		{"findings", with(func(f *RunFacts) { f.Findings = 3 }), Verdict{secscan.OutcomeFindings, ""}},
		{"digest mismatch", with(func(f *RunFacts) { f.Runner = extrun.OutcomeRefused; f.Refuse = extrun.RefuseDigestMismatch }), Verdict{secscan.OutcomeFailed, "driver_unverified"}},
		{"other refusal", with(func(f *RunFacts) { f.Runner = extrun.OutcomeRefused; f.Refuse = extrun.RefuseEnv }), Verdict{secscan.OutcomeFailed, "refused"}},
		{"start failed", with(func(f *RunFacts) { f.Runner = extrun.OutcomeStartFailed }), Verdict{secscan.OutcomeFailed, "start_failed"}},
		{"timeout", with(func(f *RunFacts) { f.Runner = extrun.OutcomeTimeout }), Verdict{secscan.OutcomeUnknown, "budget_exceeded"}},
		{"children cap", with(func(f *RunFacts) { f.Runner = extrun.OutcomeChildrenCap }), Verdict{secscan.OutcomeUnknown, "budget_exceeded"}},
		{"canceled", with(func(f *RunFacts) { f.Runner = extrun.OutcomeCanceled }), Verdict{secscan.OutcomeUnknown, "canceled"}},
		{"signal", with(func(f *RunFacts) { f.Runner = extrun.OutcomeSignaled }), Verdict{secscan.OutcomeFailed, "engine_crashed"}},
		{"failure exit", with(func(f *RunFacts) { f.Exit = extrun.ExitFailure }), Verdict{secscan.OutcomeFailed, "engine_failure"}},
		{"no input", with(func(f *RunFacts) { f.Exit = extrun.ExitNoInput }), Verdict{secscan.OutcomeNotScanned, "nothing_to_scan"}},
		{"no SARIF", with(func(f *RunFacts) { f.NoSARIF = true }), Verdict{secscan.OutcomeFailed, "no_sarif"}},
		{"exit says findings, SARIF empty", with(func(f *RunFacts) { f.Exit = extrun.ExitFindings }), Verdict{secscan.OutcomeUnknown, "exit_says_findings"}},
		{"results refused", with(func(f *RunFacts) { f.Refused = 1 }), Verdict{secscan.OutcomeUnknown, "results_refused"}},
	}
	for _, c := range cases {
		if got := Classify(c.f); got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
	if CanCloseMissing(with(func(f *RunFacts) { f.Findings = 1; f.UnknownMarker = true }), Verdict{Outcome: secscan.OutcomeFindings}) {
		t.Error("an unknown-marked run must not close earlier findings")
	}
	if !CanCloseMissing(ok, Classify(ok)) {
		t.Error("a clean run with a current self-test closes the driver's own missing findings")
	}
}

func TestStderrMarksUnknown(t *testing.T) {
	t.Parallel()
	m := testRecord(t, "gosec").Manifest
	if !StderrMarksUnknown(m, []byte("[gosec] package main has type errors, skipping SSA analysis\n")) || StderrMarksUnknown(m, []byte("ok")) {
		t.Fatal("stderr pattern")
	}
}

func readSARIF(t *testing.T, name string) *sarif.Log {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	l, err := sarif.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// TestAdaptRealOutput reads the spike's real gosec and Bandit SARIF
// (JSP-12): every result lands as one project-relative finding, the
// absolute file:/// prefix of Bandit's absolute-target run is stripped,
// and nothing of the planted password survives into any field.
func TestAdaptRealOutput(t *testing.T) {
	t.Parallel()
	const root = "/home/user/work/pyproj"
	cases := []struct {
		file, tpl string
		want      int
	}{
		{"gosec.sarif", "gosec", 11},
		{"gosec-abs-target.sarif", "gosec", 11},
		{"bandit.sarif", "bandit", 7},
		{"bandit-abs-target.sarif", "bandit", 7},
		{"gosec-empty-path.sarif", "gosec", 0},
	}
	for _, c := range cases {
		rec := testRecord(t, c.tpl)
		got := Adapt(AdaptInput{Record: rec, ProjectRoot: root, ProjectRootHash: "h", Scope: policy.FindingScopeManual}, readSARIF(t, c.file))
		if len(got.Findings) != c.want || len(got.Refused) != 0 {
			t.Fatalf("%s: %d findings, refused %+v", c.file, len(got.Findings), got.Refused)
		}
		for _, f := range got.Findings {
			b, _ := json.Marshal(f)
			if strings.Contains(string(b), "hunter2") || strings.HasPrefix(f.Location.RelPath, "/") || strings.Contains(f.Location.RelPath, ":") {
				t.Fatalf("%s: finding keeps content or a local path: %s", c.file, b)
			}
			if f.Engine.Driver != "custom:"+c.tpl || f.Confidence == policy.FindingConfidenceHigh || f.Baseline != policy.FindingBaselineUnknown {
				t.Fatalf("%s: not flag-only: %+v", c.file, f)
			}
		}
	}
	// gosec's severity comes from the rule's tags (G101 is HIGH there).
	got := Adapt(AdaptInput{Record: testRecord(t, "gosec"), ProjectRoot: root, ProjectRootHash: "h"}, readSARIF(t, "gosec.sarif"))
	for _, f := range got.Findings {
		if f.Rule.ID == "G101" && f.Severity != policy.FindingSeverityHigh {
			t.Fatalf("G101 severity %s", f.Severity)
		}
	}
}

// TestAdaptBlockingNeedsTheOrg: a rule the org decision allows keeps its
// confidence and is untrusted_baseline, which a managed floor counts.
func TestAdaptBlockingNeedsTheOrg(t *testing.T) {
	t.Parallel()
	got := Adapt(AdaptInput{
		Record: testRecord(t, "bandit"), ProjectRoot: "/x", ProjectRootHash: "h",
		BlockingAllowed: func(r string) bool { return r == "B602" },
	}, readSARIF(t, "bandit.sarif"))
	for _, f := range got.Findings {
		blocking := f.Baseline == policy.FindingBaselineUntrusted
		if blocking != (f.Rule.ID == "B602") {
			t.Fatalf("%s: baseline %s", f.Rule.ID, f.Baseline)
		}
		if f.Rule.ID == "B602" && f.Confidence != policy.FindingConfidenceHigh {
			t.Fatalf("B602 confidence %s", f.Confidence)
		}
	}
}

// hostileResult renders one SARIF document with one result.
func hostileResult(uri, base, level string, extra string) string {
	q := func(v string) string { b, _ := json.Marshal(v); return string(b) }
	loc := fmt.Sprintf(`{"physicalLocation":{"artifactLocation":{"uri":%s,"uriBaseId":%s},"region":{"startLine":3}}}`, q(uri), q(base))
	return fmt.Sprintf(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x","rules":[{"id":"R1"}]}},
		"originalUriBaseIds":{"EVIL":{"uri":"file:///etc/"}},
		"results":[{"ruleId":"R1","level":%q,"message":{"text":"m"},"locations":[%s]%s}]}]}`, level, loc, extra)
}

// TestHostileSARIF is the JSP-12 hostile SARIF suite against the strict
// adapter: each row is refused, or (where the row says so) accepted.
func TestHostileSARIF(t *testing.T) {
	t.Parallel()
	const root = "/home/u/proj"
	rec := Record{ID: "t", Manifest: Manifest{
		Name: "t", Version: "1", Category: "code_vuln", ExecutableSHA256: testSum,
		Severity:   SeverityMap{Source: SeverityLevel, Levels: map[string]secfinding.Severity{"warning": "low", "error": "high"}},
		Confidence: ConfidenceMap{Source: ConfidenceFixed, Fixed: "medium"},
	}}
	rows := []struct {
		name, doc string
		accept    bool
	}{
		{"plain relative path", hostileResult("src/a.go", "", "warning", ""), true},
		{"file:/// under the root (Bandit absolute target)", hostileResult("file:///home/u/proj/src/a.py", "", "warning", ""), true},
		{"file://localhost under the root", hostileResult("file://localhost/home/u/proj/a.py", "", "warning", ""), true},
		{"%SRCROOT% base id", hostileResult("src/a.go", "%SRCROOT%", "warning", ""), true},
		{"traversal", hostileResult("../../etc/passwd", "", "warning", ""), false},
		{"percent-encoded traversal", hostileResult("%2e%2e/%2e%2e/etc/passwd", "", "warning", ""), false},
		{"absolute path without a scheme", hostileResult("/etc/passwd", "", "warning", ""), false},
		{"file:// outside the root", hostileResult("file:///etc/passwd", "", "warning", ""), false},
		{"file:// on a sibling prefix", hostileResult("file:///home/u/project2/a.go", "", "warning", ""), false},
		{"file:// with a remote host", hostileResult("file://evil.example/home/u/proj/a.go", "", "warning", ""), false},
		{"https", hostileResult("https://evil.example/a.go", "", "warning", ""), false},
		{"javascript", hostileResult("javascript:alert(1)", "", "warning", ""), false},
		{"data", hostileResult("data:text/plain,hi", "", "warning", ""), false},
		{"a drive letter", hostileResult("C:/Windows/win.ini", "", "warning", ""), false},
		{"backslashes", hostileResult(`src\a.go`, "", "warning", ""), false},
		{"a foreign uriBaseId redirected by originalUriBaseIds", hostileResult("passwd", "EVIL", "warning", ""), false},
		{"file uri with a base id", hostileResult("file:///home/u/proj/a.go", "%SRCROOT%", "warning", ""), false},
		{"NUL in the path", hostileResult("a\x00b.go", "", "warning", ""), false},
		{"newline in the path", hostileResult("a\nb.go", "", "warning", ""), false},
		{"percent-encoded newline", hostileResult("a%0Ab.go", "", "warning", ""), false},
		{"ANSI escape in the path", hostileResult("\x1b[31mred.py", "", "warning", ""), false},
		{"query string", hostileResult("a.go?x=1", "", "warning", ""), false},
		{"fragment", hostileResult("a.go#L1", "", "warning", ""), false},
		{"over-long URI", hostileResult(strings.Repeat("a/", 600)+"x.go", "", "warning", ""), false},
		{"unmapped level", hostileResult("a.go", "", "note", ""), false},
		{"SARIF default level (absent) maps through warning", hostileResult("a.go", "", "", ""), true},
		{"over-long rule id", strings.Replace(hostileResult("a.go", "", "warning", ""), `"ruleId":"R1"`, `"ruleId":"`+strings.Repeat("R", 200)+`"`, 1), false},
		{"rule id with a space", strings.Replace(hostileResult("a.go", "", "warning", ""), `"ruleId":"R1"`, `"ruleId":"R 1"`, 1), false},
		{"out-of-range line", strings.Replace(hostileResult("a.go", "", "warning", ""), `"startLine":3`, `"startLine":99999999`, 1), false},
		{"negative line", strings.Replace(hostileResult("a.go", "", "warning", ""), `"startLine":3`, `"startLine":-4`, 1), false},
		{"no location", strings.Replace(hostileResult("a.go", "", "warning", ""), `"locations":[`, `"x":[`, 1), false},
	}
	for _, r := range rows {
		log, err := sarif.Decode([]byte(r.doc))
		if err != nil {
			t.Fatalf("%s: decode: %v", r.name, err)
		}
		got := Adapt(AdaptInput{Record: rec, ProjectRoot: root, ProjectRootHash: "h"}, log)
		if (len(got.Findings) == 1) != r.accept {
			t.Errorf("%s: findings %d refused %+v", r.name, len(got.Findings), got.Refused)
		}
	}
	// A 200 KiB message with ANSI escapes never reaches the finding.
	doc := hostileResult("a.go", "", "warning", "")
	doc = strings.Replace(doc, `"text":"m"`, `"text":"`+strings.Repeat("\\u001b[31mX", 20000)+`"`, 1)
	log, _ := sarif.Decode([]byte(doc))
	got := Adapt(AdaptInput{Record: rec, ProjectRoot: root, ProjectRootHash: "h"}, log)
	if len(got.Findings) != 1 || strings.Contains(got.Findings[0].Message, "X") {
		t.Fatalf("engine message reached the finding: %+v", got.Findings)
	}
	// Over the result cap: truncated.
	var res []string
	for i := 0; i < MaxResults+5; i++ {
		res = append(res, `{"ruleId":"R1","level":"warning","locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1}}}]}`)
	}
	big := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[` + strings.Join(res, ",") + `]}]}`
	log, _ = sarif.Decode([]byte(big))
	got = Adapt(AdaptInput{Record: rec, ProjectRoot: root, ProjectRootHash: "h"}, log)
	if !got.Truncated || len(got.Findings) != MaxResults {
		t.Fatalf("cap: %d truncated %v", len(got.Findings), got.Truncated)
	}
	// Windows: a real file:///C:/ URI under a drive root (the owed live
	// check uses a real Windows SARIF; this row pins the lexical rule).
	if rel, why := StrictLocation("file:///C:/Users/u/proj/src/a.py", "", `C:\Users\u\proj`); why != "" || rel != "src/a.py" {
		t.Fatalf("windows file uri: %q %q", rel, why)
	}
}

func TestCheckSelfTest(t *testing.T) {
	t.Parallel()
	st := &SelfTest{Fixture: "go-basic", ExpectRules: []string{"G101", "G401", "G703"}}
	all := []secfinding.Finding{{Rule: secfinding.Rule{ID: "G101"}}, {Rule: secfinding.Rule{ID: "G401"}}, {Rule: secfinding.Rule{ID: "G703"}}}
	if r := CheckSelfTest(st, Verdict{Outcome: secscan.OutcomeFindings}, all); !r.Passed {
		t.Fatalf("all present: %+v", r)
	}
	// The Go 1.26 against 1.27 skew drops G703: the self-test fails.
	if r := CheckSelfTest(st, Verdict{Outcome: secscan.OutcomeFindings}, all[:2]); r.Passed || !slices.Equal(r.Missing, []string{"G703"}) {
		t.Fatalf("skew: %+v", r)
	}
	// gosec with no go companion: empty and exit 0.
	if r := CheckSelfTest(st, Verdict{Outcome: secscan.OutcomeUnknown}, nil); r.Passed {
		t.Fatal("an empty run passed the self-test")
	}
	s := SelfTestState{Ran: true, Passed: true, BinaryDigest: "a", Companions: map[string]string{"go": "g"}, Versions: map[string]string{"go": "1.27.2"}}
	if !s.Current("a", map[string]string{"go": "g"}, map[string]string{"go": "1.27.2"}) || s.Current("a", map[string]string{"go": "g"}, map[string]string{"go": "1.27.3"}) || s.Current("b", nil, nil) {
		t.Fatal("Current")
	}
}

func TestDecideOrg(t *testing.T) {
	t.Parallel()
	rec := testRecord(t, "gosec")
	rec.Manifest.BlockingRules = []string{"G101", "G401"}
	entry := OrgEntry{
		ManifestSHA256: rec.ManifestSHA256, ExecutableSHA256: rec.Manifest.ExecutableSHA256,
		BlockingRules: []OrgBlockingRule{{"G101", 0.97}, {"G401", 0}},
	}
	catalog := OrgPolicy{Mode: OrgModeCatalogOnly, Entries: []OrgEntry{entry}}
	cases := []struct {
		name     string
		p        OrgPolicy
		f        OrgFacts
		run      bool
		blocking []string
		approved bool
	}{
		{"individual node: runs, flag-only, no remote raise", catalog, OrgFacts{Isolated: true}, true, nil, false},
		{"managed, no org rule: runs flag-only", OrgPolicy{}, OrgFacts{Managed: true, Isolated: true}, true, nil, false},
		{"managed, forbid", OrgPolicy{Mode: OrgModeForbid}, OrgFacts{Managed: true}, false, nil, false},
		{"managed, catalog only, not in the catalog", OrgPolicy{Mode: OrgModeCatalogOnly}, OrgFacts{Managed: true}, false, nil, false},
		{"managed, catalog, isolated: blocking rules with a precision figure", catalog, OrgFacts{Managed: true, Isolated: true}, true, []string{"G101"}, true},
		{"managed, catalog, NOT isolated: flag-only (D7)", catalog, OrgFacts{Managed: true}, true, nil, true},
	}
	for _, c := range cases {
		d := DecideOrg(c.p, c.f, rec)
		if d.Run != c.run || !slices.Equal(d.Blocking, c.blocking) || d.OrgApproved != c.approved {
			t.Errorf("%s: %+v", c.name, d)
		}
	}
	if m := RequiredMissing(OrgPolicy{Mode: OrgModeRequire, Entries: []OrgEntry{entry, {ManifestSHA256: "other"}}}, OrgFacts{Managed: true}, []Record{rec}); !slices.Equal(m, []string{"other"}) {
		t.Fatalf("required missing %v", m)
	}
}

func TestChildrenUnitPerOS(t *testing.T) {
	t.Parallel()
	if ChildrenUnit("linux") != "tasks" || ChildrenUnit("windows") != "processes" || ChildrenUnit("darwin") != "processes" {
		t.Fatal("per-OS child units")
	}
	if LimitSteps(LimitChildren)[0] != 64 {
		t.Fatal("the smallest child step is 64")
	}
}

// TestNetworkWordsSaysHostsAreNotEnforced: network none says nothing; a
// declared host list is said plainly to be not enforced.
func TestNetworkWordsSaysHostsAreNotEnforced(t *testing.T) {
	t.Parallel()
	if w := NetworkWords(Network{Mode: NetworkNone}); w != "" {
		t.Fatalf("none: %q", w)
	}
	w := NetworkWords(Network{Mode: NetworkHosts, Hosts: []string{"semgrep.dev", "pypi.org"}})
	if !strings.Contains(w, "semgrep.dev, pypi.org") || !strings.Contains(w, "not enforced") || !strings.Contains(w, "any host") {
		t.Fatalf("hosts: %q", w)
	}
}
