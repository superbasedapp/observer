package secscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secfinding/sarif"
)

func loadRun(t *testing.T, name string) sarif.Run {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "sarif", name))
	if err != nil {
		t.Fatal(err)
	}
	lg, err := sarif.Decode(data)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return lg.Runs[0]
}

// TestAdaptEachPlannedEngine runs a fixture from each planned engine
// through its semantic adapter (acceptance A).
func TestAdaptEachPlannedEngine(t *testing.T) {
	t.Parallel()
	cases := []struct {
		file, adapter, root, prefix string
		wantN                       int
		wantRule, wantPath          string
		wantSev                     secfinding.Severity
		wantCat                     secfinding.Category
	}{
		{"opengrep.sarif", "opengrep", "/work/project", "home.u.observer.rules", 1, "python.sqli", "app/db.py", policy.FindingSeverityHigh, policy.FindingCodeVuln},
		{"osv.sarif", "osv", "/work/project", "", 1, "GHSA-xxxx-yyyy-zzzz", "package-lock.json", policy.FindingSeverityCritical, policy.FindingVulnerableDependency},
		{"gitleaks.sarif", "gitleaks", "/work/project", "", 1, "aws-access-token", "config.env", policy.FindingSeverityHigh, policy.FindingSecret},
		{"trivy.sarif", "trivy", "/work/project", "", 1, "CVE-2024-0001", "go.mod", policy.FindingSeverityHigh, policy.FindingVulnerableDependency},
		{"kics.sarif", "kics", "/work/project", "", 1, "a227ec01-f97a-4084-91a4-47b350c1db54", "deploy/pod.yaml", policy.FindingSeverityHigh, policy.FindingIaC},
		{"actionlint.sarif", "actionlint", "/work/project", "", 1, "expression", ".github/workflows/ci.yml", policy.FindingSeverityLow, policy.FindingCIConfig},
		{"bandit.sarif", "sarif-import", "/work/project", "", 1, "B105", "src/settings.py", policy.FindingSeverityLow, policy.FindingCodeVuln},
		{"gosec-windows.sarif", "custom", `C:\Work\Project`, "", 1, "G101", "cmd/main.go", policy.FindingSeverityMedium, policy.FindingCodeVuln},
	}
	for _, tc := range cases {
		row, ok := Adapter(tc.adapter)
		if !ok {
			t.Fatalf("no adapter %q", tc.adapter)
		}
		fs, cov := Adapt(row, loadRun(t, tc.file), AdaptOptions{ProjectRoot: tc.root, ProjectRootHash: "h", RulePrefix: tc.prefix, Scope: policy.FindingScopeManual})
		if len(fs) != tc.wantN {
			t.Fatalf("%s: %d findings, want %d (coverage %+v)", tc.file, len(fs), tc.wantN, cov)
		}
		f := fs[0]
		if f.Rule.ID != tc.wantRule || f.Location.RelPath != tc.wantPath || f.Severity != tc.wantSev || f.Category != tc.wantCat {
			t.Errorf("%s: got rule %q path %q sev %s cat %s", tc.file, f.Rule.ID, f.Location.RelPath, f.Severity, f.Category)
		}
		if cov.Outcome != OutcomeFindings || f.LocalKey == "" {
			t.Errorf("%s: outcome %s, local key %q", tc.file, cov.Outcome, f.LocalKey)
		}
		// Engine text never reaches the finding (section 9 T8): no message
		// text and no snippet survives.
		for _, s := range []string{f.Message, f.FixHint, f.EvidenceRedacted} {
			if strings.Contains(s, "hunter2") || strings.Contains(s, "AKIA") || strings.Contains(s, "SELECT") || strings.Contains(s, "secret_value") {
				t.Errorf("%s: engine text leaked into the finding: %q", tc.file, s)
			}
		}
	}
}

// TestAdaptRefusesHostileRows: remote URIs, paths outside the root,
// traversal and a bad rule id are dropped and counted, never stored.
func TestAdaptRefusesHostileRows(t *testing.T) {
	t.Parallel()
	row, _ := Adapter("sarif-import")
	fs, cov := Adapt(row, loadRun(t, "bandit.sarif"), AdaptOptions{ProjectRoot: "/work/project", SelfTestPassed: true})
	if len(fs) != 1 {
		t.Fatalf("findings = %d, want only the in-root one", len(fs))
	}
	reasons := map[string]bool{}
	for _, s := range cov.Skipped {
		reasons[s.Reason] = true
	}
	for _, want := range []string{"remote_uri", "outside_project_root", "path_traversal", "bad_rule_id"} {
		if !reasons[want] {
			t.Errorf("missing skip reason %s in %+v", want, cov.Skipped)
		}
	}
}

// TestEmptyRunIsUnknownWithoutSelfTest: exit 0 with an empty SARIF is not
// clean (revision 2.4 [JSP-12]).
func TestEmptyRunIsUnknownWithoutSelfTest(t *testing.T) {
	t.Parallel()
	row, _ := Adapter("custom")
	_, cov := Adapt(row, loadRun(t, "empty.sarif"), AdaptOptions{})
	if cov.Outcome != OutcomeUnknown {
		t.Fatalf("no self-test: %s, want unknown", cov.Outcome)
	}
	_, cov = Adapt(row, loadRun(t, "empty.sarif"), AdaptOptions{SelfTestPassed: true})
	if cov.Outcome != OutcomeClean {
		t.Fatalf("self-test passed: %s, want clean", cov.Outcome)
	}
	_, cov = Adapt(row, loadRun(t, "empty.sarif"), AdaptOptions{SelfTestPassed: true, UnknownMarker: true})
	if cov.Outcome != OutcomeUnknown {
		t.Fatalf("unknown marker: %s, want unknown", cov.Outcome)
	}
}

// TestLocalKeyStableAcrossLinesDifferentAcrossProjects: an engine
// fingerprint keys the finding without its line, and the project is part
// of the key.
func TestLocalKeyStableAcrossLinesDifferentAcrossProjects(t *testing.T) {
	t.Parallel()
	row, _ := Adapter("opengrep")
	run := loadRun(t, "opengrep.sarif")
	a, _ := Adapt(row, run, AdaptOptions{ProjectRoot: "/work/project", ProjectRootHash: "p1"})
	run.Results[0].Locations[0].StartLine = 40
	b, _ := Adapt(row, run, AdaptOptions{ProjectRoot: "/work/project", ProjectRootHash: "p1"})
	c, _ := Adapt(row, run, AdaptOptions{ProjectRoot: "/work/project", ProjectRootHash: "p2"})
	if a[0].LocalKey != b[0].LocalKey {
		t.Error("a line move must keep the local key")
	}
	if a[0].LocalKey == c[0].LocalKey {
		t.Error("another project must key differently")
	}
}

func TestNormalizeLocation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		uri, root, want string
		why             LocationReason
	}{
		{"src/a.go", "/r", "src/a.go", LocOK},
		{"./src/a.go", "/r", "src/a.go", LocOK},
		{"file:///r/src/a.go", "/r", "src/a.go", LocOK},
		{"file://localhost/r/a.go", "/r", "a.go", LocOK},
		{"/r/a%20b.go", "/r", "a b.go", LocOK},
		{"file:///C:/R/x.go", `c:\r`, "x.go", LocOK},
		{"file://host/r/a.go", "/r", "", LocRemote},
		{"https://x/a.go", "/r", "", LocRemote},
		{"/rx/a.go", "/r", "", LocOutsideRoot},
		{"/etc/passwd", "/r", "", LocOutsideRoot},
		{"../a.go", "/r", "", LocTraversal},
		{"a/../../b", "/r", "", LocTraversal},
		{"a\x00b", "/r", "", LocBadChars},
		{"a\nb", "/r", "", LocBadChars},
		{"", "/r", "", LocEmpty},
		{"/r", "/r", "", LocEmpty},
		{"%zz", "/r", "", LocBadEncoding},
		{strings.Repeat("a/", 300) + "x", "/r", "", LocTooLong},
		{"/r/a.go", "", "", LocOutsideRoot},
		// Audit P-002 finding 6: case folding never changes the slice, and a
		// non-ASCII drive root whose lower case is longer cannot panic.
		{"file:///C:/Ⱥ/x.go", `C:\Ⱥ`, "x.go", LocOK},
		{"file:///c:/Ⱥ", `C:\Ⱥ`, "", LocEmpty},
		{"file:///C:/ⱥ/x.go", `C:\Ⱥ`, "", LocOutsideRoot},
		{"C:/rx/a.go", `C:\r`, "", LocOutsideRoot},
		{"/a.go", "/", "a.go", LocOK},
		// A relative path with a colon is a path, not a remote URI.
		{"src/a:b.go", "/r", "src/a:b.go", LocOK},
		{"a b:c", "/r", "a b:c", LocOK},
		{"ssh+git://h/x", "/r", "", LocRemote},
	}
	for _, tc := range cases {
		got, why := NormalizeLocation(tc.uri, tc.root)
		if got != tc.want || why != tc.why {
			t.Errorf("NormalizeLocation(%q, %q) = %q, %q; want %q, %q", tc.uri, tc.root, got, why, tc.want, tc.why)
		}
	}
}

type fakeDriver struct{ row DriverRow }

func (f fakeDriver) Row() DriverRow                               { return f.row }
func (f fakeDriver) Probe(context.Context) Probe                  { return Probe{} }
func (f fakeDriver) Scan(context.Context, Target) (Result, error) { return Result{}, nil }

func TestRegistryValidation(t *testing.T) {
	t.Parallel()
	ok := DriverRow{ID: "secrets", Kind: KindNative, ComponentID: "security.secrets", Triggers: []secfinding.Scope{"pre_write"}}
	cases := []struct {
		name string
		rows []DriverRow
		want string
	}{
		{"valid native", []DriverRow{ok}, ""},
		{"no id", []DriverRow{{Kind: KindNative, ComponentID: "security"}}, "no id"},
		{"bad kind", []DriverRow{{ID: "x", Kind: "magic", ComponentID: "security"}}, "unknown kind"},
		{"outside tree", []DriverRow{{ID: "x", Kind: KindNative, ComponentID: "guard"}}, "outside the security tree"},
		{"no adapter", []DriverRow{{ID: "x", Kind: KindProcess, ComponentID: "security.scan.x", SemanticAdapter: "nope"}}, "unknown adapter"},
		{"process in a hook", []DriverRow{{ID: "x", Kind: KindProcess, ComponentID: "security.scan.x", SemanticAdapter: "opengrep", Triggers: []secfinding.Scope{"pre_write"}}}, "may not run"},
		{"duplicate", []DriverRow{ok, ok}, "twice"},
	}
	for _, tc := range cases {
		var ds []Driver
		for _, r := range tc.rows {
			ds = append(ds, fakeDriver{r})
		}
		reg, err := NewRegistry(ds...)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: err %v, want %q", tc.name, err, tc.want)
		case tc.want == "":
			if len(reg.IDs()) != 1 || len(reg.ForScope("pre_write")) != 1 || len(reg.ForScope("ci")) != 0 {
				t.Errorf("%s: registry %+v", tc.name, reg.IDs())
			}
			if _, found := reg.Get("secrets"); !found {
				t.Errorf("%s: Get", tc.name)
			}
		}
	}
	for _, n := range AdapterNames() {
		r, _ := Adapter(n)
		if r.Name != n || r.Category == "" || r.Confidence == "" {
			t.Errorf("adapter %s is incomplete: %+v", n, r)
		}
	}
}
