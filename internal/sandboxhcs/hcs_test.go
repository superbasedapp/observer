package sandboxhcs

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func goodFacts() Facts {
	return Facts{
		Windows: true, Active: true, Edition: "Professional", HyperV: true, Containers: true,
		UVMImage: `C:\images\uvm`, UVMVerified: true, Loader: &LoaderFacts{Loaded: true}, SchemaMinor: 1,
	}
}

// TestProbeLadder has one case per row.
func TestProbeLadder(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		edit func(*Facts)
		code string
	}{
		{"not windows", func(f *Facts) { f.Windows = false }, VerdictUnsupportedPlatform},
		{"inactive", func(f *Facts) { f.Active = false }, VerdictDisabledByConfig},
		{"home", func(f *Facts) { f.Edition = "Core" }, VerdictEditionUnsupported},
		{"no hyper-v", func(f *Facts) { f.HyperV = false }, VerdictNoHypervisor},
		{"no containers feature", func(f *Facts) { f.Containers = false }, VerdictBackendMissing},
		{"no image (this release)", func(f *Facts) { f.UVMImage, f.UVMVerified = "", false }, VerdictImageMissing},
		{"unverified image", func(f *Facts) { f.UVMVerified = false }, VerdictImageMissing},
		{"loader not run", func(f *Facts) { f.Loader = nil }, VerdictBackendMissing},
		{"dll missing", func(f *Facts) { f.Loader = &LoaderFacts{Err: "The specified module could not be found."} }, VerdictBackendMissing},
		{"function missing", func(f *Facts) { f.Loader = &LoaderFacts{Loaded: true, Missing: []string{"HcsCreateOperation"}} }, VerdictVersionUntested},
		{"old schema", func(f *Facts) { f.SchemaMinor = 0 }, VerdictVersionUntested},
	}
	if len(cases) < len(rules) {
		t.Fatalf("%d cases for %d rows", len(cases), len(rules))
	}
	for _, c := range cases {
		f := goodFacts()
		c.edit(&f)
		if v := Probe(f); v.Code != c.code || v.Reason == "" {
			t.Errorf("%s: %+v, want %s", c.name, v, c.code)
		}
	}
	if !Probe(goodFacts()).OK() {
		t.Fatal("a sound host refused")
	}
	// What a node sees in this release: nothing configured, the image row
	// refuses before any library is loaded.
	f := goodFacts()
	f.UVMImage, f.UVMVerified, f.Loader = "", false, nil
	if v := Probe(f); v.Code != VerdictImageMissing {
		t.Fatalf("this release's probe = %+v", v)
	}
}

// TestDocumentsGolden pins the two compute system documents: no network
// adapter, the workspace mapped by the source rule, protected paths
// read-only.
func TestDocumentsGolden(t *testing.T) {
	t.Parallel()
	uvm, c, err := Build(Plan{
		RunID: "run0001", Layers: []Layer{{ID: "11111111-1111-1111-1111-111111111111", Path: `C:\images\base`}},
		Workspace: `C:\work\repo`, ContainerWorkspace: `C:\work`,
		Protected: []MappedDirectory{{HostPath: `C:\work\repo\.git\hooks`, ContainerPath: `C:\work\.git\hooks`, ReadOnly: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := Marshal(uvm)
	k, _ := Marshal(c)
	if strings.Contains(u, "Network") || strings.Contains(k, "Network") {
		t.Fatal("a document carries a network section")
	}
	const wantUVM = `{"Owner":"superbased-observer","SchemaVersion":{"Major":2,"Minor":1},"ShouldTerminateOnLastHandleClosed":true,"VirtualMachine":{"StopOnReset":true,"ComputeTopology":{"Memory":{"SizeInMB":2048},"Processor":{"Count":2}},"Devices":{}}}`
	const wantContainer = `{"Owner":"superbased-observer","SchemaVersion":{"Major":2,"Minor":1},"HostingSystemId":"observer-uvm-run0001","Container":{"Storage":{"Layers":[{"Id":"11111111-1111-1111-1111-111111111111","Path":"C:\\images\\base"}]},"MappedDirectories":[{"HostPath":"C:\\work\\repo","ContainerPath":"C:\\work","ReadOnly":false},{"HostPath":"C:\\work\\repo\\.git\\hooks","ContainerPath":"C:\\work\\.git\\hooks","ReadOnly":true}]}}`
	if u != wantUVM || k != wantContainer {
		sum := sha256.Sum256([]byte(u + k))
		t.Fatalf("documents changed (%s):\n%s\n%s", hex.EncodeToString(sum[:8]), u, k)
	}
	if _, _, err := Build(Plan{RunID: "r", Layers: []Layer{{ID: "x"}}, Workspace: `C:\w`, ContainerWorkspace: `C:\w`, Protected: []MappedDirectory{{HostPath: `C:\w\.git`, ContainerPath: `C:\w\.git`}}}); err == nil {
		t.Fatal("a writable protected path was planned")
	}
	if _, _, err := Build(Plan{RunID: "r", Workspace: `C:\w`, ContainerWorkspace: `C:\w`}); err == nil {
		t.Fatal("a plan without layers was planned")
	}
}

type fakeLib map[string]bool

func (f fakeLib) Has(n string) bool { return f[n] }

// TestLoaderErrorPaths: off Windows, a failed load, a nil library and a
// library missing functions; the load runs once.
func TestLoaderErrorPaths(t *testing.T) {
	t.Parallel()
	if f := NewSystemLoaderForTest(); f.Loaded {
		t.Skip("the system loader loaded on this OS")
	}
	if f := NewLoader(nil).Facts(); f.Loaded || f.Err == "" {
		t.Fatalf("nil open: %+v", f)
	}
	calls := 0
	l := NewLoader(func() (Library, error) { calls++; return nil, errors.New("module not found") })
	if f := l.Facts(); f.Loaded || !strings.Contains(f.Err, "module not found") {
		t.Fatalf("failed load: %+v", f)
	}
	_ = l.Facts()
	if calls != 1 {
		t.Fatalf("loaded %d times", calls)
	}
	if f := NewLoader(func() (Library, error) { return nil, nil }).Facts(); f.Loaded {
		t.Fatal("a nil library loaded")
	}
	all := fakeLib{}
	for _, p := range RequiredProcs {
		all[p] = true
	}
	if f := NewLoader(func() (Library, error) { return all, nil }).Facts(); !f.Loaded || len(f.Missing) != 0 {
		t.Fatalf("full library: %+v", f)
	}
	delete(all, "HcsCreateComputeSystem")
	if f := NewLoader(func() (Library, error) { return all, nil }).Facts(); len(f.Missing) != 1 || f.Missing[0] != "HcsCreateComputeSystem" {
		t.Fatalf("missing function: %+v", f)
	}
}

// NewSystemLoaderForTest is the platform loader's facts.
func NewSystemLoaderForTest() LoaderFacts { return NewSystemLoader().Facts() }
