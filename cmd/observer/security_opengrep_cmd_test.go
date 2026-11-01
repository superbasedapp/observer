//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/extrun/extruntest"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/secengine"
	"github.com/marmutapp/superbased-observer/internal/secrulepack"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/opengrep"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// security_opengrep_cmd_test.go is lane SEC-G1 milestone 5: the offer of
// security.scan.opengrep to an install with no [components] block is one
// step. The orchestrator offers it by deleting its securityOptIn entry and
// the skip in TestOpengrepOfferedByDefault; until then
// TestOpengrepHeldWithNoComponentsBlock pins that such an install runs none
// of it.

// noBlockConfig writes an existing install's config: no [components] block.
func noBlockConfig(t *testing.T) string {
	t.Helper()
	setTestHome(t, t.TempDir())
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, []byte("# an existing install: no [components] block\n[observer]\ndb_path = \""+filepath.ToSlash(filepath.Join(dir, "observer.db"))+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestOpengrepHeldWithNoComponentsBlock: while the driver is opt-in, a
// config with no [components] block does not select it; every verb
// refuses "not selected" before it opens the database, and the doctor
// prints one line.
func TestOpengrepHeldWithNoComponentsBlock(t *testing.T) {
	if !securityOptIn[opengrepComponent] {
		t.Skip("security.scan.opengrep is offered: TestOpengrepOfferedByDefault covers it")
	}
	cfg := noBlockConfig(t)
	if codeScanSelected(componentSnapshotFor(cfg)) {
		t.Fatal("security.scan.opengrep ran with no [components] block while it is opt-in")
	}
	if _, err := openCodeEnv(context.Background(), cfg); !errors.Is(err, errCodeNotSelected) {
		t.Fatalf("openCodeEnv = %v, want the not-selected refusal", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(cfg), "observer.db")); err == nil {
		t.Error("a refused verb created the database")
	}
	c := securityCodeDoctorCheck(context.Background(), cfg)
	if c.Status != diag.StatusOK || !strings.Contains(c.Message, "not selected") {
		t.Errorf("doctor %+v", c)
	}
	if slices.Contains(securityActivePacks(componentstate.Legacy()), opengrepComponent) {
		t.Error("the legacy pack set carries the opt-in driver")
	}
	// Selected under a block, it is selected.
	if !codeScanSelected(componentstate.Resolve(config.ComponentsConfig{Add: []string{opengrepComponent}}, nil)) {
		t.Error("a [components] block that adds security.scan.opengrep does not select it")
	}
}

// TestOpengrepOfferedByDefault states what an install with no [components]
// block (every existing install) sees once security.scan.opengrep is
// offered: the `observer security code` verbs work, the doctor row checks
// the engine, and with no Opengrep installed a scan starts no process and
// reports "not scanned". Nothing runs unless the developer runs a scan:
// G1 adds no daemon loop, no download and no hook path.
func TestOpengrepOfferedByDefault(t *testing.T) {
	if securityOptIn[opengrepComponent] {
		t.Skip("security.scan.opengrep is opt-in until the orchestrator offers it (lane sec-g1); the offer deletes its securityOptIn entry and this skip")
	}
	snap := componentSnapshotForConfig(config.Default())
	if !codeScanSelected(snap) {
		t.Fatal("security.scan.opengrep is not selected with no [components] block although it is offered")
	}
	if !slices.Contains(securityActivePacks(snap), opengrepComponent) {
		t.Fatal("the offered driver is not in the active pack set")
	}
	cfg := noBlockConfig(t)
	c := securityCodeDoctorCheck(context.Background(), cfg)
	if strings.Contains(c.Message, "not selected") {
		t.Errorf("doctor still says not selected: %+v", c)
	}
	// No Opengrep on the machine: nothing starts, the result is not scanned.
	ex := &extruntest.Executor{}
	r := extruntest.NewRunner("linux", extruntest.Files{"/usr/bin/git": {}}, ex, nil)
	r.Resolve = func(s integration.BinaryResolveSpec) toolresolve.Resolution {
		return toolresolve.Resolution{Verdict: toolresolve.VerdictNotFound}
	}
	pack, err := secrulepack.Floor()
	if err != nil {
		t.Fatal(err)
	}
	d := opengrep.New(opengrep.Env{
		Runner: r, Pack: pack, PackDir: "/c/pack", CacheDir: "/c/engine", OutDir: "/c/run", GOOS: "linux", GOARCH: "amd64",
		ListTree: func(string) secengine.TreeListing { return secengine.TreeListing{Missing: true} },
		ReadFile: func(string, int64) ([]byte, error) { return nil, os.ErrNotExist },
	})
	res, err := d.Scan(context.Background(), secscan.Target{ProjectRoot: "/home/u/src/p"})
	if err != nil || res.Coverage.Outcome != secscan.OutcomeNotScanned || len(ex.Calls()) != 0 {
		t.Fatalf("no Opengrep installed: %+v, %d processes, %v", res.Coverage, len(ex.Calls()), err)
	}
}

func TestDiffBaseRefusesFlagShapedRefs(t *testing.T) {
	for _, ref := range []string{"--upload-pack=x", "-n", "", "a b", "HEAD:path", strings.Repeat("a", 300)} {
		if _, err := resolveDiffBase(context.Background(), t.TempDir(), ref); err == nil {
			t.Errorf("resolveDiffBase accepted %q", ref)
		}
	}
	if got, err := resolveDiffBase(context.Background(), t.TempDir(), "c3fef7c"); err != nil || got != "c3fef7c" {
		t.Errorf("a commit id: %q %v", got, err)
	}
}

func TestMaterializePackRewritesAChangedCopy(t *testing.T) {
	pack, err := secrulepack.Floor()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	dir, err := materializePack(root, pack)
	if err != nil {
		t.Fatal(err)
	}
	rule := filepath.Join(dir, "rules", "python.sql-string-concat.yaml")
	if err := os.WriteFile(rule, []byte("rules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := materializePack(root, pack); err != nil {
		t.Fatal(err)
	}
	got, err := readPackDir(dir)
	if err != nil || secrulepack.CanonicalDigest(got) != pack.Digest() {
		t.Fatalf("the changed copy was not rewritten: %v", err)
	}
}

func TestListEngineTree(t *testing.T) {
	dir := t.TempDir()
	if l := listEngineTree(filepath.Join(dir, "none")); !l.Missing {
		t.Errorf("a missing directory: %+v", l)
	}
	if err := os.MkdirAll(filepath.Join(dir, "lib"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"opengrep.bin", "lib/_opcode.so"} {
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(f)), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	l := listEngineTree(dir)
	if l.Missing || l.Irregular || strings.Join(l.Files, ",") != "lib/_opcode.so,opengrep.bin" {
		t.Errorf("listing %+v", l)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "lib", "link.so")); err == nil {
		if l := listEngineTree(dir); !l.Irregular {
			t.Errorf("a symlink in the tree was not reported: %+v", l)
		}
	}
}
