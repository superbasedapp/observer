//go:build linux && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// terminal_sandbox_oci_runsc_linux_test.go: the oci-runsc row (lane
// SBX-P3B) against the fake Engine API: the create asks for runsc and the
// read-back requires the engine to report it, the socket bridge is decided
// by the runtime's own --host-uds, tool state is projected, and the guest's
// db-copy copies are read back no-follow and capped.

// ociRunscPlan is a plan for a rootful Docker engine with runsc.
func ociRunscPlan(t *testing.T, f *ociFake) ociPlanFile {
	t.Helper()
	f.rootless = false
	plan := ociRunPlan(t, f)
	v := sandboxoci.VersionFacts{Version: "29.9.1", APIVersion: "1.52", PlatformName: "Docker Engine - Community"}
	id, _ := sandboxoci.Classify(v, sandboxoci.InfoFacts{ID: "fake-daemon", Name: "box", OperatingSystem: "Ubuntu", SecurityOptions: []string{"name=seccomp,profile=builtin"}})
	plan.Mode, plan.Fingerprint = id.Mode, id.Fingerprint
	plan.Backend = sandboxbackend.BackendOCIRunsc
	plan.Create.Runtime = "runsc"
	plan.Create.User = sandboxoci.UserPlan{Row: "rootful engine (opt-in)", User: "1000:1000"}
	return plan
}

// TestOCIRunscCreatesWithRunscAndReadsItBack: the create body asks for
// runsc, the engine reports runsc, and the run goes on to the agent's own
// status.
func TestOCIRunscCreatesWithRunscAndReadsItBack(t *testing.T) {
	f := newOCIFake(t)
	f.runscArgs = []string{"--host-uds=open"}
	plan := ociRunscPlan(t, f)
	tt := newOCITestTerm()
	done := make(chan int, 1)
	go func() {
		done <- driveOCIRun(context.Background(), plan, []string{"/usr/bin/observer", "claude"}, nil, tt.term)
	}()
	tt.waitFor(t, "agent$ ")
	_, _ = tt.inW.Write([]byte("exit\n"))
	select {
	case code := <-done:
		if code != 42 {
			t.Fatalf("exit %d out %q", code, tt.out.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the run never ended")
	}
	if f.body.HostConfig.Runtime != "runsc" {
		t.Fatalf("the create asked for runtime %q, want runsc", f.body.HostConfig.Runtime)
	}
}

// TestOCIRunscRefusesAContainerNotReportedAsRunsc: an engine that builds the
// container on runc (a daemon that ignored the runtime) is refused before
// anything starts.
func TestOCIRunscRefusesAContainerNotReportedAsRunsc(t *testing.T) {
	f := newOCIFake(t)
	f.runscArgs = []string{"--host-uds=open"}
	f.reportRuntime = "runc"
	tt := newOCITestTerm()
	code := driveOCIRun(context.Background(), ociRunscPlan(t, f), []string{"/usr/bin/observer", "claude"}, nil, tt.term)
	if code != sandboxHelperFailCode || !strings.Contains(tt.out.String(), "built_below_plan") || !strings.Contains(tt.out.String(), "runsc") {
		t.Fatalf("code %d out %q", code, tt.out.String())
	}
	if f.callIndex("POST /containers/c1/start") >= 0 {
		t.Fatalf("a runc container started on the runsc row: %v", f.calls)
	}
}

// TestOCIRunscRefusesWithoutTheSocketBridge: runsc registered without
// --host-uds=open (or not at all) is refused before any container is made,
// naming the remedy.
func TestOCIRunscRefusesWithoutTheSocketBridge(t *testing.T) {
	for name, args := range map[string][]string{"no host-uds": {}, "not registered": nil} {
		t.Run(name, func(t *testing.T) {
			f := newOCIFake(t)
			f.runscArgs = args
			tt := newOCITestTerm()
			code := driveOCIRun(context.Background(), ociRunscPlan(t, f), []string{"/usr/bin/observer", "claude"}, nil, tt.term)
			if code != sandboxHelperFailCode || f.callIndex("POST /containers/create") >= 0 {
				t.Fatalf("code %d calls %v", code, f.calls)
			}
			want := sandboxoci.VerdictSocketBridgeUnavailable
			if args == nil {
				want = sandboxoci.VerdictRuntimeMissing
			}
			if !strings.Contains(tt.out.String(), want) {
				t.Fatalf("out %q, want %s", tt.out.String(), want)
			}
		})
	}
}

// TestOCIRunscComposeProjectsToolState: the oci-runsc driver binds a
// per-run projected directory at the tool's state path (never the real
// one), asks for runsc, names its row in the plan and tells the init to run
// db-copy in each projection.
func TestOCIRunscComposeProjectsToolState(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if real, err := filepath.EvalSymlinks(home); err == nil {
		home = real
	}
	_ = os.MkdirAll(filepath.Join(home, ".claude"), 0o700)
	ws := filepath.Join(home, "proj")
	_ = os.MkdirAll(ws, 0o700)
	cfg := ociTestConfig(t, true, "oci-runsc")
	cfg.Terminal.Sandbox.OCI.AllowRootful = true
	exe, _ := os.Executable()
	rt, err := newSandboxRuntime(cfg.Terminal.Sandbox, nil, filepath.Join(home, ".observer"), exe, nil)
	if err != nil {
		t.Fatal(err)
	}
	rt.applyDaemonConfig(cfg)
	d, ok := rt.drivers[sandboxbackend.BackendOCIRunsc].(*ociDriver)
	if !ok {
		t.Fatalf("no oci-runsc driver: %v", rt.drivers)
	}
	if d.backend() != sandboxbackend.BackendOCIRunsc || !d.profile.CrossesKernel {
		t.Fatalf("driver profile %+v", d.profile)
	}
	runID := "runrunsc000000001"
	res := sandboxoci.ProbeResult{
		Socket:   "/run/docker.sock",
		Identity: sandboxoci.Identity{Engine: sandboxoci.EngineDocker, Mode: sandboxoci.ModeRootful, APIVersion: "1.52", Fingerprint: "f"},
		User:     sandboxoci.UserPlan{Row: "rootful engine (opt-in)", User: "1000:1000"},
		Bridge:   sandboxoci.BridgeHostUDS,
	}
	wrap, err := d.compose(termsvc.CreateResult{Run: termsvc.SandboxRun{ID: runID, Tool: "claude-code", Dir: ws}, ProxyRouted: true}, res)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := readOCIPlan(wrap[3])
	if err != nil {
		t.Fatal(err)
	}
	if plan.Backend != sandboxbackend.BackendOCIRunsc || plan.Create.Runtime != "runsc" {
		t.Fatalf("plan backend %q runtime %q", plan.Backend, plan.Create.Runtime)
	}
	claude := filepath.Join(home, ".claude")
	var stateBind *sandboxoci.Bind
	for i, b := range plan.Create.Binds {
		if b.Target == claude {
			stateBind = &plan.Create.Binds[i]
		}
		if b.Source == claude {
			t.Fatalf("the real tool state is bound on a row that crosses a kernel: %+v", b)
		}
	}
	root := filepath.Join(rt.managedRoot, runID+sandboxoci.ProjectionLeaf)
	if stateBind == nil || stateBind.ReadOnly || !strings.HasPrefix(stateBind.Source, root+string(filepath.Separator)) {
		t.Fatalf("the state bind is not the projection: %+v (root %s)", stateBind, root)
	}
	if fi, err := os.Lstat(stateBind.Source); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("the projected dir is not a private directory: %v %v", fi, err)
	}
	if len(plan.Projections) == 0 || plan.DBCopyDest == "" || !strings.HasPrefix(plan.DBCopyDest, ociStateDir(rt.observerDir)) {
		t.Fatalf("projections %+v dest %q", plan.Projections, plan.DBCopyDest)
	}
	entry := plan.Create.Entrypoint
	i := slices.Index(entry, ociInitDBCopyFlag)
	if i < 0 || entry[i+1] != claude || slices.Index(entry, "--") < i {
		t.Fatalf("entrypoint %v does not run db-copy in %s", entry, claude)
	}
}

// TestRuntimeProfilesMatchTheRegistry: each runtime profile is a registry
// row with the same CrossesKernel, and a row that crosses a kernel never
// writes the home database directly and is projected (section 5.4).
func TestRuntimeProfilesMatchTheRegistry(t *testing.T) {
	for _, p := range sandboxoci.RuntimeProfiles() {
		row, ok := sandboxbackend.Get(p.Backend)
		if !ok || !row.Offered() {
			t.Fatalf("profile %s has no offered registry row", p.Backend)
		}
		if row.Iso.CrossesKernel != p.CrossesKernel {
			t.Errorf("%s: registry CrossesKernel %v, profile %v", p.Backend, row.Iso.CrossesKernel, p.CrossesKernel)
		}
		if row.Iso.CrossesKernel && (row.Capture.HookPath == sandboxbackend.HookDirectDB || sandboxoci.StateModeFor(row.Iso.CrossesKernel) != sandboxoci.StateProject) {
			t.Errorf("%s crosses a kernel but is not relayed and projected", p.Backend)
		}
		if _, registered := sandboxDriverRegs[p.Backend]; !registered {
			t.Errorf("%s has no registered driver", p.Backend)
		}
	}
}

// TestParseOCIInitArgs: the init's db-copy flags come before `--`.
func TestParseOCIInitArgs(t *testing.T) {
	dbc, launch, ok := parseOCIInitArgs([]string{ociInitDBCopyFlag, "/home/dev/.claude", ociInitDBCopyFlag, "/home/dev/.codex", "--", "/usr/bin/observer", "claude"})
	if !ok || len(dbc) != 2 || dbc[1] != "/home/dev/.codex" || launch[1] != "claude" {
		t.Fatalf("%v %v %v", dbc, launch, ok)
	}
	if _, _, ok := parseOCIInitArgs([]string{ociInitDBCopyFlag, "/x"}); ok {
		t.Fatal("no launch accepted")
	}
	if _, launch, ok := parseOCIInitArgs([]string{"--", "a"}); !ok || launch[0] != "a" {
		t.Fatal("the plain form broke")
	}
}

// makeSQLite writes a small SQLite store at p.
func makeSQLite(t *testing.T, p string) {
	t.Helper()
	db, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec("CREATE TABLE s(k TEXT); INSERT INTO s VALUES ('one'),('two')"); err != nil {
		t.Fatal(err)
	}
}

// TestDBCopyRoundTrip (SBX-BE-10, A5's hostile-SQLite half): the guest
// one-shot copies only SQLite files (found by header, links not followed),
// and the host keeps a copy only through a no-follow read of a name the
// one-shot makes, under the cap, that opens read-only and passes
// quick_check. A planted link, a forged name and a malformed copy are
// refused; the good copy is kept.
func TestDBCopyRoundTrip(t *testing.T) {
	proj := t.TempDir()
	makeSQLite(t, filepath.Join(proj, "store.db"))
	_ = os.MkdirAll(filepath.Join(proj, "sub"), 0o700)
	makeSQLite(t, filepath.Join(proj, "sub", "history.sqlite"))
	_ = os.WriteFile(filepath.Join(proj, "notes.txt"), []byte("not a database"), 0o600)
	outside := filepath.Join(t.TempDir(), "secret.db")
	makeSQLite(t, outside)
	if err := os.Symlink(outside, filepath.Join(proj, "linked.db")); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(proj, sandboxoci.DBCopyDirName)
	n, err := guestDBCopy(sandbox.DBCopyRequest{Root: proj, Out: out})
	if err != nil || n != 2 {
		t.Fatalf("copied %d (%v), want the 2 stores and not the link or the text file", n, err)
	}
	dest := filepath.Join(t.TempDir(), "kept")
	kept, err := collectGuestDBCopies(proj, dest)
	if err != nil || kept != 2 {
		t.Fatalf("kept %d (%v)", kept, err)
	}
	var count int
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dest, sandbox.DBCopyName("store.db"))+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT count(*) FROM s").Scan(&count); err != nil || count != 2 {
		t.Fatalf("the kept copy reads %d (%v)", count, err)
	}
	_ = db.Close()

	// A hostile guest: a forged manifest entry, a link in place of a copy
	// and a malformed copy.
	var m sandbox.DBCopyManifest
	raw, _ := os.ReadFile(filepath.Join(out, sandbox.DBCopyManifestName))
	_ = json.Unmarshal(raw, &m)
	linkName := sandbox.DBCopyName("evil-link")
	_ = os.Symlink(outside, filepath.Join(out, linkName))
	badName := sandbox.DBCopyName("evil-bad")
	_ = os.WriteFile(filepath.Join(out, badName), append([]byte(sandbox.SQLiteHeader), []byte(strings.Repeat("x", 600))...), 0o600)
	m.Files = append(m.Files,
		sandbox.DBCopyEntry{Rel: "../../etc/passwd", Name: "passwd"},
		sandbox.DBCopyEntry{Rel: "evil-link", Name: linkName},
		sandbox.DBCopyEntry{Rel: "evil-bad", Name: badName},
	)
	b, _ := json.Marshal(m)
	_ = os.WriteFile(filepath.Join(out, sandbox.DBCopyManifestName), b, 0o600)
	dest2 := filepath.Join(t.TempDir(), "kept2")
	kept, err = collectGuestDBCopies(proj, dest2)
	if kept != 2 || err == nil {
		t.Fatalf("kept %d err %v: the forged, linked and malformed copies must be refused and the good ones kept", kept, err)
	}
	for _, refused := range []string{"passwd", linkName, badName} {
		if _, err := os.Lstat(filepath.Join(dest2, refused)); err == nil {
			t.Errorf("%s was kept", refused)
		}
	}
	// The copy directory itself replaced by a link: nothing is read.
	_ = os.RemoveAll(out)
	_ = os.Symlink(t.TempDir(), out)
	if _, err := collectGuestDBCopies(proj, filepath.Join(t.TempDir(), "kept3")); err == nil {
		t.Fatal("a linked copy directory was followed")
	}
}
