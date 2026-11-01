//go:build linux && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
)

// p3cInstallPlan is a plan whose tool must be installed first.
func p3cInstallPlan(t *testing.T, f *p3cFake) ociPlanFile {
	t.Helper()
	plan := p3cRunPlan(t, f)
	digest := "sha256:" + strings.Repeat("b", 64)
	vol := sandboxoci.CacheVolumeName(plan.Create.InstallID, digest, "tool-a", "2.1.309")
	stale := sandboxoci.CacheVolumeName(plan.Create.InstallID, digest, "tool-a", "2.1.300")
	src := sandboxoci.InstallSource{Kind: "npm", Package: "@vendor/tool-a", Bin: "tool-a", Hosts: []string{"registry.npmjs.org"}}
	plan.Install = &ociInstallStep{
		Tool: "tool-a", Kind: "npm", Package: "@vendor/tool-a", Bin: "tool-a", Hosts: src.Hosts,
		DocURL: "https://vendor.example/docs/install", Version: "2.1.309", Image: digest, Volume: vol,
		Others: []string{stale}, Refresh: true, Line: sandboxoci.InstallLine("tool-a", src, "2.1.309", vol, true),
	}
	plan.Create.Volumes = []sandboxoci.VolumeMount{{Name: vol, Target: sandboxoci.ToolCacheMount, ReadOnly: true}}
	f.mu.Lock()
	f.volumes[stale] = map[string]any{"Labels": sandboxoci.CacheLabels(plan.Create.InstallID, digest, "tool-a", "2.1.300", "@vendor/tool-a")}
	f.mu.Unlock()
	return plan
}

func p3cInteractiveTerm() *ociTestTerm {
	tt := newOCITestTerm()
	tt.term.interactive = func() bool { return true }
	return tt
}

// TestOCIInstallConsentedFillsTheCache is the first-start install with a
// yes: the line names what is downloaded and from where, the cache volume is
// created over an owner-only host directory with this install's labels, the
// setup container gets no workspace, no tool state, no host environment and
// only its gateway socket, the cache is recorded only after the install
// exited 0, the stale cache goes, and the agent's container mounts the cache
// read-only.
func TestOCIInstallConsentedFillsTheCache(t *testing.T) {
	f := newP3CFake(t)
	tt := p3cInteractiveTerm()
	plan := p3cInstallPlan(t, f)
	done := make(chan int, 1)
	go func() {
		done <- driveOCIRun(context.Background(), plan, []string{"/usr/bin/observer", "tool-a"}, []string{"TERM=xterm"}, tt.term)
	}()
	tt.waitFor(t, "Install it now? [y/N] ")
	out := tt.out.String()
	for _, want := range []string{"@vendor/tool-a@2.1.309", "registry.npmjs.org", plan.Install.Volume, "https://vendor.example/docs/install", "the cache is stale"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the consent line does not say %q: %q", want, out)
		}
	}
	if len(f.callList()) == 0 || slices.Contains(f.callList(), "POST /volumes/create") {
		t.Fatalf("something was created before the answer: %v", f.callList())
	}
	_, _ = tt.inW.Write([]byte("y\n"))
	tt.waitFor(t, "agent$ ")
	_, _ = tt.inW.Write([]byte("exit\n"))
	select {
	case code := <-done:
		if code != 42 {
			t.Fatalf("exit %d, out %q", code, tt.out.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("the run never ended: %q", tt.out.String())
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	vb := f.volumes[plan.Install.Volume]
	if vb == nil {
		t.Fatalf("the cache volume was not created: %v", f.calls)
	}
	opts, _ := vb["DriverOpts"].(map[string]any)
	wantDir := ociCacheDir(plan.Create.ObserverDir, plan.Install.Volume)
	if opts["device"] != wantDir || opts["o"] != "bind" {
		t.Fatalf("driver opts %v", opts)
	}
	if fi, err := os.Stat(wantDir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("the cache directory %v %v", fi, err)
	}
	labels, _ := vb["Labels"].(map[string]any)
	if labels[sandboxoci.LabelRole] != sandboxoci.RoleToolCache || labels[sandboxoci.LabelCacheVersion] != "2.1.309" || labels[sandboxoci.LabelInstall] != plan.Create.InstallID {
		t.Fatalf("labels %v", labels)
	}
	if len(f.order) != 2 {
		t.Fatalf("containers %v", f.order)
	}
	setup, agent := f.bodies[f.order[0]], f.bodies[f.order[1]]
	if !slices.Equal(setup.Env, sandboxoci.InstallEnv(sandboxoci.InstallProxyPort)) {
		t.Fatalf("the setup container's environment is not the allow-list: %v", setup.Env)
	}
	for _, m := range setup.HostConfig.Mounts {
		switch {
		case m.Type == "volume" && m.Target == sandboxoci.ToolCacheMount && !m.ReadOnly:
		case m.Type == "bind" && m.ReadOnly && (m.Target == "/usr/bin/observer" || m.Target == sandbox.GuestSocketDir):
		default:
			t.Fatalf("the setup container has an unplanned mount %+v", m)
		}
		if m.Source == plan.Create.WorkDir {
			t.Fatal("the setup container got the workspace")
		}
	}
	if setup.HostConfig.NetworkMode != sandboxoci.NetworkNone || !setup.HostConfig.ReadonlyRootfs {
		t.Fatalf("setup hardening %+v", setup.HostConfig)
	}
	cacheRO := false
	for _, m := range agent.HostConfig.Mounts {
		if m.Type == "volume" && m.Source == plan.Install.Volume && m.Target == sandboxoci.ToolCacheMount && m.ReadOnly {
			cacheRO = true
		}
	}
	if !cacheRO {
		t.Fatalf("the agent's container does not mount the cache read-only: %+v", agent.HostConfig.Mounts)
	}
	if !slices.Contains(f.removed, f.order[0]) {
		t.Fatalf("the setup container was not removed: %v", f.removed)
	}
	if !slices.Contains(f.volRemoved, plan.Install.Others[0]) {
		t.Fatalf("the stale cache was not removed: %v", f.volRemoved)
	}
	if _, ok := ociCacheRecords(plan.Create.ObserverDir)[plan.Install.Volume]; !ok {
		t.Fatal("the completed cache was not recorded")
	}
}

// TestOCIInstallNoOrHeadlessInstallsNothing: a no, a terminal that cannot
// answer, and a failed install each end the launch with nothing of the
// agent created, and leave no volume and no cache directory.
func TestOCIInstallNoOrHeadlessInstallsNothing(t *testing.T) {
	cases := []struct {
		name        string
		interactive bool
		answer      string
		installExit int
		want        string
	}{
		{"no", true, "n\n", 0, "install_not_consented"},
		{"empty answer", true, "\n", 0, "install_not_consented"},
		{"headless", false, "", 0, "no terminal to answer on"},
		{"install fails", true, "yes\n", 1, "exited with status 1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newP3CFake(t)
			f.installExit = c.installExit
			tt := newOCITestTerm()
			tt.term.interactive = func() bool { return c.interactive }
			plan := p3cInstallPlan(t, f)
			done := make(chan int, 1)
			go func() {
				done <- driveOCIRun(context.Background(), plan, []string{"/usr/bin/observer", "tool-a"}, nil, tt.term)
			}()
			if c.answer != "" {
				tt.waitFor(t, "[y/N] ")
				_, _ = tt.inW.Write([]byte(c.answer))
			}
			select {
			case code := <-done:
				if code != sandboxHelperFailCode {
					t.Fatalf("exit %d", code)
				}
			case <-time.After(15 * time.Second):
				t.Fatal("the launch never ended")
			}
			tt.waitFor(t, c.want)
			f.mu.Lock()
			defer f.mu.Unlock()
			if _, ok := f.volumes[plan.Install.Volume]; ok {
				t.Fatal("a cache volume was left")
			}
			for _, id := range f.order {
				if !f.isInstall(id) {
					t.Fatalf("the agent's container was created: %v", f.order)
				}
			}
			if _, err := os.Stat(ociCacheDir(plan.Create.ObserverDir, plan.Install.Volume)); err == nil {
				t.Fatal("the cache directory was left")
			}
			if _, ok := ociCacheRecords(plan.Create.ObserverDir)[plan.Install.Volume]; ok {
				t.Fatal("a refused or failed install was recorded")
			}
		})
	}
}

// TestOCIInstallSkippedWhenTheCacheIsComplete: a cache another launch
// finished since this one was planned is used as is, without asking.
func TestOCIInstallSkippedWhenTheCacheIsComplete(t *testing.T) {
	f := newP3CFake(t)
	tt := newOCITestTerm()
	plan := p3cInstallPlan(t, f)
	if err := setOCICacheRecord(plan.Create.ObserverDir, plan.Install.Volume, &ociCacheRecord{Tool: "tool-a", Version: "2.1.309"}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.volumes[plan.Install.Volume] = map[string]any{"Labels": map[string]string{}}
	f.mu.Unlock()
	done := make(chan int, 1)
	go func() {
		done <- driveOCIRun(context.Background(), plan, []string{"/usr/bin/observer", "tool-a"}, nil, tt.term)
	}()
	tt.waitFor(t, "agent$ ")
	_, _ = tt.inW.Write([]byte("exit\n"))
	<-done
	if strings.Contains(tt.out.String(), "[y/N]") {
		t.Fatal("a complete cache asked again")
	}
}

// TestOCIInstallGatewayReachesOnlyTheInstallHosts: the install gateway the
// helper serves refuses a host outside the tool's install hosts at the
// gateway (before any resolution), and says so in one plain line.
func TestOCIInstallGatewayReachesOnlyTheInstallHosts(t *testing.T) {
	tt := newOCITestTerm()
	stop, dir, err := ociStartInstallGateway(&ociInstallStep{Hosts: []string{"registry.npmjs.org"}}, tt.term)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("the gateway socket directory %v %v", fi, err)
	}
	c, err := net.Dial("unix", filepath.Join(dir, sandbox.GatewaySocketName))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, _ = io.WriteString(c, "CONNECT evil.example.com:443 HTTP/1.1\r\nHost: evil.example.com:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
	tt.waitFor(t, "observer sandbox: blocked evil.example.com (host-not-listed)")
}

func TestOCIInstallGuestVerb(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "gw.sock")
	if code := runOCIInstallGuest([]string{"--gateway", sock, "--port", "0", "--", "sh", "-c", "exit 3"}); code != 2 {
		t.Fatalf("a port 0 must be refused, got %d", code)
	}
	if code := runOCIInstallGuest([]string{"--gateway", sock, "--port", "39871", "--", "sh", "-c", "exit 3"}); code != 3 {
		t.Fatalf("the installer's status must pass through, got %d", code)
	}
	if code := runOCIInstallGuest([]string{"--gateway", "relative.sock", "--port", "39872", "--", "true"}); code != 2 {
		t.Fatalf("a relative socket must be refused, got %d", code)
	}
}

func TestOCIPrependPath(t *testing.T) {
	got := ociPrependPath([]string{"TERM=x", "PATH=/usr/bin:/bin"}, "/observer-tool-cache/bin")
	if !slices.Equal(got, []string{"TERM=x", "PATH=/observer-tool-cache/bin:/usr/bin:/bin"}) {
		t.Fatalf("%v", got)
	}
	got = ociPrependPath([]string{"TERM=x"}, "/c/bin")
	if !strings.HasPrefix(got[1], "PATH=/c/bin:") {
		t.Fatalf("%v", got)
	}
}

// TestOCICacheDecision is the daemon's half: an absent cache plans the
// install with its consent line (the Create note both launch paths show),
// a completed cache of the host's version is mounted without an install,
// and a cache of another version is stale and refreshed.
func TestOCICacheDecision(t *testing.T) {
	f := newP3CFake(t)
	c, err := ociEngineClient(f.sock, "1.52")
	if err != nil {
		t.Fatal(err)
	}
	obs := t.TempDir()
	d := &ociDriver{r: &sandboxRuntime{observerDir: obs}}
	image := "node@sha256:" + strings.Repeat("b", 64)
	digest := "sha256:" + strings.Repeat("b", 64)
	inst := "inst000000000001"
	// A source that needs its own install script is refused by name, never
	// installed with it (audit finding 2), unless a reviewed pin covers the
	// version (lane LEFT-SBX, ruling P-136): 2.1.309 has no pin.
	if _, _, err := d.ociCacheDecision(context.Background(), c, inst, image, "claude-code", "2.1.309"); err == nil || !strings.Contains(err.Error(), sandboxoci.VerdictInstallScriptsUnpinned) {
		t.Fatalf("a scripts-needing source with no pin for its version: %v", err)
	}
	d.cfg.InstallScripts = sandboxoci.ScriptsNone
	if _, _, err := d.ociCacheDecision(context.Background(), c, inst, image, "claude-code", "2.1.310"); err == nil || !strings.Contains(err.Error(), sandboxoci.VerdictInstallScriptsRequired) {
		t.Fatalf("install_scripts = none: %v", err)
	}
	d.cfg.InstallScripts = ""
	cc, note, err := d.ociCacheDecision(context.Background(), c, inst, image, "codex", "2.1.309")
	if err != nil {
		t.Fatal(err)
	}
	if cc.install == nil || cc.install.Refresh || cc.volume != sandboxoci.CacheVolumeName(inst, digest, "codex", "2.1.309") || cc.binDir != sandboxoci.ToolCacheMount+"/bin" {
		t.Fatalf("absent: %+v", cc)
	}
	for _, want := range []string{"@openai/codex@2.1.309", "registry.npmjs.org", "the terminal asks first"} {
		if !strings.Contains(note, want) {
			t.Fatalf("the launch note %q does not say %q", note, want)
		}
	}
	if !strings.Contains(cc.install.Line, "registry.npmjs.org") || cc.install.DocURL == "" {
		t.Fatalf("consent line %q doc %q", cc.install.Line, cc.install.DocURL)
	}
	// Complete it: the next launch mounts it as is.
	f.mu.Lock()
	f.volumes[cc.volume] = map[string]any{"Labels": sandboxoci.CacheLabels(inst, digest, "codex", "2.1.309", "@openai/codex")}
	f.mu.Unlock()
	if err := setOCICacheRecord(obs, cc.volume, &ociCacheRecord{Tool: "codex", Version: "2.1.309", Image: digest}); err != nil {
		t.Fatal(err)
	}
	cur, note, err := d.ociCacheDecision(context.Background(), c, inst, image, "codex", "2.1.309")
	if err != nil || cur.install != nil || cur.volume != cc.volume || !strings.Contains(note, "tool=cache(") {
		t.Fatalf("current: %+v %q %v", cur, note, err)
	}
	// The host moved on: stale, refreshed, the old one removed after.
	st, note, err := d.ociCacheDecision(context.Background(), c, inst, image, "codex", "2.1.310")
	if err != nil || st.install == nil || !st.install.Refresh || !slices.Contains(st.install.Others, cc.volume) || !strings.Contains(note, "stale") {
		t.Fatalf("stale: %+v %q %v", st, note, err)
	}
	if _, _, err := d.ociCacheDecision(context.Background(), c, inst, image, "no-such-tool", "1.0.0"); err == nil || !strings.Contains(err.Error(), sandboxoci.VerdictInstallSourceUnknown) {
		t.Fatalf("unknown source: %v", err)
	}
}

func TestOCIHostToolVersion(t *testing.T) {
	dir := t.TempDir()
	pkg := filepath.Join(dir, "lib", "node_modules", "@vendor", "tool-a")
	if err := os.MkdirAll(filepath.Join(pkg, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkg, "package.json"), []byte(`{"name":"@vendor/tool-a","version":"2.1.309"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(pkg, "bin", "tool-a")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho 'nope'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if v := ociHostToolVersion(bin, "@vendor/tool-a"); v != "2.1.309" {
		t.Fatalf("package.json version %q", v)
	}
	// Another package's manifest is not this tool's version; the binary's
	// own answer is used, and one that is not a plain version is none.
	if v := ociHostToolVersion(bin, "@vendor/other"); v != "" {
		t.Fatalf("a non-version answer gave %q", v)
	}
	native := filepath.Join(dir, "native-tool")
	if err := os.WriteFile(native, []byte("#!/bin/sh\necho '2.0.7 (Tool)'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if v := ociHostToolVersion(native, "@vendor/tool-a"); v != "2.0.7" {
		t.Fatalf("--version answer %q", v)
	}
	if v := ociHostToolVersion("", "x"); v != "" {
		t.Fatalf("no binary gave %q", v)
	}
}

// TestOCIInstallRecordedButVolumeGone is audit finding 4: a cache recorded
// complete whose volume the engine no longer has is never skipped (the
// engine would create an empty volume for the agent): the record is
// forgotten and the install asks again; with no yes nothing is created.
func TestOCIInstallRecordedButVolumeGone(t *testing.T) {
	f := newP3CFake(t)
	tt := newOCITestTerm()
	plan := p3cInstallPlan(t, f)
	if err := setOCICacheRecord(plan.Create.ObserverDir, plan.Install.Volume, &ociCacheRecord{Tool: "tool-a", Version: "2.1.309"}); err != nil {
		t.Fatal(err)
	}
	code := driveOCIRun(context.Background(), plan, []string{"/usr/bin/observer", "tool-a"}, nil, tt.term)
	if code == 0 {
		t.Fatal("a launch whose cache volume is gone ran")
	}
	out := tt.out.String()
	if !strings.Contains(out, plan.Install.Volume) || !strings.Contains(out, "no longer has it") || !strings.Contains(out, "nothing is installed") {
		t.Fatalf("the terminal does not say what happened: %q", out)
	}
	for _, call := range f.callList() {
		if strings.Contains(call, "/volumes/create") || strings.Contains(call, "/containers/create") {
			t.Fatalf("something was created: %v", f.callList())
		}
	}
	if _, ok := ociCacheRecords(plan.Create.ObserverDir)[plan.Install.Volume]; ok {
		t.Fatal("the stale record was kept")
	}
}

// TestOCICacheVolumeGoneRefusesBeforeCreate: a plan that mounts a cache
// (no install step) whose volume the engine no longer has is refused naming
// the volume, before the agent's container is created.
func TestOCICacheVolumeGoneRefusesBeforeCreate(t *testing.T) {
	f := newP3CFake(t)
	tt := newOCITestTerm()
	plan := p3cInstallPlan(t, f)
	vol := plan.Install.Volume
	plan.Install = nil
	if err := setOCICacheRecord(plan.Create.ObserverDir, vol, &ociCacheRecord{Tool: "tool-a", Version: "2.1.309"}); err != nil {
		t.Fatal(err)
	}
	code := driveOCIRun(context.Background(), plan, []string{"/usr/bin/observer", "tool-a"}, nil, tt.term)
	if code == 0 {
		t.Fatal("a launch whose cache volume is gone ran")
	}
	if !strings.Contains(tt.out.String(), vol) || !strings.Contains(tt.out.String(), "no longer on the engine") {
		t.Fatalf("the refusal does not name the volume: %q", tt.out.String())
	}
	for _, call := range f.callList() {
		if strings.Contains(call, "/volumes/create") || strings.Contains(call, "/containers/create") {
			t.Fatalf("something was created: %v", f.callList())
		}
	}
	if _, ok := ociCacheRecords(plan.Create.ObserverDir)[vol]; ok {
		t.Fatal("the stale record was kept")
	}
}
