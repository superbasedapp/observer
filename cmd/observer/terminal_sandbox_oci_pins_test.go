//go:build !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// TestOCIPinsTheRepositories (lane SHR-FOLLOWUPS, ledger SBX-BE-10, the
// P-082 follow-up): the oci driver binds the launch's pins onto themselves
// as bwrap does: the live workspace's .git, and a repository folder and its
// .git under an org write bind. The composed plan still builds. With the
// pins left out the same paths are not mounts, which is what this pins.
func TestOCIPinsTheRepositories(t *testing.T) {
	skipDriverOffHost(t, "the OCI driver")
	home := t.TempDir()
	setTestHome(t, home)
	if real, err := filepath.EvalSymlinks(home); err == nil {
		home = real
	}
	org := filepath.Join(t.TempDir(), "org")
	if real, err := filepath.EvalSymlinks(filepath.Dir(org)); err == nil {
		org = filepath.Join(real, "org")
	}
	repo := filepath.Join(org, "team", "repo")
	for _, d := range []string{".claude", ".observer", "proj/.git/hooks"} {
		_ = os.MkdirAll(filepath.Join(home, d), 0o700)
	}
	if err := os.MkdirAll(filepath.Join(repo, ".git", "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".git", "config"), []byte("[core]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := ociTestConfig(t, true, "oci-runc")
	cfg.Terminal.Sandbox.ExtraRWBinds = []string{org}
	exe, _ := os.Executable()
	rt, err := newSandboxRuntime(cfg.Terminal.Sandbox, nil, filepath.Join(home, ".observer"), exe, nil)
	if err != nil {
		t.Fatal(err)
	}
	rt.applyDaemonConfig(cfg)
	rt.orgRWBinds = []string{org}
	d := rt.drivers[sandboxbackend.BackendOCIRunc].(*ociDriver)
	ws := filepath.Join(home, "proj")
	run := termsvc.SandboxRun{ID: "runid000000000000009", Tool: "claude-code", Dir: ws}
	spec := ociClaudeSpec(t)
	overlays, pins, err := rt.protection(home, ws, spec)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(ws, ".git"), repo, filepath.Join(repo, ".git")}
	for _, w := range want {
		if !slices.Contains(pins, w) {
			t.Fatalf("protection pins %v lack %s", pins, w)
		}
	}
	p := d.bindPlan(home, run, spec, overlays, "/tmp/observer-sbx-runid9", nil)
	unpinned := p
	unpinned.Pins = nil
	ociPinMounts(&p, pins)
	for _, w := range want {
		if !slices.Contains(p.Pins, w) {
			t.Errorf("plan pins %v lack %s", p.Pins, w)
		}
	}
	p.RunID, p.InstallID, p.Image = run.ID, "inst000000000009", ociTestImage
	p.User = sandboxoci.UserPlan{Row: "rootless docker", User: "0:0", ContainerRootIsHostUser: true}
	p.Engine = sandboxoci.EngineDocker
	p.EngineSocket, p.ObserverDir, p.ReadonlyRootfs = "/run/user/1000/docker.sock", rt.observerDir, true
	p.Entrypoint = []string{exe, ociInitVerb, "--", exe, "claude"}
	_, body, err := sandboxoci.BuildCreate(p)
	if err != nil {
		t.Fatalf("the plan with pins does not build: %v", err)
	}
	mounted := func(ms []sandboxoci.MountSpec, target string) bool {
		for _, m := range ms {
			if m.Target == target && m.Source == target && !m.ReadOnly {
				return true
			}
		}
		return false
	}
	for _, w := range want {
		if !mounted(body.HostConfig.Mounts, w) {
			t.Errorf("%s is not bound onto itself read-write", w)
		}
	}
	unpinned.RunID, unpinned.InstallID, unpinned.Image, unpinned.User, unpinned.Engine = p.RunID, p.InstallID, p.Image, p.User, p.Engine
	unpinned.EngineSocket, unpinned.ObserverDir, unpinned.ReadonlyRootfs, unpinned.Entrypoint = p.EngineSocket, p.ObserverDir, true, p.Entrypoint
	_, body2, err := sandboxoci.BuildCreate(unpinned)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range want {
		if mounted(body2.HostConfig.Mounts, w) {
			t.Errorf("%s is a mount without the pins; the test would not catch their removal", w)
		}
	}
	// A pin already mounted (an overlay) or outside every write bind is
	// left out rather than refusing the create.
	q := sandboxoci.CreatePlan{Binds: []sandboxoci.Bind{{Source: ws, Target: ws}, {Source: filepath.Join(ws, ".git"), Target: filepath.Join(ws, ".git"), ReadOnly: true}}}
	ociPinMounts(&q, []string{filepath.Join(ws, ".git"), filepath.Join(home, ".claude")})
	if len(q.Pins) != 0 {
		t.Fatalf("pins %v; want none", q.Pins)
	}
}

// TestOCIComposePinsThroughTheLaunch (lane SHR-FOLLOWUPS audit findings 1
// and 2): the oci launch's own compose writes the pins into the plan file
// the helper runs, so dropping the ociPinMounts call fails here, not only a
// direct call of it. A repository under an extra_ro_binds directory nested
// inside the org write bind is left out: its nearest enclosing bind is
// read-only, so its .git is never reopened writable by a pin.
func TestOCIComposePinsThroughTheLaunch(t *testing.T) {
	skipDriverOffHost(t, "the OCI driver")
	home := t.TempDir()
	setTestHome(t, home)
	if real, err := filepath.EvalSymlinks(home); err == nil {
		home = real
	}
	org := filepath.Join(t.TempDir(), "org")
	if real, err := filepath.EvalSymlinks(filepath.Dir(org)); err == nil {
		org = filepath.Join(real, "org")
	}
	repo := filepath.Join(org, "team", "repo")
	vendor := filepath.Join(org, "vendor")
	roRepo := filepath.Join(vendor, "lib")
	ws := filepath.Join(home, "proj")
	for _, d := range []string{filepath.Join(home, ".claude"), filepath.Join(home, ".observer"), filepath.Join(ws, ".git", "hooks"), filepath.Join(repo, ".git", "hooks"), filepath.Join(roRepo, ".git", "hooks")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := ociTestConfig(t, true, "oci-runc")
	cfg.Terminal.Sandbox.ExtraRWBinds = []string{org}
	cfg.Terminal.Sandbox.ExtraROBinds = []string{vendor}
	exe, _ := os.Executable()
	rt, err := newSandboxRuntime(cfg.Terminal.Sandbox, nil, filepath.Join(home, ".observer"), exe, nil)
	if err != nil {
		t.Fatal(err)
	}
	rt.applyDaemonConfig(cfg)
	rt.orgRWBinds = []string{org}
	_, pins, err := rt.protection(home, ws, ociClaudeSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(pins, filepath.Join(roRepo, ".git")) {
		t.Fatalf("protection pins %v lack the nested read-only repository's .git; the test would prove nothing", pins)
	}
	d := rt.drivers[sandboxbackend.BackendOCIRunc].(*ociDriver)
	runID := "runocipins0000000001"
	res := sandboxoci.ProbeResult{
		Socket:   "/run/user/1000/docker.sock",
		Identity: sandboxoci.Identity{Engine: sandboxoci.EngineDocker, Mode: sandboxoci.ModeRootless, APIVersion: "1.52", Fingerprint: "f"},
		User:     sandboxoci.UserPlan{Row: "rootless docker", User: "0:0", ContainerRootIsHostUser: true},
	}
	wrap, err := d.compose(termsvc.CreateResult{Run: termsvc.SandboxRun{ID: runID, Tool: "claude-code", Dir: ws}, ProxyRouted: true}, res)
	if err != nil {
		t.Fatal(err)
	}
	if len(wrap) < 4 || wrap[1] != ociHostVerb || wrap[2] != "--plan" {
		t.Fatalf("argv %v", wrap)
	}
	plan, err := readOCIPlan(wrap[3])
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{filepath.Join(ws, ".git"), repo, filepath.Join(repo, ".git")} {
		if !slices.Contains(plan.Create.Pins, w) {
			t.Errorf("the launch's plan pins %v lack %s", plan.Create.Pins, w)
		}
	}
	for _, gone := range []string{roRepo, filepath.Join(roRepo, ".git")} {
		if slices.Contains(plan.Create.Pins, gone) {
			t.Errorf("%s is pinned read-write under the read-only bind %s", gone, vendor)
		}
	}
	roBound := false
	for _, b := range plan.Create.Binds {
		roBound = roBound || (b.Target == vendor && b.ReadOnly)
	}
	if !roBound {
		t.Fatalf("%s is not bound read-only in %+v", vendor, plan.Create.Binds)
	}
}
