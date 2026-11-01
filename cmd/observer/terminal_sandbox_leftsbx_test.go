//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter/defaults"
	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// terminal_sandbox_leftsbx_test.go: lane LEFT-SBX milestone 1, the git-dir
// protection gaps (ledger SBX-BE-21 residual, SBX-GOV-3, SBX-BE-16).

// mkLinkedWorktree registers a linked worktree named name in repo's .git the
// way `git worktree add` lays it out: .git/worktrees/<name> holding HEAD,
// commondir and the gitdir back pointer, nothing else.
func mkLinkedWorktree(t *testing.T, repo, name string) string {
	t.Helper()
	d := filepath.Join(repo, ".git", "worktrees", name)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	for f, body := range map[string]string{"HEAD": "ref: refs/heads/" + name + "\n", "commondir": "../..\n", "gitdir": "/elsewhere/" + name + "/.git\n"} {
		if err := os.WriteFile(filepath.Join(d, f), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

// TestSandboxLinkedWorktreeGitDirsProtected: a live workspace's linked
// worktree git dirs (.git/worktrees/<name>) get every WorkspaceExecState row
// the .git itself gets, read only (an existing commondir in place, a missing
// one a placeholder), and the worktrees folder, each worktree git dir and
// the folders holding its protected paths are pinned. Removing the rows (the
// sandboxLinkedWorktreeRows call in protection) fails this test.
func TestSandboxLinkedWorktreeGitDirsProtected(t *testing.T) {
	ws := t.TempDir()
	mkGitDir(t, ws)
	wt1 := mkLinkedWorktree(t, ws, "feature")
	wt2 := mkLinkedWorktree(t, ws, "hotfix")
	if err := os.MkdirAll(filepath.Join(wt2, "info"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := &sandboxRuntime{observerDir: filepath.Join(t.TempDir(), "obs")}
	ovs, pins, err := r.protection(filepath.Join(t.TempDir(), "home"), ws, integration.SandboxSpec{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]sandbox.Overlay{}
	for _, o := range ovs {
		got[o.Path] = o
	}
	for _, wt := range []string{wt1, wt2} {
		// commondir exists: protected in place, never a placeholder.
		if o, ok := got[filepath.Join(wt, "commondir")]; !ok || o.Kind != sandbox.OverlayReadOnly || o.Placeholder != sandbox.PlaceholderNone {
			t.Errorf("%s/commondir: %+v (present %v)", wt, o, ok)
		}
		// config and hooks are missing in a worktree git dir: read-only
		// placeholders the box cannot create or replace.
		for _, rel := range []string{"config", "hooks", "config.worktree"} {
			if o, ok := got[filepath.Join(wt, rel)]; !ok || o.Kind != sandbox.OverlayReadOnly || o.Placeholder == sandbox.PlaceholderNone {
				t.Errorf("%s/%s: %+v (present %v), want a read-only placeholder", wt, rel, o, ok)
			}
		}
		if !slices.Contains(pins, wt) {
			t.Errorf("%s is not pinned (pins %v)", wt, pins)
		}
	}
	// wt2's real info folder is pinned onto itself, and its missing
	// attributes file is a placeholder inside it.
	if !slices.Contains(pins, filepath.Join(wt2, "info")) {
		t.Errorf("%s/info is not pinned: %v", wt2, pins)
	}
	if o, ok := got[filepath.Join(wt2, "info", "attributes")]; !ok || o.Placeholder != sandbox.PlaceholderFile {
		t.Errorf("%s/info/attributes: %+v (present %v)", wt2, o, ok)
	}
	// wt1 has no info folder: its topmost missing component is the
	// placeholder.
	if o, ok := got[filepath.Join(wt1, "info")]; !ok || o.Placeholder != sandbox.PlaceholderDir {
		t.Errorf("%s/info: %+v (present %v)", wt1, o, ok)
	}
	worktrees := filepath.Join(ws, ".git", "worktrees")
	if i, j := slices.Index(pins, worktrees), slices.Index(pins, wt1); i < 0 || j < 0 || i > j {
		t.Errorf("the worktrees folder must be pinned before the worktree git dirs: %v", pins)
	}
	// Every row of the one table, for every worktree git dir.
	for _, wt := range []string{wt1, wt2} {
		for _, pp := range sandbox.WorkspaceExecState {
			p := filepath.Join(wt, filepath.FromSlash(strings.TrimPrefix(pp.Rel, ".git/")))
			covered := false
			for path := range got {
				covered = covered || path == p || isWithinPath(p, path)
			}
			if !covered {
				t.Errorf("%s is not covered by any overlay", p)
			}
		}
	}

	// allow_tool_config_writes lifts the workspace's own rows, these with
	// them; nothing is pinned for them either.
	r.cfg = config.TerminalSandboxConfig{AllowToolConfigWrites: true}
	ovs, pins, err = r.protection(filepath.Join(t.TempDir(), "home"), ws, integration.SandboxSpec{})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range ovs {
		if isWithinPath(o.Path, worktrees) {
			t.Errorf("allow_tool_config_writes kept %s", o.Path)
		}
	}
	if slices.Contains(pins, wt1) {
		t.Errorf("allow_tool_config_writes kept the worktree pin")
	}
}

// TestSandboxLinkedWorktreeFailsClosed: a symlinked worktree git dir refuses
// the launch naming it, and a worktrees folder that cannot be listed refuses
// it too (fail closed, as for any repository the walk cannot list).
func TestSandboxLinkedWorktreeFailsClosed(t *testing.T) {
	ws := t.TempDir()
	mkGitDir(t, ws)
	if err := os.MkdirAll(filepath.Join(ws, ".git", "worktrees"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(ws, ".git", "worktrees", "evil")
	if err := testSymlink(t, t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	r := &sandboxRuntime{observerDir: filepath.Join(t.TempDir(), "obs")}
	if _, _, err := r.protection(filepath.Join(t.TempDir(), "home"), ws, integration.SandboxSpec{}); err == nil || !strings.Contains(err.Error(), link) {
		t.Fatalf("a symlinked worktree git dir: %v, want a refusal naming %s", err, link)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("root lists any folder")
	}
	worktrees := filepath.Join(ws, ".git", "worktrees")
	// chmod 000 on POSIX; a deny ACE on Windows, where the mode bits do not
	// stop a listing (WINFIX4 audit).
	makeUnlistable(t, worktrees)
	if _, _, err := r.protection(filepath.Join(t.TempDir(), "home"), ws, integration.SandboxSpec{}); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("an unlistable worktrees folder: %v, want a refusal", err)
	}
}

// TestSandboxOrgBindProtectsLinkedWorktrees: a repository under an org write
// bind gets its linked-worktree git dirs protected and pinned like its
// .git, whatever allow_tool_config_writes says (the bind is the org's).
func TestSandboxOrgBindProtectsLinkedWorktrees(t *testing.T) {
	bind := t.TempDir()
	repo := filepath.Join(bind, "team", "repo")
	mkGitDir(t, repo)
	wt := mkLinkedWorktree(t, repo, "side")
	rows, pins, err := sandboxOrgBindGitRows([]string{bind}, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range rows {
		if row.path == filepath.Join(wt, "commondir") {
			found = row.kind == sandbox.OverlayReadOnly && row.remedy == remedyOrgWriteBind
		}
	}
	if !found || !slices.Contains(pins, wt) || !slices.Contains(pins, filepath.Join(repo, ".git", "worktrees")) {
		t.Fatalf("org-bind linked worktree: row %v, pins %v", found, pins)
	}
}

// tierValues is every OBSERVER_SANDBOX_EGRESS value in env, in order.
func tierValues(env []string) []string {
	var out []string
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, sandbox.EnvEgress+"="); ok {
			out = append(out, v)
		}
	}
	return out
}

// TestSandboxTierNeverInherited (ledger SBX-BE-16 "fix owed"): on the CLI
// path (sandboxTierChildEnv over os.Environ) and the dashboard launch path
// (launchChildEnv), a sandboxed child carries exactly one tier value, the
// one its own wrap resolves; a spoofed inherited value is gone, and a wrap
// with no host helper leaves no tier at all rather than the inherited one.
func TestSandboxTierNeverInherited(t *testing.T) {
	skipOnWindows(t, "the bwrap and oci relay argv takes a POSIX host socket directory")
	t.Setenv(sandbox.EnvEgress, "internet")
	t.Setenv(sandboxEnvMarker, "0")
	wrap := tierWrap(t, sandbox.EgressNone)
	cli := sandboxTierChildEnv(os.Environ(), wrap)
	if got := tierValues(cli); !slices.Equal(got, []string{"none"}) {
		t.Errorf("CLI path tier values %q, want [none]", got)
	}
	if n := countEnvKey(cli, sandboxEnvMarker); n != 1 || !slices.Contains(cli, sandboxEnvMarker+"=1") {
		t.Errorf("CLI path marker: %d values", n)
	}
	if got := tierValues(sandboxTierChildEnv(os.Environ(), []string{"/usr/bin/bwrap", "--"})); len(got) != 0 {
		t.Errorf("a wrap with no host helper kept an inherited tier %q", got)
	}
	dash := launchChildEnv(termsvc.LaunchRequest{Tool: "claude-code", Sandboxed: true, WrapArgv: wrap}, "tok")
	if got := tierValues(dash); !slices.Equal(got, []string{"none"}) {
		t.Errorf("dashboard path tier values %q, want [none]", got)
	}
	dash = launchChildEnv(termsvc.LaunchRequest{Tool: "claude-code", Sandboxed: true, WrapArgv: []string{"/usr/bin/bwrap", "--"}}, "tok")
	if got := tierValues(dash); len(got) != 0 {
		t.Errorf("dashboard path with no host helper kept an inherited tier %q", got)
	}
}

// countEnvKey counts env entries for key.
func countEnvKey(env []string, key string) int {
	n := 0
	for _, kv := range env {
		if strings.HasPrefix(kv, key+"=") {
			n++
		}
	}
	return n
}

// TestProjectionSeedTranscriptsAreAdapterWatchRoots (lane LEFT-SBX, G27):
// every transcript subtree a projection seed row registers is one of that
// tool's own adapter watch roots under the home, so the watcher reads what
// the box writes with the adapter that owns the shape.
func TestProjectionSeedTranscriptsAreAdapterWatchRoots(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	for _, s := range integration.ProjectionSeeds() {
		a, ok := defaults.ByTool(s.Tool)
		if !ok && slices.Contains(components.Omitted(), "adapter."+s.Tool) {
			continue // compiled out of this build (an sbo_omit_adapter_* tag, R-008)
		}
		if !ok {
			t.Errorf("%s: no adapter", s.Tool)
			continue
		}
		roots := a.WatchPaths()
		for _, tr := range s.Transcripts {
			if !slices.Contains(roots, filepath.Join(home, filepath.FromSlash(tr))) {
				t.Errorf("%s: transcript subtree %s is not an adapter watch root (%v)", s.Tool, tr, roots)
			}
		}
	}
}

// TestNativeManagedProbeShapes (lane LEFT-SBX, the sourced managed-policy
// rows): a probe merges its file with the drop-in directory beside it (a
// key counts when one document sets it true and none sets it otherwise), a
// TOML probe reads Codex's requirements.toml, and a LacksValue probe is true
// only when the list exists without the value. The rows themselves name a
// vendor source and a date.
func TestNativeManagedProbeShapes(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "managed-settings.json")
	drop := filepath.Join(dir, "managed-settings.d")
	if err := os.MkdirAll(drop, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(p, body string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	probe := integration.NativeSettingProbe{
		Paths: map[string]string{nativeGOOS: file}, DropIns: map[string]string{nativeGOOS: drop},
		Keys:      [][]string{{"sandbox", "enabled"}, {"sandbox", "failIfUnavailable"}},
		SourceURL: "https://example.com/doc", VerifiedOn: "2026-10-24",
	}
	write(file, `{"sandbox":{"enabled":true}}`)
	if nativeSettingTrue(probe) {
		t.Fatal("one key alone forced it")
	}
	write(filepath.Join(drop, "10-sandbox.json"), `{"sandbox":{"failIfUnavailable":true}}`)
	if !nativeSettingTrue(probe) {
		t.Fatal("the drop-in's key was not merged with the file's")
	}
	write(filepath.Join(drop, "20-team.json"), `{"sandbox":{"enabled":false}}`)
	if nativeSettingTrue(probe) {
		t.Fatal("a drop-in setting the key false was ignored")
	}
	// Last writer wins in sorted order (audit finding 7): a later drop-in
	// setting it true again overrides the earlier false.
	write(filepath.Join(drop, "30-later.json"), `{"sandbox":{"enabled":true}}`)
	if !nativeSettingTrue(probe) {
		t.Fatal("a later true after an earlier false was under-detected")
	}
	_ = os.Remove(filepath.Join(drop, "30-later.json"))
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(drop, "20-team.json"))
	write(filepath.Join(drop, "00-all.json"), `{"sandbox":{"enabled":true,"failIfUnavailable":true}}`)
	if !nativeSettingTrue(probe) {
		t.Fatal("drop-ins alone, with no file, were not read")
	}

	req := filepath.Join(dir, "requirements.toml")
	codex := integration.NativeSettingProbe{
		Paths: map[string]string{nativeGOOS: req}, Format: "toml",
		Keys: [][]string{{"allowed_sandbox_modes"}}, LacksValue: "danger-full-access",
		SourceURL: "https://example.com/src", VerifiedOn: "2026-10-24",
	}
	for body, forced := range map[string]bool{
		`allowed_sandbox_modes = ["read-only", "workspace-write"]`:                       true,
		`allowed_sandbox_modes = ["read-only", "workspace-write", "danger-full-access"]`: false,
		`allow_managed_hooks_only = true`:                                                false,
		`not toml [`:                                                                     false,
	} {
		write(req, body)
		if nativeSettingTrue(codex) != forced {
			t.Errorf("%q: forced %v, want %v", body, !forced, forced)
		}
	}

	for _, tool := range []string{"claude-code", "codex"} {
		n, _ := integration.NativeSandboxFor(tool)
		if len(n.Managed) == 0 {
			t.Errorf("%s: no managed-policy row", tool)
		}
		for _, m := range n.Managed {
			if !m.Grounded() || !strings.HasPrefix(m.SourceURL, "https://") {
				t.Errorf("%s: an unsourced managed-policy row %+v", tool, m)
			}
		}
	}
}
