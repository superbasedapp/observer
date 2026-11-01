//go:build linux && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/watcher"
)

// terminal_sandbox_oci_leftsbx_linux_test.go: lane LEFT-SBX milestone 3 on
// the container driver.

// TestOCIInstallGuestRunsOnlyPinnedScripts (lane LEFT-SBX, ruling P-136):
// the setup container's guest runs the installer, then the installed
// package's own lifecycle script only when its file hash is one the plan
// names, as `node <file>` in the package directory; a script no pin names
// exits 3 with the mismatch named and never runs; a plan with no script
// flags runs none whatever the package declares.
func TestOCIInstallGuestRunsOnlyPinnedScripts(t *testing.T) {
	bin := t.TempDir()
	marker := filepath.Join(t.TempDir(), "ran")
	// A fake node: records the script it was asked to run.
	if err := os.WriteFile(filepath.Join(bin, "node"), []byte("#!/bin/sh\necho \"$1\" >> "+marker+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	pkg := filepath.Join(t.TempDir(), "lib", "node_modules", "@v", "tool")
	if err := os.MkdirAll(pkg, 0o755); err != nil {
		t.Fatal(err)
	}
	script := []byte("console.log('place the binary')\n")
	if err := os.WriteFile(filepath.Join(pkg, "install.cjs"), script, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkg, "package.json"), []byte(`{"name":"@v/tool","scripts":{"postinstall":"node install.cjs"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(script)
	good := hex.EncodeToString(sum[:])
	sock := filepath.Join(relayShortDir(t), "gw.sock")
	run := func(extra ...string) int {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()
		args := append([]string{"--gateway", sock, "--port", strconv.Itoa(port)}, extra...)
		return runOCIInstallGuest(append(args, "--", "true"))
	}
	if code := run(sandboxoci.ScriptRunFlag, pkg, sandboxoci.ScriptSHAFlag, good); code != 0 {
		t.Fatalf("a pinned script: exit %d", code)
	}
	if b, _ := os.ReadFile(marker); string(b) != "install.cjs\n" {
		t.Fatalf("the pinned script ran as %q", b)
	}
	_ = os.Remove(marker)
	if code := run(sandboxoci.ScriptRunFlag, pkg, sandboxoci.ScriptSHAFlag, strings.Repeat("0", 64)); code != 3 {
		t.Fatalf("an unpinned script: exit %d, want 3", code)
	}
	if code := run(); code != 0 {
		t.Fatalf("no script flags: exit %d", code)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a script ran without a matching pin")
	}
	for _, bad := range [][]string{
		{"--gateway", sock, "--port", "1", sandboxoci.ScriptRunFlag, pkg, "--", "true"},
		{"--gateway", sock, "--port", "1", sandboxoci.ScriptSHAFlag, good, "--", "true"},
		{"--gateway", sock, "--port", "1", sandboxoci.ScriptRunFlag, "rel/dir", sandboxoci.ScriptSHAFlag, good, "--", "true"},
		{"--gateway", sock, "--port", "1", "--other", "x", "--", "true"},
	} {
		if _, err := parseOCIInstallArgs(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// TestBuiltinScriptPinsWellFormed: every install-source row that needs its
// own script ships at least one well-formed pin, and every pin names a
// lifecycle command of the one runnable shape; a row that needs no script
// ships none.
func TestBuiltinScriptPinsWellFormed(t *testing.T) {
	for _, src := range integration.InstallSources() {
		if !src.NeedsInstallScripts && len(src.ScriptPins) > 0 {
			t.Errorf("%s: pins on a source that needs no script", src.Tool)
		}
		if src.NeedsInstallScripts && len(src.ScriptPins) == 0 {
			t.Errorf("%s: needs its script but ships no pin", src.Tool)
		}
		for _, p := range src.ScriptPins {
			if why := sandboxoci.ValidScriptPin(sandboxoci.ScriptPin{Tool: src.Tool, Version: p.Version, SHA256: p.SHA256}); why != "" {
				t.Errorf("%s %s: %s", src.Tool, p.Version, why)
			}
			cmd := strings.Replace(p.Command, "node ./", "node ", 1)
			if cmd != "node "+p.File || p.Grounding == "" {
				t.Errorf("%s %s: command %q file %q", src.Tool, p.Version, p.Command, p.File)
			}
			// A script that reaches the network is pinned only when that
			// fetch is to a listed host of an exact pinned artifact, which
			// its grounding must say, and (ruling P-142) every artifact the
			// install fetches is pinned by its registry integrity: the
			// package itself and its platform packages.
			if p.Network && !strings.Contains(p.Grounding, "exact version") {
				t.Errorf("%s %s: a network-reaching script whose grounding does not name the exact pinned artifact", src.Tool, p.Version)
			}
			if p.Network != src.ScriptFetchesPackages {
				t.Errorf("%s %s: Network %v but the row's ScriptFetchesPackages is %v", src.Tool, p.Version, p.Network, src.ScriptFetchesPackages)
			}
			if p.Network && (len(p.Packages) < 2 || p.Packages[0].Name != src.Package || p.PackagesGrounding == "") {
				t.Errorf("%s %s: a network-reaching script must pin the package and its platform packages by integrity, with a grounding", src.Tool, p.Version)
			}
			for _, pk := range p.Packages {
				if why := sandboxoci.ValidPackagePin(sandboxoci.PackagePin{Name: pk.Name, Version: pk.Version, Integrity: pk.Integrity}); why != "" || pk.Version != p.Version {
					t.Errorf("%s %s: package pin %+v: %s", src.Tool, p.Version, pk, why)
				}
			}
		}
	}
}

// TestComposeSandboxManagedInstallScripts (ruling P-136): on a managed node
// with the body in force, the org's install_scripts floor lowers the mode,
// narrows the tool list and adds its signed pins (shown as the org's); a
// body with no install_scripts leaves the node's policy whole; the floor
// never turns install_cache on; and a governance pin on the key wins (the
// row is refused pinned_by_org, the pin's none stands).
func TestComposeSandboxManagedInstallScripts(t *testing.T) {
	local := config.TerminalSandboxConfig{OCI: config.TerminalSandboxOCIConfig{InstallScripts: "pinned", InstallScriptsTools: []string{"claude-code", "codex"}}}
	h := strings.Repeat("e", 64)
	body := orgcontract.SandboxManagedPolicyV1{Schema: orgcontract.SandboxManagedSchema, InstallScripts: &orgcontract.SandboxManagedInstallScriptsV1{
		Tools: []string{"claude-code"}, Pins: []orgcontract.SandboxManagedScriptPinV1{{Tool: "claude-code", Version: "2.1.311", SHA256: h, Note: "reviewed by security"}},
	}}
	eff, refused := composeSandboxManaged(local, body, sandboxManagedEnv{})
	if len(refused) != 0 || eff.OCI.InstallScripts != "pinned" || !slices.Equal(eff.OCI.InstallScriptsTools, []string{"claude-code"}) || eff.OCI.InstallCache {
		t.Fatalf("floor: %+v refused %v", eff.OCI, refused)
	}
	if len(eff.OCI.OrgInstallScriptPins) != 1 || eff.OCI.OrgInstallScriptPins[0].SHA256 != h || !strings.Contains(eff.OCI.OrgInstallScriptPins[0].Added, "organization") {
		t.Fatalf("org pins: %+v", eff.OCI.OrgInstallScriptPins)
	}
	d := &ociDriver{r: &sandboxRuntime{}, cfg: eff.OCI}
	if _, err := sandboxoci.DecideInstallScripts("claude-code", "2.1.311", true, d.ociScriptPolicy()); err != nil {
		t.Fatalf("an org pin is not honoured: %v", err)
	}
	pol := d.ociScriptPolicy()
	if pol.Pins[len(pol.Pins)-1].Source != sandboxoci.PinSourceOrg {
		t.Fatalf("the org pin's source: %+v", pol.Pins)
	}
	body.InstallScripts.Mode = "none"
	if eff, _ = composeSandboxManaged(local, body, sandboxManagedEnv{}); eff.OCI.InstallScripts != "none" {
		t.Fatalf("org none: %q", eff.OCI.InstallScripts)
	}
	none := local
	none.OCI.InstallScripts = "none"
	body.InstallScripts.Mode = "pinned"
	if eff, _ = composeSandboxManaged(none, body, sandboxManagedEnv{}); eff.OCI.InstallScripts != "none" {
		t.Fatalf("the org raised none to pinned: %q", eff.OCI.InstallScripts)
	}
	if eff, _ = composeSandboxManaged(local, orgcontract.SandboxManagedPolicyV1{Schema: orgcontract.SandboxManagedSchema}, sandboxManagedEnv{}); !slices.Equal(eff.OCI.InstallScriptsTools, local.OCI.InstallScriptsTools) || eff.OCI.OrgInstallScriptPins != nil {
		t.Fatalf("no install_scripts changed the node: %+v", eff.OCI)
	}
	pinnedEnv := sandboxManagedEnv{pinned: func(k string) bool { return k == "terminal.sandbox.oci.install_scripts" }}
	if _, refused = composeSandboxManaged(none, body, pinnedEnv); len(refused) != 1 || refused[0].Reason != sandboxRefusedPinned {
		t.Fatalf("a pinned key: %v", refused)
	}
}

// TestSandboxInstallScriptsDoctorLine: doctor says the effective mode and
// the pin counts only while install_cache is on.
func TestSandboxInstallScriptsDoctorLine(t *testing.T) {
	if got := sandboxInstallScriptsDoctorChecks(config.TerminalSandboxConfig{}); got != nil {
		t.Fatalf("install_cache off: %v", got)
	}
	got := sandboxInstallScriptsDoctorChecks(config.TerminalSandboxConfig{OCI: config.TerminalSandboxOCIConfig{InstallCache: true}})
	if len(got) != 1 || !strings.Contains(got[0].Message, "pinned") || !strings.Contains(got[0].Message, " built in, 0 yours") {
		t.Fatalf("default: %+v", got)
	}
	got = sandboxInstallScriptsDoctorChecks(config.TerminalSandboxConfig{OCI: config.TerminalSandboxOCIConfig{InstallCache: true, InstallScripts: "none"}})
	if len(got) != 1 || !strings.Contains(got[0].Message, "no package install script runs") {
		t.Fatalf("none: %+v", got)
	}
}

// TestOCIIngestUnwatchedKeepsCLITranscripts (lane LEFT-SBX, CLI runsc
// transcripts): a run no watcher took (a CLI launch) has its projection's
// transcripts read once into the daemon's database by the helper before
// the projection is removed, bound to the run; a watched run reads nothing
// here (the daemon's watcher has them).
func TestOCIIngestUnwatchedKeepsCLITranscripts(t *testing.T) {
	obs := relayShortDir(t)
	// The Claude Code adapter, selected where this edition leaves it
	// inactive by default (managed): the helper reads with that adapter.
	cfgPath := writeRelayConfig(t, obs, selectionTOMLIfInactive(t, components.AdapterID("claude-code")))
	host := filepath.Join(t.TempDir(), "run1.state", "0", "projects")
	if err := os.MkdirAll(filepath.Join(host, "-ws"), 0o700); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join("..", "..", "testdata", "claudecode", "simple-session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(host, "-ws", "session.jsonl"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	// The box mounts the home at its own path, so the box path is the
	// adapter's own root under the home.
	home := t.TempDir()
	t.Setenv("HOME", home)
	box := filepath.Join(home, ".claude", "projects")
	plan := ociPlanFile{
		ConfigPath: cfgPath, Tool: "claude-code",
		Transcripts: []sandboxoci.TranscriptRoot{{Host: host, Box: box}},
		Create:      sandboxoci.CreatePlan{RunID: "run0000000000000001", WorkDir: t.TempDir()},
	}
	var out strings.Builder
	calls := 0
	prev := ociIngestProjectionFn
	t.Cleanup(func() { ociIngestProjectionFn = prev })
	ociIngestProjectionFn = func(ctx context.Context, cfg, tool string, root sandboxoci.TranscriptRoot, bind watcher.ProjectionBinding) (int, error) {
		calls++
		return prev(ctx, cfg, tool, root, bind)
	}
	plan.TranscriptsWatched = true
	ociIngestUnwatched(plan, ociTerm{out: &out})
	if calls != 0 {
		t.Fatal("a watched run was read again by the helper")
	}
	plan.TranscriptsWatched = false
	ociIngestUnwatched(plan, ociTerm{out: &out})
	if calls != 1 || out.Len() != 0 {
		t.Fatalf("calls %d, terminal %q", calls, out.String())
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	database, err := db.Open(context.Background(), db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	if n, _ := store.New(database).CountActions(context.Background()); n == 0 {
		t.Fatal("the CLI run's transcript was not ingested")
	}
	plan.ConfigPath = ""
	ociIngestUnwatched(plan, ociTerm{out: &out})
	if !strings.Contains(out.String(), "not kept") {
		t.Fatalf("a plan with no config said nothing: %q", out.String())
	}
}

// TestOCISweepReturnRepos (lane LEFT-SBX): the daemon-start sweep removes a
// clone-remote return repository whose run ended with nothing returned, or
// whose returned ref is older than the retention bound; it keeps one whose
// run is live (a return may be in flight) and one still to be fetched, and
// never follows a symlink at the name.
func TestOCISweepReturnRepos(t *testing.T) {
	managed := t.TempDir()
	now := time.Now()
	mk := func(id string, withRef bool, age time.Duration) string {
		repo := filepath.Join(managed, id+".return.git")
		ref := filepath.Join(repo, "refs", "observer", "sandbox")
		if err := os.MkdirAll(ref, 0o700); err != nil {
			t.Fatal(err)
		}
		if withRef {
			if err := os.WriteFile(filepath.Join(ref, id), []byte(strings.Repeat("a", 40)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		old := now.Add(-age)
		for _, p := range []string{filepath.Join(ref, id), repo} {
			_ = os.Chtimes(p, old, old)
		}
		return repo
	}
	empty := mk("runEmpty00000001", false, time.Hour)
	fresh := mk("runFresh00000001", true, 24*time.Hour)
	stale := mk("runStale00000001", true, 40*24*time.Hour)
	live := mk("runLive000000001", false, 90*24*time.Hour)
	packed := mk("runPacked0000001", false, time.Hour)
	if err := os.WriteFile(filepath.Join(packed, "packed-refs"), []byte("# pack-refs\n"+strings.Repeat("b", 40)+" refs/observer/sandbox/runPacked0000001\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(managed, "runLink000000001.return.git")); err != nil {
		t.Fatal(err)
	}
	n, err := ociSweepReturnRepos(managed, func(id string) bool { return id == "runLive000000001" }, now, ociReturnRepoRetention(0))
	if err != nil || n != 2 {
		t.Fatalf("removed %d, %v; want 2", n, err)
	}
	for p, want := range map[string]bool{empty: false, stale: false, fresh: true, live: true, packed: true, target: true} {
		if _, err := os.Lstat(p); (err == nil) != want {
			t.Errorf("%s: present %v, want %v", p, err == nil, want)
		}
	}
	if ociReturnRepoRetention(7) != 7*24*time.Hour {
		t.Error("workspace_retention_days does not bound the return repositories")
	}
}

// TestOCIInstallGuestChecksPackageIntegrity (ruling P-142, the LEFT-SBX
// merge's audit finding 6): before the guest runs a pinned script whose
// install fetches more packages, every fetched artifact must match a pin by
// name, version and registry integrity (the sha512 of a file in the setup
// container's own npm cache). A tarball that is not the pinned one, or no
// platform package placed (the script would fetch one itself), exits 3
// with the package named, and no script runs.
func TestOCIInstallGuestChecksPackageIntegrity(t *testing.T) {
	bin := t.TempDir()
	marker := filepath.Join(t.TempDir(), "ran")
	if err := os.WriteFile(filepath.Join(bin, "node"), []byte("#!/bin/sh\necho \"$1\" >> "+marker+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	cache := t.TempDir()
	old := ociGuestNPMCache
	ociGuestNPMCache = cache
	t.Cleanup(func() { ociGuestNPMCache = old })
	prefix := t.TempDir()
	pkg := filepath.Join(prefix, "lib", "node_modules", "tool")
	plat := filepath.Join(pkg, "node_modules", "tool-linux-x64")
	if err := os.MkdirAll(plat, 0o755); err != nil {
		t.Fatal(err)
	}
	script := []byte("console.log('place the binary')\n")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(pkg, "postinstall.mjs"), script, 0o600))
	must(os.WriteFile(filepath.Join(pkg, "package.json"), []byte(`{"name":"tool","version":"1.0.0","optionalDependencies":{"tool-linux-x64":"1.0.0","tool-darwin-arm64":"1.0.0"},"scripts":{"postinstall":"node ./postinstall.mjs"}}`), 0o600))
	must(os.WriteFile(filepath.Join(plat, "package.json"), []byte(`{"name":"tool-linux-x64","version":"1.0.0"}`), 0o600))
	put := func(content string) string {
		sum := sha512.Sum512([]byte(content))
		integ := "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
		rel, _, err := sandboxoci.IntegrityContentPath(integ)
		must(err)
		p := filepath.Join(cache, "_cacache", filepath.FromSlash(rel))
		must(os.MkdirAll(filepath.Dir(p), 0o755))
		must(os.WriteFile(p, []byte(content), 0o400))
		return integ
	}
	mainInt, platInt := put("main tarball"), put("platform tarball")
	darwinSum := sha512.Sum512([]byte("darwin tarball"))
	darwinInt := "sha512-" + base64.StdEncoding.EncodeToString(darwinSum[:])
	sum := sha256.Sum256(script)
	good := hex.EncodeToString(sum[:])
	sock := filepath.Join(relayShortDir(t), "gw.sock")
	flags := []string{
		sandboxoci.ScriptRunFlag, pkg, sandboxoci.ScriptSHAFlag, good,
		sandboxoci.PackageIntegrityFlag, "tool@1.0.0=" + mainInt,
		sandboxoci.PackageIntegrityFlag, "tool-linux-x64@1.0.0=" + platInt,
		sandboxoci.PackageIntegrityFlag, "tool-darwin-arm64@1.0.0=" + darwinInt,
	}
	run := func() int {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		must(err)
		port := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()
		args := append([]string{"--gateway", sock, "--port", strconv.Itoa(port)}, flags...)
		return runOCIInstallGuest(append(args, "--", "true"))
	}
	if code := run(); code != 0 {
		t.Fatalf("every fetched artifact pinned: exit %d", code)
	}
	if b, _ := os.ReadFile(marker); string(b) != "postinstall.mjs\n" {
		t.Fatalf("the pinned script ran as %q", b)
	}
	_ = os.Remove(marker)
	// The platform tarball npm fetched is not the pinned one.
	rel, _, _ := sandboxoci.IntegrityContentPath(platInt)
	must(os.Chmod(filepath.Join(cache, "_cacache", filepath.FromSlash(rel)), 0o600))
	must(os.WriteFile(filepath.Join(cache, "_cacache", filepath.FromSlash(rel)), []byte("swapped"), 0o600))
	if code := run(); code != 3 {
		t.Fatalf("a swapped platform tarball: exit %d, want 3", code)
	}
	must(os.WriteFile(filepath.Join(cache, "_cacache", filepath.FromSlash(rel)), []byte("platform tarball"), 0o600))
	// No platform package placed: the script would fetch one itself.
	must(os.RemoveAll(plat))
	if code := run(); code != 3 {
		t.Fatalf("no platform package placed: exit %d, want 3", code)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a script ran although a fetched artifact was not the pinned one")
	}
	for _, bad := range [][]string{
		{"--gateway", sock, "--port", "1", sandboxoci.PackageIntegrityFlag, "tool@1.0.0=" + mainInt, "--", "true"},
		{"--gateway", sock, "--port", "1", sandboxoci.ScriptRunFlag, pkg, sandboxoci.ScriptSHAFlag, good, sandboxoci.PackageIntegrityFlag, "tool@1.0.0=sha1-x", "--", "true"},
	} {
		if _, err := parseOCIInstallArgs(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
