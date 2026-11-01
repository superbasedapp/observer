//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

func managedBody(t *testing.T, p orgcontract.SandboxManagedPolicyV1) []byte {
	t.Helper()
	p.Schema = orgcontract.SandboxManagedSchema
	raw, err := orgcontract.MarshalSandboxManagedPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func ptr[T any](v T) *T { return &v }

// resetSandboxManaged clears the process overlay after a test.
func resetSandboxManaged(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		processSandboxManaged.observe(orgclient.ManagedPullOutcome{})
		processSandboxManaged.bindGovernance(nil)
	})
}

// TestComposeSandboxManaged walks the composition table: every key the body
// sets replaces the local value, a key it leaves out keeps it, and the
// floor (min_isolation) and the keys not on the pull never move.
func TestComposeSandboxManaged(t *testing.T) {
	local := config.TerminalSandboxConfig{
		Enabled: false, Backend: "bwrap", HomeMode: "tmpfs", Egress: "internet", MinIsolation: "process",
		PrepTimeoutSeconds: 300, AllowWorktreeSource: false, WorkspaceRetentionDays: 0,
	}
	p := orgcontract.SandboxManagedPolicyV1{
		Schema: orgcontract.SandboxManagedSchema, Enabled: ptr(true), Backends: &[]string{"bwrap"}, DefaultOn: ptr(true),
		Egress: ptr("proxy_only"), AllowRemoteClone: ptr(true), RemoteAllowedHosts: &[]string{"github.com"},
		WorkspaceRetentionDays: ptr(14), PrepTimeoutSeconds: ptr(600), MaskPaths: &[]string{nativeAbs("/mnt/c")},
	}
	got, refused := composeSandboxManaged(local, p, sandboxManagedEnv{})
	if len(refused) != 0 {
		t.Fatalf("nothing should be refused: %+v", refused)
	}
	want := local
	want.Enabled, want.Backends, want.DefaultOn, want.Egress = true, []string{"bwrap"}, true, "proxy_only"
	want.AllowRemoteClone, want.RemoteAllowedHosts = true, []string{"github.com"}
	want.WorkspaceRetentionDays, want.PrepTimeoutSeconds, want.MaskPaths = 14, 600, []string{nativeAbs("/mnt/c")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("compose:\n got %+v\nwant %+v", got, want)
	}
	// Absent keys keep the local values.
	if got, _ := composeSandboxManaged(local, orgcontract.SandboxManagedPolicyV1{Schema: orgcontract.SandboxManagedSchema}, sandboxManagedEnv{}); !reflect.DeepEqual(got, local) {
		t.Fatalf("a schema-only body must change nothing: %+v", got)
	}
	// The only path that shortens retention: a finite value onto forever.
	if got.WorkspaceRetentionDays != 14 || local.WorkspaceRetentionDays != 0 {
		t.Fatal("retention")
	}
}

// TestComposeSandboxManagedEmptyBackendsEnablesNothing: an empty managed list
// leaves no backend enabled, even with the local legacy backend set.
func TestComposeSandboxManagedEmptyBackendsEnablesNothing(t *testing.T) {
	local := config.TerminalSandboxConfig{Enabled: true, Backend: "bwrap", Backends: []string{"bwrap"}}
	got, _ := composeSandboxManaged(local, orgcontract.SandboxManagedPolicyV1{
		Schema: orgcontract.SandboxManagedSchema, Enabled: ptr(true), Backends: &[]string{},
	}, sandboxManagedEnv{})
	if got.Enabled || len(got.Backends) != 0 {
		t.Fatalf("an empty backend list must enable nothing: %+v", got)
	}
}

// TestComposeSandboxManagedPinsWin: a key the org pinned keeps its pinned
// value and is reported.
func TestComposeSandboxManagedPinsWin(t *testing.T) {
	local := config.TerminalSandboxConfig{AllowRemoteClone: false}
	got, refused := composeSandboxManaged(local, orgcontract.SandboxManagedPolicyV1{
		Schema: orgcontract.SandboxManagedSchema, AllowRemoteClone: ptr(true),
	}, sandboxManagedEnv{pinned: func(k string) bool { return k == "terminal.sandbox.allow_remote_clone" }})
	if got.AllowRemoteClone || len(refused) != 1 || refused[0].Reason != sandboxRefusedPinned {
		t.Fatalf("a pin must win: %+v %+v", got, refused)
	}
}

// TestComposeSandboxManagedNodePathRules: per-node paths get the bind-plan
// rules a local value gets, and a refused key keeps the local value.
func TestComposeSandboxManagedNodePathRules(t *testing.T) {
	dir := t.TempDir()
	obs := filepath.Join(dir, "observer")
	if err := os.MkdirAll(filepath.Join(obs, "workspaces"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link-to-observer")
	if err := testSymlink(t, obs, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	env := sandboxManagedEnv{observerDir: obs, resolve: resolveSandboxBindPath}
	// The same rules on every node, each spelled for its OS: a whole root
	// is "/" on POSIX and a drive root on Windows (the product refused only
	// "/" before, so a Windows node took a writable bind of C:\).
	root, srv, sep := "/", "/srv", "/"
	if runtime.GOOS == "windows" {
		root, srv, sep = `C:\`, `C:\srv`, `\`
	}
	local := config.TerminalSandboxConfig{ExtraRWBinds: []string{srv + sep + "local"}, WorkspacesDir: srv + sep + "ws"}
	// On Windows the test's temp folder lies under the profile's AppData,
	// which a write bind may never name, so the workspaces bind there is
	// refused as sensitive; elsewhere it applies.
	fineKey, fineWant := "", ""
	if runtime.GOOS == "windows" && strings.Contains(strings.ToLower(obs), `\appdata\`) {
		fineKey, fineWant = "terminal.sandbox.extra_rw_binds", sandboxRefusedSensitive
	}
	cases := []struct {
		name string
		node orgcontract.SandboxManagedNodeV1
		key  string
		want string
	}{
		{"rw bind of the observer dir", orgcontract.SandboxManagedNodeV1{ExtraRWBinds: &[]string{obs}}, "terminal.sandbox.extra_rw_binds", sandboxRefusedObserverDir},
		{"rw bind of a parent", orgcontract.SandboxManagedNodeV1{ExtraRWBinds: &[]string{dir}}, "terminal.sandbox.extra_rw_binds", sandboxRefusedObserverDir},
		{"ro bind through a symlink", orgcontract.SandboxManagedNodeV1{ExtraROBinds: &[]string{link}}, "terminal.sandbox.extra_ro_binds", sandboxRefusedObserverDir},
		{"rw whole root", orgcontract.SandboxManagedNodeV1{ExtraRWBinds: &[]string{root}}, "terminal.sandbox.extra_rw_binds", sandboxRefusedWholeRoot},
		{"dot dot", orgcontract.SandboxManagedNodeV1{ExtraROBinds: &[]string{srv + sep + ".." + sep + "etc"}}, "terminal.sandbox.extra_ro_binds", sandboxRefusedDotDot},
		{"leading dash", orgcontract.SandboxManagedNodeV1{ExtraROBinds: &[]string{"-" + srv}}, "terminal.sandbox.extra_ro_binds", sandboxRefusedLeadingDash},
		{"whitespace", orgcontract.SandboxManagedNodeV1{ExtraROBinds: &[]string{srv + sep + "a b"}}, "terminal.sandbox.extra_ro_binds", sandboxRefusedBadCharacter},
		{"inside the workspaces tree is fine", orgcontract.SandboxManagedNodeV1{ExtraRWBinds: &[]string{filepath.Join(obs, "workspaces")}}, fineKey, fineWant},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			node := tc.node
			got, refused := composeSandboxManaged(local, orgcontract.SandboxManagedPolicyV1{Schema: orgcontract.SandboxManagedSchema, Node: &node}, env)
			if tc.want == "" {
				if len(refused) != 0 {
					t.Fatalf("want applied: %+v", refused)
				}
				return
			}
			if len(refused) != 1 || refused[0].Key != tc.key || refused[0].Reason != tc.want {
				t.Fatalf("want %s refused (%s), got %+v", tc.key, tc.want, refused)
			}
			if !reflect.DeepEqual(got, local) {
				t.Fatalf("a refused override must keep the local value: %+v", got)
			}
		})
	}
	// A CIDR outside the allow-listable private ranges is refused on the node.
	_, refused := composeSandboxManaged(local, orgcontract.SandboxManagedPolicyV1{
		Schema: orgcontract.SandboxManagedSchema, EgressAllowCIDRs: &[]string{"8.8.8.0/24"},
	}, env)
	if len(refused) != 1 || refused[0].Reason != sandboxRefusedCIDRNotAllowable {
		t.Fatalf("a public CIDR must be refused: %+v", refused)
	}
}

type fixedGov struct{ eff govern.Effective }

func (f fixedGov) Effective(context.Context) govern.Effective { return f.eff }

// TestSandboxManagedOverlay: the overlay applies a body only while it is in
// force and unexpired; anything else leaves the local block whole, and every
// change moves the generation the sandbox holder watches.
func TestSandboxManagedOverlay(t *testing.T) {
	resetSandboxManaged(t)
	full := config.Config{}
	full.Terminal.Sandbox = config.TerminalSandboxConfig{Enabled: false, Backend: "bwrap", Egress: "internet"}
	body := managedBody(t, orgcontract.SandboxManagedPolicyV1{Enabled: ptr(true), Egress: ptr("proxy_only")})
	future := time.Now().Add(time.Hour).Unix()

	var seen uint64
	sandboxManagedChanged(&seen)
	processSandboxManaged.observe(orgclient.ManagedPullOutcome{Rail: "sandbox", InForce: true, Version: 2, ExpiresAt: future, Body: body})
	if !sandboxManagedChanged(&seen) {
		t.Fatal("an in-force body must move the generation")
	}
	if got := effectiveSandboxConfig(full); !got.Enabled || got.Egress != "proxy_only" {
		t.Fatalf("in force: %+v", got)
	}
	if sandboxManagedChanged(&seen) {
		t.Fatal("no change, no generation move")
	}
	// The same document, now not preauthorized (a revoked authority).
	processSandboxManaged.observe(orgclient.ManagedPullOutcome{Rail: "sandbox", InForce: false, Version: 2, ExpiresAt: future, Body: body})
	if got := effectiveSandboxConfig(full); !reflect.DeepEqual(got, full.Terminal.Sandbox) || !sandboxManagedChanged(&seen) {
		t.Fatalf("not preauthorized must leave the local values: %+v", got)
	}
	// In force but past its expiry at read time.
	processSandboxManaged.observe(orgclient.ManagedPullOutcome{Rail: "sandbox", InForce: true, Version: 3, ExpiresAt: time.Now().Add(-time.Second).Unix(), Body: body})
	if got := effectiveSandboxConfig(full); !reflect.DeepEqual(got, full.Terminal.Sandbox) {
		t.Fatalf("expired must leave the local values: %+v", got)
	}
	// In force but a body that does not validate.
	processSandboxManaged.observe(orgclient.ManagedPullOutcome{Rail: "sandbox", InForce: true, Version: 4, ExpiresAt: future, Body: []byte(`{"schema":"sbo-sandbox-managed-v1","allow_reduced_capture":true}`)})
	if got := effectiveSandboxConfig(full); !reflect.DeepEqual(got, full.Terminal.Sandbox) {
		t.Fatalf("an invalid body must leave the local values: %+v", got)
	}
	// Cleared (the kit reports InForce false and no body).
	processSandboxManaged.observe(orgclient.ManagedPullOutcome{Rail: "sandbox", InForce: true, Version: 5, ExpiresAt: future, Body: body})
	processSandboxManaged.observe(orgclient.ManagedPullOutcome{Rail: "sandbox", State: orgclient.ManagedPullStateCleared})
	if got := effectiveSandboxConfig(full); got.Enabled {
		t.Fatalf("a clear must drop the managed values: %+v", got)
	}
	// Pins from the bound grant win over the body. A pin the overlay applies
	// (prep_timeout_seconds) keeps the loaded value; a pin it skips (egress is
	// not a pinnable key) is not applicable for that key only, so the body
	// sets it (the SBX-P1B semantics).
	full.Terminal.Sandbox.PrepTimeoutSeconds = 300
	pinBody := managedBody(t, orgcontract.SandboxManagedPolicyV1{Enabled: ptr(true), Egress: ptr("proxy_only"), PrepTimeoutSeconds: ptr(600)})
	processSandboxManaged.bindGovernance(fixedGov{govern.Effective{Active: true, Pinned: map[string]any{
		"terminal.sandbox.prep_timeout_seconds": float64(300), "terminal.sandbox.egress": "internet",
	}}})
	processSandboxManaged.observe(orgclient.ManagedPullOutcome{Rail: "sandbox", InForce: true, Version: 6, ExpiresAt: future, Body: pinBody})
	if got := effectiveSandboxConfig(full); !got.Enabled || got.PrepTimeoutSeconds != 300 || got.Egress != "proxy_only" {
		t.Fatalf("a pinned key keeps its pin, a skipped pin does not bind: %+v", got)
	}
}

// TestComposeSandboxManagedKeepsEmptiedPinSemantics: the body composes with
// pins as the SBX-P1B overlay applies them. An empty host intersection forces
// allow_remote_clone=false, which the body may not turn back on; an emptied
// backends filter (PinnedNoBackend) keeps backends pinned; an empty managed
// backend list never switches off a pinned enabled.
func TestComposeSandboxManagedKeepsEmptiedPinSemantics(t *testing.T) {
	local := config.Config{}
	local.Terminal.Sandbox = config.TerminalSandboxConfig{
		Enabled: true, Backends: []string{"bwrap"}, AllowRemoteClone: true, RemoteAllowedHosts: []string{"gitlab.com"},
	}
	pins := map[string]any{
		"terminal.sandbox.remote_allowed_hosts": []any{"github.com"},
		"terminal.sandbox.backends":             []any{"oci-runc"},
	}
	governed, out := config.ApplyGovernancePinsTo(local, pins)
	if governed.Terminal.Sandbox.AllowRemoteClone || governed.Terminal.Sandbox.PinnedNoBackend == "" {
		t.Fatalf("the overlay: %+v (%+v)", governed.Terminal.Sandbox, out)
	}
	body := orgcontract.SandboxManagedPolicyV1{
		Schema: orgcontract.SandboxManagedSchema, AllowRemoteClone: ptr(true), Backends: &[]string{"bwrap"}, DefaultOn: ptr(true),
	}
	got, refused := composeSandboxManaged(governed.Terminal.Sandbox, body, sandboxManagedEnv{pinned: sandboxPinnedSet(governed, pins)})
	if got.AllowRemoteClone || got.PinnedNoBackend == "" || len(got.Backends) != 0 || !got.DefaultOn {
		t.Fatalf("emptied pins must hold, the unpinned key applies: %+v", got)
	}
	keys := map[string]string{}
	for _, r := range refused {
		keys[r.Key] = r.Reason
	}
	if keys["terminal.sandbox.allow_remote_clone"] != sandboxRefusedPinned || keys["terminal.sandbox.backends"] != sandboxRefusedPinned {
		t.Fatalf("refused: %+v", refused)
	}
	// An empty managed backend list never overrides a pinned enabled.
	pinnedEnabled := func(k string) bool { return k == "terminal.sandbox.enabled" }
	got, refused = composeSandboxManaged(config.TerminalSandboxConfig{Enabled: true, Backend: "bwrap"},
		orgcontract.SandboxManagedPolicyV1{Schema: orgcontract.SandboxManagedSchema, Backends: &[]string{}}, sandboxManagedEnv{pinned: pinnedEnabled})
	if !got.Enabled || len(refused) != 1 || refused[0].Reason != sandboxRefusedPinnedEnabled {
		t.Fatalf("an empty list must not switch off a pinned enabled: %+v %+v", got, refused)
	}
}

// TestComposeSandboxManagedMaskPathsAdd: managed masks add to the
// developer's own, never replace them.
func TestComposeSandboxManagedMaskPathsAdd(t *testing.T) {
	sec, c, d := nativeAbs("/srv/secret"), nativeAbs("/mnt/c"), nativeAbs("/mnt/d")
	got, refused := composeSandboxManaged(config.TerminalSandboxConfig{MaskPaths: []string{sec, c}},
		orgcontract.SandboxManagedPolicyV1{Schema: orgcontract.SandboxManagedSchema, MaskPaths: &[]string{c, d}}, sandboxManagedEnv{})
	if len(refused) != 0 || !reflect.DeepEqual(got.MaskPaths, []string{sec, c, d}) {
		t.Fatalf("mask union: %v %+v", got.MaskPaths, refused)
	}
}

// TestComposeSandboxManagedSensitiveWriteBinds is the node half of the bind
// decision: a body naming a sensitive location under the node's REAL home is
// refused for that key with its reason, a path under ~/.config passes only
// when the developer already binds it, and read-only binds and a project
// write bind pass.
func TestComposeSandboxManagedSensitiveWriteBinds(t *testing.T) {
	// A home under %LOCALAPPDATA% (t.TempDir on Windows) is itself inside a
	// sensitive location there, so the home is a never-created drive path.
	home := nonSensitiveTestDir(t)
	env := sandboxManagedEnv{
		home: home, observerDir: filepath.Join(home, ".observer"), resolve: resolveSandboxBindPath,
		localRWBinds: []string{filepath.Join(home, ".config", "gh")},
	}
	cases := []struct {
		name string
		node orgcontract.SandboxManagedNodeV1
		want string
	}{
		{"ssh", orgcontract.SandboxManagedNodeV1{ExtraRWBinds: &[]string{filepath.Join(home, ".ssh")}}, sandboxRefusedSensitive},
		{"bashrc", orgcontract.SandboxManagedNodeV1{ExtraRWBinds: &[]string{filepath.Join(home, ".bashrc")}}, sandboxRefusedSensitive},
		{"config not bound locally", orgcontract.SandboxManagedNodeV1{ExtraRWBinds: &[]string{filepath.Join(home, ".config", "other")}}, sandboxRefusedSensitive},
		{"config bound locally", orgcontract.SandboxManagedNodeV1{ExtraRWBinds: &[]string{filepath.Join(home, ".config", "gh", "hosts")}}, ""},
		{"project", orgcontract.SandboxManagedNodeV1{ExtraRWBinds: &[]string{filepath.Join(home, "proj")}}, ""},
		{"read-only ssh", orgcontract.SandboxManagedNodeV1{ExtraROBinds: &[]string{filepath.Join(home, ".ssh")}}, ""},
		{"a parent of .local/bin", orgcontract.SandboxManagedNodeV1{ExtraRWBinds: &[]string{filepath.Join(home, ".local")}}, sandboxRefusedSensitive},
		{"a .git directory", orgcontract.SandboxManagedNodeV1{ExtraRWBinds: &[]string{filepath.Join(home, "proj", ".git")}}, sandboxRefusedSensitive},
	}
	// "/" is the POSIX filesystem root; on Windows it is not an absolute
	// path at all (refused not_absolute), so the case is POSIX-only (the
	// PT-02 pattern, SBX-P2E audit finding 9).
	if runtime.GOOS != "windows" {
		cases = append(cases, struct {
			name string
			node orgcontract.SandboxManagedNodeV1
			want string
		}{"the filesystem root", orgcontract.SandboxManagedNodeV1{ExtraRWBinds: &[]string{"/"}}, sandboxRefusedWholeRoot})
		// /etc is a POSIX system location (on Windows "/etc/ssh" is not
		// absolute and is refused not_absolute instead).
		cases = append(cases, struct {
			name string
			node orgcontract.SandboxManagedNodeV1
			want string
		}{"etc", orgcontract.SandboxManagedNodeV1{ExtraRWBinds: &[]string{"/etc/ssh"}}, sandboxRefusedSensitive})
	}
	for _, tc := range cases {
		node := tc.node
		_, refused := composeSandboxManaged(config.TerminalSandboxConfig{}, orgcontract.SandboxManagedPolicyV1{Schema: orgcontract.SandboxManagedSchema, Node: &node}, env)
		switch {
		case tc.want == "" && len(refused) != 0:
			t.Errorf("%s: want applied, got %+v", tc.name, refused)
		case tc.want != "" && (len(refused) != 1 || refused[0].Reason != tc.want):
			t.Errorf("%s: want %s, got %+v", tc.name, tc.want, refused)
		}
	}
	// An ancestor of a denied location exposes it (ruling P-050): the home
	// itself and its parents are refused as write binds, read-only they
	// pass. The Observer directory sits outside this home, so the rule
	// refusing is the sensitive one, not the observer-dir one.
	ancEnv := env
	ancEnv.observerDir = "/nonexistent-sbx-p2e/obs"
	for _, tc := range []struct {
		name string
		node orgcontract.SandboxManagedNodeV1
		want string
	}{
		{"the real home itself", orgcontract.SandboxManagedNodeV1{ExtraRWBinds: &[]string{home}}, sandboxRefusedSensitive},
		{"a parent of the real home", orgcontract.SandboxManagedNodeV1{ExtraRWBinds: &[]string{filepath.Dir(home)}}, sandboxRefusedSensitive},
		{"read-only home", orgcontract.SandboxManagedNodeV1{ExtraROBinds: &[]string{home}}, ""},
		{"a project under the home", orgcontract.SandboxManagedNodeV1{ExtraRWBinds: &[]string{filepath.Join(home, "proj")}}, ""},
	} {
		node := tc.node
		_, refused := composeSandboxManaged(config.TerminalSandboxConfig{}, orgcontract.SandboxManagedPolicyV1{Schema: orgcontract.SandboxManagedSchema, Node: &node}, ancEnv)
		switch {
		case tc.want == "" && len(refused) != 0:
			t.Errorf("%s: want applied, got %+v", tc.name, refused)
		case tc.want != "" && (len(refused) != 1 || refused[0].Reason != tc.want):
			t.Errorf("%s: want %s, got %+v", tc.name, tc.want, refused)
		}
	}
	// The literal ~/.ssh spelling never reaches composition: the node refuses
	// the whole body at decode, naming why.
	raw := []byte(`{"schema":"sbo-sandbox-managed-v1","node":{"extra_rw_binds":["~/.ssh"]}}`)
	if _, err := orgcontract.DecodeSandboxManagedPolicy(raw); err == nil || !strings.Contains(err.Error(), sandboxRefusedSensitive) {
		t.Fatalf("a body naming ~/.ssh: %v", err)
	}
}

// TestCLISandboxManagedUsesTheSidecarPins is SBX-P1C merge finding 2: the CLI
// path (`--observer-sandbox`, `observer sandbox status`) composes with the
// governance sidecar's pins in force, the map config.Load applied, so a key
// the org pinned keeps its pinned value against a body that tries to change
// it, exactly as on the daemon path. An empty grant (the old CLI path) would
// have let the body win.
func TestCLISandboxManagedUsesTheSidecarPins(t *testing.T) {
	dbDir := t.TempDir()
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	toml := "[observer]\ndb_path = \"" + filepath.ToSlash(filepath.Join(dbDir, "observer.db")) + "\"\n" +
		"[terminal.sandbox]\nprep_timeout_seconds = 300\nallow_remote_clone = true\nremote_allowed_hosts = [\"gitlab.com\"]\n"
	if err := os.WriteFile(cfgPath, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	sidecar := `{"schema":1,"state":"applied","pinned":{"terminal.sandbox.prep_timeout_seconds":120,"terminal.sandbox.remote_allowed_hosts":["github.com"]}}`
	if err := os.WriteFile(filepath.Join(dbDir, config.GovernanceSidecarFilename), []byte(sidecar), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, gov, err := config.LoadGovernance(config.LoadOptions{GlobalPath: cfgPath, Env: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Terminal.Sandbox.PrepTimeoutSeconds != 120 || cfg.Terminal.Sandbox.AllowRemoteClone || len(gov.PinsInForce) != 2 {
		t.Fatalf("the loaded config: %+v pins %v", cfg.Terminal.Sandbox, gov.PinsInForce)
	}
	body := orgcontract.SandboxManagedPolicyV1{
		Schema: orgcontract.SandboxManagedSchema, PrepTimeoutSeconds: ptr(600), AllowRemoteClone: ptr(true), DefaultOn: ptr(true),
	}
	got, refused := composeSandboxManaged(cfg.Terminal.Sandbox, body, sandboxManagedEnvFor(cfg, gov.PinsInForce))
	if got.PrepTimeoutSeconds != 120 || got.AllowRemoteClone || !got.DefaultOn || len(refused) != 2 {
		t.Fatalf("pinned keys must win on the CLI path: %+v %+v", got, refused)
	}
	if old, _ := composeSandboxManaged(cfg.Terminal.Sandbox, body, sandboxManagedEnvFor(cfg, nil)); old.PrepTimeoutSeconds != 600 {
		t.Fatalf("control: with no pins the body sets the key: %+v", old)
	}
}

// TestSandboxManagedRegistersOnlyWhenActive: the consumer is registered, and
// its sink is offered only while the module is active.
func TestSandboxManagedRegistersOnlyWhenActive(t *testing.T) {
	found := false
	for _, c := range managedPullConsumers {
		if c.rail == sandboxManagedRail {
			found = true
		}
	}
	if !found || !sandboxManagedCompiled {
		t.Fatal("the sandbox consumer must register in a build with the module")
	}
	off := config.Config{}
	off.Components.Remove = []string{sandboxComponent}
	if _, ok := managedPullSinks(componentSnapshotForConfig(off))[sandboxManagedRail]; ok {
		t.Fatal("an inactive sandbox module must register no sink (no request)")
	}
}

// TestDecideSandboxRailState walks the status rows.
func TestDecideSandboxRailState(t *testing.T) {
	now := time.Now().Unix()
	inForce := orgclient.ManagedPullOutcome{InForce: true, Version: 3, ExpiresAt: now + 60}
	cases := []struct {
		f    sandboxRailFacts
		want string
	}{
		{sandboxRailFacts{now: now}, sandboxRailNotEnrolled},
		{sandboxRailFacts{enrolled: true, now: now}, sandboxRailNotSupported},
		{sandboxRailFacts{enrolled: true, haveRow: true, tombstone: true, now: now}, sandboxRailCleared},
		{sandboxRailFacts{enrolled: true, haveRow: true, now: now}, sandboxRailUnverified},
		{sandboxRailFacts{enrolled: true, haveRow: true, outcome: orgclient.ManagedPullOutcome{Version: 3, ExpiresAt: now - 1}, now: now}, sandboxRailExpired},
		{sandboxRailFacts{enrolled: true, haveRow: true, outcome: orgclient.ManagedPullOutcome{Version: 3, ExpiresAt: now + 60}, now: now}, sandboxRailNotPreauthorized},
		{sandboxRailFacts{enrolled: true, haveRow: true, outcome: inForce, bodyErr: "bad", now: now}, sandboxRailRefused},
		{sandboxRailFacts{enrolled: true, haveRow: true, outcome: inForce, now: now}, sandboxRailInForce},
	}
	for _, tc := range cases {
		if got := decideSandboxRailState(tc.f); got != tc.want {
			t.Errorf("%+v: got %s want %s", tc.f, got, tc.want)
		}
		if line := sandboxManagedStatusLine(sandboxManagedRailStatus{State: tc.want}); !strings.HasPrefix(line, "Organization managed settings: ") {
			t.Errorf("status line for %s: %q", tc.want, line)
		}
	}
}

// TestManagedPOSIXPathOnAWindowsNodeIsRefused pins the ruling of the Windows
// 11 Pro rerun 2026-10-25 (D5 group 4): a managed body's paths are POSIX by
// contract, so a Windows node, where they are not absolute, refuses the path
// key not_absolute (the org sees that it did not apply) instead of skipping
// it silently, and applies the rest of the body. Elsewhere the mask applies.
func TestManagedPOSIXPathOnAWindowsNodeIsRefused(t *testing.T) {
	got, refused := composeSandboxManaged(config.TerminalSandboxConfig{},
		orgcontract.SandboxManagedPolicyV1{Schema: orgcontract.SandboxManagedSchema, PrepTimeoutSeconds: ptr(600), MaskPaths: &[]string{"/mnt/c"}}, sandboxManagedEnv{})
	if got.PrepTimeoutSeconds != 600 {
		t.Fatalf("the rest of the body did not apply: %+v", got)
	}
	if runtime.GOOS == "windows" {
		if len(refused) != 1 || refused[0].Key != "terminal.sandbox.mask_paths" || refused[0].Reason != sandboxRefusedNotAbsolute || len(got.MaskPaths) != 0 {
			t.Fatalf("a POSIX mask on a Windows node: %+v %v", refused, got.MaskPaths)
		}
		return
	}
	if len(refused) != 0 || !reflect.DeepEqual(got.MaskPaths, []string{"/mnt/c"}) {
		t.Fatalf("mask %v refused %+v", got.MaskPaths, refused)
	}
}
