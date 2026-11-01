//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
)

// macTestRuntime builds a sandbox runtime over cfg for the macOS drivers'
// tests.
func macTestRuntime(t *testing.T, cfg config.Config) *sandboxRuntime {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	rt, err := newSandboxRuntime(cfg.Terminal.Sandbox, nil, t.TempDir(), exe, nil)
	if err != nil {
		t.Fatal(err)
	}
	rt.applyDaemonConfig(cfg)
	return rt
}

// sandboxMacSettingsInventory is the inventory of the macOS drivers'
// blocks, keyed "<block>.<key>": their node home is the macOS sandboxes
// panel (SandboxMacPanel.tsx).
var sandboxMacSettingsInventory = map[string]adminHome{
	"seatbelt.allow_keychain":    {Pin: "terminal.sandbox.seatbelt.allow_keychain"},
	"seatbelt.driver":            {Pin: "terminal.sandbox.seatbelt.driver"},
	"apple_container.memory_mib": {Pin: "terminal.sandbox.apple_container.memory_mib"},
	"apple_container.cpus":       {Pin: "terminal.sandbox.apple_container.cpus"},
	"apple_container.image":      {Pin: "terminal.sandbox.apple_container.image"},
}

// TestSandboxMacSettingsInventory walks both macOS blocks: every key has a
// row, a node home in the panel and an admin home in this build.
func TestSandboxMacSettingsInventory(t *testing.T) {
	panel, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "components", "SandboxMacPanel.tsx"))
	if err != nil {
		t.Fatalf("read the panel: %v", err)
	}
	seen := map[string]bool{}
	for block, typ := range map[string]reflect.Type{
		"seatbelt":        reflect.TypeOf(config.TerminalSandboxSeatbeltConfig{}),
		"apple_container": reflect.TypeOf(config.TerminalSandboxAppleContainerConfig{}),
	} {
		for i := 0; i < typ.NumField(); i++ {
			key := block + "." + strings.SplitN(typ.Field(i).Tag.Get("toml"), ",", 2)[0]
			seen[key] = true
			home, ok := sandboxMacSettingsInventory[key]
			if !ok {
				t.Errorf("[terminal.sandbox.%s] has no inventory row", key)
				continue
			}
			field := strings.TrimPrefix(key, block+".")
			if !strings.Contains(string(panel), field) {
				t.Errorf("[terminal.sandbox.%s] has no node home in the macOS sandboxes panel", key)
			}
			switch {
			case home.Pin != "":
				if !nodegov.IsPinnableKey(home.Pin) {
					t.Errorf("%s: pin %q is not a settings.pin row", key, home.Pin)
				}
			case home.Owed != "":
				if !owedAdminHomes[key] {
					t.Errorf("%s: only %v may have an owed admin home", key, owedAdminHomes)
				}
			default:
				t.Errorf("[terminal.sandbox.%s] has no admin home", key)
			}
		}
	}
	for key := range sandboxMacSettingsInventory {
		if !seen[key] {
			t.Errorf("inventory row %q names no macOS block key", key)
		}
	}
}

// mustMacDirs is macDirsFor for a test whose temp dir is short enough.
func mustMacDirs(t *testing.T, runID string) macRunDirs {
	t.Helper()
	d, err := macDirsFor(runID)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestMacSocketDirForADeepTMPDIR (lane SBX-P3B, the P-074 observation): a
// TMPDIR deep enough that the run's relay socket passes macOS's 103 bytes
// takes the short per-user parent instead of refusing the launch; an
// unusable short parent (owned by someone else, a link) refuses by name;
// the default TMPDIR keeps today's parent.
func TestMacSocketDirForADeepTMPDIR(t *testing.T) {
	run := "AbCdEfGhIjKlMnOpQrStUv"
	short := macShortSocketParentPrefix + "501"
	deep := "/private/var/folders/zz/" + strings.Repeat("d", 80) + "/T"
	cases := []struct {
		name   string
		cands  []string
		usable func(string) bool
		want   string
		err    bool
	}{
		{"default TMPDIR fits", []string{"/private/var/folders/x1/abcdefgh/T/obsbx", short}, nil, "/private/var/folders/x1/abcdefgh/T/obsbx", false},
		{"deep TMPDIR takes the short parent", []string{deep + "/obsbx", short}, nil, short, false},
		{"short parent not ours", []string{deep + "/obsbx", short}, func(d string) bool { return d != short }, "", true},
		{"usable temp parent wins", []string{"/T/obsbx", short}, func(string) bool { return true }, "/T/obsbx", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := macPickSocketParent(tc.cands, run, tc.usable)
			if (err != nil) != tc.err {
				t.Fatalf("err %v, want error %v", err, tc.err)
			}
			if err != nil {
				if !errors.Is(err, errMacSocketPathTooLong) || !strings.Contains(err.Error(), "relay_socket_path_too_long") {
					t.Fatalf("refusal does not name itself: %v", err)
				}
				return
			}
			if got != tc.want {
				t.Fatalf("parent %q, want %q", got, tc.want)
			}
			if p := filepath.Join(got, run, macRelaySocketName); len(p) > macRelaySocketMax {
				t.Fatalf("chosen path %d bytes", len(p))
			}
		})
	}
	// Through macDirsFor itself, with TMPDIR set deep.
	if runtime.GOOS == "windows" {
		return
	}
	t.Setenv("TMPDIR", "/nonexistent/"+strings.Repeat("t", 90))
	d, err := macDirsFor(run)
	if err != nil {
		t.Fatalf("a deep TMPDIR refused: %v", err)
	}
	if !strings.HasPrefix(d.SocketParent, macShortSocketParentPrefix) || filepath.Dir(d.SocketDir) != d.SocketParent {
		t.Fatalf("dirs %+v", d)
	}
	if !strings.HasPrefix(d.TempDir, "/nonexistent/") {
		t.Fatalf("the run's TMPDIR left the user's temp dir: %s", d.TempDir)
	}
}

// TestMacSocketParentUsable: an existing parent must be a private
// directory this user owns, never a link.
func TestMacSocketParentUsable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ownership is a unix check")
	}
	dir := t.TempDir()
	if !macSocketParentUsable(filepath.Join(dir, "missing")) {
		t.Fatal("a parent the helper will create was refused")
	}
	priv := filepath.Join(dir, "priv")
	if err := os.Mkdir(priv, 0o700); err != nil {
		t.Fatal(err)
	}
	if !macSocketParentUsable(priv) {
		t.Fatal("a private directory was refused")
	}
	open := filepath.Join(dir, "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if macSocketParentUsable(open) {
		t.Fatal("a group-readable directory was accepted")
	}
	link := filepath.Join(dir, "link")
	if err := testSymlink(t, priv, link); err != nil {
		t.Fatal(err)
	}
	if macSocketParentUsable(link) {
		t.Fatal("a link was accepted")
	}
}
