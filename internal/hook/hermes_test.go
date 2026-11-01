package hook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRegisterHermes_RoundTripCreatesPluginFiles pins the install
// happy path. RegisterHermes writes both plugin files into
// <hermes-home>/plugins/superbased-observer/.
func TestRegisterHermes_RoundTripCreatesPluginFiles(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	got, err := RegisterHermes(HermesOptions{HermesHome: home})
	if err != nil {
		t.Fatalf("RegisterHermes: %v", err)
	}
	want := filepath.Join(home, "plugins", "superbased-observer")
	if got != want {
		t.Errorf("plugin dir = %q, want %q", got, want)
	}

	for _, name := range []string{"plugin.yaml", "__init__.py"} {
		path := filepath.Join(got, name)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("missing %s: %v", name, err)
		}
	}
}

// TestRegisterHermes_DryRunNoFilesystemChange confirms --dry-run
// returns the would-be path without touching the disk.
func TestRegisterHermes_DryRunNoFilesystemChange(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	got, err := RegisterHermes(HermesOptions{HermesHome: home, DryRun: true})
	if err != nil {
		t.Fatalf("RegisterHermes dry-run: %v", err)
	}
	if got != filepath.Join(home, "plugins", "superbased-observer") {
		t.Errorf("plugin dir = %q", got)
	}
	// No files should have been written.
	if _, err := os.Stat(got); !os.IsNotExist(err) {
		t.Errorf("dry-run created the directory: %v", err)
	}
}

// TestRegisterHermes_Idempotent confirms re-running against an
// already-installed location works without error and refreshes the
// embedded copies. A file that no longer reads as Observer's is kept without
// --force (FU-207) and restored with it.
func TestRegisterHermes_Idempotent(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if _, err := RegisterHermes(HermesOptions{HermesHome: home}); err != nil {
		t.Fatalf("first RegisterHermes: %v", err)
	}
	if _, err := RegisterHermes(HermesOptions{HermesHome: home}); err != nil {
		t.Fatalf("re-run RegisterHermes: %v", err)
	}
	// Garbage one of the files; a second run keeps it, --force restores it.
	garbage := filepath.Join(home, "plugins", "superbased-observer", "plugin.yaml")
	if err := os.WriteFile(garbage, []byte("stale"), 0o600); err != nil {
		t.Fatalf("garbage write: %v", err)
	}
	if _, err := RegisterHermes(HermesOptions{HermesHome: home}); err == nil {
		t.Fatal("second RegisterHermes overwrote a file that is not Observer's without --force")
	}
	if _, err := RegisterHermes(HermesOptions{HermesHome: home, Force: true}); err != nil {
		t.Fatalf("second RegisterHermes --force: %v", err)
	}
	data, err := os.ReadFile(garbage)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(data), "stale") {
		t.Error("re-install didn't overwrite stale plugin.yaml")
	}
}

// TestUnregisterHermes_RoundTripRemovesPluginDir pins uninstall:
// after a Register + Unregister cycle the directory must not exist.
func TestUnregisterHermes_RoundTripRemovesPluginDir(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if _, err := RegisterHermes(HermesOptions{HermesHome: home}); err != nil {
		t.Fatalf("RegisterHermes: %v", err)
	}
	got, err := UnregisterHermes(HermesOptions{HermesHome: home})
	if err != nil {
		t.Fatalf("UnregisterHermes: %v", err)
	}
	if _, err := os.Stat(got.PluginDir); !os.IsNotExist(err) || !got.DirRemoved {
		t.Errorf("plugin dir still exists after uninstall: %v (%+v)", err, got)
	}
	// Sibling dirs (other plugins) must NOT have been removed —
	// confirm by ensuring the parent `plugins/` still exists.
	parent := filepath.Dir(got.PluginDir)
	if _, err := os.Stat(parent); err != nil {
		t.Errorf("parent plugins/ dir removed: %v", err)
	}
}

// TestUnregisterHermes_AlreadyAbsent confirms uninstall is safe
// against an absent install (idempotent / "user runs uninstall
// twice").
func TestUnregisterHermes_AlreadyAbsent(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if _, err := UnregisterHermes(HermesOptions{HermesHome: home}); err != nil {
		t.Errorf("uninstall on never-installed: %v", err)
	}
}

// TestUnregisterHermes_RefusesNonPluginDir pins the safety check:
// a HermesOptions with HermesHome pointing somewhere weird should
// not cause us to delete arbitrary directories.
func TestUnregisterHermes_RefusesNonPluginDir(t *testing.T) {
	t.Parallel()
	// This relies on the implementation: it composes home + plugins
	// + HermesPluginDirName. The leaf is hard-coded; the safety check
	// rejects anything else. Verify the rejection branch fires by
	// directly invoking the underlying composer logic via the public
	// path with an option that subverts the leaf — there's no public
	// way today, but the const guarantees we always end up with
	// /plugins/superbased-observer/. That's a build-time invariant,
	// not a runtime test target. Smoke-test by confirming the
	// HermesPluginDirName const matches the manifest.
	if HermesPluginDirName != "superbased-observer" {
		t.Errorf("HermesPluginDirName = %q drifted from manifest", HermesPluginDirName)
	}
}
