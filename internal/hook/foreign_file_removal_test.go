package hook

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

// FU-212: no uninstall deletes a whole file, or a directory, that is not
// Observer's. Each row is one unregister path that deletes a whole file:
// install writes Observer's file (path), uninstall runs the path's
// unregister and returns the files it reports kept. Two plants per row, each
// run without and with --force:
//
//   - a foreign file AT the path: kept byte for byte, reported;
//   - a foreign file BESIDE Observer's in its directory: kept byte for
//     byte, Observer's own file still removed, the directory kept.
//
// Before the rule the Goose manifest was deleted whenever Observer's hooks
// entry was, the native Command Code mod, the Windows mod and the plugin
// shims were deleted by a --force uninstall whatever they held, and the
// Hermes uninstall removed the whole plugin directory with RemoveAll.

const fu212Foreign = "the developer's own file, not Observer's\n"

// fu212ForeignHooks is a developer's own hooks file at a dedicated hooks
// file's path.
const fu212ForeignHooks = `{"hooks":{"PreToolUse":[{"matcher":".*","hooks":[{"type":"command","command":"/usr/local/bin/my-guard"}]}]}}` + "\n"

type fu212Case struct {
	name string
	// foreign, when set, is the foreign file planted at the path (a JSON
	// hooks file's own hook set); reportsNone marks a row whose foreign
	// file holds nothing of Observer's, so the uninstall finds nothing to
	// remove and has nothing to report.
	foreign     string
	reportsNone bool
	// install writes Observer's artifact in a fresh home and returns the
	// whole file the uninstall deletes.
	install func(t *testing.T) (path string, uninstall func(force bool) (kept []string, err error))
}

// fu212Hook is a row driven through the hook Registry: setup prepares the
// fresh home (the vendor directory the writer needs), file picks the whole
// file out of the registration.
func fu212Hook(target string, setup func(t *testing.T, home string) Options, file func(RegistrationResult) string) func(t *testing.T) (string, func(bool) ([]string, error)) {
	return func(t *testing.T) (string, func(bool) ([]string, error)) {
		t.Helper()
		opts := setup(t, t.TempDir())
		r, err := NewRegistry(opts)
		if err != nil {
			t.Fatal(err)
		}
		res := r.Register(target)
		if res.Error != nil || res.Skipped {
			t.Fatalf("register %s = %+v", target, res)
		}
		return file(res), func(force bool) ([]string, error) {
			o := opts
			o.Force = force
			r, err := NewRegistry(o)
			if err != nil {
				t.Fatal(err)
			}
			u := r.Unregister(target)
			return u.FilesKeptForeign, u.Error
		}
	}
}

func fu212Cases() []fu212Case {
	const bin = "/opt/observer/bin/observer"
	base := func(home string) Options {
		return Options{BinaryPath: bin, HomeDir: home, ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json")}
	}
	mkdir := func(rel ...string) func(t *testing.T, home string) Options {
		return func(t *testing.T, home string) Options {
			t.Helper()
			if err := os.MkdirAll(filepath.Join(append([]string{home}, rel...)...), 0o755); err != nil {
				t.Fatal(err)
			}
			return base(home)
		}
	}
	configPath := func(res RegistrationResult) string { return res.ConfigPath }
	return []fu212Case{
		{name: "command-code mod", install: fu212Hook("command-code", mkdir(".commandcode"), configPath)},
		{name: "command-code-windows mod", install: fu212Hook("command-code-windows", func(t *testing.T, home string) Options {
			t.Helper()
			winHome := filepath.Join(nestedWinHome(t, home), ".commandcode")
			if err := os.MkdirAll(winHome, 0o755); err != nil {
				t.Fatal(err)
			}
			o := base(home)
			o.WSLDistro, o.WindowsCommandCodeHome = "Ubuntu-20.04", winHome
			return o
		}, configPath)},
		{name: "opencode plugin shim", install: fu212Hook("opencode", mkdir(".config", "opencode"), configPath)},
		{name: "goose plugin manifest", install: fu212Hook("goose", mkdir(".agents"), func(res RegistrationResult) string {
			return filepath.Join(filepath.Dir(filepath.Dir(res.ConfigPath)), "plugin.json")
		})},
		{name: "goose hooks file", foreign: fu212ForeignHooks, reportsNone: true, install: fu212Hook("goose", mkdir(".agents"), configPath)},
		{name: "grok hooks file", foreign: fu212ForeignHooks, reportsNone: true, install: fu212Hook("grok", mkdir(".grok"), configPath)},
		{name: "hermes plugin manifest", install: fu212Hermes("plugin.yaml")},
		{name: "hermes plugin bridge", install: fu212Hermes("__init__.py")},
	}
}

// fu212Hermes is the Hermes row: `observer init --hermes` and its
// --uninstall (UnregisterHermes), for the plugin file rel.
func fu212Hermes(rel string) func(t *testing.T) (string, func(bool) ([]string, error)) {
	return func(t *testing.T) (string, func(bool) ([]string, error)) {
		t.Helper()
		opts := HermesOptions{HermesHome: t.TempDir(), BinaryPath: "/opt/observer/bin/observer"}
		dir, err := RegisterHermes(opts)
		if err != nil {
			t.Fatal(err)
		}
		return filepath.Join(dir, rel), func(force bool) ([]string, error) {
			o := opts
			o.Force = force
			rm, err := UnregisterHermes(o)
			return rm.KeptForeign, err
		}
	}
}

func TestFU212UninstallKeepsForeignFiles(t *testing.T) {
	for _, c := range fu212Cases() {
		for _, force := range []bool{false, true} {
			t.Run(c.name+"/at the path/force="+boolWord(force), func(t *testing.T) {
				path, uninstall := c.install(t)
				foreign := fu212Foreign
				if c.foreign != "" {
					foreign = c.foreign
				}
				if err := os.WriteFile(path, []byte(foreign), 0o600); err != nil {
					t.Fatal(err)
				}
				kept, err := uninstall(force)
				if err != nil {
					t.Fatalf("uninstall: %v", err)
				}
				if got, err := os.ReadFile(path); err != nil || string(got) != foreign {
					t.Fatalf("the foreign file at %s was not kept byte for byte: %q, %v", path, got, err)
				}
				if !c.reportsNone && !slices.Contains(kept, path) {
					t.Errorf("kept = %v, want it to name %s", kept, path)
				}
			})
			t.Run(c.name+"/beside it/force="+boolWord(force), func(t *testing.T) {
				path, uninstall := c.install(t)
				beside := filepath.Join(filepath.Dir(path), "developer-notes.txt")
				if err := os.WriteFile(beside, []byte(fu212Foreign), 0o600); err != nil {
					t.Fatal(err)
				}
				if _, err := uninstall(force); err != nil {
					t.Fatalf("uninstall: %v", err)
				}
				if got, err := os.ReadFile(beside); err != nil || string(got) != fu212Foreign {
					t.Fatalf("the foreign file beside Observer's was not kept byte for byte: %q, %v", got, err)
				}
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Errorf("Observer's own %s was not removed: %v", path, err)
				}
			})
		}
	}
}

// TestFU212UninstallStillRemovesObserversOwnFiles: with nothing foreign
// planted every row leaves no file and no directory of Observer's behind.
func TestFU212UninstallStillRemovesObserversOwnFiles(t *testing.T) {
	for _, c := range fu212Cases() {
		t.Run(c.name, func(t *testing.T) {
			path, uninstall := c.install(t)
			kept, err := uninstall(false)
			if err != nil || len(kept) > 0 {
				t.Fatalf("uninstall = kept %v, %v", kept, err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Errorf("Observer's own %s was not removed: %v", path, err)
			}
		})
	}
}

// TestFU212DedicatedHooksFileWithAUserKeyIsKept: a dedicated hooks file
// (Observer's Kiro agent, Grok's file) that holds a member Observer did not
// write is written back without Observer's entries, never deleted; with only
// Observer's members it is deleted.
func TestFU212DedicatedHooksFileWithAUserKeyIsKept(t *testing.T) {
	for _, c := range []struct{ name, target, homeDir string }{
		{"grok", "grok", ".grok"},
		{"kiro agent", "kiro-cli", ".kiro"},
	} {
		t.Run(c.name, func(t *testing.T) {
			home := t.TempDir()
			if err := os.MkdirAll(filepath.Join(home, c.homeDir), 0o755); err != nil {
				t.Fatal(err)
			}
			opts := Options{BinaryPath: "/opt/observer/bin/observer", HomeDir: home, ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json")}
			r, err := NewRegistry(opts)
			if err != nil {
				t.Fatal(err)
			}
			res := r.Register(c.target)
			if res.Error != nil {
				t.Fatalf("register: %v", res.Error)
			}
			path := res.ConfigPath
			if c.target == "kiro-cli" {
				path = filepath.Join(home, ".kiro", "agents", kiroAgentName+".json")
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			top := map[string]json.RawMessage{}
			if err := json.Unmarshal(raw, &top); err != nil {
				t.Fatal(err)
			}
			top["prompt"] = json.RawMessage(`"the developer's own prompt"`)
			b, _ := json.Marshal(top)
			if err := os.WriteFile(path, b, 0o600); err != nil {
				t.Fatal(err)
			}
			u := r.Unregister(c.target)
			if u.Error != nil {
				t.Fatalf("unregister: %v", u.Error)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("the file holding the developer's member was deleted: %v", err)
			}
			if !bytes.Contains(got, []byte("the developer's own prompt")) || bytes.Contains(got, []byte(" hook "+c.target+" ")) {
				t.Errorf("the file was not written back without Observer's entries:\n%s", got)
			}
		})
	}
}

// TestFU212HermesBytecodeOfObserversBridge: the bytecode CPython compiled
// from Observer's __init__.py is removed with it and the directory goes;
// bytecode of another source, or any other file in __pycache__, is kept.
func TestFU212HermesBytecodeOfObserversBridge(t *testing.T) {
	pyc := func(source []byte) []byte {
		b := make([]byte, 16, 32)
		copy(b, []byte{0xcb, 0x0d, 0x0d, 0x0a})
		binary.LittleEndian.PutUint32(b[12:], uint32(len(source)))
		return append(b, "code"...)
	}
	for _, c := range []struct {
		name     string
		size     int
		wantGone bool
	}{
		{"observer's bytecode", 0, true},
		{"another source's bytecode", 7, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			opts := HermesOptions{HermesHome: t.TempDir(), BinaryPath: "/opt/observer/bin/observer"}
			dir, err := RegisterHermes(opts)
			if err != nil {
				t.Fatal(err)
			}
			src, err := os.ReadFile(filepath.Join(dir, "__init__.py"))
			if err != nil {
				t.Fatal(err)
			}
			body := pyc(src)
			if c.size != 0 {
				body = pyc(make([]byte, c.size))
			}
			cache := filepath.Join(dir, "__pycache__", "__init__.cpython-312.pyc")
			if err := os.MkdirAll(filepath.Dir(cache), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(cache, body, 0o600); err != nil {
				t.Fatal(err)
			}
			rm, err := UnregisterHermes(opts)
			if err != nil {
				t.Fatal(err)
			}
			if c.wantGone {
				if _, err := os.Stat(dir); !os.IsNotExist(err) || !rm.DirRemoved {
					t.Errorf("plugin dir kept: %+v, %v", rm, err)
				}
				return
			}
			if got, err := os.ReadFile(cache); err != nil || !bytes.Equal(got, body) {
				t.Errorf("foreign bytecode not kept byte for byte: %v", err)
			}
			if !slices.Contains(rm.KeptForeign, cache) || rm.DirRemoved {
				t.Errorf("removal = %+v, want %s kept and the directory kept", rm, cache)
			}
		})
	}
}

// TestFU212ChecksumRegistryKeptUnlessItsLastEntryGoes: the checksum
// registry is deleted only when the entry an unregister drops was its last,
// never because the file at its path holds no entry.
func TestFU212ChecksumRegistryKeptUnlessItsLastEntryGoes(t *testing.T) {
	home := t.TempDir()
	cs := filepath.Join(home, ".observer", "hook_checksums.json")
	if err := os.MkdirAll(filepath.Dir(cs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cs, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Options{BinaryPath: "/opt/observer/bin/observer", HomeDir: home, ChecksumsPath: cs})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.removeChecksum(filepath.Join(home, "never-recorded.json")); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(cs); err != nil || string(got) != "{}\n" {
		t.Fatalf("a registry with no entry for the path was not kept: %q, %v", got, err)
	}
	if err := os.WriteFile(cs, []byte(`{"/x":{"sha256":"aa"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.removeChecksum("/x"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cs); !os.IsNotExist(err) {
		t.Errorf("the registry whose last entry went was kept: %v", err)
	}
}

func boolWord(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// TestFU212GooseManifestGoesOnlyAfterTheHooksFile: when the hooks file
// cannot be deleted (a symlink is refused), Observer's manifest stays with
// it: the extras are removed only after the hooks file is gone.
func TestFU212GooseManifestGoesOnlyAfterTheHooksFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".agents"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Options{BinaryPath: "/opt/observer/bin/observer", HomeDir: home, ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json")})
	if err != nil {
		t.Fatal(err)
	}
	res := r.Register("goose")
	if res.Error != nil {
		t.Fatal(res.Error)
	}
	hooksFile := res.ConfigPath
	manifest := filepath.Join(filepath.Dir(filepath.Dir(hooksFile)), "plugin.json")
	real := filepath.Join(home, "dotfiles-hooks.json")
	raw, err := os.ReadFile(hooksFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(hooksFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, hooksFile); err != nil {
		t.Fatal(err)
	}
	u := r.Unregister("goose")
	if u.Error == nil {
		t.Fatalf("unregister over a symlinked hooks file = %+v, want the refusal", u)
	}
	if _, err := os.Stat(manifest); err != nil {
		t.Errorf("the manifest went although the hooks file stayed: %v", err)
	}
}

// TestFU212HermesUninstallKeepsABridgeRunningAnotherBinary (audit row 6 on
// the w13 hand-back): `observer init --hermes --uninstall` judges each file
// the way hermesPluginConflicts does: a bridge in Observer's own shape whose
// OBSERVER_BIN default runs a binary that is not an observer binary is kept
// byte for byte, with or without --force, with the directory; a bridge of a
// moved Observer is still removed.
func TestFU212HermesUninstallKeepsABridgeRunningAnotherBinary(t *testing.T) {
	const bin = "/opt/observer/bin/observer"
	for _, c := range []struct {
		name, other string
		kept        bool
	}{
		{"another program", "/opt/lc/lc-hook.sh", true},
		{"a moved observer", "/usr/lib/observer-new/observer", false},
	} {
		for _, force := range []bool{false, true} {
			t.Run(c.name+"/force="+boolWord(force), func(t *testing.T) {
				opts := HermesOptions{HermesHome: t.TempDir(), BinaryPath: bin}
				dir, err := RegisterHermes(opts)
				if err != nil {
					t.Fatal(err)
				}
				bridge := filepath.Join(dir, "__init__.py")
				ours, err := os.ReadFile(bridge)
				if err != nil {
					t.Fatal(err)
				}
				body := bytes.Replace(ours, []byte(`"`+bin+`"`), []byte(`"`+c.other+`"`), 1)
				if bytes.Equal(body, ours) {
					t.Fatal("the bridge carries no OBSERVER_BIN default to replace")
				}
				if err := os.WriteFile(bridge, body, 0o600); err != nil {
					t.Fatal(err)
				}
				o := opts
				o.Force = force
				rm, err := UnregisterHermes(o)
				if err != nil {
					t.Fatal(err)
				}
				got, rerr := os.ReadFile(bridge)
				if !c.kept {
					if !os.IsNotExist(rerr) || !rm.DirRemoved {
						t.Errorf("a moved Observer's bridge was kept: %+v, %v", rm, rerr)
					}
					return
				}
				if rerr != nil || !bytes.Equal(got, body) || !slices.Contains(rm.KeptForeign, bridge) || rm.DirRemoved {
					t.Errorf("the bridge running %s was not kept byte for byte and reported: %+v, %v", c.other, rm, rerr)
				}
			})
		}
	}
}
