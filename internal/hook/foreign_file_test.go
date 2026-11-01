package hook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hook/hermesplugin"
)

// FU-207: every writer that writes a whole file Observer owns by name keeps a
// file at its path that does not read as Observer's, byte for byte, without
// --force ("doesn't look like an observer-managed file"); --force replaces it
// and keeps the previous bytes at <file>.bak; a managed repair of a
// neutralised file Observer installed follows ownership.go. Before it,
// registerCommandCodeWindows (and the Goose plugin manifest, and the Hermes
// plugin files) overwrote such a file.

const fu207Foreign = "// the developer's own file, not Observer's\nexport default {}\n"

// fu207Case is one whole-file writer: register runs it in a fixed home; file
// is the path of the whole file it writes, found from a first install.
type fu207Case struct {
	name     string
	register func(force, repair bool) RegistrationResult
	file     func(first RegistrationResult) string
}

func fu207Registry(t *testing.T, opts Options, target string) func(force, repair bool) RegistrationResult {
	t.Helper()
	return func(force, repair bool) RegistrationResult {
		o := opts
		o.Force, o.RepairOwnedArtifacts = force, repair
		r, err := NewRegistry(o)
		if err != nil {
			t.Fatal(err)
		}
		return r.Register(target)
	}
}

func fu207Cases(t *testing.T) []fu207Case {
	const bin = "/opt/observer/bin/observer"
	configPath := func(res RegistrationResult) string { return res.ConfigPath }

	winWSL := t.TempDir()
	winHome := filepath.Join(nestedWinHome(t, winWSL), ".commandcode")
	if err := os.MkdirAll(winHome, 0o755); err != nil {
		t.Fatal(err)
	}
	native := t.TempDir()
	if err := os.MkdirAll(filepath.Join(native, ".commandcode"), 0o755); err != nil {
		t.Fatal(err)
	}
	opencode := t.TempDir()
	if err := os.MkdirAll(filepath.Join(opencode, ".config", "opencode"), 0o755); err != nil {
		t.Fatal(err)
	}
	goose := t.TempDir()
	if err := os.MkdirAll(filepath.Join(goose, ".agents"), 0o755); err != nil {
		t.Fatal(err)
	}
	opts := func(home string) Options {
		return Options{BinaryPath: bin, HomeDir: home, ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json")}
	}
	win := opts(winWSL)
	win.WSLDistro, win.WindowsCommandCodeHome = "Ubuntu-20.04", winHome
	return []fu207Case{
		{name: "command-code-windows", register: fu207Registry(t, win, "command-code-windows"), file: configPath},
		{name: "command-code", register: fu207Registry(t, opts(native), "command-code"), file: configPath},
		{name: "opencode plugin shim", register: fu207Registry(t, opts(opencode), "opencode"), file: configPath},
		{
			name: "goose plugin manifest", register: fu207Registry(t, opts(goose), "goose"),
			file: func(res RegistrationResult) string {
				return filepath.Join(filepath.Dir(filepath.Dir(res.ConfigPath)), "plugin.json")
			},
		},
	}
}

// TestFU207ForeignFileIsKeptByEveryWholeFileWriter: a foreign file at the
// path is left unchanged without --force (byte compare), replaced with it
// (the old bytes kept at .bak), and a neutralised file Observer installed is
// rewritten by a managed repair pass.
func TestFU207ForeignFileIsKeptByEveryWholeFileWriter(t *testing.T) {
	for _, c := range fu207Cases(t) {
		t.Run(c.name, func(t *testing.T) {
			first := c.register(false, false)
			if first.Error != nil || first.Skipped {
				t.Fatalf("first register = %+v", first)
			}
			path := c.file(first)
			ours, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("the writer wrote no %s: %v", path, err)
			}
			plant := func() {
				t.Helper()
				if err := os.WriteFile(path, []byte(fu207Foreign), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			plant()
			res := c.register(false, false)
			if res.Error == nil || !strings.Contains(res.Error.Error(), "doesn't look like an observer-managed file; pass --force to overwrite") || !strings.Contains(res.Error.Error(), path) {
				t.Errorf("register over a foreign file = %+v, want the foreign-file refusal naming %s", res, path)
			}
			if got, _ := os.ReadFile(path); string(got) != fu207Foreign {
				t.Fatalf("the foreign file changed without --force:\n%s", got)
			}

			forced := c.register(true, false)
			if forced.Error != nil {
				t.Fatalf("--force register: %v", forced.Error)
			}
			if got, _ := os.ReadFile(path); string(got) != string(ours) {
				t.Errorf("--force did not write Observer's file:\n%s", got)
			}
			if bak, err := os.ReadFile(path + ".bak"); err != nil || string(bak) != fu207Foreign {
				t.Errorf("--force kept no copy of the foreign bytes at .bak: %q, %v", bak, err)
			}

			// A managed repair pass rewrites Observer's own neutralised
			// file (installed by Observer, hook_checksums.json says so).
			plant()
			repaired := c.register(false, true)
			if repaired.Error != nil {
				t.Fatalf("managed repair: %v", repaired.Error)
			}
			if got, _ := os.ReadFile(path); string(got) != string(ours) {
				t.Errorf("the managed repair did not rewrite the neutralised file:\n%s", got)
			}
		})
	}
}

// TestFU207HermesPluginKeepsAForeignFile: `observer init --hermes` keeps a
// plugin file that is not Observer's (and a bridge running another binary)
// without --force, rewrites Observer's own (an older render, another
// Observer binary), and with --force replaces a foreign file keeping .bak.
func TestFU207HermesPluginKeepsAForeignFile(t *testing.T) {
	const bin = "/opt/observer/bin/observer"
	home := t.TempDir()
	opts := HermesOptions{HermesHome: home, BinaryPath: bin}
	dir, err := RegisterHermes(opts)
	if err != nil {
		t.Fatal(err)
	}
	ours := map[string][]byte{}
	for _, rel := range hermesplugin.Files() {
		b, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			t.Fatal(err)
		}
		ours[rel] = b
	}
	initPy := filepath.Join(dir, "__init__.py")
	yaml := filepath.Join(dir, "plugin.yaml")

	for _, tc := range []struct {
		name, rel, body, want string
	}{
		{"foreign manifest", "plugin.yaml", "name: someone-elses-plugin\n", "doesn't look like an observer-managed file; pass --force to overwrite"},
		{"foreign bridge", "__init__.py", "print('mine')\n", "doesn't look like an observer-managed file; pass --force to overwrite"},
		{"bridge running another binary", "__init__.py", strings.Replace(string(ours["__init__.py"]), `"`+bin+`"`, `"/opt/lc/lc-hook.sh"`, 1), foreignBinaryReason},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, tc.rel)
			if err := os.WriteFile(p, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = os.WriteFile(p, ours[tc.rel], 0o600) }()
			for _, dry := range []bool{true, false} {
				o := opts
				o.DryRun = dry
				_, err := RegisterHermes(o)
				if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), p) {
					t.Errorf("dry=%v: RegisterHermes over %s = %v, want %q naming %s", dry, tc.rel, err, tc.want, p)
				}
				if got, _ := os.ReadFile(p); string(got) != tc.body {
					t.Fatalf("dry=%v: %s changed without --force", dry, tc.rel)
				}
			}
			o := opts
			o.Force = true
			if _, err := RegisterHermes(o); err != nil {
				t.Fatalf("--force: %v", err)
			}
			if got, _ := os.ReadFile(p); string(got) != string(ours[tc.rel]) {
				t.Errorf("--force did not write Observer's %s", tc.rel)
			}
			if bak, err := os.ReadFile(p + ".bak"); err != nil || string(bak) != tc.body {
				t.Errorf("--force kept no .bak of %s: %v", tc.rel, err)
			}
			_ = os.Remove(p + ".bak")
		})
	}

	// Observer's own plugin rendered for another Observer binary (a moved
	// install) is rewritten without --force.
	moved := strings.Replace(string(ours["__init__.py"]), `"`+bin+`"`, `"/usr/lib/observer-new/observer"`, 1)
	if err := os.WriteFile(initPy, []byte(moved), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(yaml, append([]byte("name: superbased-observer\n"), "version: \"0.9\"\n"...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RegisterHermes(opts); err != nil {
		t.Fatalf("a moved Observer's plugin: %v", err)
	}
	for rel, want := range ours {
		if got, _ := os.ReadFile(filepath.Join(dir, rel)); string(got) != string(want) {
			t.Errorf("%s was not rewritten to Observer's current file", rel)
		}
	}
}
