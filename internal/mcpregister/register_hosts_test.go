package mcpregister

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hostfile"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/platform/jetbrainshost"
)

// hostTree hashes every file and directory under root.
func hostTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	if err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if d.IsDir() {
			out[rel] = "dir"
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		out[rel] = hex.EncodeToString(sum[:])
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func sameTree(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// hostFixture lays out every host's directory (and an existing file with a
// sibling server and a comment for Zed) under a fresh home, for this OS.
// It returns the home and the file each target writes here.
func hostFixture(t *testing.T) (string, map[string]string) {
	t.Helper()
	home := t.TempDir()
	r := newHostRegistrar(t, home)
	files := map[string]string{}
	for _, tg := range hostMCPTargets {
		fs, err := tg.files(r)
		if err != nil || len(fs) == 0 {
			continue
		}
		files[tg.target] = fs[0]
	}
	// JetBrains: one product configuration directory.
	vendor := filepath.Join(home, jetbrainsVendorRel())
	if err := os.MkdirAll(filepath.Join(vendor, "IntelliJIdea2026.2"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(vendor, "acp-agents"), 0o755); err != nil {
		t.Fatal(err)
	}
	files["gemini-code-assist-jetbrains"] = filepath.Join(vendor, "IntelliJIdea2026.2", "mcp.json")
	for target, p := range files {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if target == "zed" {
			body := "// Zed\n{\n  \"theme\": \"x\", // keep me\n  \"context_servers\": { \"other\": { \"command\": \"o\", \"env\": { \"K\": \"secret\" } } },\n}\n"
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return home, files
}

// jetbrainsVendorRel is the JetBrains vendor root relative to a pinned home
// on this OS (jetbrainshost.VendorRoot's convention).
func jetbrainsVendorRel() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join("AppData", "Roaming", jetbrainshost.VendorDirName)
	case "darwin":
		return filepath.Join("Library", "Application Support", jetbrainshost.VendorDirName)
	}
	return filepath.Join(".config", jetbrainshost.VendorDirName)
}

func newHostRegistrar(t *testing.T, home string) *Registrar {
	t.Helper()
	r, err := NewRegistrar(RegisterOptions{BinaryPath: "/opt/observer/bin/observer", HomeDir: home, ConfigPath: "/etc/observer/config.toml", Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// withWindowsCatalogue pins the catalogue OS to windows, so the Visual
// Studio row (Windows only) resolves under the test home.
func withWindowsCatalogue(t *testing.T) {
	t.Helper()
	prev := hostGOOS
	hostGOOS = func() string { return "windows" }
	t.Cleanup(func() { hostGOOS = prev })
}

func withLiveGatedHostWriters(t *testing.T) {
	t.Helper()
	runLiveGatedHostWriters = true
	t.Cleanup(func() { runLiveGatedHostWriters = false })
}

// TestHostMCPTargetsAreGated: each host target's gate is its integration
// WriterKindHostMCP row (a live-check id, listed by LiveGatedWriters).
func TestHostMCPTargetsAreGated(t *testing.T) {
	want := map[string]string{
		"zed": "LC27", "visual-studio": "LCR-68", "gemini-code-assist-jetbrains": "LCR-64", "aider-desk": "LCR-60",
		"codebuddy": "LCR-76", "cortex-code": "LC18", "dimcode": "LCR-77", "gemini-cli": "LCR-64", "ibm-bob": "LCR-75",
		"junie": "LCR-84", "kimchi": "LCR-70", "qoder": "LCR-82", "qwen-code": "LC33",
	}
	listed := map[string]bool{}
	for _, w := range integration.LiveGatedWriters() {
		if w.Kind == integration.WriterKindHostMCP {
			listed[w.Tool+"/"+string(w.Gate)] = true
		}
	}
	for _, tg := range hostMCPTargets {
		id, ok := want[tg.target]
		if !ok {
			t.Errorf("%s: no expected gate", tg.target)
			continue
		}
		g := HostMCPLiveGate(tg.target)
		if !g.Waiting() || g.Text() != "built, waiting on live check "+id {
			t.Errorf("%s gate = %v (%q), want %s", tg.target, g, g.Text(), id)
		}
		if !listed[tg.gateTool+"/"+id] {
			t.Errorf("%s: %s/%s not in LiveGatedWriters", tg.target, tg.gateTool, id)
		}
		delete(want, tg.target)
	}
	for target := range want {
		t.Errorf("%s: no target row", target)
	}
}

// TestHostMCPGateClosedWritesNothing: with every gate closed, Register on
// every host target (Force too) writes nothing: the home tree is byte for
// byte unchanged, and the refusal names the live check.
func TestHostMCPGateClosedWritesNothing(t *testing.T) {
	for _, tg := range hostMCPTargets {
		for _, force := range []bool{false, true} {
			home, _ := hostFixture(t)
			before := hostTree(t, home)
			r := newHostRegistrar(t, home)
			r.opts.Force = force
			res := r.Register(tg.target)
			if !res.Skipped || res.Error != nil || !strings.Contains(res.SkipReason, "built, waiting on live check") {
				t.Errorf("%s force=%v: Register = %+v", tg.target, force, res)
			}
			if after := hostTree(t, home); !sameTree(before, after) {
				t.Errorf("%s force=%v: the gated writer changed the home tree", tg.target, force)
			}
		}
	}
}

// TestHostMCPWritersWhenSwitchedOn: switched on, each target with a file on
// this OS writes exactly its member (the shape its host documents), keeps
// the rest (Zed's comments and sibling server), is AlreadySet on a re-run,
// refuses a foreign command under the name without --force, and Unregister
// removes the member.
func TestHostMCPWritersWhenSwitchedOn(t *testing.T) {
	withLiveGatedHostWriters(t)
	for _, tg := range hostMCPTargets {
		t.Run(tg.target, func(t *testing.T) {
			if tg.target == "visual-studio" && runtime.GOOS != "windows" {
				withWindowsCatalogue(t)
			}
			home, files := hostFixture(t)
			path, ok := files[tg.target]
			if !ok {
				t.Fatalf("%s resolved no file", tg.target)
			}
			r := newHostRegistrar(t, home)
			res := r.Register(tg.target)
			if res.Error != nil || !res.Added {
				t.Fatalf("Register = %+v", res)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if tg.target == "zed" {
				for _, keep := range []string{"// Zed", "// keep me", `"K": "secret"`} {
					if !strings.Contains(string(raw), keep) {
						t.Errorf("zed lost %q:\n%s", keep, raw)
					}
				}
			} else {
				var doc map[string]map[string]map[string]any
				if err := json.Unmarshal(raw, &doc); err != nil {
					t.Fatalf("%s: %v\n%s", path, err, raw)
				}
				e := doc[tg.topKey][ServerName]
				if e["command"] != "/opt/observer/bin/observer" {
					t.Errorf("entry = %v", e)
				}
				if tg.typed && e["type"] != "stdio" {
					t.Errorf("entry %v lacks type stdio", e)
				}
			}
			if again := r.Register(tg.target); again.Error != nil || !again.AlreadySet {
				t.Errorf("re-run = %+v", again)
			}
			other := newHostRegistrar(t, home)
			other.opts.BinaryPath = "/somewhere/else/tool"
			other.opts.commandExists = func(string) bool { return true }
			if c := other.Register(tg.target); c.Error == nil {
				t.Errorf("a different binary overwrote without --force: %+v", c)
			}
			un := r.Unregister(tg.target)
			if un.Error != nil || !un.Removed {
				t.Fatalf("Unregister = %+v", un)
			}
			if b, _ := os.ReadFile(path); strings.Contains(string(b), ServerName) {
				t.Errorf("entry left after Unregister:\n%s", b)
			}
		})
	}
}

// TestHostMCPNeedsTheHostDir: switched on, a host whose directory does not
// exist gets nothing written and no directory created.
func TestHostMCPNeedsTheHostDir(t *testing.T) {
	withLiveGatedHostWriters(t)
	for _, tg := range hostMCPTargets {
		home := t.TempDir()
		before := hostTree(t, home)
		r := newHostRegistrar(t, home)
		res := r.Register(tg.target)
		if res.Error != nil || res.Added {
			t.Errorf("%s: Register = %+v", tg.target, res)
		}
		if after := hostTree(t, home); !sameTree(before, after) {
			t.Errorf("%s: wrote into a home with no host directory", tg.target)
		}
	}
}

// TestHostMCPTargetsDeclareTheirFile: every host target names its
// credential-file reason (HOOKCRED-1) and a distinct id that no locate
// client shadows.
func TestHostMCPTargetsDeclareTheirFile(t *testing.T) {
	seen := map[string]bool{}
	for _, tg := range hostMCPTargets {
		if tg.credential == "" {
			t.Errorf("%s: no credential-file declaration", tg.target)
		}
		if seen[tg.target] {
			t.Errorf("%s: listed twice", tg.target)
		}
		seen[tg.target] = true
		r := newHostRegistrar(t, t.TempDir())
		if _, ok := r.location(tg.target); ok {
			t.Errorf("%s: a locate client of the same id would be shadowed by the host target", tg.target)
		}
	}
}

// TestHostMCPUnregisterRemovesOnlyObserversEntry: an entry under Observer's
// name that runs another command is left in place with a reason (removed
// only under --force); Observer's own entry goes.
func TestHostMCPUnregisterRemovesOnlyObserversEntry(t *testing.T) {
	tg, ok := hostMCPTargetFor("junie")
	if !ok {
		t.Fatal("no junie host target")
	}
	home, files := hostFixture(t)
	path := files[tg.target]
	foreign := `{"` + tg.topKey + `":{"` + ServerName + `":{"command":"/other/tool","args":["run"]}}}` + "\n"
	if err := os.WriteFile(path, []byte(foreign), 0o600); err != nil {
		t.Fatal(err)
	}
	r := newHostRegistrar(t, home)
	r.opts.commandExists = func(string) bool { return true }
	un := r.Unregister(tg.target)
	if un.Error != nil || un.Removed || !un.Skipped || !strings.Contains(un.SkipReason, "not Observer's") {
		t.Fatalf("Unregister over a foreign entry = %+v", un)
	}
	if b, _ := os.ReadFile(path); string(b) != foreign {
		t.Errorf("a foreign entry was touched:\n%s", b)
	}
	r.opts.Force = true
	if un := r.Unregister(tg.target); un.Error != nil || !un.Removed {
		t.Errorf("--force Unregister = %+v", un)
	}

	// Observer's own shape whose command was deleted is Observer's.
	stale := `{"` + tg.topKey + `":{"` + ServerName + `":{"command":"/gone/observer","args":["serve"]}}}` + "\n"
	if err := os.WriteFile(path, []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	r = newHostRegistrar(t, home)
	r.opts.commandExists = func(string) bool { return false }
	if un := r.Unregister(tg.target); un.Error != nil || !un.Removed {
		t.Errorf("Unregister of a stale Observer entry = %+v", un)
	}
}

// TestHostMCPLinkIsASkipWithAReason: switched on, a host file that is a
// symbolic link is passed over with a reason by Register and Unregister,
// and the link's target is never written.
func TestHostMCPLinkIsASkipWithAReason(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need privilege on windows")
	}
	withLiveGatedHostWriters(t)
	tg, ok := hostMCPTargetFor("junie")
	if !ok {
		t.Fatal("no junie host target")
	}
	home, files := hostFixture(t)
	path := files[tg.target]
	real := filepath.Join(t.TempDir(), "elsewhere.json")
	body := `{"` + tg.topKey + `":{"` + ServerName + `":{"command":"/opt/observer/bin/observer","args":["serve","--config","/etc/observer/config.toml"]}}}` + "\n"
	if err := os.WriteFile(real, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(path)
	if err := os.Symlink(real, path); err != nil {
		t.Fatal(err)
	}
	r := newHostRegistrar(t, home)
	if res := r.Register(tg.target); res.Error != nil || res.Added || !res.Skipped || !strings.Contains(res.SkipReason, "symbolic link") {
		t.Errorf("Register through a link = %+v", res)
	}
	if un := r.Unregister(tg.target); un.Error != nil || un.Removed || !strings.Contains(un.SkipReason, "symbolic link") {
		t.Errorf("Unregister through a link = %+v", un)
	}
	if b, _ := os.ReadFile(real); string(b) != body {
		t.Errorf("the link target was written:\n%s", b)
	}
}

// TestHostMCPLinkedFileIsReportedWithItsComponent (audit row 7, FU-198): a
// host target with several files reports a file reached through a symbolic
// link even when it wrote another file (a non-fatal note), and every report
// carries the hostfile refusal naming the linked path; the link's target is
// never written.
func TestHostMCPLinkedFileIsReportedWithItsComponent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need privilege on windows")
	}
	withLiveGatedHostWriters(t)
	const target = "gemini-code-assist-jetbrains"
	home, files := hostFixture(t)
	vendor := filepath.Join(home, jetbrainsVendorRel())
	product := filepath.Join(vendor, "PyCharm2026.2")
	if err := os.MkdirAll(product, 0o755); err != nil {
		t.Fatal(err)
	}
	elsewhere := filepath.Join(t.TempDir(), "mcp.json")
	if err := os.WriteFile(elsewhere, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(product, "mcp.json")
	if err := os.Symlink(elsewhere, linked); err != nil {
		t.Fatal(err)
	}
	r := newHostRegistrar(t, home)
	res := r.Register(target)
	if res.Error != nil || !res.Added {
		t.Fatalf("Register = %+v, want the real product's file written", res)
	}
	if b, err := os.ReadFile(files[target]); err != nil || !strings.Contains(string(b), ServerName) {
		t.Fatalf("the real product's file was not written: %v", err)
	}
	if !strings.Contains(res.ProbeWarning, "not written to "+linked) || !strings.Contains(res.ProbeWarning, hostfile.ErrLink.Error()) {
		t.Errorf("the linked product's file is not reported: %+v", res)
	}
	if b, _ := os.ReadFile(elsewhere); string(b) != "{}\n" {
		t.Errorf("the link's target was written: %s", b)
	}
	un := r.Unregister(target)
	if un.Error != nil || !un.Removed || !strings.Contains(un.SkipReason, "nothing removed from "+linked) || !strings.Contains(un.SkipReason, hostfile.ErrLink.Error()) {
		t.Errorf("Unregister = %+v, want the linked file named", un)
	}

	// Only the linked file: a skip whose reason carries the refusal.
	if err := os.RemoveAll(filepath.Join(vendor, "IntelliJIdea2026.2")); err != nil {
		t.Fatal(err)
	}
	only := r.Register(target)
	if only.Error != nil || !only.Skipped || !strings.Contains(only.SkipReason, linked) || !strings.Contains(only.SkipReason, hostfile.ErrLink.Error()) {
		t.Errorf("Register with only the linked product = %+v", only)
	}
}
