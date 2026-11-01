package diag

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hook/pluginshim"
)

// TestCheckPluginShimBinaries (lane LEFT-SHARED): a shim naming the running
// observer is fine; one naming a missing binary, or an observer older than
// the running one, is a warning naming the shim; a shim that is not
// Observer's is not read; no shim at all is fine.
func TestCheckPluginShimBinaries(t *testing.T) {
	home := t.TempDir()
	env := func(string) string { return "" }
	running := filepath.Join(home, "bin", "observer")
	old := filepath.Join(home, "old", "observer")
	for _, p := range []string{running, old} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("bin"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	id := HookBinaryIdentity{Command: running, Real: running}
	versions := map[string]string{running: "v1.37.0", old: "v1.36.0"}
	versionOf := func(p string) string { return versions[p] }
	if c := checkPluginShimBinaries(home, env, id, "v1.37.0", versionOf); c.Status != StatusOK || !strings.Contains(c.Message, "no plugin shim") {
		t.Fatalf("no shim: %+v", c)
	}
	var hosts []pluginshim.Host
	for _, tool := range pluginshim.Tools() {
		if h, ok := pluginshim.HostFor(tool); ok && h.Writable() {
			hosts = append(hosts, h)
		}
	}
	if len(hosts) < 2 {
		t.Skip("needs two writable plugin hosts")
	}
	write := func(h pluginshim.Host, bin string) string {
		t.Helper()
		dir, err := h.Dir(home, env)
		if err != nil {
			t.Fatal(err)
		}
		path, err := pluginshim.Write(dir, h, pluginshim.RenderOptions{Bin: bin})
		if err != nil {
			t.Fatal(err)
		}
		return path
	}
	write(hosts[0], running)
	if c := checkPluginShimBinaries(home, env, id, "v1.37.0", versionOf); c.Status != StatusOK || !strings.Contains(c.Message, "1 plugin shim") {
		t.Fatalf("current shim: %+v", c)
	}
	write(hosts[1], old)
	c := checkPluginShimBinaries(home, env, id, "v1.37.0", versionOf)
	if c.Status != StatusWarn || len(c.Details) != 1 || !strings.Contains(c.Details[0], "v1.36.0, older than the running v1.37.0") {
		t.Fatalf("older shim: %+v", c)
	}
	write(hosts[1], filepath.Join(home, "gone", "observer"))
	if c := checkPluginShimBinaries(home, env, id, "v1.37.0", versionOf); c.Status != StatusWarn || !strings.Contains(strings.Join(c.Details, " "), "missing") {
		t.Fatalf("missing binary: %+v", c)
	}
	// A dev build compares no versions: only a missing binary warns.
	write(hosts[1], old)
	if c := checkPluginShimBinaries(home, env, id, "dev", versionOf); c.Status != StatusOK {
		t.Fatalf("dev build: %+v", c)
	}
	// A file that is not Observer's shim is never read as one.
	dir, _ := hosts[1].Dir(home, env)
	if err := os.WriteFile(filepath.Join(dir, hosts[1].File()), []byte("export default {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c := checkPluginShimBinaries(home, env, id, "v1.37.0", versionOf); c.Status != StatusOK {
		t.Fatalf("foreign file: %+v", c)
	}
}

// TestCheckPathObserver (lane LEFT-SHARED): no observer on PATH, or the
// running one, is fine; an older observer on PATH is a warning naming it; a
// newer or unversioned one is not.
func TestCheckPathObserver(t *testing.T) {
	dir := t.TempDir()
	running, other := filepath.Join(dir, "running"), filepath.Join(dir, "other")
	for _, p := range []string{running, other} {
		if err := os.WriteFile(p, []byte("bin"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	id := HookBinaryIdentity{Command: running, Real: running}
	look := func(p string) func() (string, error) {
		return func() (string, error) {
			if p == "" {
				return "", errors.New("not found")
			}
			return p, nil
		}
	}
	cases := []struct {
		name, path, version string
		want                Status
	}{
		{"none on PATH", "", "", StatusOK},
		{"the running one", running, "v1.36.0", StatusOK},
		{"older on PATH", other, "v1.36.0", StatusWarn},
		{"newer on PATH", other, "v1.38.0", StatusOK},
		{"unversioned on PATH", other, "", StatusOK},
	}
	for _, c := range cases {
		versionOf := func(string) string { return c.version }
		got := checkPathObserver(look(c.path), id, "v1.37.0", versionOf)
		if got.Status != c.want {
			t.Errorf("%s: %+v", c.name, got)
		}
		if c.want == StatusWarn && !strings.Contains(got.Message, "older than the running v1.37.0") {
			t.Errorf("%s: message %q", c.name, got.Message)
		}
	}
}

// TestBinaryVersionOfAndOlderThan pins the version helpers.
func TestBinaryVersionOfAndOlderThan(t *testing.T) {
	if BinaryVersionOf(filepath.Join(t.TempDir(), "nope")) != "" {
		t.Fatal("a missing file has no version")
	}
	if m := ldflagsVersion.FindStringSubmatch("-s -w -X main.version=v1.36.0"); m == nil || m[1] != "v1.36.0" {
		t.Fatalf("ldflags parse: %v", m)
	}
	for _, c := range []struct {
		a, b string
		want bool
	}{{"1.36.0", "v1.37.0", true}, {"v1.37.0", "1.37.0", false}, {"v1.38.0", "v1.37.0", false}, {"dev", "v1.37.0", false}, {"v1.36.0", "dev", false}, {"v1.37.0-rc.1", "v1.37.0", true}, {"v1.37.0", "v1.37.0-rc.1", false}, {"v1.10.0", "v1.9.0", false}, {"v1.37", "v1.38.0", false}} {
		if got := olderThan(c.a, c.b); got != c.want {
			t.Errorf("olderThan(%q, %q) = %v", c.a, c.b, got)
		}
	}
}
