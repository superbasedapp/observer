//go:build !sbo_omit_terminals_sandbox_seatbelt && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxenv"
	"github.com/marmutapp/superbased-observer/internal/sandboxsbpl"
)

// TestSeatbeltDarwinToolRows pins D-MU6 per tool against the darwin
// Seatbelt profile (built and evaluated by internal/sandboxsbpl, so it runs
// on any OS): opencode, goose and copilot-cli can write the macOS state the
// live install showed they need; junie's JVM gets the run's TMPDIR; and
// gemini-cli's /bin/ps limitation is stated on its row. (The live refusal
// of the setuid /bin/ps comes from macOS itself, which this evaluator does
// not model; Observer does not widen the box to let it run.)
func TestSeatbeltDarwinToolRows(t *testing.T) {
	const home = "/Users/dev"
	const tmp = "/private/var/folders/xy/abc/T/obsbx-tmp/run1"
	profileFor := func(t *testing.T, tool string) ([]sandboxsbpl.Rule, map[string]string) {
		t.Helper()
		spec, err := macToolSpec(tool)
		if err != nil {
			t.Fatal(err)
		}
		spec = spec.ForOS("darwin")
		p, err := sandboxsbpl.Build(sandboxsbpl.Request{
			Home: home, ObserverDir: home + "/.observer", WorkspaceRoot: home + "/src/app",
			ObserverBin: "/opt/homebrew/bin/observer", ObserverRealDir: "/opt/homebrew/bin",
			TempDir: tmp, SocketParent: "/private/var/folders/xy/abc/T/obsbx", SocketDir: "/private/var/folders/xy/abc/T/obsbx/run1",
			StateRW: spec.StateRW, StateRO: spec.StateRO,
			TempRoots: []string{"/private/var/folders/xy/abc/T", "/private/tmp"},
			Net:       sandboxsbpl.Net{Egress: sandbox.EgressInternet, ProxyPort: 8820, GatewayPort: 50123},
			Resolve:   func(p string) string { return p },
		})
		if err != nil {
			t.Fatal(err)
		}
		rules, err := sandboxsbpl.Check(p.Text, p.ParamMap())
		if err != nil {
			t.Fatal(err)
		}
		return rules, p.ParamMap()
	}
	for _, c := range []struct{ tool, rel string }{
		{"opencode", ".local/state/opencode/prompt-history.jsonl"},
		{"opencode", ".cache/opencode/bin/node_modules/x"},
		{"goose", ".local/state/goose/logs/cli.log"},
		{"copilot-cli", "Library/Caches/copilot/pkg/index"},
	} {
		t.Run(c.tool, func(t *testing.T) {
			rules, params := profileFor(t, c.tool)
			p := filepath.Join(home, c.rel)
			if !sandboxsbpl.Allowed(rules, params, sandboxsbpl.Query{Op: "file-write-data", Path: p}) {
				t.Errorf("%s cannot write %s in its darwin box", c.tool, p)
			}
			if sandboxsbpl.Allowed(rules, params, sandboxsbpl.Query{Op: "file-read-data", Path: home + "/Documents/secret.txt"}) {
				t.Errorf("%s's box reads an unrelated home folder", c.tool)
			}
		})
	}
	t.Run("junie", func(t *testing.T) {
		env := sandboxenv.WithJVMTempDir([]string{"JAVA_TOOL_OPTIONS=-Xmx1g"}, sandboxenv.TempDirJVMEnv("junie"), tmp)
		if len(env) != 1 || env[0] != "JAVA_TOOL_OPTIONS=-Xmx1g -Djava.io.tmpdir="+tmp {
			t.Errorf("junie env = %v", env)
		}
		// N3: the darwin helper's composition, as seatbelt_darwin.go runs it.
		box := append([]string{"JAVA_TOOL_OPTIONS=-Xmx1g"}, sandbox.GuestProxyEnv(50123)...)
		box = sandboxenv.WithJVMTempDir(box, sandboxenv.TempDirJVMEnv("junie"), tmp)
		box = sandboxenv.WithJVMOptions(box, sandboxenv.TempDirJVMEnv("junie"), sandboxenv.JVMProxyOptions(box))
		for _, want := range []string{"-Djava.io.tmpdir=" + tmp, "-Dhttps.proxyHost=127.0.0.1", "-Dhttps.proxyPort=50123", "-Dhttp.proxyPort=50123"} {
			if !strings.Contains(box[0], want) {
				t.Errorf("junie JAVA_TOOL_OPTIONS = %q lacks %s", box[0], want)
			}
		}
	})
	t.Run("gemini-cli", func(t *testing.T) {
		spec, err := macToolSpec("gemini-cli")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(spec.OSNote("darwin"), "/bin/ps") {
			t.Errorf("gemini-cli darwin note = %q", spec.OSNote("darwin"))
		}
	})
}
