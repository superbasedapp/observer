package sandboxsbpl

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
)

// eval_test.go is the oracle suite: each generated profile is parsed by the
// strict checker and asked, through the evaluator, about the accesses the
// bwrap plan allows and refuses. Register MAC-37 runs the same matrix
// against Seatbelt itself.

func built(t *testing.T, r Request) ([]Rule, map[string]string) {
	t.Helper()
	p, err := Build(r)
	if err != nil {
		t.Fatal(err)
	}
	params := p.ParamMap()
	rules, err := Check(p.Text, params)
	if err != nil {
		t.Fatalf("%v\n%s", err, p.Text)
	}
	return rules, params
}

type access struct {
	name string
	q    Query
	want bool
}

func file(op, path string) Query { return Query{Op: op, Path: path} }

func runMatrix(t *testing.T, rules []Rule, params map[string]string, cases []access) {
	t.Helper()
	for _, c := range cases {
		if got := Allowed(rules, params, c.q); got != c.want {
			t.Errorf("%s: allowed = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestOracleFiles(t *testing.T) {
	rules, params := built(t, baseRequest(sandbox.EgressInternet))
	runMatrix(t, rules, params, []access{
		{"system binary reads", file("file-read-data", "/usr/bin/git"), true},
		{"system file write denied by default", file("file-write-data", "/etc/hosts"), false},
		{"workspace writes", file("file-write-data", "/Users/dev/src/app/main.go"), true},
		{"workspace reads", file("file-read-data", "/Users/dev/src/app/main.go"), true},
		{"tool state writes", file("file-write-data", "/Users/dev/.claude/settings.json"), true},
		{"tool state file writes", file("file-write-data", "/Users/dev/.claude.json"), true},
		{"read-only state reads", file("file-read-data", "/Users/dev/.gitconfig"), true},
		{"read-only state does not write", file("file-write-data", "/Users/dev/.gitconfig"), false},
		{"runtime ladder reads", file("file-read-data", "/Users/dev/.nvm/versions/node/v22/bin/node"), true},
		{"home is blinded", file("file-read-data", "/Users/dev/.ssh/id_ed25519"), false},
		{"home cannot be listed", file("file-read-data", "/Users/dev"), false},
		{"home keeps its metadata", file("file-read-metadata", "/Users/dev"), true},
		{"ancestor keeps its metadata", file("file-read-metadata", "/Users/dev/src"), true},
		{"ancestor is not listable", file("file-read-data", "/Users/dev/src"), false},
		{"a sibling project stays hidden", file("file-read-data", "/Users/dev/src/other/secret.txt"), false},
		{"temp writes", file("file-write-data", "/private/var/folders/xy/abc/T/obsbx-tmp/run1/x"), true},
		{"another run's temp is not writable", file("file-write-data", "/private/var/folders/xy/abc/T/obsbx-tmp/run2/x"), false},
		{"observer db hidden", file("file-read-data", "/Users/dev/.observer/observer.db"), false},
		{"observer run records hidden", file("file-read-data", "/Users/dev/.observer/sandbox-relay/runs/run1.json"), false},
		{"observer config reads", file("file-read-data", "/Users/dev/.observer/config.toml"), true},
		{"observer config does not write", file("file-write-data", "/Users/dev/.observer/config.toml"), false},
		{"git config reads", file("file-read-data", "/Users/dev/src/app/.git/config"), true},
		{"git config does not write", file("file-write-data", "/Users/dev/src/app/.git/config"), false},
		{"git hooks cannot be planted", file("file-write-create", "/Users/dev/src/app/.git/hooks/pre-commit"), false},
		{"git objects still write", file("file-write-data", "/Users/dev/src/app/.git/objects/ab/cd"), true},
		{"hidden credential unreadable", file("file-read-data", "/Users/dev/.claude/.credentials.json"), false},
		{"hidden credential unwritable", file("file-write-data", "/Users/dev/.claude/.credentials.json"), false},
		{"observer binary reads", file("file-read-data", "/opt/homebrew/bin/observer"), true},
		{"observer binary does not write", file("file-write-data", "/opt/homebrew/bin/observer"), false},
		{"own launch record reads", file("file-read-data", "/private/var/folders/xy/abc/T/obsbx/run1/launch.json"), true},
		{"own socket dir does not write", file("file-write-data", "/private/var/folders/xy/abc/T/obsbx/run1/launch.json"), false},
		{"another run's launch record hidden", file("file-read-data", "/private/var/folders/xy/abc/T/obsbx/run2/launch.json"), false},
		{"the inherited pty ioctl", file("file-ioctl", "/dev/ttys004"), true},
		{"the inherited pty writes", file("file-write-data", "/dev/ttys004"), true},
		{"another terminal is refused", file("file-ioctl", "/dev/ttys005"), false},
		{"another terminal does not write", file("file-write-data", "/dev/ttys005"), false},
		{"/dev/tty ioctl", file("file-ioctl", "/dev/tty"), true},
		{"/dev/null writes", file("file-write-data", "/dev/null"), true},
	})
}

func TestOracleNetworkPerTier(t *testing.T) {
	ip := func(a string) Query { return Query{Op: "network-outbound", RemoteIP: a} }
	sock := func(p string) Query { return Query{Op: "network-outbound", Socket: p} }
	relay := "/private/var/folders/xy/abc/T/obsbx/run1/relay.sock"
	common := []access{
		{"own relay socket", sock(relay), true},
		{"another run's relay socket", sock("/private/var/folders/xy/abc/T/obsbx/run2/relay.sock"), false},
		{"daemon attach socket", sock("/Users/dev/.observer/sandbox-relay/attach/attach.sock"), false},
		{"mDNSResponder (DNS)", sock("/private/var/run/mDNSResponder"), false},
		{"dashboard port", ip("localhost:8822"), false},
		{"a provider by name", ip("api.anthropic.com:443"), false},
		{"a provider by literal IP", ip("160.79.104.10:443"), false},
		{"a LAN address", ip("192.168.1.10:22"), false},
		{"inbound", Query{Op: "network-inbound", RemoteIP: "localhost:9999"}, false},
		{"bind", Query{Op: "network-bind", RemoteIP: "localhost:9999"}, false},
	}
	tiers := []struct {
		tier           sandbox.Egress
		proxy, gateway bool
	}{
		{sandbox.EgressInternet, true, true},
		{sandbox.EgressProxyOnly, true, false},
		{sandbox.EgressNone, false, false},
	}
	for _, tc := range tiers {
		t.Run(string(tc.tier), func(t *testing.T) {
			rules, params := built(t, baseRequest(tc.tier))
			cases := append([]access{
				{"proxy port", ip("localhost:8820"), tc.proxy},
				{"proxy port by 127.0.0.1", ip("127.0.0.1:8820"), tc.proxy},
				{"gateway port", ip("localhost:50123"), tc.gateway},
			}, common...)
			runMatrix(t, rules, params, cases)
		})
	}
}

func TestOracleProcessAndMach(t *testing.T) {
	rules, params := built(t, baseRequest(sandbox.EgressNone))
	runMatrix(t, rules, params, []access{
		{"exec", Query{Op: "process-exec", Path: "/bin/sh"}, true},
		{"signal inside", Query{Op: "signal", SameSandbox: true}, true},
		{"signal outside", Query{Op: "signal"}, false},
		{"libinfo", Query{Op: "mach-lookup", GlobalName: "com.apple.system.opendirectoryd.libinfo"}, true},
		{"keychain off by default", Query{Op: "mach-lookup", GlobalName: "com.apple.SecurityServer"}, false},
		{"pasteboard", Query{Op: "mach-lookup", GlobalName: "com.apple.pasteboard.1"}, false},
		{"apple events", Query{Op: "appleevent-send"}, false},
	})
	r := baseRequest(sandbox.EgressNone)
	r.MachServices = KeychainMachServices
	rules, params = built(t, r)
	if !Allowed(rules, params, Query{Op: "mach-lookup", GlobalName: "com.apple.SecurityServer"}) {
		t.Fatal("the Keychain switch did not add its services")
	}
}

// TestOracleWorkspaceAtHomeKeepsObserverHidden is the bwrap step 8b case: a
// project at the home binds the observer dir again, so it is hidden once
// more; the mutation drops that rule and the observer database leaks.
func TestOracleWorkspaceAtHomeKeepsObserverHidden(t *testing.T) {
	r := baseRequest(sandbox.EgressProxyOnly)
	r.WorkspaceRoot = "/Users/dev"
	r.Overlays = nil
	rules, params := built(t, r)
	db := file("file-read-data", "/Users/dev/.observer/observer.db")
	if Allowed(rules, params, db) {
		t.Fatal("the observer database is readable from a workspace at the home")
	}
	if !Allowed(rules, params, file("file-write-data", "/Users/dev/notes.txt")) {
		t.Fatal("the workspace at the home is not writable")
	}
	// Mutation: without the re-hide the database leaks.
	var mutated []Rule
	seen := 0
	for _, x := range rules {
		if !x.Allow && len(x.Filters) == 1 && x.Filters[0].Value == "OBS" {
			seen++
			if seen == 2 {
				continue
			}
		}
		mutated = append(mutated, x)
	}
	if seen != 2 || !Allowed(mutated, params, db) {
		t.Fatal("the mutation proof did not bite: the re-hide rule is not what keeps the database hidden")
	}
}

func TestOracleReadonlyHome(t *testing.T) {
	r := baseRequest(sandbox.EgressInternet)
	r.HomeMode = HomeModeReadonly
	rules, params := built(t, r)
	runMatrix(t, rules, params, []access{
		{"home reads in readonly mode", file("file-read-data", "/Users/dev/notes.txt"), true},
		{"home does not write", file("file-write-data", "/Users/dev/notes.txt"), false},
		{"observer dir still hidden", file("file-read-data", "/Users/dev/.observer/observer.db"), false},
	})
}

// TestDenyByDefault: a profile of only the two mandatory forms refuses
// everything, and the generated one refuses what no section grants.
func TestDenyByDefault(t *testing.T) {
	rules, err := Check("(version 1)\n(deny default)\n", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []Query{
		file("file-read-data", "/etc/hosts"),
		{Op: "process-exec", Path: "/bin/sh"},
		{Op: "network-outbound", RemoteIP: "localhost:8820"},
		{Op: "mach-lookup", GlobalName: "com.apple.logd"},
	} {
		if Allowed(rules, nil, q) {
			t.Errorf("%+v allowed by deny default", q)
		}
	}
	rules, params := built(t, baseRequest(sandbox.EgressInternet))
	for _, q := range []Query{
		{Op: "iokit-open"},
		{Op: "system-socket"},
		{Op: "file-write-data", Path: "/Library/LaunchAgents/x.plist"},
		{Op: "file-write-data", Path: "/Users/dev/Library/LaunchAgents/x.plist"},
		{Op: "file-write-data", Path: "/Users/dev/.zshrc"},
	} {
		if Allowed(rules, params, q) {
			t.Errorf("%+v allowed", q)
		}
	}
}

func TestCheckerRefusals(t *testing.T) {
	head := "(version 1)\n(deny default)\n"
	p := map[string]string{"X": "/x"}
	cases := []struct {
		name, text string
		params     map[string]string
		want       string
	}{
		{"unbalanced", head + "(allow process-exec", nil, "unbalanced"},
		{"stray close", head + ")", nil, "unbalanced"},
		{"regex literal", head + `(allow file-read* (regex #"^/x"))`, nil, "reader syntax"},
		{"missing version", "(deny default)\n(allow process-exec)", nil, "version"},
		{"version 2", "(version 2)\n(deny default)", nil, "version"},
		{"missing deny default", "(version 1)\n(allow process-exec)", nil, "deny default"},
		{"allow default", head + "(allow default)", nil, "forbidden"},
		{"unknown op", head + "(allow appleevent-send)", nil, "unknown operation"},
		{"unknown filter", head + `(allow file-read* (prefix "/x"))`, nil, "unknown filter"},
		{"unfiltered connect", head + "(allow network-outbound)", nil, "unfiltered"},
		{"network star", head + `(allow network* (remote ip "localhost:1"))`, nil, "forbidden"},
		{"inbound", head + `(allow network-inbound (remote ip "localhost:1"))`, nil, "forbidden"},
		{"wildcard host", head + `(allow network-outbound (remote ip "*:443"))`, nil, "only localhost"},
		{"wildcard port", head + `(allow network-outbound (remote ip "localhost:*"))`, nil, "port"},
		{"provider host", head + `(allow network-outbound (remote ip "api.anthropic.com:443"))`, nil, "only localhost"},
		{"connect by path filter", head + `(allow network-outbound (literal "/dev/x"))`, nil, "filtered by"},
		{"unfiltered write", head + "(allow file-write*)", nil, "unfiltered"},
		{"unfiltered mach", head + "(allow mach-lookup)", nil, "unfiltered"},
		{"signal anywhere", head + "(allow signal)", nil, "same-sandbox"},
		{"literal path in text", head + `(allow file-read* (subpath "/Users"))`, nil, "parameter"},
		{"undefined param", head + `(allow file-read* (subpath (param "X")))`, nil, "not defined"},
		{"unused param", head + "(allow process-exec)", p, "never used"},
		{"bad escape", head + `(allow mach-lookup (global-name "a\nb"))`, nil, "escape"},
		{"socket literal", head + `(allow network-outbound (remote unix-socket (path-literal "/tmp/x")))`, nil, "parameter"},
		{"bad symbol", head + "(allow Process-exec)", nil, "character"},
		{"unfiltered shm", head + "(allow ipc-posix-shm*)", nil, "forbidden"},
		{"shm read unfiltered", head + "(allow ipc-posix-shm-read-data)", nil, "unfiltered"},
		{"shm by path", head + `(allow ipc-posix-shm-read-data (literal "/dev/x"))`, nil, "filtered by"},
		{"top-level atom", head + "allow", nil, "top-level"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Check(c.text, c.params)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
}
