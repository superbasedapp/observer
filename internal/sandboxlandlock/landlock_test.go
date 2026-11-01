package sandboxlandlock

import (
	"errors"
	"strings"
	"testing"
)

func TestFeaturesFor(t *testing.T) {
	cases := []struct {
		abi                  int
		net, scoped, resolve bool
		udp                  bool
	}{
		{0, false, false, false, false},
		{3, false, false, false, false},
		{4, true, false, false, false},
		{6, true, true, false, false},
		{7, true, true, false, false},
		{9, true, true, true, false},
		{10, true, true, true, true},
	}
	for _, c := range cases {
		f := FeaturesFor(c.abi)
		if (f.Net != 0) != c.net || (f.Scoped != 0) != c.scoped || f.ResolveUnix != c.resolve || f.UDP != c.udp {
			t.Errorf("ABI %d: %+v", c.abi, f)
		}
	}
	if FeaturesFor(1).FS&AccessFSRefer != 0 || FeaturesFor(2).FS&AccessFSRefer == 0 || FeaturesFor(5).FS&AccessFSIoctlDev == 0 {
		t.Fatal("the fs rights do not follow the ABI table")
	}
	if Floor(0) != 9 || Floor(7) != 9 || Floor(11) != 11 {
		t.Fatal("min_abi can only raise the floor")
	}
}

// TestProbeLadder: one case per row; nothing is read while inactive, and
// WSL2's ABI 7 is refused by name.
func TestProbeLadder(t *testing.T) {
	read := false
	abi := func(n int) func() (int, error) { return func() (int, error) { read = true; return n, nil } }
	cases := []struct {
		name string
		env  ProbeEnv
		want string
		rule string
	}{
		{"healthy 7.1 host", ProbeEnv{Host: HostLinux, Active: true, ABI: abi(9)}, VerdictAvailable, ""},
		{"macOS", ProbeEnv{Host: HostOther, Active: true, ABI: abi(9)}, VerdictUnsupportedPlatform, "L1 platform"},
		{"inactive reads nothing", ProbeEnv{Host: HostLinux, ABI: abi(9)}, VerdictDisabledByConfig, "L2 active"},
		{"no landlock", ProbeEnv{Host: HostLinux, Active: true, ABI: func() (int, error) { return 0, errors.New("EOPNOTSUPP") }}, VerdictLandlockUnavailable, "L3 abi"},
		{"WSL2 ABI 7", ProbeEnv{Host: HostWSL2, Active: true, ABI: abi(7)}, VerdictLandlockABITooOld, "L4 floor"},
		{"min_abi raised", ProbeEnv{Host: HostLinux, Active: true, MinABI: 10, ABI: abi(9)}, VerdictLandlockABITooOld, "L4 floor"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			read = false
			r := Probe(c.env)
			if r.Verdict.Code != c.want || (c.rule != "" && r.Rule != c.rule) {
				t.Fatalf("%v at %s, want %s at %s", r.Verdict, r.Rule, c.want, c.rule)
			}
			if c.want == VerdictDisabledByConfig && read {
				t.Fatal("the ABI was read while inactive")
			}
			if c.name == "WSL2 ABI 7" && !strings.Contains(r.Verdict.Reason, "WSL2") {
				t.Fatalf("WSL2 is not named: %s", r.Verdict.Reason)
			}
		})
	}
}

// TestProbeRefusalNamesTheRealFloor (Linux live check 2026-10-23): the
// refusal names the floor in force; a raised min_abi is named as such, never
// as "without ABI 9".
func TestProbeRefusalNamesTheRealFloor(t *testing.T) {
	abi := func(n int) func() (int, error) { return func() (int, error) { return n, nil } }
	raised := Probe(ProbeEnv{Host: HostLinux, Active: true, MinABI: 11, ABI: abi(10)}).Verdict.Reason
	if !strings.Contains(raised, "ABI is 10, below 11") || !strings.Contains(raised, "min_abi") || strings.Contains(raised, "without ABI 9") {
		t.Fatalf("raised floor: %q", raised)
	}
	row := Probe(ProbeEnv{Host: HostLinux, Active: true, ABI: abi(8)}).Verdict.Reason
	if !strings.Contains(row, "ABI is 8, below 9") || !strings.Contains(row, "below ABI 9 the daemon's relay endpoint") || strings.Contains(row, "min_abi") {
		t.Fatalf("row floor: %q", row)
	}
}

// TestBuildRulesetGrantsTheConfigViewReadOnly (LIN-1 F3): the launcher's
// config view is readable inside the observer directory and nothing else
// there is; the database and a secret stay unreachable, and a config entry
// that also carries a write right is refused.
func TestBuildRulesetGrantsTheConfigViewReadOnly(t *testing.T) {
	in := testInput()
	in.ConfigRO = []string{"/home/dev/.observer/config.toml", "/home/dev/.observer/guard-org-lock.json", "/etc/observer/team.toml"}
	rs, err := BuildRuleset(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range in.ConfigRO {
		if a := rs.Allowed(p); a&AccessFSReadFile == 0 || a&^accessRead != 0 {
			t.Errorf("%s: allowed %#x, want read only", p, a)
		}
	}
	for _, denied := range []string{"/home/dev/.observer/observer.db", "/home/dev/.observer/remote-secret", "/home/dev/.observer"} {
		if a := rs.Allowed(denied); a != 0 {
			t.Errorf("%s is reachable: %#x", denied, a)
		}
	}
	in.ExtraRW = []string{"/home/dev/.observer/config.toml"}
	if _, err := BuildRuleset(in); err == nil {
		t.Fatal("a writable config view was accepted")
	}
	in = testInput()
	in.ConfigRO = []string{"/home/dev/.observer"}
	if _, err := BuildRuleset(in); err == nil {
		t.Fatal("the whole observer directory was accepted as the config view")
	}
}

// TestAllowedPorts: every TCP port but Observer's own.
func TestAllowedPorts(t *testing.T) {
	rs, err := AllowedPorts([]int{8081, 1, 65535, 8081, 4318})
	if err != nil {
		t.Fatal(err)
	}
	if Allows(rs, 8081) || Allows(rs, 1) || Allows(rs, 65535) || Allows(rs, 4318) || !Allows(rs, 8820) || !Allows(rs, 2) || !Allows(rs, 65534) {
		t.Fatalf("ranges %v", rs)
	}
	if PortCount(rs) != 65535-4 {
		t.Fatalf("count %d", PortCount(rs))
	}
	all, _ := AllowedPorts(nil)
	if len(all) != 1 || all[0] != (PortRange{1, 65535}) {
		t.Fatalf("no denied port: %v", all)
	}
	for _, bad := range []int{0, -1, 65536} {
		if _, err := AllowedPorts([]int{bad}); err == nil {
			t.Errorf("port %d accepted", bad)
		}
	}
}

func testInput() PlanInput {
	return PlanInput{
		ABI: 9, Workspace: "/home/dev/proj",
		StateRW: []string{"/home/dev/.claude"}, StateRO: []string{"/home/dev/.gitconfig"},
		ToolBinDirs: []string{"/home/dev/.local/bin"}, RuntimeDirs: []string{"/home/dev/.nvm"},
		ObserverBin: "/usr/local/bin/observer",
		SocketDir:   "/tmp/observer-sbx-run1", TempDir: "/tmp/observer-sbx-tmp-run1",
		ObserverDir:   "/home/dev/.observer",
		DaemonSockets: []string{"/home/dev/.observer/relay/daemon.sock", "/run/user/1000/observer-attach.sock"},
		DeniedPorts:   []int{8081},
	}
}

// TestBuildRulesetMirrorsTheBindPlan: the workspace and tool state are
// writable, the tool's bins executable, the run's socket dir connectable
// and nothing else, the observer dir and the daemon's sockets unreachable,
// and TCP allows every port but Observer's.
func TestBuildRulesetMirrorsTheBindPlan(t *testing.T) {
	rs, err := BuildRuleset(testInput())
	if err != nil {
		t.Fatal(err)
	}
	if rs.HandledFS&AccessFSResolveUnix == 0 || rs.HandledNet == 0 || rs.Scoped == 0 || !rs.UDPUnrestricted {
		t.Fatalf("handled %+v", rs)
	}
	checks := []struct {
		path string
		want uint64
		not  uint64
	}{
		{"/home/dev/proj/src/a.go", AccessFSWriteFile | AccessFSExecute, AccessFSResolveUnix},
		{"/home/dev/.claude/settings.json", AccessFSWriteFile, 0},
		{"/home/dev/.gitconfig", AccessFSReadFile, AccessFSWriteFile},
		{"/home/dev/.local/bin/claude", AccessFSExecute, AccessFSWriteFile},
		{"/usr/bin/git", AccessFSExecute, AccessFSWriteFile},
		{"/etc/hosts", AccessFSReadFile, AccessFSWriteFile | AccessFSExecute},
		{"/tmp/observer-sbx-run1/relay.sock", AccessFSResolveUnix, AccessFSWriteFile | AccessFSMakeSock},
		{"/tmp/observer-sbx-tmp-run1/x", AccessFSWriteFile, AccessFSResolveUnix},
	}
	for _, c := range checks {
		got := rs.Allowed(c.path)
		if got&c.want != c.want || got&c.not != 0 {
			t.Errorf("%s: allowed %#x, want %#x and not %#x", c.path, got, c.want, c.not)
		}
	}
	for _, denied := range []string{"/home/dev/.observer/observer.db", "/home/dev/.observer/relay/daemon.sock", "/run/user/1000/observer-attach.sock", "/home/dev/.ssh/id_ed25519", "/tmp/other"} {
		if a := rs.Allowed(denied); a != 0 {
			t.Errorf("%s is reachable: %#x", denied, a)
		}
	}
	if Allows(rs.Ports, 8081) || !Allows(rs.Ports, 443) {
		t.Fatal("the port allow-list is wrong")
	}
	f := FeaturesFor(9)
	for _, r := range rs.Paths {
		if r.Access&^f.FS != 0 {
			t.Errorf("%s carries an unhandled right", r.Path)
		}
	}
}

// TestBuildRulesetRefuses: one case per validation row.
func TestBuildRulesetRefuses(t *testing.T) {
	cases := map[string]func(in *PlanInput){
		"abi below 9":           func(in *PlanInput) { in.ABI = 7 },
		"whole root":            func(in *PlanInput) { in.ExtraRO = []string{"/"} },
		"relative grant":        func(in *PlanInput) { in.ExtraRW = []string{"home/x"} },
		"workspace":             func(in *PlanInput) { in.Workspace = "rel" },
		"observer dir parent":   func(in *PlanInput) { in.StateRW = []string{"/home/dev"} },
		"inside observer dir":   func(in *PlanInput) { in.ExtraRO = []string{"/home/dev/.observer/sandbox-oci"} },
		"no observer dir named": func(in *PlanInput) { in.ObserverDir = "" },
		"socket dir holds the daemon's": func(in *PlanInput) {
			in.SocketDir = "/run/user/1000"
		},
		"overlap": func(in *PlanInput) { in.TempDir = "/tmp/observer-sbx-run1/t" },
		"port":    func(in *PlanInput) { in.DeniedPorts = []int{70000} },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			in := testInput()
			edit(&in)
			if _, err := BuildRuleset(in); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
