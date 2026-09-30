package sandbox

import (
	"reflect"
	"strings"
	"testing"
)

func TestResolveEgress(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		want    Egress
		wantErr bool
	}{
		{"", DefaultEgress, false},
		{"host", EgressHost, false},
		{"internet", EgressInternet, false},
		{" proxy_only ", EgressProxyOnly, false},
		{"none", EgressNone, false},
		{"HOST", "", true},
		{"shared", "", true},
	}
	for _, tc := range tests {
		got, err := ResolveEgress(tc.in)
		if (err != nil) != tc.wantErr {
			t.Fatalf("ResolveEgress(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
		}
		if got.Mode != tc.want {
			t.Errorf("ResolveEgress(%q) = %q, want %q", tc.in, got.Mode, tc.want)
		}
	}
	if DefaultEgress == EgressHost {
		t.Fatal("the default tier must not share the host network (SR27-SBX-1)")
	}
}

// TestEgressProfileInvariants pins the security meaning of the table: only
// the shared-namespace tier leaves the control plane reachable, and every
// other tier builds a private namespace.
func TestEgressProfileInvariants(t *testing.T) {
	t.Parallel()
	seen := map[Egress]bool{}
	for _, p := range EgressProfiles() {
		if seen[p.Mode] {
			t.Errorf("duplicate tier %q", p.Mode)
		}
		seen[p.Mode] = true
		if p.ControlPlaneReachable == p.UnshareNet {
			t.Errorf("%q: ControlPlaneReachable=%v but UnshareNet=%v", p.Mode, p.ControlPlaneReachable, p.UnshareNet)
		}
		if p.Gateway && !p.UnshareNet {
			t.Errorf("%q: a gateway only makes sense in a private namespace", p.Mode)
		}
		if p.Summary == "" || strings.ContainsRune(p.Summary, '—') {
			t.Errorf("%q: summary empty or carries an em-dash", p.Mode)
		}
	}
	if got := strings.Join(EgressModes(), ","); got != "host,internet,proxy_only,none" {
		t.Errorf("EgressModes = %s", got)
	}
}

func netReq(mode Egress) Request {
	r := canonicalReq()
	r.Net = NetRequest{Egress: mode, HostSocketDir: "/tmp/observer-sbx-abc", ProxyPort: 8820}
	return r
}

func indexOf(argv []string, tok string) int {
	for i, a := range argv {
		if a == tok {
			return i
		}
	}
	return -1
}

func TestBuildPlanEgressTiers(t *testing.T) {
	t.Parallel()
	const sockBindSrc = "/tmp/observer-sbx-abc"
	tests := []struct {
		mode      Egress
		unshare   bool
		sockBind  bool
		wantGuest []string
	}{
		{EgressHost, false, false, nil},
		{EgressInternet, true, true, []string{
			"/home/dev/.local/bin/observer", GuestVerb,
			"--proxy-port", "8820", "--proxy-sock", GuestSocketDir + "/proxy.sock",
			"--gateway-port", "3128", "--gateway-sock", GuestSocketDir + "/gateway.sock",
			"--",
		}},
		{EgressProxyOnly, true, true, []string{
			"/home/dev/.local/bin/observer", GuestVerb,
			"--proxy-port", "8820", "--proxy-sock", GuestSocketDir + "/proxy.sock",
			"--",
		}},
		{EgressNone, true, false, nil},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(string(tc.mode), func(t *testing.T) {
			t.Parallel()
			plan, err := BuildPlan(netReq(tc.mode))
			if err != nil {
				t.Fatalf("BuildPlan: %v", err)
			}
			if plan.Egress.Mode != tc.mode {
				t.Errorf("plan.Egress = %q", plan.Egress.Mode)
			}
			argv := plan.Argv([]string{"observer", "claude"})
			sep := indexOf(argv, "--")
			flags, after := argv[:sep], argv[sep+1:]
			if got := indexOf(flags, flagUnshareNet) >= 0; got != tc.unshare {
				t.Errorf("--unshare-net present = %v, want %v", got, tc.unshare)
			}
			bi := findFlagOperand(flags, flagROBind, sockBindSrc)
			if (bi >= 0) != tc.sockBind {
				t.Fatalf("socket-dir bind present = %v, want %v", bi >= 0, tc.sockBind)
			}
			if bi >= 0 {
				if flags[bi+2] != GuestSocketDir {
					t.Errorf("socket dir bound to %q, want %q", flags[bi+2], GuestSocketDir)
				}
				if tmp := findFlagOperand(flags, flagTmpfs, "/tmp"); tmp < 0 || tmp > bi {
					t.Errorf("socket bind (%d) must follow the /tmp tmpfs (%d)", bi, tmp)
				}
			}
			wantAfter := append(append([]string(nil), tc.wantGuest...), "observer", "claude")
			if !reflect.DeepEqual(after, wantAfter) {
				t.Errorf("after --:\n got %#v\nwant %#v", after, wantAfter)
			}
		})
	}
}

func TestBuildPlanEgressGuards(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		mut  func(r *Request)
	}{
		{"empty tier", func(r *Request) { r.Net.Egress = "" }},
		{"unknown tier", func(r *Request) { r.Net.Egress = "wide-open" }},
		{"no socket dir", func(r *Request) { r.Net.HostSocketDir = "" }},
		{"relative socket dir", func(r *Request) { r.Net.HostSocketDir = "tmp/x" }},
		{"flag socket dir", func(r *Request) { r.Net.HostSocketDir = "-x" }},
		{"socket path too long", func(r *Request) { r.Net.HostSocketDir = "/" + strings.Repeat("a", 100) }},
		{"zero proxy port", func(r *Request) { r.Net.ProxyPort = 0 }},
		{"proxy port too big", func(r *Request) { r.Net.ProxyPort = 70000 }},
		{"no observer bin for the guest", func(r *Request) { r.ObserverBin = "" }},
	}
	for _, tc := range tests {
		r := netReq(EgressInternet)
		tc.mut(&r)
		if _, err := BuildPlan(r); err == nil {
			t.Errorf("%s: BuildPlan accepted an invalid network request", tc.name)
		}
	}
	// none/host need no socket dir or port.
	for _, m := range []Egress{EgressHost, EgressNone} {
		r := canonicalReq()
		r.Net = NetRequest{Egress: m}
		if _, err := BuildPlan(r); err != nil {
			t.Errorf("%s without socket dir: %v", m, err)
		}
	}
}

func TestGatewayPortAvoidsProxyPort(t *testing.T) {
	t.Parallel()
	if GatewayPort(8820) != 3128 || GatewayPort(3128) != 3129 {
		t.Fatalf("GatewayPort: %d %d", GatewayPort(8820), GatewayPort(3128))
	}
}

func TestHostArgvAndParseRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		mode    Egress
		want    []string
		gateway bool
	}{
		{EgressHost, nil, false},
		{EgressNone, nil, false},
		{EgressProxyOnly, []string{"/o/observer", HostVerb, "--sock-dir", "/tmp/s", "--proxy-addr", "127.0.0.1:8820", "--"}, false},
		{EgressInternet, []string{"/o/observer", HostVerb, "--sock-dir", "/tmp/s", "--proxy-addr", "127.0.0.1:8820", "--gateway", "--"}, true},
	}
	for _, tc := range tests {
		got, err := HostArgv("/o/observer", NetRequest{Egress: tc.mode, HostSocketDir: "/tmp/s", ProxyPort: 8820})
		if err != nil {
			t.Fatalf("%s: %v", tc.mode, err)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: HostArgv = %#v, want %#v", tc.mode, got, tc.want)
		}
		if got == nil {
			continue
		}
		parsed, err := ParseHostArgs(append(append([]string(nil), got[2:]...), "/usr/bin/bwrap", "--ro-bind", "/", "/"))
		if err != nil {
			t.Fatalf("%s: ParseHostArgs: %v", tc.mode, err)
		}
		if parsed.SockDir != "/tmp/s" || parsed.ProxyAddr != "127.0.0.1:8820" || parsed.Gateway != tc.gateway {
			t.Errorf("%s: parsed %+v", tc.mode, parsed)
		}
		if parsed.Command[0] != "/usr/bin/bwrap" || len(parsed.Command) != 4 {
			t.Errorf("%s: command %v", tc.mode, parsed.Command)
		}
	}

	plan, err := BuildPlan(netReq(EgressInternet))
	if err != nil {
		t.Fatal(err)
	}
	argv := plan.Argv([]string{"/bin/sh", "-c", "true"})
	gi := indexOf(argv, GuestVerb)
	g, err := ParseGuestArgs(argv[gi+1:])
	if err != nil {
		t.Fatalf("ParseGuestArgs: %v", err)
	}
	want := GuestArgs{
		ProxyPort: 8820, ProxySock: GuestSocketDir + "/proxy.sock",
		GatewayPort: 3128, GatewaySock: GuestSocketDir + "/gateway.sock",
		Command: []string{"/bin/sh", "-c", "true"},
	}
	if !reflect.DeepEqual(g, want) {
		t.Errorf("guest parse = %+v, want %+v", g, want)
	}
}

func TestParseHelperArgsErrors(t *testing.T) {
	t.Parallel()
	host := [][]string{
		{"--proxy-addr", "127.0.0.1:1", "--", "bwrap"},     // no sock dir
		{"--sock-dir", "rel", "--", "bwrap"},               // relative
		{"--sock-dir", "/tmp/s", "bwrap"},                  // no --
		{"--sock-dir", "/tmp/s", "--"},                     // no command
		{"--sock-dir", "/tmp/s", "--", "--evil"},           // flag-shaped command
		{"--sock-dir", "/tmp/s", "--bogus", "--", "bwrap"}, // unknown flag
		{"--sock-dir"}, // missing value
	}
	for _, a := range host {
		if _, err := ParseHostArgs(a); err == nil {
			t.Errorf("ParseHostArgs(%v) accepted", a)
		}
	}
	guest := [][]string{
		{"--proxy-port", "8820", "--", "x"},                     // port without sock
		{"--gateway-sock", "/tmp/g", "--", "x"},                 // sock without port
		{"--proxy-port", "0", "--proxy-sock", "/p", "--", "x"},  // bad port
		{"--proxy-port", "x", "--proxy-sock", "/p", "--", "x"},  // non-numeric
		{"--proxy-port", "1", "--proxy-sock", "rel", "--", "x"}, // relative sock
	}
	for _, a := range guest {
		if _, err := ParseGuestArgs(a); err == nil {
			t.Errorf("ParseGuestArgs(%v) accepted", a)
		}
	}
}

func TestGuestProxyEnv(t *testing.T) {
	t.Parallel()
	env := GuestProxyEnv(3128)
	joined := strings.Join(env, "\n")
	for _, want := range []string{
		"HTTP_PROXY=http://127.0.0.1:3128", "HTTPS_PROXY=http://127.0.0.1:3128",
		"http_proxy=http://127.0.0.1:3128", "https_proxy=http://127.0.0.1:3128",
		"NO_PROXY=127.0.0.1,localhost,::1", "no_proxy=127.0.0.1,localhost,::1",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("GuestProxyEnv missing %q", want)
		}
	}
}

func TestBuildPlanOverlays(t *testing.T) {
	t.Parallel()
	r := canonicalReq()
	r.ExtraRW = []string{"/home/dev/.claude/settings.json"}
	r.Overlays = []Overlay{
		{Path: "/home/dev/.observer/config.toml", Kind: OverlayReadOnly},
		{Path: "/home/dev/.observer/attach", Kind: OverlayHideDir},
		{Path: "/home/dev/.observer/remote-secret", Kind: OverlayHideFile},
		{Path: "/home/dev/.claude/settings.json", Kind: OverlayReadOnly},
	}
	plan, err := BuildPlan(r)
	if err != nil {
		t.Fatal(err)
	}
	argv := plan.Argv([]string{"true"})
	lastRW := findFlagOperand(argv, flagBind, "/home/dev/.claude/settings.json")
	for _, c := range []struct{ flag, operand string }{
		{flagROBindTry, "/home/dev/.observer/config.toml"},
		{flagTmpfs, "/home/dev/.observer/attach"},
		{flagROBind, devNull},
		{flagROBindTry, "/home/dev/.claude/settings.json"},
	} {
		i := findFlagOperand(argv, c.flag, c.operand)
		if i < 0 {
			t.Fatalf("missing %s %s", c.flag, c.operand)
		}
		if i < lastRW {
			t.Errorf("%s %s at %d precedes the last rw bind at %d: an rw bind could re-open it", c.flag, c.operand, i, lastRW)
		}
	}
	if i := findFlagOperand(argv, flagROBind, devNull); argv[i+2] != "/home/dev/.observer/remote-secret" {
		t.Errorf("hide_file target = %q", argv[i+2])
	}

	for _, bad := range []Overlay{
		{Path: "/", Kind: OverlayHideDir},
		{Path: "rel", Kind: OverlayReadOnly},
		{Path: "/x", Kind: "bogus"},
	} {
		r2 := canonicalReq()
		r2.Overlays = []Overlay{bad}
		if _, err := BuildPlan(r2); err == nil {
			t.Errorf("overlay %+v accepted", bad)
		}
	}
}

// TestBuildPlanReprotectsBinsUnderRW: a binary a later unsandboxed session
// runs must not become writable just because it lives under an rw bind.
func TestBuildPlanReprotectsBinsUnderRW(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		observer   string
		toolDirs   []string
		wantReRO   []string
		wantNoReRO []string
	}{
		{
			name:     "observer binary under ~/.observer",
			observer: "/home/dev/.observer/bin/observer",
			wantReRO: []string{"/home/dev/.observer/bin/observer"},
		},
		{
			name:     "tool binary dir under a tool state dir",
			observer: "/home/dev/.local/bin/observer",
			toolDirs: []string{"/home/dev/.claude/local"},
			wantReRO: []string{"/home/dev/.claude/local"},
		},
		{
			name:       "dir that contains an rw target is left alone",
			observer:   "/home/dev/.local/bin/observer",
			toolDirs:   []string{"/home/dev"},
			wantNoReRO: []string{"/home/dev"},
		},
		{
			name:       "bin outside every rw bind is not re-bound twice",
			observer:   "/home/dev/.local/bin/observer",
			toolDirs:   []string{"/usr/local/bin"},
			wantNoReRO: []string{"/usr/local/bin"},
		},
	}
	for _, tc := range tests {
		r := canonicalReq()
		r.ObserverBin = tc.observer
		r.ToolBinDirs = tc.toolDirs
		plan, err := BuildPlan(r)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		argv := plan.Argv([]string{"true"})
		obs := findFlagOperand(argv, flagBind, "/home/dev/.observer")
		for _, p := range tc.wantReRO {
			last := -1
			for i := 0; i+1 < len(argv); i++ {
				if argv[i] == flagROBindTry && argv[i+1] == p {
					last = i
				}
			}
			if last < obs {
				t.Errorf("%s: %s not re-bound read-only after the rw binds", tc.name, p)
			}
		}
		for _, p := range tc.wantNoReRO {
			n := 0
			for i := 0; i+1 < len(argv); i++ {
				if argv[i] == flagROBindTry && argv[i+1] == p {
					n++
				}
			}
			if n > 1 {
				t.Errorf("%s: %s ro-bound %d times", tc.name, p, n)
			}
		}
	}
}

// TestHostArgvCarriesAllowCIDRsAndPlaceholders: the helper prefix carries the
// gateway allow-list (gateway tiers only) and every placeholder, and parses
// back to the same values; a tier with nothing to forward still gets the
// helper when a placeholder must be created, with no --sock-dir.
func TestHostArgvCarriesAllowCIDRsAndPlaceholders(t *testing.T) {
	t.Parallel()
	ph := []Overlay{
		{Path: "/home/dev/.observer/guard-policy.toml", Kind: OverlayReadOnly, Placeholder: PlaceholderFile},
		{Path: "/home/dev/.observer/attach", Kind: OverlayHideDir, Placeholder: PlaceholderDir},
	}
	tests := []struct {
		name      string
		mode      Egress
		cidrs     []string
		ph        []Overlay
		want      []string
		wantCIDRs []string
	}{
		{
			name: "internet with allow-list and placeholders", mode: EgressInternet,
			cidrs: []string{"10.20.0.0/16", "fd00:1::/32"}, ph: ph,
			want: []string{
				"/o/observer", HostVerb, "--sock-dir", "/tmp/s", "--proxy-addr", "127.0.0.1:8820", "--gateway",
				"--egress-allow-cidr", "10.20.0.0/16", "--egress-allow-cidr", "fd00:1::/32",
				"--placeholder-file", "/home/dev/.observer/guard-policy.toml", "--placeholder-dir", "/home/dev/.observer/attach", "--",
			},
			wantCIDRs: []string{"10.20.0.0/16", "fd00:1::/32"},
		},
		{
			name: "proxy_only ignores the allow-list", mode: EgressProxyOnly, cidrs: []string{"10.20.0.0/16"},
			want: []string{"/o/observer", HostVerb, "--sock-dir", "/tmp/s", "--proxy-addr", "127.0.0.1:8820", "--"},
		},
		{
			name: "host tier with placeholders runs the helper without a socket dir", mode: EgressHost, ph: ph,
			want: []string{
				"/o/observer", HostVerb,
				"--placeholder-file", "/home/dev/.observer/guard-policy.toml", "--placeholder-dir", "/home/dev/.observer/attach", "--",
			},
		},
		{
			name: "none tier with nothing to do needs no helper", mode: EgressNone,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := hostArgv("/o/observer", NetRequest{Egress: tc.mode, HostSocketDir: "/tmp/s", ProxyPort: 8820, EgressAllowCIDRs: tc.cidrs}, tc.ph)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("hostArgv = %#v\nwant %#v", got, tc.want)
			}
			if got == nil {
				return
			}
			parsed, err := ParseHostArgs(append(append([]string(nil), got[2:]...), "/usr/bin/bwrap"))
			if err != nil {
				t.Fatalf("ParseHostArgs: %v", err)
			}
			if !reflect.DeepEqual(parsed.AllowCIDRs, tc.wantCIDRs) {
				t.Errorf("AllowCIDRs = %v, want %v", parsed.AllowCIDRs, tc.wantCIDRs)
			}
			var files, dirs []string
			for _, o := range tc.ph {
				if o.Placeholder == PlaceholderFile {
					files = append(files, o.Path)
				} else {
					dirs = append(dirs, o.Path)
				}
			}
			if !reflect.DeepEqual(parsed.PlaceholderFiles, files) || !reflect.DeepEqual(parsed.PlaceholderDirs, dirs) {
				t.Errorf("placeholders parsed %v / %v, want %v / %v", parsed.PlaceholderFiles, parsed.PlaceholderDirs, files, dirs)
			}
		})
	}

	// A flag-shaped or whitespace-carrying CIDR is rejected at plan time.
	for _, bad := range []string{"-10.0.0.0/8", "10.0.0.0/8 x", ""} {
		if _, err := hostArgv("/o/observer", NetRequest{Egress: EgressInternet, HostSocketDir: "/tmp/s", ProxyPort: 8820, EgressAllowCIDRs: []string{bad}}, nil); err == nil {
			t.Errorf("allow cidr %q accepted", bad)
		}
	}
	// Parse-side guards.
	for _, a := range [][]string{
		{"--egress-allow-cidr", "10.0.0.0/8", "--", "bwrap"},                              // cidr without gateway
		{"--sock-dir", "/tmp/s", "--gateway", "--egress-allow-cidr", "-x", "--", "bwrap"}, // flag-shaped cidr
		{"--placeholder-file", "rel/path", "--", "bwrap"},                                 // relative placeholder
		{"--placeholder-dir", "/", "--", "bwrap"},                                         // root placeholder
		{"--gateway", "--", "bwrap"},                                                      // gateway without sock dir
	} {
		if _, err := ParseHostArgs(a); err == nil {
			t.Errorf("ParseHostArgs(%v) accepted", a)
		}
	}
}

// TestBuildPlanPlaceholdersBindStrictly: a placeholder overlay is rendered
// with the strict --ro-bind (a missing path fails the launch, never a silent
// skip), is reported by Plan.Placeholders and reaches Plan.HostArgv; a kind
// that cannot fit its placeholder shape is refused.
func TestBuildPlanPlaceholdersBindStrictly(t *testing.T) {
	t.Parallel()
	r := canonicalReq()
	r.Overlays = []Overlay{
		{Path: "/home/dev/.observer/config.toml", Kind: OverlayReadOnly},
		{Path: "/home/dev/.observer/guard-policy.toml", Kind: OverlayReadOnly, Placeholder: PlaceholderFile},
		{Path: "/home/dev/.observer/workspaces/abc/repo/.git", Kind: OverlayReadOnly, Placeholder: PlaceholderDir},
		{Path: "/home/dev/.observer/remote-secret", Kind: OverlayHideFile, Placeholder: PlaceholderFile},
	}
	plan, err := BuildPlan(r)
	if err != nil {
		t.Fatal(err)
	}
	argv := plan.Argv([]string{"true"})
	if findFlagOperand(argv, flagROBindTry, "/home/dev/.observer/config.toml") < 0 {
		t.Errorf("existing overlay not ro-bind-try")
	}
	for _, p := range []string{"/home/dev/.observer/guard-policy.toml", "/home/dev/.observer/workspaces/abc/repo/.git"} {
		if findFlagOperand(argv, flagROBind, p) < 0 {
			t.Errorf("placeholder %s not bound with strict --ro-bind", p)
		}
		if findFlagOperand(argv, flagROBindTry, p) >= 0 {
			t.Errorf("placeholder %s bound with -try (would skip silently)", p)
		}
	}
	if got := plan.Placeholders(); len(got) != 3 {
		t.Fatalf("Placeholders = %v, want 3", got)
	}
	host, err := plan.HostArgv("/o/observer")
	if err != nil || len(host) == 0 {
		t.Fatalf("host tier with placeholders: HostArgv = %v, %v", host, err)
	}
	if indexOf(host, "--placeholder-dir") < 0 || indexOf(host, "--placeholder-file") < 0 || indexOf(host, "--sock-dir") >= 0 {
		t.Errorf("HostArgv = %v", host)
	}

	for _, bad := range []Overlay{
		{Path: "/x", Kind: OverlayHideDir, Placeholder: PlaceholderFile},
		{Path: "/x", Kind: OverlayHideFile, Placeholder: PlaceholderDir},
		{Path: "/x", Kind: OverlayReadOnly, Placeholder: "bogus"},
	} {
		r2 := canonicalReq()
		r2.Overlays = []Overlay{bad}
		if _, err := BuildPlan(r2); err == nil {
			t.Errorf("overlay %+v accepted", bad)
		}
	}
}

// TestBuildPlanHostMasksAndIsolation: host socket masks render before the
// punch-backs (so an explicit bind can still re-expose one deliberately),
// every tier gets a private PID namespace, and every GuestUnsetEnv row is
// dropped.
func TestBuildPlanHostMasksAndIsolation(t *testing.T) {
	t.Parallel()
	for _, mode := range []Egress{EgressHost, EgressInternet, EgressProxyOnly, EgressNone} {
		r := netReq(mode)
		r.SocketSweeps = []DirRebuild{{Path: "/run", Keep: []RebuildEntry{
			{Name: "user"}, {Name: "systemd"}, {Name: "shm", Symlink: "/dev/shm"},
		}}}
		r.HostMasks = []Overlay{
			{Path: "/run/user/1000", Kind: OverlayHideDir},
			{Path: "/run/WSL", Kind: OverlayHideDir},
			{Path: "/mnt/wsl", Kind: OverlayHideDir},
		}
		r.HostMaskKeep = []string{"/mnt/wsl/resolv.conf"}
		plan, err := BuildPlan(r)
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		argv := plan.Argv([]string{"true"})
		if indexOf(argv, flagUnsharePid) < 0 {
			t.Errorf("%s: no --unshare-pid", mode)
		}
		obs := findFlagOperand(argv, flagBind, r.ObserverDir)
		for _, m := range []string{"/run/user/1000", "/run/WSL"} {
			i := findFlagOperand(argv, flagTmpfs, m)
			if i < 0 || i > obs {
				t.Errorf("%s: %s tmpfs at %d, want before the observer bind at %d", mode, m, i, obs)
			}
		}
		// The sweep: tmpfs /run, kept entries put back, before the masks.
		run := findFlagOperand(argv, flagTmpfs, "/run")
		user := findFlagOperand(argv, flagROBind, "/run/user")
		shm := findFlagOperand(argv, flagSymlink, "/dev/shm")
		runUser := findFlagOperand(argv, flagTmpfs, "/run/user/1000")
		if run < 0 || user < run || shm < run || runUser < user {
			t.Errorf("%s: sweep order tmpfs=%d bind=%d symlink=%d mask=%d", mode, run, user, shm, runUser)
		}
		if shm >= 0 && argv[shm+2] != "/run/shm" {
			t.Errorf("%s: symlink dest %q", mode, argv[shm+2])
		}
		if findFlagOperand(argv, flagROBind, "/run/docker.sock") >= 0 {
			t.Errorf("%s: a swept socket was put back", mode)
		}
		keep := findFlagOperand(argv, flagROBindTry, "/mnt/wsl/resolv.conf")
		if keep < findFlagOperand(argv, flagTmpfs, "/mnt/wsl") {
			t.Errorf("%s: resolv.conf keep at %d precedes its mask", mode, keep)
		}
		for _, v := range GuestUnsetEnv {
			if findFlagOperand(argv, flagUnsetenv, v) < 0 {
				t.Errorf("%s: %s not unset", mode, v)
			}
		}
	}
	for _, bad := range []Overlay{
		{Path: "/run/x", Kind: OverlayReadOnly},
		{Path: "/run/x", Kind: OverlayHideDir, Placeholder: PlaceholderDir},
		{Path: "rel", Kind: OverlayHideDir},
	} {
		r := canonicalReq()
		r.HostMasks = []Overlay{bad}
		if _, err := BuildPlan(r); err == nil {
			t.Errorf("host mask %+v accepted", bad)
		}
	}
	for _, bad := range []DirRebuild{
		{Path: "/", Keep: nil},
		{Path: "rel"},
		{Path: "/run", Keep: []RebuildEntry{{Name: "a/b"}}},
		{Path: "/run", Keep: []RebuildEntry{{Name: ".."}}},
		{Path: "/run", Keep: []RebuildEntry{{Name: ""}}},
		{Path: "/run", Keep: []RebuildEntry{{Name: "x y"}}},
		{Path: "/run", Keep: []RebuildEntry{{Name: "l", Symlink: "-evil"}}},
		{Path: "/run", Keep: []RebuildEntry{{Name: "l", Symlink: "a b"}}},
	} {
		r := canonicalReq()
		r.SocketSweeps = []DirRebuild{bad}
		if _, err := BuildPlan(r); err == nil {
			t.Errorf("socket sweep %+v accepted", bad)
		}
	}
}

func TestExpandHostSocketPaths(t *testing.T) {
	t.Parallel()
	got := ExpandHostSocketPaths(1234)
	if len(got) != len(HostSocketPaths) {
		t.Fatalf("len = %d", len(got))
	}
	want := map[string]bool{"/run/user/1234": true, "/run/WSL": true, "/run/docker": true, "/mnt/wslg": true}
	for _, p := range got {
		delete(want, p)
		if strings.Contains(p, "{uid}") || !strings.HasPrefix(p, "/") {
			t.Errorf("unexpanded or relative %q", p)
		}
	}
	if len(want) != 0 {
		t.Errorf("missing rows %v", want)
	}
}

func TestPlaceholderContent(t *testing.T) {
	t.Parallel()
	for path, want := range map[string]string{
		"/h/.claude/settings.json":             "{}\n",
		"/h/.factory/HOOKS.JSON":               "{}\n",
		"/h/.observer/guard-policy.toml":       "",
		"/h/.observer/remote-secret":           "",
		"/h/.observer/features-effective.json": "{}\n",
	} {
		if got := string(PlaceholderContent(path)); got != want {
			t.Errorf("PlaceholderContent(%s) = %q, want %q", path, got, want)
		}
	}
}
