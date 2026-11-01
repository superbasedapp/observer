package sandbox

import (
	"strings"
	"testing"
)

// relayReq is the canonical request with the capture relay on.
func relayReq(mode Egress) Request {
	r := canonicalReq()
	r.Net = NetRequest{Egress: mode, HostSocketDir: "/tmp/observer-sbx-abc", ProxyPort: 8820}
	r.Relay = RelayRequest{RunID: "run-1", HostObserverDir: "/home/dev/.observer"}
	return r
}

// TestBuildPlanRelay (lane sbx-p2, roadmap section 11 item 4): with the
// relay on, the observer dir is a tmpfs, never a read-write bind (the node
// DB is absent in the box), the socket dir is bound read-only on every
// tier (the host tier too), and the host helper always runs with the
// relay flags.
func TestBuildPlanRelay(t *testing.T) {
	t.Parallel()
	for _, mode := range []Egress{EgressHost, EgressInternet, EgressProxyOnly, EgressNone} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			plan, err := BuildPlan(relayReq(mode))
			if err != nil {
				t.Fatal(err)
			}
			argv := plan.Argv([]string{"observer", "claude"})
			flags := argv[:indexOf(argv, "--")]
			if i := findFlagOperand(flags, flagBind, "/home/dev/.observer"); i >= 0 {
				t.Fatalf("the observer dir is bound read-write with the relay on: %v", flags)
			}
			if findFlagOperand(flags, flagTmpfs, "/home/dev/.observer") < 0 {
				t.Fatalf("the observer dir is not a tmpfs: %v", flags)
			}
			bi := findFlagOperand(flags, flagROBind, "/tmp/observer-sbx-abc")
			if bi < 0 || flags[bi+2] != GuestSocketDir {
				t.Fatalf("the socket dir is not bound read-only at %s: %v", GuestSocketDir, flags)
			}
			host, err := plan.HostArgv("/home/dev/.local/bin/observer")
			if err != nil {
				t.Fatal(err)
			}
			joined := strings.Join(host, " ")
			for _, want := range []string{HostVerb, flagSockDir + " /tmp/observer-sbx-abc", flagRelayRun + " run-1", flagObserverDir + " /home/dev/.observer"} {
				if !strings.Contains(joined, want) {
					t.Errorf("host argv %q lacks %q", joined, want)
				}
			}
			h, err := ParseHostArgs(append(host[2:], "/usr/bin/bwrap"))
			if err != nil {
				t.Fatal(err)
			}
			if h.RelayRun != "run-1" || h.ObserverDir != "/home/dev/.observer" || h.SockDir != "/tmp/observer-sbx-abc" {
				t.Fatalf("parsed %+v", h)
			}
		})
	}
}

// TestBuildPlanWithoutRelayUnchanged: with no relay the observer dir stays
// a read-write bind (byte-identical to before the relay).
func TestBuildPlanWithoutRelayUnchanged(t *testing.T) {
	t.Parallel()
	plan, err := BuildPlan(canonicalReq())
	if err != nil {
		t.Fatal(err)
	}
	argv := plan.Argv([]string{"x"})
	if findFlagOperand(argv, flagBind, "/home/dev/.observer") < 0 {
		t.Fatal("without the relay the observer dir is not bound")
	}
}

// TestRelayGuards: a bad run id, a relative observer dir or a missing
// socket dir is refused, by the planner and by the helper's parser.
func TestRelayGuards(t *testing.T) {
	t.Parallel()
	for name, mut := range map[string]func(r *Request){
		"run id with a slash":   func(r *Request) { r.Relay.RunID = "../x" },
		"run id too long":       func(r *Request) { r.Relay.RunID = strings.Repeat("a", 65) },
		"relative observer dir": func(r *Request) { r.Relay.HostObserverDir = "obs" },
		"no socket dir":         func(r *Request) { r.Net.HostSocketDir = "" },
	} {
		r := relayReq(EgressHost)
		mut(&r)
		if _, err := BuildPlan(r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, args := range map[string][]string{
		"relay run without observer dir": {flagSockDir, "/tmp/s", flagRelayRun, "r", "--", "/usr/bin/bwrap"},
		"relay without socket dir":       {flagRelayRun, "r", flagObserverDir, "/o", "--", "/usr/bin/bwrap"},
		"bad relay run":                  {flagSockDir, "/tmp/s", flagRelayRun, "a/b", flagObserverDir, "/o", "--", "/usr/bin/bwrap"},
	} {
		if _, err := ParseHostArgs(args); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// TestRelayRefusesObserverDirBinds (plans decision log P-026 c): with the
// relay on, no state or extra bind may show the observer dir again (the
// node DB, the run records with their secrets, the link socket): the dir,
// any parent of it, or a path inside it outside the managed workspaces, in
// the written or the resolved spelling. Without the relay nothing changes.
func TestRelayRefusesObserverDirBinds(t *testing.T) {
	t.Parallel()
	links := map[string]string{"/data/homelink": "/home", "/data/obslink": "/home/dev/.observer/sandbox-relay"}
	resolve := func(p string) string {
		if r, ok := links[p]; ok {
			return r
		}
		return p
	}
	for _, tc := range []struct {
		name string
		mut  func(r *Request)
		ok   bool
	}{
		{"extra ro bind of the observer dir", func(r *Request) { r.ExtraRO = []string{"/home/dev/.observer"} }, false},
		{"extra ro bind of the home (a parent)", func(r *Request) { r.ExtraRO = []string{"/home/dev"} }, false},
		{"extra ro bind of the root", func(r *Request) { r.ExtraRO = []string{"/"} }, false},
		{"extra rw bind of the relay dir", func(r *Request) { r.ExtraRW = []string{"/home/dev/.observer/sandbox-relay"} }, false},
		{"extra ro bind of the database", func(r *Request) { r.ExtraRO = []string{"/home/dev/.observer/observer.db"} }, false},
		{"state rw bind of the observer dir", func(r *Request) { r.StateRW = []string{".observer"} }, false},
		{"extra ro bind through a link to a parent", func(r *Request) { r.ExtraRO = []string{"/data/homelink"} }, false},
		{"extra ro bind through a link into the relay dir", func(r *Request) { r.ExtraRO = []string{"/data/obslink"} }, false},
		{"a sibling of the observer dir", func(r *Request) { r.ExtraRO = []string{"/home/dev/.observer-other"} }, true},
		{"inside the managed workspaces", func(r *Request) { r.ExtraRO = []string{"/home/dev/.observer/workspaces/abc/cache"} }, true},
		{"an unrelated path", func(r *Request) { r.ExtraRW = []string{"/srv/data"} }, true},
	} {
		r := relayReq(EgressNone)
		r.ResolvePath = resolve
		tc.mut(&r)
		_, err := BuildPlan(r)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err %v, want ok %v", tc.name, err, tc.ok)
		}
		plain := canonicalReq()
		plain.ResolvePath = resolve
		tc.mut(&plain)
		if _, err := BuildPlan(plain); err != nil && tc.name != "extra ro bind of the root" {
			t.Errorf("%s without the relay: %v", tc.name, err)
		}
	}
}

// TestRelayReblindsAWorkspaceParent (P-026 c): a workspace that is a parent
// of the observer dir (a project at the home directory) is bound, and the
// observer dir is blinded again after it, before the overlays.
func TestRelayReblindsAWorkspaceParent(t *testing.T) {
	t.Parallel()
	r := relayReq(EgressNone)
	r.WorkspaceRoot = "/home/dev"
	r.Overlays = []Overlay{{Path: "/home/dev/.observer/config.toml", Kind: OverlayReadOnly}}
	plan, err := BuildPlan(r)
	if err != nil {
		t.Fatal(err)
	}
	argv := plan.Argv([]string{"x"})
	ws := findFlagOperand(argv, flagBind, "/home/dev")
	if ws < 0 {
		t.Fatalf("the workspace is not bound: %v", argv)
	}
	re := -1
	for i := ws; i < len(argv)-1; i++ {
		if argv[i] == flagTmpfs && argv[i+1] == "/home/dev/.observer" {
			re = i
			break
		}
	}
	ov := findFlagOperand(argv, flagROBindTry, "/home/dev/.observer/config.toml")
	if re < 0 || ov < re {
		t.Fatalf("the observer dir is not blinded again between the workspace bind (%d) and the overlays (%d): %v", ws, ov, argv)
	}
	plan, err = BuildPlan(relayReq(EgressNone))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for i, a := range plan.Argv([]string{"x"}) {
		if a == flagTmpfs && plan.Argv([]string{"x"})[i+1] == "/home/dev/.observer" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("a workspace inside the managed tree blinds the observer dir %d times, want once", n)
	}
}
