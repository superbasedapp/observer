package sandboxvm

import (
	"strings"
	"testing"
)

func testSpec() GuestSpec {
	return GuestSpec{
		Schema: GuestSpecSchema, RunID: "run-1", UID: 1000, GID: 1000,
		HostBin: "/home/u/.local/bin/observer", Workdir: "/home/u/proj",
		Mounts:   []GuestMount{{Tag: WorkspaceTag, Target: "/home/u/proj"}},
		ReadOnly: []string{"/home/u/proj/.git/config"},
		PTYPort:  1024, RelayPort: 1025, Rows: 24, Cols: 80,
		Command: []string{"/home/u/.local/bin/observer", "claude"},
	}
}

func TestGuestSpecRoundTrip(t *testing.T) {
	b, err := testSpec().Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseGuestSpec(b)
	if err != nil || got.Workdir != "/home/u/proj" || got.RelayPort != 1025 {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := ParseGuestSpec([]byte(strings.Replace(string(b), `"schema"`, `"secret": "x", "schema"`, 1))); err == nil {
		t.Fatal("an unknown field (a secret) was accepted")
	}
	m, ro := ExpectedGuestMounts(got)
	if len(m) != 2 || len(ro) != 1 || m[0] != GuestHookBin || ro[0] != GuestHookBin {
		t.Fatalf("%v %v", m, ro)
	}
}

func TestGuestSpecRules(t *testing.T) {
	cases := map[string]func(*GuestSpec){
		"root uid":          func(s *GuestSpec) { s.UID = 0 },
		"hostbin on rootfs": func(s *GuestSpec) { s.HostBin = "/usr/bin/observer" },
		"hookbin on rootfs": func(s *GuestSpec) { s.HostBin, s.HookBin = "/usr/bin/observer", "/usr/bin/observer" },
		"unclean hostbin":   func(s *GuestSpec) { s.HostBin = "usr/bin/observer" },
		"target on rootfs":  func(s *GuestSpec) { s.Mounts[0].Target = "/etc/proj" },
		"target is a root":  func(s *GuestSpec) { s.Mounts[0].Target = "/home" },
		"boot tag reused":   func(s *GuestSpec) { s.Mounts[0].Tag = BootTag },
		"workdir outside":   func(s *GuestSpec) { s.Workdir = "/home/u/elsewhere" },
		"equal ports":       func(s *GuestSpec) { s.RelayPort = s.PTYPort },
		"host range port":   func(s *GuestSpec) { s.PTYPort = HostPortMin },
		"relative command":  func(s *GuestSpec) { s.Command = []string{"observer"} },
		"unclean ro path":   func(s *GuestSpec) { s.ReadOnly = []string{"/a/../b"} },
		"schema":            func(s *GuestSpec) { s.Schema = "x" },
	}
	for name, mut := range cases {
		s := testSpec()
		s.Mounts = append([]GuestMount(nil), s.Mounts...)
		mut(&s)
		if _, err := s.Encode(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestEventTable(t *testing.T) {
	for line, want := range map[string]EventAction{
		`{"timestamp":{"secs":1,"nanos":2},"source":"vm","event":"booted","properties":null}`: EventReadBack,
		`{"source":"vm","event":"booting"}`:                                                   EventIgnore,
		`{"source":"vm","event":"shutdown"}`:                                                  EventEnded,
		`{"source":"vmm","event":"shutdown"}`:                                                 EventEnded,
		`{"source":"virtio-device","event":"activated","properties":{"id":"_fs9"}}`:           EventReadBack,
		`{"source":"vm","event":"device-added"}`:                                              EventReadBack,
	} {
		e, err := ParseEvent([]byte(line))
		if err != nil || ActionFor(e) != want {
			t.Errorf("%s: %v %v, want %v", line, ActionFor(e), err, want)
		}
	}
	for _, bad := range []string{`{}`, `not json`, `{"source":"vm"}`} {
		if _, err := ParseEvent([]byte(bad)); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

// TestGuestHookBin (audit finding 3): a host observer outside the writable
// roots launches through the fixed read-only guest path; one under a root
// keeps its own path, linked to it.
func TestGuestHookBin(t *testing.T) {
	for host, want := range map[string]string{
		"/usr/local/bin/observer":                      GuestHookBin,
		"/usr/bin/observer":                            GuestHookBin,
		"/usr/lib/node_modules/@superbased/x/observer": GuestHookBin,
		"/home/u/.local/bin/observer":                  "/home/u/.local/bin/observer",
		"relative/observer":                            GuestHookBin,
	} {
		if got := GuestHookBinFor(host); got != want {
			t.Errorf("%s: %s, want %s", host, got, want)
		}
	}
	s := testSpec()
	s.HostBin = "/usr/local/bin/observer"
	s.HookBin = GuestHookBinFor(s.HostBin)
	if err := s.Validate(); err != nil {
		t.Fatalf("an observer in /usr/local/bin: %v", err)
	}
	if s.HookLink() != "" || s.HookPath() != GuestHookBin {
		t.Fatalf("link %q path %q", s.HookLink(), s.HookPath())
	}
	u := testSpec()
	if u.HookLink() != "/home/u/.local/bin/observer" {
		t.Fatalf("an observer under a root is linked: %q", u.HookLink())
	}
}

// TestExpectedGuestMountsLeaveSharePathsToTheWitness (live run 2026-10-24,
// D4): a host-pinned read-only path inside a virtio-fs share is the host's
// mount, read back on the host from the confined virtiofsd; the guest sees
// no mount point there, so the in-guest mount judge never requires one
// (every live launch ended "built_below_plan: .../.git/config is not
// mounted in the box"). The guest's own read-only mounts stay judged.
func TestExpectedGuestMountsLeaveSharePathsToTheWitness(t *testing.T) {
	s := testSpec()
	s.ReadOnly = []string{"/home/u/proj/.git/config", "/home/u/proj/.git/hooks"}
	s.Mounts = append(s.Mounts, GuestMount{Tag: "ro1", Target: "/home/u/ref", ReadOnly: true})
	m, ro := ExpectedGuestMounts(s)
	for _, p := range s.ReadOnly {
		for _, q := range append(append([]string(nil), m...), ro...) {
			if q == p {
				t.Fatalf("%s is judged as a guest mount: mounts %v ro %v", p, m, ro)
			}
		}
	}
	if strings.Join(ro, ",") != GuestHookBin+",/home/u/ref" {
		t.Fatalf("the guest's own read-only mounts: %v", ro)
	}
}
