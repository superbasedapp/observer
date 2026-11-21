package callerid

import (
	"net/netip"
	"strings"
	"testing"
)

// TestDecideRows is the decision table, one case per row, plus the shapes
// the dashboard relies on.
func TestDecideRows(t *testing.T) {
	box := Facts{Mutating: true, LocalPeer: true, ExposedBoxLive: true}
	cases := []struct {
		name string
		f    Facts
		want Verdict
		rule string
	}{
		{"C1 a read passes", Facts{LocalPeer: true, ExposedBoxLive: true}, Allow, "C1-read-only"},
		{"C2 a remote peer is no local box", Facts{Mutating: true, ExposedBoxLive: true}, Allow, "C2-remote-peer"},
		{"C3 no reachable box live: no lookup needed", Facts{Mutating: true, LocalPeer: true}, Allow, "C3-no-exposed-box"},
		{"C3 even an unidentified caller passes with no reachable box", Facts{Mutating: true, LocalPeer: true, Identified: false}, Allow, "C3-no-exposed-box"},
		{"C4 identified inside a box", func() Facts { f := box; f.Identified, f.InBox = true, true; return f }(), RefuseBox, "C4-in-box"},
		{"C4 a descendant of a box root holds the socket (WSL fallback scan)", func() Facts { f := box; f.Identified, f.InBox = true, true; return f }(), RefuseBox, "C4-in-box"},
		{"C5 a reachable box whose root is unknown", func() Facts { f := box; f.Identified, f.UnrootedExposedBox = true, true; return f }(), RefuseUnrooted, "C5-unrooted-exposed-box"},
		{"C5 beats a proven-outside answer", func() Facts { f := box; f.ProvenOutside, f.UnrootedExposedBox = true, true; return f }(), RefuseUnrooted, "C5-unrooted-exposed-box"},
		{"C6 the owner's browser, holder found outside every box", func() Facts { f := box; f.Identified = true; return f }(), Allow, "C6-identified-outside"},
		{"C7 another uid's socket, no readable holder, every box descendant readable", func() Facts { f := box; f.ProvenOutside, f.SocketOtherUID = true, true; return f }(), Allow, "C7-other-uid-outside-boxes"},
		{"C8 the daemon's uid's socket, no readable holder, every box descendant readable", func() Facts { f := box; f.ProvenOutside = true; return f }(), RefuseUnidentified, "C8-unidentified-fail-closed"},
		{"C8 another uid's socket, no readable holder, a box descendant unreadable", func() Facts { f := box; f.SocketOtherUID = true; return f }(), RefuseUnidentified, "C8-unidentified-fail-closed"},
		{"C8 no readable holder and a box descendant unreadable", box, RefuseUnidentified, "C8-unidentified-fail-closed"},
	}
	for _, tc := range cases {
		v, rule := Decide(tc.f)
		if v != tc.want || rule != tc.rule {
			t.Errorf("%s: %v by %s, want %v by %s", tc.name, v, rule, tc.want, tc.rule)
		}
	}
	seen := map[string]bool{}
	for _, r := range rules {
		if seen[r.id] {
			t.Fatalf("duplicate rule %s", r.id)
		}
		seen[r.id] = true
	}
}

// TestAncestorsAndInBox: the walk stops at init, at a repeated pid and at
// a missing parent, and only a strict ancestor makes a caller a box's.
func TestAncestorsAndInBox(t *testing.T) {
	tree := map[int]int{40: 30, 30: 20, 20: 10, 10: 1, 1: 0, 7: 8, 8: 7}
	parent := func(pid int) (int, bool) { p, ok := tree[pid]; return p, ok }
	if got := Ancestors(40, parent); len(got) != 4 || got[0] != 30 || got[3] != 1 {
		t.Fatalf("ancestors of 40 = %v", got)
	}
	if got := Ancestors(7, parent); len(got) != 1 || got[0] != 8 {
		t.Fatalf("a cycle: %v", got)
	}
	if got := Ancestors(99, parent); len(got) != 0 {
		t.Fatalf("unknown pid: %v", got)
	}
	roots := map[int]string{20: "run-box"}
	if run, ok := InBox(Ancestors(40, parent), roots); !ok || run != "run-box" {
		t.Fatalf("40 descends from the box root: %q %v", run, ok)
	}
	if _, ok := InBox(Ancestors(20, parent), roots); ok {
		t.Fatal("the box root itself (the host-side helper or CLI) is not inside its box")
	}
	if _, ok := InBox(Ancestors(10, parent), roots); ok {
		t.Fatal("an ancestor of the root is not inside the box")
	}
}

// TestParseProcNetTCP reads real-format rows (127.0.0.1:8081 is
// 0100007F:1F91; ::1 is 00000000000000000000000001000000).
func TestParseProcNetTCP(t *testing.T) {
	v4 := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F91 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 11111 1 0000000000000000 100 0 0 10 0
   1: 0100007F:D431 0100007F:1F91 01 00000000:00000000 00:00000000 00000000  1000        0 22222 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:1F91 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1000        0 33333 1 0000000000000000 20 4 30 10 -1
   3: garbage
`
	socks := ParseProcNetTCP([]byte(v4))
	if len(socks) != 3 {
		t.Fatalf("parsed %d rows, want 3: %+v", len(socks), socks)
	}
	client := netip.MustParseAddrPort("127.0.0.1:54321")
	server := netip.MustParseAddrPort("127.0.0.1:8081")
	if socks[1].Local != client || socks[1].Remote != server || socks[1].UID != 1000 || socks[1].Inode != 22222 {
		t.Fatalf("row 1 = %+v", socks[1])
	}
	if sk, ok := FindClientSocket(socks, client, server); !ok || sk.Inode != 22222 {
		t.Fatalf("client socket = %d %v, want the client side 22222 (not the daemon's 33333)", sk.Inode, ok)
	}
	if _, ok := FindClientSocket(socks, netip.MustParseAddrPort("127.0.0.1:1"), server); ok {
		t.Fatal("an unknown client matched")
	}
	v6 := `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:D431 00000000000000000000000001000000:1F91 01 00000000:00000000 00:00000000 00000000  1000        0 44444 1 0000000000000000 20 4 30 10 -1
`
	s6 := ParseProcNetTCP([]byte(v6))
	if len(s6) != 1 || s6[0].Local != netip.MustParseAddrPort("[::1]:54321") || s6[0].Inode != 44444 {
		t.Fatalf("v6 = %+v", s6)
	}
	// A v4-mapped client still matches the v4 row.
	if _, ok := FindClientSocket(socks, netip.MustParseAddrPort("[::ffff:127.0.0.1]:54321"), server); !ok {
		t.Fatal("a v4-mapped client address did not match")
	}
}

// TestParseStat reads the parent and start time past a command name that
// holds spaces and parentheses.
func TestParseStat(t *testing.T) {
	line := "4242 (evil) (name x) S 4100 4242 4100 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000000 100 18446744073709551615"
	st, err := ParseStat(line)
	if err != nil || st.PPID != 4100 || st.StartTicks != 987654 || st.State != 'S' || st.Exited() {
		t.Fatalf("stat = %+v %v", st, err)
	}
	// A zombie (exited, not reaped) and one being reaped keep their stat
	// and start time but have exited; every other state has not.
	for state, exited := range map[string]bool{"Z": true, "X": true, "R": false, "S": false, "D": false, "T": false, "I": false} {
		st, err := ParseStat(strings.Replace(line, ") S ", ") "+state+" ", 1))
		if err != nil || st.StartTicks != 987654 || st.Exited() != exited {
			t.Errorf("state %s: stat = %+v %v, exited want %v", state, st, err, exited)
		}
	}
	for _, bad := range []string{"", "1 (x)", "1 (x) S notanumber 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20"} {
		if _, err := ParseStat(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

// TestIsLocalPeer: loopback and the listener's own address are local; any
// other host is not.
func TestIsLocalPeer(t *testing.T) {
	srv := netip.MustParseAddrPort("192.168.1.5:8081")
	for client, want := range map[string]bool{
		"127.0.0.1:5000":          true,
		"[::1]:5000":              true,
		"192.168.1.5:5000":        true,
		"192.168.1.9:5000":        false,
		"[::ffff:127.0.0.1]:5000": true,
	} {
		if got := IsLocalPeer(netip.MustParseAddrPort(client), srv); got != want {
			t.Errorf("%s: %v, want %v", client, got, want)
		}
	}
}

// TestDescendants: every strict descendant of a root, never the root
// itself, never a process outside the trees.
func TestDescendants(t *testing.T) {
	parents := map[int]int{10: 1, 20: 10, 21: 20, 22: 21, 30: 1, 31: 30, 7: 8, 8: 7}
	got := Descendants(parents, map[int]string{10: "run-a"})
	if len(got) != 3 || got[0] != 20 || got[1] != 21 || got[2] != 22 {
		t.Fatalf("descendants of 10 = %v, want [20 21 22]", got)
	}
	if got := Descendants(parents, map[int]string{}); len(got) != 0 {
		t.Fatalf("no roots: %v", got)
	}
	if got := Descendants(parents, map[int]string{30: "run-b", 10: "run-a"}); len(got) != 4 {
		t.Fatalf("two roots: %v", got)
	}
}

// TestEnvValue pins the marker read: only the named keys, the first set one
// wins, an empty value is not set.
func TestEnvValue(t *testing.T) {
	env := []byte("PATH=/bin\x00ANTHROPIC_API_KEY=secret\x00CLAUDE_CODE_SESSION_ID=sess-1\x00EMPTY=\x00")
	if v, ok := EnvValue(env, []string{"CLAUDE_CODE_SESSION_ID"}); !ok || v != "sess-1" {
		t.Fatalf("EnvValue = %q %v", v, ok)
	}
	if _, ok := EnvValue(env, []string{"EMPTY", "MISSING"}); ok {
		t.Fatal("an empty or missing key reported a value")
	}
	if v, ok := EnvValue(env, []string{"MISSING", "CLAUDE_CODE_SESSION_ID"}); !ok || v != "sess-1" {
		t.Fatalf("second key: %q %v", v, ok)
	}
	if _, ok := EnvValue(env, []string{"CLAUDE_CODE"}); ok {
		t.Fatal("a key prefix matched")
	}
}
