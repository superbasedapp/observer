package sandboxvm

import (
	"strings"
	"testing"
)

// TestGuestAccounts (the first live run, D9): the agent's uid and gid get
// a name in the guest when the image has none; an id the image names is
// left alone, and a name the image uses for another id is not reused.
func TestGuestAccounts(t *testing.T) {
	passwd := []byte("root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n")
	group := []byte("root:x:0:\nnogroup:x:65534:")
	pw, gr := GuestAccounts(passwd, group, 1001, 1001, "/home/u/proj")
	if !strings.HasPrefix(string(pw), string(passwd)) || !strings.HasSuffix(string(pw), "agent:x:1001:1001:Observer sandbox agent:/home/u/proj:/bin/sh\n") {
		t.Fatalf("passwd %q", pw)
	}
	if string(gr) != "root:x:0:\nnogroup:x:65534:\nagent:x:1001:\n" {
		t.Fatalf("group %q", gr)
	}
	same, sameGr := GuestAccounts(pw, gr, 1001, 1001, "/x")
	if string(same) != string(pw) || string(sameGr) != string(gr) {
		t.Fatal("an id the image names was named again")
	}
	taken := []byte("agent:x:2000:2000::/home/agent:/bin/sh\n")
	pw2, gr2 := GuestAccounts(taken, []byte("agent:x:2000:\n"), 1001, 1002, "/w")
	if !strings.Contains(string(pw2), "agent-1001:x:1001:1002:") || !strings.Contains(string(gr2), "agent-1002:x:1002:") {
		t.Fatalf("a taken name: %q %q", pw2, gr2)
	}
}
