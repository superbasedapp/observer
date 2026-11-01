package secposture

import (
	"bytes"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestHistoryOnlyHold (lane sec-gate3 audit finding 2): the history-only
// keys sign as a subset of Blocking under the MAC and reach the state and
// the facts; a file with no such hold encodes as before.
func TestHistoryOnlyHold(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{7}, 32)
	now := time.Now()
	base := File{
		ProjectRootHash: ProjectRootHash("/p"), Packs: []string{"security"}, Sequence: 1,
		IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	f := base
	f.Blocking, f.HistoryOnly = []string{"b", "a"}, []string{"b", "z", "b"}
	f = Sign(f, key)
	if !slices.Equal(f.HistoryOnly, []string{"b"}) {
		t.Fatalf("history-only = %v, want the subset of blocking [b]", f.HistoryOnly)
	}
	if !Verify(&f, key) {
		t.Fatal("a signed file with a history-only hold does not verify")
	}
	tampered := f
	tampered.HistoryOnly = nil
	if Verify(&tampered, key) {
		t.Fatal("dropping the history-only keys keeps the MAC valid")
	}
	in := Input{Module: ModuleActive, Read: ReadOK, File: &f, Now: now, SeenOK: true, DirtyOK: true}
	st := Derive(in)
	if st.Posture != policy.SecurityPostureBlocking || st.Blocking != 2 || st.HistoryOnly != 1 {
		t.Fatalf("state = %+v, want blocking(2) with 1 history-only", st)
	}
	sec := Facts(Reading{Input: in, State: st, File: &f})
	if sec.Blocking != 2 || sec.BlockingHistoryOnly != 1 {
		t.Fatalf("facts = %+v, want 2 blocking, 1 history-only", sec)
	}
	plain := base
	plain.Blocking = []string{"a"}
	data, err := Encode(Sign(plain, key))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("history_only")) {
		t.Fatalf("a file with no history-only hold carries the key: %s", data)
	}
}

// TestHeldPerRemote (lane sec-gate4 milestone 1a): the per-remote counts
// and the held commits sign under the MAC, are normalized (bad remote
// names and commit ids dropped, counts capped at the history-only count,
// the list capped at MaxHeld) and reach the state and the facts; a capped
// list keeps the commits but no count; a file with no hold carries neither
// key.
func TestHeldPerRemote(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{7}, 32)
	now := time.Now()
	a := strings.Repeat("a", 40)
	f := File{
		ProjectRootHash: ProjectRootHash("/p"), Packs: []string{"security"}, Sequence: 1,
		IssuedAt: now, ExpiresAt: now.Add(time.Minute),
		Blocking: []string{"k1", "k2"}, HistoryOnly: []string{"k1"},
		HistoryOnlyOn: map[string]int{"origin": 5, "../x": 1, "backup": 0},
		Held:          []HeldCommit{{Commit: strings.ToUpper(a), Remotes: []string{"origin", "-bad"}}, {Commit: "nothex"}},
	}
	f = Sign(f, key)
	if len(f.HistoryOnlyOn) != 1 || f.HistoryOnlyOn["origin"] != 1 {
		t.Fatalf("on = %v, want origin capped at 1", f.HistoryOnlyOn)
	}
	if len(f.Held) != 1 || f.Held[0].Commit != a || !slices.Equal(f.Held[0].Remotes, []string{"origin"}) {
		t.Fatalf("held = %+v", f.Held)
	}
	if !Verify(&f, key) {
		t.Fatal("does not verify")
	}
	tampered := f
	tampered.HistoryOnlyOn = map[string]int{"origin": 1, "backup": 1}
	if Verify(&tampered, key) {
		t.Fatal("adding a remote keeps the MAC valid")
	}
	in := Input{Module: ModuleActive, Read: ReadOK, File: &f, Now: now, SeenOK: true, DirtyOK: true}
	st := Derive(in)
	sec := Facts(Reading{Input: in, State: st, File: &f})
	if sec.BlockingHistoryOnlyOn["origin"] != 1 || len(sec.HeldCommits) != 1 || sec.HeldCommits[0].Commit != a {
		t.Fatalf("facts = %+v", sec)
	}
	if held, ok := HeldOf(Reading{Input: in, State: st, File: &f}); !ok || len(held) != 1 {
		t.Fatalf("held of = %+v %v", held, ok)
	}
	var many []HeldCommit
	for i := range MaxHeld + 2 {
		many = append(many, HeldCommit{Commit: strings.Repeat(string(rune('a'+i%6)), 39) + string(rune('0'+i%10))})
	}
	c := f
	c.Held, c.HeldOverflow = many, false
	c = Sign(c, key)
	if len(c.Held) != MaxHeld || !c.HeldOverflow {
		t.Fatalf("capped held = %d %v", len(c.Held), c.HeldOverflow)
	}
	cin := Input{Module: ModuleActive, Read: ReadOK, File: &c, Now: now, SeenOK: true, DirtyOK: true}
	if cs := Facts(Reading{Input: cin, State: Derive(cin), File: &c}); cs.BlockingHistoryOnlyOn != nil || len(cs.HeldCommits) != MaxHeld {
		t.Fatalf("capped facts = %+v", cs)
	}
	if !HeldOverflowOf(Reading{Input: cin, State: Derive(cin), File: &c}) || HeldOverflowOf(Reading{Input: in, State: st, File: &f}) {
		t.Fatal("HeldOverflowOf does not report the cap")
	}
	plain := File{
		ProjectRootHash: ProjectRootHash("/p"), Packs: []string{"security"}, Sequence: 1, IssuedAt: now, ExpiresAt: now.Add(time.Minute),
		Blocking: []string{"k1"}, HistoryOnlyOn: map[string]int{"origin": 1}, Held: []HeldCommit{{Commit: a}}, DefaultPushRemote: "origin",
	}
	data, err := Encode(Sign(plain, key))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("history_only_on")) || bytes.Contains(data, []byte(`"held"`)) || bytes.Contains(data, []byte("default_push_remote")) {
		t.Fatalf("a file with no history-only hold carries the held keys: %s", data)
	}
}

// TestDefaultPushRemoteSigned (lane sec-gate4 audit finding 5): the
// default push remote signs under the MAC, reaches the state and the facts
// with a history-only hold, and is dropped when it is not a remote name.
func TestDefaultPushRemoteSigned(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{9}, 32)
	now := time.Now()
	f := Sign(File{
		ProjectRootHash: ProjectRootHash("/p"), Packs: []string{"security"}, Sequence: 1,
		IssuedAt: now, ExpiresAt: now.Add(time.Minute),
		Blocking: []string{"k1"}, HistoryOnly: []string{"k1"}, DefaultPushRemote: "origin",
	}, key)
	if f.DefaultPushRemote != "origin" || !Verify(&f, key) {
		t.Fatalf("signed = %+v", f)
	}
	tampered := f
	tampered.DefaultPushRemote = "backup"
	if Verify(&tampered, key) {
		t.Fatal("changing the default push remote keeps the MAC valid")
	}
	in := Input{Module: ModuleActive, Read: ReadOK, File: &f, Now: now, SeenOK: true, DirtyOK: true}
	if sec := Facts(Reading{Input: in, State: Derive(in), File: &f}); sec.DefaultPushRemote != "origin" {
		t.Fatalf("facts = %+v", sec)
	}
	bad := Sign(File{
		ProjectRootHash: ProjectRootHash("/p"), Packs: []string{"security"}, Sequence: 1,
		IssuedAt: now, ExpiresAt: now.Add(time.Minute),
		Blocking: []string{"k1"}, HistoryOnly: []string{"k1"}, DefaultPushRemote: "../x",
	}, key)
	if bad.DefaultPushRemote != "" {
		t.Fatalf("a default that is not a remote name survived: %q", bad.DefaultPushRemote)
	}
}
