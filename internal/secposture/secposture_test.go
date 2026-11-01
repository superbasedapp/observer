package secposture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

var t0 = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

func goodFile(hash string) *File {
	return &File{
		Schema: SchemaVersion, ProjectRootHash: hash, Packs: []string{"security"},
		Sequence: 5, IssuedAt: t0.Add(-time.Minute), ExpiresAt: t0.Add(4 * time.Minute),
		DirtyCleanEpoch: 3,
	}
}

func baseInput() Input {
	return Input{Module: ModuleActive, Read: ReadOK, File: goodFile(strings.Repeat("a", 64)), Now: t0, Seen: 5, SeenOK: true, Dirty: 3, DirtyOK: true}
}

// TestDeriveStateTable has one row per row of the state table, plus the
// combinations where two rows compete (the earlier row must win).
func TestDeriveStateTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mut    func(*Input)
		want   policy.SecurityPosture
		reason Reason
		n      int
	}{
		{"module inactive", func(in *Input) { in.Module = ModuleInactive }, policy.SecurityPostureAbsent, ReasonModuleInactive, 0},
		{"module inactive beats a missing file", func(in *Input) { in.Module = ModuleInactive; in.Read = ReadMissing; in.File = nil }, policy.SecurityPostureAbsent, ReasonModuleInactive, 0},
		{"no daemon", func(in *Input) { in.Module = ModuleNoDaemon }, policy.SecurityPostureAbsent, ReasonNoDaemon, 0},
		{"guard posture unverified", func(in *Input) { in.Module = ModuleUnverified }, policy.SecurityPostureUnknown, ReasonGuardUnverified, 0},
		{"missing", func(in *Input) { in.Read = ReadMissing; in.File = nil }, policy.SecurityPostureUnknown, ReasonMissing, 0},
		{"too large", func(in *Input) { in.Read = ReadTooLarge; in.File = nil }, policy.SecurityPostureUnknown, ReasonTooLarge, 0},
		{"unverified", func(in *Input) { in.Read = ReadUnverified; in.File = nil }, policy.SecurityPostureUnknown, ReasonUnverified, 0},
		{"ok outcome without a file", func(in *Input) { in.File = nil }, policy.SecurityPostureUnknown, ReasonUnverified, 0},
		{"no active pack", func(in *Input) { in.File.Packs = nil }, policy.SecurityPostureAbsent, ReasonNoActivePack, 0},
		{"expired", func(in *Input) { in.Now = in.File.ExpiresAt }, policy.SecurityPostureUnknown, ReasonExpired, 0},
		{"expired beats dirty", func(in *Input) { in.Now = in.File.ExpiresAt.Add(time.Hour); in.Dirty = 99 }, policy.SecurityPostureUnknown, ReasonExpired, 0},
		{"issued in the future", func(in *Input) { in.File.IssuedAt = t0.Add(2 * MaxClockSkew) }, policy.SecurityPostureUnknown, ReasonFromFuture, 0},
		{"seen unreadable", func(in *Input) { in.SeenOK = false }, policy.SecurityPostureUnknown, ReasonSeenUnreadable, 0},
		{"rollback", func(in *Input) { in.Seen = 6 }, policy.SecurityPostureUnknown, ReasonRollback, 0},
		{"rollback beats blocking", func(in *Input) { in.Seen = 6; in.File.Blocking = []string{"k"} }, policy.SecurityPostureUnknown, ReasonRollback, 0},
		{"version mismatch", func(in *Input) { in.Want = Versions{Check: true, Policy: "2"} }, policy.SecurityPostureUnknown, ReasonVersionMismatch, 0},
		{"versions match", func(in *Input) { in.Want = Versions{Check: true}; in.File.PolicyVersion = "" }, policy.SecurityPostureClean, ReasonClean, 0},
		{"versions unchecked", func(in *Input) { in.File.BundleVersion = "9" }, policy.SecurityPostureClean, ReasonClean, 0},
		{"overflow", func(in *Input) { in.File.Overflow = true }, policy.SecurityPostureUnknown, ReasonOverflow, 0},
		{"dirty unreadable", func(in *Input) { in.DirtyOK = false }, policy.SecurityPostureDirty, ReasonDirtyUnreadable, 0},
		{"dirty", func(in *Input) { in.Dirty = 4 }, policy.SecurityPostureDirty, ReasonDirty, 0},
		{"dirty beats blocking", func(in *Input) { in.Dirty = 4; in.File.Blocking = []string{"k"} }, policy.SecurityPostureDirty, ReasonDirty, 0},
		{"blocking", func(in *Input) { in.File.Blocking = []string{"k1", "k2"} }, policy.SecurityPostureBlocking, ReasonBlocking, 2},
		{"clean", func(*Input) {}, policy.SecurityPostureClean, ReasonClean, 0},
		{"dirty equal to the clean epoch is clean", func(in *Input) { in.Dirty = in.File.DirtyCleanEpoch }, policy.SecurityPostureClean, ReasonClean, 0},
	}
	for _, tc := range cases {
		in := baseInput()
		tc.mut(&in)
		got := Derive(in)
		if got.Posture != tc.want || got.Reason != tc.reason || got.Blocking != tc.n {
			t.Errorf("%s: Derive = %+v, want %s/%s/%d", tc.name, got, tc.want, tc.reason, tc.n)
		}
	}
}

// TestUntrustworthyNeverClean is the mutation guard of acceptance A: every
// input the plan reads as unknown must never derive clean. Turning any
// unknown row into clean fails here.
func TestUntrustworthyNeverClean(t *testing.T) {
	t.Parallel()
	muts := []func(*Input){
		func(in *Input) { in.Module = ModuleUnverified },
		func(in *Input) { in.Read = ReadMissing; in.File = nil },
		func(in *Input) { in.Read = ReadTooLarge; in.File = nil },
		func(in *Input) { in.Read = ReadUnverified; in.File = nil },
		func(in *Input) { in.Now = in.File.ExpiresAt },
		func(in *Input) { in.File.IssuedAt = t0.Add(time.Hour) },
		func(in *Input) { in.SeenOK = false },
		func(in *Input) { in.Seen = in.File.Sequence + 1 },
		func(in *Input) { in.Want = Versions{Check: true, Bundle: "x"} },
		func(in *Input) { in.File.Overflow = true },
		func(in *Input) { in.DirtyOK = false },
	}
	for i, m := range muts {
		in := baseInput()
		m(&in)
		if got := Derive(in); got.Posture == policy.SecurityPostureClean || got.Posture == policy.SecurityPostureAbsent {
			t.Errorf("mutation %d derived %s; an untrustworthy input is never clean or absent", i, got.Posture)
		}
	}
}

// TestGateTable has one row per decision table cell (section 4.8).
func TestGateTable(t *testing.T) {
	t.Parallel()
	want := map[policy.SecurityPosture][]GateOutcome{
		policy.SecurityPostureAbsent:   {GateAllow, GateAllow, GateAllow, GateAllow, GateRefuseMissing},
		policy.SecurityPostureClean:    {GateAllow, GateAllow, GateAllow, GateAllow, GateAllow},
		policy.SecurityPostureBlocking: {GateAsk, GateDeny, GateDeny, GateAsk, GateDeny},
		policy.SecurityPostureDirty:    {GateQuickScanAsk, GateQuickScanDeny, GateQuickScanAsk, GateAsk, GateWaitScanDeny},
		policy.SecurityPostureUnknown:  {GateAsk, GateDeny, GateAsk, GateAsk, GateDeny},
	}
	for _, st := range policy.SecurityPostures() {
		for i, col := range GateColumns() {
			if got := Gate(st, col); got != want[st][i] {
				t.Errorf("Gate(%s, %s) = %s, want %s", st, col, got, want[st][i])
			}
		}
	}
	if got := Gate("bogus", GateIndividualObserve); got != GateAsk {
		t.Errorf("an unknown state reads as unknown: got %s", got)
	}
	if got := Gate(policy.SecurityPostureBlocking, "bogus"); got != GateDeny {
		t.Errorf("an unknown column reads as the floor: got %s", got)
	}
}

func TestAfterQuickScan(t *testing.T) {
	t.Parallel()
	cases := []struct {
		o    GateOutcome
		v    policy.QuickScanVerdict
		want GateOutcome
	}{
		{GateQuickScanAsk, policy.QuickScanClean, GateAllow},
		{GateQuickScanAsk, policy.QuickScanBlocking, GateAsk},
		{GateQuickScanAsk, policy.QuickScanUnknown, GateAsk},
		{GateQuickScanAsk, policy.QuickScanNone, GateAsk},
		{GateQuickScanDeny, policy.QuickScanClean, GateAllow},
		{GateQuickScanDeny, policy.QuickScanBlocking, GateDeny},
		{GateQuickScanDeny, policy.QuickScanUnknown, GateDeny},
		{GateWaitScanDeny, policy.QuickScanClean, GateAllow},
		{GateWaitScanDeny, policy.QuickScanUnknown, GateDeny},
		{GateAsk, policy.QuickScanClean, GateAsk},
	}
	for _, tc := range cases {
		if got := AfterQuickScan(tc.o, tc.v); got != tc.want {
			t.Errorf("AfterQuickScan(%s, %q) = %s, want %s", tc.o, tc.v, got, tc.want)
		}
	}
}

func TestSignVerifyAndTamper(t *testing.T) {
	t.Parallel()
	key := []byte(strings.Repeat("k", 32))
	f := Sign(*goodFile(strings.Repeat("b", 64)), key)
	if !Verify(&f, key) {
		t.Fatal("a signed file must verify")
	}
	g := f
	g.Blocking = []string{"x"}
	if Verify(&g, key) {
		t.Fatal("an edited file must not verify")
	}
	if Verify(&f, []byte(strings.Repeat("z", 32))) {
		t.Fatal("another key must not verify")
	}
	// Normalization: list order and duplicates do not change the MAC.
	h := *goodFile(strings.Repeat("b", 64))
	h.Packs = []string{"security", "security"}
	if Sign(h, key).MAC != f.MAC {
		t.Fatal("a duplicate pack must normalize away")
	}
	big := *goodFile(strings.Repeat("b", 64))
	for i := 0; i < MaxBlocking+10; i++ {
		big.Blocking = append(big.Blocking, strings.Repeat("k", 4)+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	if s := Sign(big, key); len(s.Blocking) != MaxBlocking || !s.Overflow {
		t.Fatalf("blocking list must cap at %d with overflow: got %d, %v", MaxBlocking, len(s.Blocking), s.Overflow)
	}
}

func TestLayoutRefusesBadHashes(t *testing.T) {
	t.Parallel()
	l := Layout{Dir: "/x/security"}
	for _, h := range []string{"", "../../etc", strings.Repeat("A", 64), strings.Repeat("a", 63)} {
		if l.PosturePath(h) != "" || l.DirtyPath(h) != "" || l.SeenPath(h) != "" {
			t.Errorf("hash %q must not name a path", h)
		}
	}
	if (Layout{}).KeyPath() != "" {
		t.Error("the zero layout names no path")
	}
	if LayoutFor(filepath.Join("/h", ".observer", "config.toml")).Dir != filepath.Join("/h", ".observer", DirName) {
		t.Error("the layout sits beside the global config")
	}
}

// TestLoadEndToEnd writes a real posture, reads it through Load, then
// proves rollback, tamper, size cap and dirty raises on disk.
func TestLoadEndToEnd(t *testing.T) {
	t.Parallel()
	l := Layout{Dir: filepath.Join(t.TempDir(), DirName)}
	root := "/work/project"
	hash := ProjectRootHash(root)
	if r := Load(l, root, ModuleActive, t0, Versions{}); r.State.Reason != ReasonMissing {
		t.Fatalf("no key and no file: %+v", r.State)
	}
	key, err := LoadOrCreateKey(l.KeyPath())
	if err != nil {
		t.Fatal(err)
	}
	f := goodFile(hash)
	f.Blocking = []string{"k1"}
	f.DirtyCleanEpoch = 0
	if _, err := Write(l, *f, key); err != nil {
		t.Fatal(err)
	}
	r := Load(l, root, ModuleActive, t0, Versions{})
	if r.State.Posture != policy.SecurityPostureBlocking || r.State.Blocking != 1 || r.File == nil {
		t.Fatalf("blocking file: %+v", r.State)
	}
	if facts := Facts(r); facts.Posture != policy.SecurityPostureBlocking || len(facts.Packs) != 1 {
		t.Fatalf("facts: %+v", facts)
	}
	if err := Accept(l, root, r); err != nil {
		t.Fatal(err)
	}
	if err := RaiseDirty(l, hash); err != nil {
		t.Fatal(err)
	}
	if n, err := ReadDirty(l, hash); err != nil || n != 1 {
		t.Fatalf("dirty = %d, %v", n, err)
	}
	if r := Load(l, root, ModuleActive, t0, Versions{}); r.State.Posture != policy.SecurityPostureDirty {
		t.Fatalf("after a raise: %+v", r.State)
	}
	// Rollback: a lower sequence put back reads as unknown.
	f.Sequence = 4
	f.DirtyCleanEpoch = 1
	if _, err := Write(l, *f, key); err != nil {
		t.Fatal(err)
	}
	if r := Load(l, root, ModuleActive, t0, Versions{}); r.State.Reason != ReasonRollback {
		t.Fatalf("rollback: %+v", r.State)
	}
	// Tamper: an edit after signing does not verify.
	path := l.PosturePath(hash)
	raw, _ := os.ReadFile(path)
	if err := os.WriteFile(path, []byte(strings.Replace(string(raw), `"k1"`, `"k2"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := Load(l, root, ModuleActive, t0, Versions{}); r.State.Reason != ReasonUnverified {
		t.Fatalf("tamper: %+v", r.State)
	}
	// Over the cap.
	if err := os.WriteFile(path, make([]byte, MaxFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := Load(l, root, ModuleActive, t0, Versions{}); r.State.Reason != ReasonTooLarge {
		t.Fatalf("over cap: %+v", r.State)
	}
	// A file signed for another project, renamed onto this one.
	other := goodFile(ProjectRootHash("/other"))
	other.Sequence = 9
	data, _ := Encode(Sign(*other, key))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if r := Load(l, root, ModuleActive, t0, Versions{}); r.State.Reason != ReasonUnverified {
		t.Fatalf("other project's file: %+v", r.State)
	}
	// Deactivation removes every posture file and the key.
	if err := RemoveAllPostures(l); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(l.PostureDir()); !os.IsNotExist(err) {
		t.Fatal("the posture directory must be gone")
	}
	if r := Load(l, root, ModuleInactive, t0, Versions{}); r.State.Posture != policy.SecurityPostureAbsent {
		t.Fatalf("inactive: %+v", r.State)
	}
	if r := Load(l, "", ModuleActive, t0, Versions{}); r.State.Reason != ReasonNoProjectRoot {
		t.Fatalf("no root: %+v", r.State)
	}
}

func TestSeenNeverGoesDown(t *testing.T) {
	t.Parallel()
	l := Layout{Dir: t.TempDir()}
	h := ProjectRootHash("/p")
	for _, s := range []uint64{3, 7, 5} {
		if err := RaiseSeen(l, h, s); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := ReadSeen(l, h); err != nil || n != 7 {
		t.Fatalf("seen = %d, %v", n, err)
	}
	if err := os.WriteFile(l.SeenPath(h), []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSeen(l, h); err == nil {
		t.Fatal("a malformed seen mark is an error, never 0")
	}
}

func TestModuleSignalFrom(t *testing.T) {
	t.Parallel()
	cases := []struct {
		state guardposture.State
		p     *guardposture.Posture
		want  ModuleSignal
	}{
		{guardposture.StateAbsent, nil, ModuleNoDaemon},
		{guardposture.StateTampered, nil, ModuleUnverified},
		{guardposture.StateValid, nil, ModuleUnverified},
		{guardposture.StateValid, &guardposture.Posture{}, ModuleInactive},
		{guardposture.StateValid, &guardposture.Posture{SecurityActive: true}, ModuleInactive},
		{guardposture.StateValid, &guardposture.Posture{SecurityRecorded: true}, ModuleInactive},
		{guardposture.StateValid, &guardposture.Posture{SecurityRecorded: true, SecurityActive: true}, ModuleActive},
	}
	for i, tc := range cases {
		if got := ModuleSignalFrom(tc.state, tc.p); got != tc.want {
			t.Errorf("case %d: got %d, want %d", i, got, tc.want)
		}
	}
}

// TestFactsOnlyFromCurrentFile: the pack set, trust verdict and project
// match are copied only for the clean, dirty, blocking and no_active_pack
// reasons (audit P-002 finding 2). A replayed, older, validly signed
// "trust clean" file must not put Trust=clean on the event.
func TestFactsOnlyFromCurrentFile(t *testing.T) {
	t.Parallel()
	file := func() *File {
		f := goodFile(strings.Repeat("a", 64))
		f.Trust = policy.TrustClean
		f.TrustReasons = []string{"r1"}
		f.OrgProjectIDs = []string{"p1"}
		return f
	}
	copied := map[Reason]bool{ReasonClean: true, ReasonDirty: true, ReasonDirtyUnreadable: true, ReasonBlocking: true, ReasonNoActivePack: true}
	cases := []struct {
		name string
		mut  func(*Input)
		want Reason
	}{
		{"clean", func(*Input) {}, ReasonClean},
		{"dirty", func(in *Input) { in.Dirty = 9 }, ReasonDirty},
		{"dirty unreadable", func(in *Input) { in.DirtyOK = false }, ReasonDirtyUnreadable},
		{"blocking", func(in *Input) { in.File.Blocking = []string{"k"} }, ReasonBlocking},
		{"no active pack", func(in *Input) { in.File.Packs = nil }, ReasonNoActivePack},
		{"expired", func(in *Input) { in.Now = in.File.ExpiresAt }, ReasonExpired},
		{"from the future", func(in *Input) { in.File.IssuedAt = in.Now.Add(time.Hour) }, ReasonFromFuture},
		{"rolled back", func(in *Input) { in.Seen = 9 }, ReasonRollback},
		{"seen unreadable", func(in *Input) { in.SeenOK = false }, ReasonSeenUnreadable},
		{"version mismatch", func(in *Input) { in.Want = Versions{Check: true, Policy: "x"} }, ReasonVersionMismatch},
		{"overflow", func(in *Input) { in.File.Overflow = true }, ReasonOverflow},
	}
	for _, tc := range cases {
		in := baseInput()
		in.File = file()
		tc.mut(&in)
		r := Reading{Input: in, State: Derive(in), File: in.File}
		if r.State.Reason != tc.want {
			t.Fatalf("%s: reason %s, want %s", tc.name, r.State.Reason, tc.want)
		}
		sec := Facts(r)
		if copied[tc.want] {
			if sec.Trust != policy.TrustClean || len(sec.TrustReasons) != 1 || len(sec.Project.OrgProjectIDs) != 1 || len(sec.Packs) != len(in.File.Packs) {
				t.Errorf("%s: facts not copied: %+v", tc.name, sec)
			}
			continue
		}
		if sec.Trust != policy.TrustUnknown || sec.TrustReasons != nil || len(sec.Packs) != 1 || sec.Packs[0] != RootPack || sec.Project.OrgProjectIDs != nil {
			t.Errorf("%s: stale facts copied: %+v", tc.name, sec)
		}
	}
	if sec := Facts(Reading{State: State{Posture: policy.SecurityPostureUnknown, Reason: ReasonMissing}}); sec.Trust != policy.TrustUnknown || len(sec.Packs) != 1 {
		t.Errorf("no file: %+v, want trust unknown and the root pack", sec)
	}
	if sec := Facts(Reading{State: State{Posture: policy.SecurityPostureAbsent, Reason: ReasonModuleInactive}}); sec.Packs != nil {
		t.Errorf("absent: packs %v, want none", sec.Packs)
	}
}

// TestSeenWriteHasNoFsync pins that the hook path's seen mark is written
// without fsync (audit P-002 finding 4; JSP-2's hook budget).
func TestSeenWriteHasNoFsync(t *testing.T) {
	t.Parallel()
	if seenWrite.Fsync {
		t.Fatal("the seen mark must be written without fsync on the hook path")
	}
}

// TestReadDirtyHealth: doctor's dirty-marker detail counts markers, recent
// raises and markers that are not a readable counter, and reads a missing
// directory as not created yet.
func TestReadDirtyHealth(t *testing.T) {
	t.Parallel()
	l := Layout{Dir: filepath.Join(t.TempDir(), DirName)}
	if h, err := ReadDirtyHealth(l, t0); err != nil || h.Exists || h.Markers != 0 {
		t.Fatalf("missing directory: %+v, %v", h, err)
	}
	for _, root := range []string{"/a", "/b"} {
		if err := RaiseDirty(l, ProjectRootHash(root)); err != nil {
			t.Fatal(err)
		}
	}
	old := l.DirtyPath(ProjectRootHash("/b"))
	if err := os.Chtimes(old, t0.Add(-48*time.Hour), t0.Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(l.DirtyPath(ProjectRootHash("/c")), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(l.Dir, DirtyDirName, "not-a-hash"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := ReadDirtyHealth(l, t0.Add(-24*time.Hour))
	if err != nil || !h.Exists || !h.Writable || h.Markers != 3 || h.Unreadable != 1 || h.Recent != 1 {
		t.Fatalf("health: %+v, %v", h, err)
	}
}

// TestFactsUnderSignedPacks (lane SEC-GATEFIX): every unknown reading whose
// file cannot be used carries the signed pack set plus the root; a current
// file keeps its own set; an absent state carries none.
func TestFactsUnderSignedPacks(t *testing.T) {
	t.Parallel()
	signed := []string{"security.secrets", "security"}
	for _, reason := range []Reason{ReasonMissing, ReasonTooLarge, ReasonUnverified, ReasonExpired, ReasonFromFuture, ReasonRollback, ReasonVersionMismatch, ReasonOverflow, ReasonNoProjectRoot, ReasonSeenUnreadable} {
		sec := FactsUnder(Reading{State: State{Posture: policy.SecurityPostureUnknown, Reason: reason}}, signed)
		if len(sec.Packs) != 2 || sec.Packs[0] != "security" || sec.Packs[1] != "security.secrets" {
			t.Errorf("%s: packs %v", reason, sec.Packs)
		}
		if sec.Trust != policy.TrustUnknown {
			t.Errorf("%s: trust %q", reason, sec.Trust)
		}
	}
	if sec := FactsUnder(Reading{State: State{Posture: policy.SecurityPostureUnknown, Reason: ReasonMissing}}, nil); len(sec.Packs) != 1 || sec.Packs[0] != RootPack {
		t.Errorf("no signed set: %v", sec.Packs)
	}
	f := goodFile(ProjectRootHash("/p"))
	f.Packs = []string{"security"}
	if sec := FactsUnder(Reading{State: State{Posture: policy.SecurityPostureClean, Reason: ReasonClean}, File: f}, signed); len(sec.Packs) != 1 {
		t.Errorf("a current file keeps its own set: %v", sec.Packs)
	}
	if sec := FactsUnder(Reading{State: State{Posture: policy.SecurityPostureAbsent, Reason: ReasonModuleInactive}}, signed); sec.Packs != nil {
		t.Errorf("absent carries packs: %v", sec.Packs)
	}
}
