package sandboxseccomp

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"
)

// auditArchI386 and auditArchARM are the 32-bit compat ABIs each target
// can be entered through (linux/audit.h).
const (
	auditArchI386 = 0x40000003
	auditArchARM  = 0x40000028
)

// foreignArches are the arch values the program must kill on, per target.
var foreignArches = map[string][]uint32{
	ArchAMD64: {auditArchI386, auditArchAArch64, 0},
	ArchARM64: {auditArchARM, auditArchX86_64, 0},
}

// readNr is a syscall every tool makes (read), allowed by the default row.
var readNr = map[string]uint32{ArchAMD64: 0, ArchARM64: 63}

func buildProgram(t *testing.T, goarch string) Program {
	t.Helper()
	p, err := Build(ProfileObserverDefault, goarch)
	if err != nil {
		t.Fatalf("Build(%s): %v", goarch, err)
	}
	return p
}

func eval(t *testing.T, p Program, d seccompData) Action {
	t.Helper()
	ret, err := run(p, d)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return actionOf(ret)
}

// TestProfileRows proves every row of the profile on every architecture it
// applies to, one subtest per row: the row's syscall gets the row's action,
// and for an argument-filtered row, every listed value gets it and an
// unlisted value is allowed.
func TestProfileRows(t *testing.T) {
	for _, id := range Profiles() {
		testProfileRows(t, id)
	}
}

// testProfileRows is TestProfileRows for one profile.
func testProfileRows(t *testing.T, id ProfileID) {
	rows, _ := Rules(id)
	for _, goarch := range []string{ArchAMD64, ArchARM64} {
		p, err := Build(id, goarch)
		if err != nil {
			t.Fatalf("Build(%s, %s): %v", id, goarch, err)
		}
		spec := archs[goarch]
		for _, r := range rows {
			t.Run(string(id)+"/"+goarch+"/"+r.Syscall, func(t *testing.T) {
				if !r.appliesTo(goarch) {
					if _, ok := spec.nr[r.Syscall]; ok {
						t.Fatalf("row %s is limited to %v but %s has the syscall", r.Syscall, r.Archs, goarch)
					}
					return
				}
				nr := spec.nr[r.Syscall]
				if len(r.Arg0In) == 0 {
					if got := eval(t, p, seccompData{nr: nr, arch: spec.audit}); got != r.Action {
						t.Fatalf("%s (nr %d): got %s, want %s", r.Syscall, nr, got, r.Action)
					}
					return
				}
				for _, v := range r.Arg0In {
					if got := eval(t, p, seccompData{nr: nr, arch: spec.audit, args: [6]uint64{uint64(v)}}); got != r.Action {
						t.Fatalf("%s arg0 %#x: got %s, want %s", r.Syscall, v, got, r.Action)
					}
					// The high half is ignored: still refused.
					if got := eval(t, p, seccompData{nr: nr, arch: spec.audit, args: [6]uint64{uint64(v) | 1<<32}}); got != r.Action {
						t.Fatalf("%s arg0 %#x with a high half: got %s, want %s", r.Syscall, v, got, r.Action)
					}
				}
				for _, v := range []uint32{0, 1, 2, 0x4201} {
					if slices.Contains(r.Arg0In, v) {
						continue
					}
					if got := eval(t, p, seccompData{nr: nr, arch: spec.audit, args: [6]uint64{uint64(v)}}); got != ActionAllow {
						t.Fatalf("%s arg0 %#x: got %s, want allow", r.Syscall, v, got)
					}
				}
			})
		}
	}
}

// TestDecisionRows proves the rows the program adds around the profile: a
// foreign architecture is killed, the x32 ABI is killed on amd64, and a
// syscall no row names is allowed.
func TestDecisionRows(t *testing.T) {
	for _, goarch := range []string{ArchAMD64, ArchARM64} {
		p := buildProgram(t, goarch)
		spec := archs[goarch]
		t.Run(goarch+"/foreign_arch", func(t *testing.T) {
			for _, a := range foreignArches[goarch] {
				for _, nr := range []uint32{readNr[goarch], spec.nr["mount"]} {
					if got := eval(t, p, seccompData{nr: nr, arch: a}); got != ActionKill {
						t.Fatalf("arch %#x nr %d: got %s, want kill", a, nr, got)
					}
				}
			}
		})
		t.Run(goarch+"/x32_abi", func(t *testing.T) {
			got := eval(t, p, seccompData{nr: readNr[goarch] | x32SyscallBit, arch: spec.audit})
			want := ActionAllow
			if spec.x32Bit != 0 {
				want = ActionKill
			}
			if got != want {
				t.Fatalf("x32 read: got %s, want %s", got, want)
			}
		})
		t.Run(goarch+"/default", func(t *testing.T) {
			denied := map[uint32]bool{}
			for _, n := range spec.nr {
				denied[n] = true
			}
			for nr := uint32(0); nr < 600; nr++ {
				if denied[nr] {
					continue
				}
				if got := eval(t, p, seccompData{nr: nr, arch: spec.audit}); got != ActionAllow {
					t.Fatalf("nr %d: got %s, want allow", nr, got)
				}
			}
		})
	}
}

// TestDecisionsShape pins the table order the program walks.
func TestDecisionsShape(t *testing.T) {
	for _, goarch := range []string{ArchAMD64, ArchARM64} {
		ds, err := Decisions(ProfileObserverDefault, goarch)
		if err != nil {
			t.Fatal(err)
		}
		if ds[0].Kind != MatchForeignArch || ds[len(ds)-1].Kind != MatchDefault || ds[len(ds)-1].Action != ActionAllow {
			t.Fatalf("%s: the table must open with the arch row and close with the default allow: %+v", goarch, ds)
		}
		hasX32 := slices.ContainsFunc(ds, func(d Decision) bool { return d.Kind == MatchX32 })
		if hasX32 != (goarch == ArchAMD64) {
			t.Fatalf("%s: x32 row present = %v", goarch, hasX32)
		}
		for _, d := range ds {
			if d.Kind != MatchSyscall && d.Action != ActionKill && d.Kind != MatchDefault {
				t.Fatalf("%s: row %+v", goarch, d)
			}
			if d.Kind == MatchSyscall && d.Action == ActionKill {
				t.Fatalf("%s: a syscall row kills (%s); profile rows answer EPERM", goarch, d.Syscall)
			}
		}
	}
}

// TestBuildRefusals: an unknown architecture or profile is refused, never a
// silent empty program.
func TestBuildRefusals(t *testing.T) {
	for _, c := range []struct {
		id     ProfileID
		goarch string
	}{{ProfileObserverDefault, "riscv64"}, {ProfileObserverDefault, "386"}, {"nope", ArchAMD64}} {
		if _, err := Build(c.id, c.goarch); err == nil {
			t.Fatalf("Build(%s, %s) succeeded", c.id, c.goarch)
		}
	}
	if Supported("riscv64") || !Supported(ArchAMD64) || !Supported(ArchARM64) {
		t.Fatal("Supported disagrees with the arch table")
	}
}

// TestValidate covers the row checks.
func TestValidate(t *testing.T) {
	spec := archs[ArchAMD64]
	ok := Rule{Syscall: "mount", Action: ActionErrno, Reason: "r", Grounding: "g"}
	for name, rs := range map[string][]Rule{
		"unknown action": {{Syscall: "mount", Action: "maybe", Reason: "r", Grounding: "g"}},
		"no reason":      {{Syscall: "mount", Action: ActionErrno, Grounding: "g"}},
		"no number":      {{Syscall: "frobnicate", Action: ActionErrno, Reason: "r", Grounding: "g"}},
		"twice":          {ok, ok},
		"unknown arch":   {{Syscall: "mount", Action: ActionErrno, Reason: "r", Grounding: "g", Archs: []string{"vax"}}},
	} {
		if err := validate(rs, ArchAMD64, spec); err == nil {
			t.Fatalf("%s: validate passed", name)
		}
	}
	if err := validate([]Rule{ok}, ArchAMD64, spec); err != nil {
		t.Fatal(err)
	}
}

// TestBytes pins the wire form bwrap reads: 8 little-endian bytes per
// instruction.
func TestBytes(t *testing.T) {
	p := buildProgram(t, ArchAMD64)
	b := p.Bytes()
	if len(b) != len(p)*InstructionSize {
		t.Fatalf("len %d, want %d", len(b), len(p)*InstructionSize)
	}
	want := make([]byte, 8)
	binary.LittleEndian.PutUint16(want[0:], opLdAbsW)
	binary.LittleEndian.PutUint32(want[4:], offArch)
	if !bytes.Equal(b[:8], want) {
		t.Fatalf("first instruction % x, want % x", b[:8], want)
	}
	if len(p) > MaxInstructions {
		t.Fatalf("program of %d instructions", len(p))
	}
}

// TestUserNamespacesStayOpen pins decision N2-A8 (lane FU4): the profile
// denies the mount syscalls but never the user namespace syscalls, so a
// browser sandbox (user namespace, no mount) keeps working and a nested
// bwrap (needs mount) fails. Changing either half is a decision, not a
// tidy-up: update the profile comment, the doc and the live matrix with it.
func TestUserNamespacesStayOpen(t *testing.T) {
	t.Parallel()
	rows, _ := Rules(ProfileObserverDefault)
	denied := map[string]bool{}
	for _, r := range rows {
		if r.Action != ActionAllow {
			denied[r.Syscall] = true
		}
	}
	for _, s := range []string{"unshare", "clone", "clone3", "setns"} {
		if denied[s] {
			t.Errorf("%s is denied: user namespaces were decided open (N2-A8)", s)
		}
	}
	for _, s := range []string{"mount", "umount2", "pivot_root", "fsopen", "fsmount", "move_mount", "open_tree", "mount_setattr"} {
		if !denied[s] {
			t.Errorf("%s is not denied: the mount half of decision N2-A8 is gone", s)
		}
	}
}
