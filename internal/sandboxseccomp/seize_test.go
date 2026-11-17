package sandboxseccomp

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// ptraceRow returns a profile's ptrace row.
func ptraceRow(t *testing.T, id ProfileID) Rule {
	t.Helper()
	rows, ok := Rules(id)
	if !ok {
		t.Fatalf("no profile %s", id)
	}
	for _, r := range rows {
		if r.Syscall == "ptrace" {
			return r
		}
	}
	t.Fatalf("%s has no ptrace row", id)
	return Rule{}
}

// TestSeizeProfilesLiftOnlySeize pins the opt-in's whole surface (PT-96): a
// seize profile is observer_default with PTRACE_SEIZE taken off the ptrace
// row, and nothing else changes (PTRACE_ATTACH, process_vm_readv and every
// other row stay as they are).
func TestSeizeProfilesLiftOnlySeize(t *testing.T) {
	t.Parallel()
	def, _ := Rules(ProfileObserverDefault)
	for _, id := range []ProfileID{ProfileObserverSeizePIDNS, ProfileObserverSeizeYama} {
		rows, ok := Rules(id)
		if !ok || len(rows) != len(def) {
			t.Fatalf("%s: %d rows, want %d", id, len(rows), len(def))
		}
		for i, r := range rows {
			if r.Syscall == "ptrace" {
				if !slices.Equal(r.Arg0In, []uint32{ptraceAttach}) || r.Action != ActionErrno {
					t.Errorf("%s ptrace row: %+v, want PTRACE_ATTACH alone denied", id, r)
				}
				continue
			}
			if !reflect.DeepEqual(r, def[i]) {
				t.Errorf("%s row %s differs from observer_default", id, r.Syscall)
			}
		}
	}
	if d := ptraceRow(t, ProfileObserverDefault); !slices.Equal(d.Arg0In, []uint32{ptraceAttach, ptraceSeize}) {
		t.Fatalf("observer_default ptrace row %v: the default must keep denying PTRACE_SEIZE", d.Arg0In)
	}
}

// TestSeizeProfileDecisions runs the assembled programs: under a seize
// profile PTRACE_SEIZE is allowed, PTRACE_ATTACH and process_vm_readv still
// get EPERM; under observer_default PTRACE_SEIZE gets EPERM.
func TestSeizeProfileDecisions(t *testing.T) {
	t.Parallel()
	for _, goarch := range []string{ArchAMD64, ArchARM64} {
		spec := archs[goarch]
		for _, c := range []struct {
			id                ProfileID
			seize, attach, vm Action
		}{
			{ProfileObserverDefault, ActionErrno, ActionErrno, ActionErrno},
			{ProfileObserverSeizePIDNS, ActionAllow, ActionErrno, ActionErrno},
			{ProfileObserverSeizeYama, ActionAllow, ActionErrno, ActionErrno},
		} {
			p, err := Build(c.id, goarch)
			if err != nil {
				t.Fatalf("Build(%s, %s): %v", c.id, goarch, err)
			}
			pt := spec.nr["ptrace"]
			if got := eval(t, p, seccompData{nr: pt, arch: spec.audit, args: [6]uint64{ptraceSeize}}); got != c.seize {
				t.Errorf("%s/%s PTRACE_SEIZE: %s, want %s", goarch, c.id, got, c.seize)
			}
			if got := eval(t, p, seccompData{nr: pt, arch: spec.audit, args: [6]uint64{ptraceAttach}}); got != c.attach {
				t.Errorf("%s/%s PTRACE_ATTACH: %s, want %s", goarch, c.id, got, c.attach)
			}
			if got := eval(t, p, seccompData{nr: spec.nr["process_vm_readv"], arch: spec.audit}); got != c.vm {
				t.Errorf("%s/%s process_vm_readv: %s, want %s", goarch, c.id, got, c.vm)
			}
		}
	}
}

// TestDecideSeize is the containment table, one case per row: off, on and
// contained by each ground, and on but not contained (still denied, with
// the reason).
func TestDecideSeize(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name    string
		f       SeizeFacts
		profile ProfileID
		ground  SeizeGround
		refusal string
	}{
		{"off", SeizeFacts{OwnPIDNamespace: true, YamaScope: 1, YamaKnown: true}, ProfileObserverDefault, "", ""},
		{"off, nothing contained", SeizeFacts{}, ProfileObserverDefault, "", ""},
		{"on, own pid namespace", SeizeFacts{OptIn: true, OwnPIDNamespace: true}, ProfileObserverSeizePIDNS, SeizeGroundPIDNamespace, ""},
		{"on, own pid namespace wins over Yama", SeizeFacts{OptIn: true, OwnPIDNamespace: true, YamaScope: 2, YamaKnown: true}, ProfileObserverSeizePIDNS, SeizeGroundPIDNamespace, ""},
		{"on, Yama 1", SeizeFacts{OptIn: true, YamaScope: 1, YamaKnown: true}, ProfileObserverSeizeYama, SeizeGroundYama, ""},
		{"on, Yama 3", SeizeFacts{OptIn: true, YamaScope: 3, YamaKnown: true}, ProfileObserverSeizeYama, SeizeGroundYama, ""},
		{"on, Yama 0: still denied", SeizeFacts{OptIn: true, YamaScope: 0, YamaKnown: true}, ProfileObserverDefault, "", "Yama ptrace_scope reads 0"},
		{"on, Yama unreadable: still denied", SeizeFacts{OptIn: true}, ProfileObserverDefault, "", "could not be read"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := DecideSeize(c.f)
			if d.Profile != c.profile || d.Ground != c.ground {
				t.Fatalf("got %+v, want profile %s ground %q", d, c.profile, c.ground)
			}
			if (c.refusal == "") != (d.Refusal == "") || !strings.Contains(d.Refusal, c.refusal) {
				t.Fatalf("refusal %q, want one naming %q", d.Refusal, c.refusal)
			}
			if g, ok := SeizeGroundOf(d.Profile); ok != (c.ground != "") || g != c.ground {
				t.Fatalf("SeizeGroundOf(%s) = %q %v", d.Profile, g, ok)
			}
		})
	}
}

// TestCheckSeizeGround is the host helper's second look: a seize profile
// whose ground does not hold now is refused; the default profile passes.
func TestCheckSeizeGround(t *testing.T) {
	t.Parallel()
	ok := []struct {
		id ProfileID
		f  SeizeFacts
	}{
		{ProfileObserverDefault, SeizeFacts{}},
		{ProfileObserverSeizePIDNS, SeizeFacts{OwnPIDNamespace: true}},
		{ProfileObserverSeizeYama, SeizeFacts{YamaScope: 1, YamaKnown: true}},
	}
	for _, c := range ok {
		if err := CheckSeizeGround(c.id, c.f); err != nil {
			t.Errorf("%s %+v: %v", c.id, c.f, err)
		}
	}
	bad := []struct {
		id   ProfileID
		f    SeizeFacts
		want string
	}{
		{ProfileObserverSeizePIDNS, SeizeFacts{YamaScope: 1, YamaKnown: true}, "pid namespace"},
		{ProfileObserverSeizeYama, SeizeFacts{OwnPIDNamespace: true, YamaScope: 0, YamaKnown: true}, "reads 0"},
		{ProfileObserverSeizeYama, SeizeFacts{}, "could not be read"},
	}
	for _, c := range bad {
		if err := CheckSeizeGround(c.id, c.f); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %+v: %v, want a refusal naming %q", c.id, c.f, err, c.want)
		}
	}
}

// TestParseYamaScope covers the file's text.
func TestParseYamaScope(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		in   string
		want int
	}{{"0\n", 0}, {"1\n", 1}, {"\t2 \n", 2}, {"3", 3}} {
		if got, ok := ParseYamaScope(c.in); !ok || got != c.want {
			t.Errorf("%q: %d %v", c.in, got, ok)
		}
	}
	for _, in := range []string{"", "4", "-1", "x", "1 2"} {
		if _, ok := ParseYamaScope(in); ok {
			t.Errorf("%q parsed", in)
		}
	}
}

// TestSeizeProfileIDsFitThePlan pins the ids to the shape the planner and
// the landlock plan file accept (lower case, digits, underscores, at most 32).
func TestSeizeProfileIDsFitThePlan(t *testing.T) {
	t.Parallel()
	for _, id := range Profiles() {
		if len(id) > 32 || strings.Trim(string(id), "abcdefghijklmnopqrstuvwxyz0123456789_") != "" {
			t.Errorf("profile id %q", id)
		}
	}
}
