package sandboxsetup

import (
	"regexp"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
)

// The live-check fix round (2026-11-07): one test per defect row.

// TestRungPassedMarksEarlierSteps (D-L5-2, F5): a probe that stops at a
// later rung of its ladder marks every earlier probe-only step done, and
// Next is then the step it stopped at, not a rung it passed.
func TestRungPassedMarksEarlierSteps(t *testing.T) {
	cases := []struct {
		name, backend, verdict, reason string
		host                           sandboxbackend.HostKind
		done                           []string
		next                           string
	}{
		{
			"apple service", sandboxbackend.BackendAppleContainer, "engine_unreachable", "the container system service is not running", sandboxbackend.HostMacOS,
			[]string{"macos-26-arm", "apple-container-cli"},
			"apple-container-service",
		},
		{
			"vm image set", sandboxbackend.BackendCloudHypervisor, "image_missing", "no guest image set is installed", sandboxbackend.HostLinux,
			[]string{"kvm-device", "kvm-group", "cloud-hypervisor", "virtiofsd"},
			"bwrap",
		},
		{
			"runsc runtime", sandboxbackend.BackendOCIRunsc, "runtime_missing", "runsc is not registered", sandboxbackend.HostLinux,
			[]string{"docker-engine", "docker-group"},
			"oci-allow-rootful",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := base(t, tc.backend)
			in.Host = tc.host
			if tc.host == sandboxbackend.HostMacOS {
				in.Family = FamilyMacOS
			}
			in.Facts = map[string]Fact{"apple-container-cli": {Present: true, Path: "/usr/local/bin/container"}}
			in.Probe = &sandboxselect.Probe{Verdict: tc.verdict, Reason: tc.reason}
			p := Build(in)
			for _, id := range tc.done {
				if st := stepOf(t, p, id); st.State != StateDone {
					t.Errorf("%s = %s (%q), want done", id, st.State, st.Reason)
				}
			}
			if p.Next < 0 || p.Steps[p.Next].Prereq != tc.next {
				t.Errorf("Next = %d (%v), want %s", p.Next, stepIDsOf(p), tc.next)
			}
		})
	}
}

// TestKVMPermissionIsTheGroupStep (F1): /dev/kvm present but not openable is
// the group step, never the firmware step.
func TestKVMPermissionIsTheGroupStep(t *testing.T) {
	in := base(t, sandboxbackend.BackendCloudHypervisor)
	in.Probe = &sandboxselect.Probe{Verdict: "no_hypervisor", Reason: "/dev/kvm exists but this user cannot open it: add the user to the device's group (usually kvm) and log in again"}
	p := Build(in)
	if st := stepOf(t, p, "kvm-device"); st.State != StateDone {
		t.Errorf("kvm-device = %s, want done (the device exists)", st.State)
	}
	if st := stepOf(t, p, "kvm-group"); st.State != StateBlocked || !strings.Contains(st.Reason, "cannot open it") {
		t.Errorf("kvm-group = %s %q, want blocked with the probe's reason", st.State, st.Reason)
	}
	in.Probe = &sandboxselect.Probe{Verdict: "no_hypervisor", Reason: "/dev/kvm is missing: hardware virtualisation is off"}
	if st := stepOf(t, Build(in), "kvm-device"); st.State != StateBlocked {
		t.Errorf("kvm-device with no device = %s, want blocked", st.State)
	}
}

// TestNextRules is one test per nextRules row.
func TestNextRules(t *testing.T) {
	enabled := nextCtx{passiveEnabled: true}
	cases := []struct {
		rule string
		c    nextCtx
		st   Step
		want bool
	}{
		{"nothing_to_do", nextCtx{}, Step{State: StateDone, Class: ClassAuto}, false},
		{"nothing_to_do", nextCtx{}, Step{State: StateNotApplicable, Class: ClassAuto}, false},
		{"unknown_on_enabled_row", enabled, Step{State: StateUnknown, Class: ClassTerminal}, false},
		{"unknown_on_enabled_row", enabled, Step{State: StateUnknown, Class: ClassElevated}, false},
		{"unknown_not_ours", nextCtx{}, Step{State: StateUnknown, Class: ClassNever}, false},
		{"unknown_not_ours", nextCtx{}, Step{State: StateUnknown, Class: ClassGuide}, false},
		{"otherwise", nextCtx{}, Step{State: StateUnknown, Class: ClassTerminal}, true},
		{"otherwise", enabled, Step{State: StateMissing, Class: ClassTerminal}, true},
		{"otherwise", nextCtx{}, Step{State: StateMissing, Class: ClassGuide}, true},
		{"otherwise", nextCtx{}, Step{State: StateBlocked, Class: ClassNever}, true},
	}
	names := map[string]bool{}
	for _, r := range nextRules {
		names[r.name] = true
	}
	covered := map[string]bool{}
	for _, tc := range cases {
		covered[tc.rule] = true
		if !names[tc.rule] {
			t.Fatalf("no next rule %q", tc.rule)
		}
		if got := nextCandidate(tc.c, tc.st); got != tc.want {
			t.Errorf("%s %+v = %v, want %v", tc.rule, tc.st, got, tc.want)
		}
	}
	for n := range names {
		if !covered[n] {
			t.Errorf("next rule %q has no test case", n)
		}
	}
}

// TestPassiveSetUpIsUnconfirmed (D-2, D-L5-1, F13): a passive plan whose only
// open steps are ones the check judges and Observer does not do reads
// unconfirmed (never ready, never a next step Observer does not do); the
// checked plan reads ready.
func TestPassiveSetUpIsUnconfirmed(t *testing.T) {
	in := base(t, sandboxbackend.BackendBwrap)
	in.SandboxOn, in.Listed = true, true
	in.Facts = map[string]Fact{"bwrap": {Present: true, Path: "/usr/bin/bwrap"}}
	p := Build(in)
	if p.Ready || !p.Unconfirmed || p.Next != -1 {
		t.Fatalf("passive = ready %v unconfirmed %v next %d", p.Ready, p.Unconfirmed, p.Next)
	}
	in.Probe = &sandboxselect.Probe{Verdict: sandboxselect.VerdictAvailable}
	if c := Build(in); !c.Ready || c.Unconfirmed {
		t.Fatalf("checked = ready %v unconfirmed %v", c.Ready, c.Unconfirmed)
	}
	// A runnable step still open: not unconfirmed, and Next names it.
	in.Probe, in.SandboxOn = nil, false
	if q := Build(in); q.Unconfirmed || q.Steps[q.Next].Prereq != PrereqEnable {
		t.Fatalf("with enable open = unconfirmed %v next %v", q.Unconfirmed, q.Next)
	}
	// The seatbelt shape (D-L5-1): the OS version step is unknown passively.
	sb := base(t, sandboxbackend.BackendSeatbelt)
	sb.Host, sb.Family, sb.SandboxOn, sb.Listed = sandboxbackend.HostMacOS, FamilyMacOS, true, true
	sb.Facts = map[string]Fact{"macos-sandbox-exec": {Present: true, Path: "/usr/bin/sandbox-exec"}}
	if s := Build(sb); !s.Unconfirmed || s.Next != -1 {
		t.Fatalf("seatbelt passive = unconfirmed %v next %d", s.Unconfirmed, s.Next)
	}
}

// TestDoneNeverStepHasNoRefusal (D-10): a never step that is done does not
// show its refusal sentence.
func TestDoneNeverStepHasNoRefusal(t *testing.T) {
	in := base(t, sandboxbackend.BackendBwrap)
	if st := stepOf(t, Build(in), "userns"); st.Display == "" {
		t.Fatal("an open never step lost its sentence")
	}
	in.Probe = &sandboxselect.Probe{Verdict: sandboxselect.VerdictAvailable}
	if st := stepOf(t, Build(in), "userns"); st.State != StateDone || st.Display != "" {
		t.Errorf("done never step = %s display %q", st.State, st.Display)
	}
}

// TestWindowsRowOnWSL (L1 copy): a native Windows row read from a WSL daemon
// says where it runs.
func TestWindowsRowOnWSL(t *testing.T) {
	in := base(t, sandboxbackend.BackendMXCProcess)
	in.Host = sandboxbackend.HostWSL2
	if p := Build(in); p.Blocked != row(t, sandboxbackend.BackendMXCProcess).Label+" runs on native Windows, not inside WSL." {
		t.Errorf("blocked = %q", p.Blocked)
	}
	names := map[string]bool{}
	for _, r := range hostRefusalRules {
		names[r.name] = true
	}
	for _, n := range []string{"row_refusal", "windows_row_on_wsl", "generic"} {
		if !names[n] {
			t.Errorf("no host refusal rule %q", n)
		}
	}
}

// TestDefaultBackendUndoNote (D-7): the enable undo of the default backend
// on an otherwise empty list is refused with a sentence.
func TestDefaultBackendUndoNote(t *testing.T) {
	in := base(t, sandboxbackend.BackendBwrap)
	in.SandboxOn, in.Listed, in.UnlistRelists = true, true, true
	st := stepOf(t, Build(in), PrereqEnable)
	if st.CanUndo || st.UndoNote != reasonDefaultBackend || !strings.Contains(st.Reason, "default backend") {
		t.Errorf("enable = can_undo %v note %q reason %q", st.CanUndo, st.UndoNote, st.Reason)
	}
	in.UnlistRelists = false
	if st := stepOf(t, Build(in), PrereqEnable); !st.CanUndo || st.UndoNote != "" {
		t.Errorf("enable with another listed row = %+v", st)
	}
}

// TestEnableNamesNoRestart (fix round 3, item 1): the enable step takes
// effect in the running daemon, so it names no restart, with the sandbox off
// or on.
func TestEnableNamesNoRestart(t *testing.T) {
	in := base(t, sandboxbackend.BackendBwrap)
	if st := stepOf(t, Build(in), PrereqEnable); st.After != "" {
		t.Errorf("enable with the sandbox off: after = %q", st.After)
	}
	in.SandboxOn = true
	if st := stepOf(t, Build(in), PrereqEnable); st.After != "" {
		t.Errorf("enable with the sandbox on: after = %q", st.After)
	}
}

// internalRef matches a reference to an internal planning document.
var internalRef = regexp.MustCompile(`(?i)\bplan (section|ruling)\b|\bruling R[0-9]|\blifecycle plan\b`)

// TestNoInternalReferencesInUserCopy (D-9): no sentence a person reads from
// the planner (a row's setup or host refusal, a step's sentence or note)
// cites an internal document.
func TestNoInternalReferencesInUserCopy(t *testing.T) {
	for _, r := range sandboxbackend.Offered() {
		if internalRef.MatchString(r.SetupUnavailable) {
			t.Errorf("%s SetupUnavailable cites a document: %q", r.ID, r.SetupUnavailable)
		}
		for h, why := range r.Iso.HostRefusals {
			if internalRef.MatchString(why) {
				t.Errorf("%s host refusal (%s) cites a document: %q", r.ID, h, why)
			}
		}
	}
	for _, p := range prereqTable {
		for _, rem := range p.Remedies {
			for _, s := range []string{rem.Display, rem.Disclosure} {
				if internalRef.MatchString(s) {
					t.Errorf("%s remedy cites a document: %q", p.ID, s)
				}
			}
		}
	}
	for _, s := range []string{reasonOrgRefused, reasonGoverned, reasonNotChecked, reasonKillSwitch, reasonElevationOff, reasonPinUnavailable, reasonNoRemedy, reasonDefaultBackend, reasonLiveRunsUnknown, reasonLiveRunsFormat, reasonUndoKillSwitch, reasonUndoElevationOff, reasonArgUnset("a.b"), reasonCheckStopped("x")} {
		if internalRef.MatchString(s) {
			t.Errorf("reason cites a document: %q", s)
		}
	}
}
