package sandboxsetup

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	"github.com/marmutapp/superbased-observer/internal/toolinstall"
)

func row(t *testing.T, id string) sandboxbackend.Capability {
	t.Helper()
	c, ok := sandboxbackend.Get(id)
	if !ok {
		t.Fatalf("no registry row %q", id)
	}
	return c
}

// base is a Debian host where everything is allowed and the row's module is
// selected but the row is not set up yet.
func base(t *testing.T, id string) PlanInput {
	t.Helper()
	return PlanInput{
		Row: row(t, id), Host: sandboxbackend.HostLinux, Family: FamilyDebian, Arch: "amd64",
		OrgAllowed: true, ComponentID: "terminals.sandbox", ComponentSelected: true,
		AllowInstall: true, AllowElevated: true, DownloadSource: SourceVendorRelease,
	}
}

func stepOf(t *testing.T, p Plan, id string) Step {
	t.Helper()
	for _, s := range p.Steps {
		if s.Prereq == id {
			return s
		}
	}
	t.Fatalf("plan %s has no step %q (steps %v)", p.Backend, id, stepIDsOf(p))
	return Step{}
}

func stepIDsOf(p Plan) []string {
	var out []string
	for _, s := range p.Steps {
		out = append(out, s.Prereq)
	}
	return out
}

// withPins installs a pin table for one test.
func withPins(t *testing.T, ps ...Pin) {
	t.Helper()
	old := pins
	pins = ps
	t.Cleanup(func() { pins = old })
}

// TestPlanRules is one test per planRules row.
func TestPlanRules(t *testing.T) {
	if len(planRules) != 6 {
		t.Fatalf("planRules has %d rows; give each new row its case here", len(planRules))
	}
	t.Run("not_offered", func(t *testing.T) {
		in := base(t, sandboxbackend.BackendCodespaces)
		in.Host = sandboxbackend.HostRemote
		p := Build(in)
		if !strings.HasPrefix(p.Blocked, "Planned for phase P7") || len(p.Steps) != 0 || p.Next != -1 || p.Ready {
			t.Errorf("plan = %+v", p)
		}
	})
	t.Run("host with the row's own refusal", func(t *testing.T) {
		in := base(t, sandboxbackend.BackendOpenShell)
		in.Host = sandboxbackend.HostWSL2
		if p := Build(in); p.Blocked != sandboxbackend.OpenShellWSL2Refusal || len(p.Steps) != 0 {
			t.Errorf("blocked = %q", p.Blocked)
		}
	})
	t.Run("host without a refusal", func(t *testing.T) {
		in := base(t, sandboxbackend.BackendBwrap)
		in.Host = sandboxbackend.HostMacOS
		if p := Build(in); !strings.Contains(p.Blocked, "does not run on this host (macos)") {
			t.Errorf("blocked = %q", p.Blocked)
		}
	})
	t.Run("org_floor", func(t *testing.T) {
		in := base(t, sandboxbackend.BackendBwrap)
		in.OrgAllowed = false
		p := Build(in)
		if p.Blocked != "" {
			t.Errorf("blocked = %q, want steps", p.Blocked)
		}
		for _, s := range p.Steps {
			if s.State != StateNotAllowed || s.CanRun || s.Reason != reasonOrgRefused {
				t.Errorf("step %s = %s canRun %v reason %q", s.Prereq, s.State, s.CanRun, s.Reason)
			}
		}
	})
	t.Run("not_in_release", func(t *testing.T) {
		in := base(t, sandboxbackend.BackendHCS)
		in.Host = sandboxbackend.HostWindows
		p := Build(in)
		if !strings.HasPrefix(p.Blocked, "Not available in this release: no utility VM image") || len(p.Steps) != 0 {
			t.Errorf("blocked = %q", p.Blocked)
		}
		in = base(t, sandboxbackend.BackendWSLC)
		in.Host = sandboxbackend.HostWindows
		if p := Build(in); !strings.HasPrefix(p.Blocked, "Not available in this release") {
			t.Errorf("wslc blocked = %q", p.Blocked)
		}
	})
	t.Run("steps", func(t *testing.T) {
		p := Build(base(t, sandboxbackend.BackendCloudHypervisor))
		want := append(append([]string{PrereqComponent}, row(t, sandboxbackend.BackendCloudHypervisor).Setup...), PrereqEnable)
		if got := stepIDsOf(p); !reflect.DeepEqual(got, want) {
			t.Errorf("steps = %v, want %v", got, want)
		}
	})
	t.Run("gate", func(t *testing.T) {
		in := base(t, sandboxbackend.BackendBwrap)
		in.SandboxOn, in.Listed = true, true
		in.Probe = &sandboxselect.Probe{Compiled: true, Verdict: sandboxselect.VerdictAvailable}
		p := Build(in)
		if !p.Ready || p.Next != -1 {
			t.Errorf("ready = %v next = %d (%+v)", p.Ready, p.Next, p.Steps)
		}
		in.Probe = nil
		if p := Build(in); p.Ready {
			t.Error("ready with no probe")
		}
	})
}

// TestStateRules is one test per stateRules row.
func TestStateRules(t *testing.T) {
	names := map[string]bool{}
	for _, r := range stateRules {
		names[r.name] = true
	}
	cases := []struct {
		rule   string
		edit   func(in *PlanInput)
		step   string
		state  StepState
		reason string
	}{
		{"org_refused", func(in *PlanInput) { in.OrgAllowed = false }, "bwrap", StateNotAllowed, reasonOrgRefused},
		{"component_not_applicable", func(in *PlanInput) { in.ComponentID = "" }, PrereqComponent, StateNotApplicable, ""},
		{"in_flight", func(in *PlanInput) {
			in.Records = map[string]Record{"bwrap": {ID: 1, Status: toolinstall.StatusInstalling, Channel: "apt"}}
		}, "bwrap", StateInFlight, ""},
		{"component", func(in *PlanInput) { in.ComponentSelected = false }, PrereqComponent, StateMissing, ""},
		{"component", func(in *PlanInput) { in.ComponentSelected, in.ComponentGoverned = false, true }, PrereqComponent, StateBlocked, reasonGoverned},
		{"component", func(*PlanInput) {}, PrereqComponent, StateDone, ""},
		{"enable", func(*PlanInput) {}, PrereqEnable, StateMissing, ""},
		{"enable", func(in *PlanInput) { in.SandboxOn, in.Listed = true, true }, PrereqEnable, StateDone, ""},
		{"probe_missing", func(in *PlanInput) {
			in.Probe = &sandboxselect.Probe{Verdict: "backend_missing", Reason: "install bubblewrap"}
		}, "bwrap", StateMissing, "install bubblewrap"},
		{"probe_missing", func(in *PlanInput) {
			in.Probe = &sandboxselect.Probe{Verdict: "userns_denied", Reason: "user namespaces are denied"}
		}, "userns", StateBlocked, "user namespaces are denied"},
		{"fact_not_applicable", func(in *PlanInput) {
			in.Facts = map[string]Fact{"bwrap": {NotApplicable: true, Reason: "Not needed here."}}
		}, "bwrap", StateNotApplicable, "Not needed here."},
		{"fact_too_old", func(in *PlanInput) {
			in.Facts = map[string]Fact{"bwrap": {Present: true, Version: "0.3.3"}}
		}, "bwrap", StateMissing, "Found version 0.3.3; this needs 0.4.0 or newer."},
		{"fact_present", func(in *PlanInput) {
			in.Facts = map[string]Fact{"bwrap": {Present: true, Version: "bubblewrap 0.9.0", Path: "/usr/bin/bwrap"}}
		}, "bwrap", StateDone, ""},
		{"fact_absent", func(in *PlanInput) {
			in.Facts = map[string]Fact{"bwrap": {Checked: true, Reason: "bwrap is not on PATH"}}
		}, "bwrap", StateMissing, "bwrap is not on PATH"},
		{"fact_absent", func(in *PlanInput) {
			in.Facts = map[string]Fact{"userns": {Checked: true, Reason: "denied"}}
		}, "userns", StateBlocked, "denied"},
		{"probe_rung_passed", func(in *PlanInput) {
			// The probe stopped at the namespaces rung, so it passed bwrap.
			in.Probe = &sandboxselect.Probe{Verdict: "userns_denied", Reason: "denied"}
		}, "bwrap", StateDone, ""},
		{"probe_passes", func(in *PlanInput) {
			in.Probe = &sandboxselect.Probe{Verdict: sandboxselect.VerdictAvailable}
		}, "bwrap", StateDone, ""},
		{"probe_unmapped", func(in *PlanInput) {
			// A verdict no step owns: the check's own reason, not "not checked".
			in.Probe = &sandboxselect.Probe{Verdict: "probe_failed", Reason: "the canary failed."}
		}, "bwrap", StateUnknown, "The check could not judge this step; it stopped at: the canary failed."},
		{"unknown", func(*PlanInput) {}, "bwrap", StateUnknown, reasonNotChecked},
	}
	covered := map[string]bool{}
	for _, tc := range cases {
		covered[tc.rule] = true
		t.Run(tc.rule+"/"+tc.step+"/"+string(tc.state), func(t *testing.T) {
			if !names[tc.rule] {
				t.Fatalf("no state rule %q", tc.rule)
			}
			in := base(t, sandboxbackend.BackendBwrap)
			tc.edit(&in)
			s := stepOf(t, Build(in), tc.step)
			if s.State != tc.state || s.Reason != tc.reason {
				t.Errorf("step %s = (%s, %q), want (%s, %q)", tc.step, s.State, s.Reason, tc.state, tc.reason)
			}
		})
	}
	for n := range names {
		if !covered[n] {
			t.Errorf("state rule %q has no test case", n)
		}
	}
}

// TestDriverBinaryVersions: a driver binary is judged against its row's
// pins (required minimum, then the tested range's beta note).
func TestDriverBinaryVersions(t *testing.T) {
	in := base(t, sandboxbackend.BackendOpenShell)
	ch := in.Row.Control.Pins
	in.Facts = map[string]Fact{"openshell-pkg": {Present: true, Version: "0.0.9"}}
	if s := stepOf(t, Build(in), "openshell-pkg"); s.State != StateMissing || !strings.Contains(s.Reason, "needs "+ch.RequiredMin) {
		t.Errorf("too old: %+v", s)
	}
	in.Facts = map[string]Fact{"openshell-pkg": {Present: true, Version: "0.1.6"}}
	if s := stepOf(t, Build(in), "openshell-pkg"); s.State != StateDone || s.Reason != "" {
		t.Errorf("tested: %+v", s)
	}
	in.Facts = map[string]Fact{"openshell-pkg": {Present: true, Version: "0.2.0"}}
	if s := stepOf(t, Build(in), "openshell-pkg"); s.State != StateDone || !strings.Contains(s.Reason, "beta here") {
		t.Errorf("beta: %+v", s)
	}
	in.Facts = map[string]Fact{"openshell-pkg": {Present: true, Version: "unreadable"}}
	if s := stepOf(t, Build(in), "openshell-pkg"); s.State != StateDone {
		t.Errorf("unreadable version is the probe's to judge: %+v", s)
	}
}

// TestClassRules is one test per classRules row.
func TestClassRules(t *testing.T) {
	names := map[string]bool{}
	for _, r := range classRules {
		names[r.name] = true
	}
	grounded := Pin{ID: "cloud-hypervisor", Version: "54.0", GOOS: "linux", GOARCH: "amd64", URL: "https://example.invalid/ch", SHA256: strings.Repeat("a", 64), Size: 4 << 20, Status: PinGrounded}
	owed := grounded
	owed.Status = PinOwed
	cases := []struct {
		rule    string
		backend string
		edit    func(in *PlanInput)
		pins    []Pin
		step    string
		class   Class
		channel Channel
		canRun  bool
	}{
		{"no_remedy", sandboxbackend.BackendBwrap, func(in *PlanInput) {
			in.Row.Iso.Hosts = append(in.Row.Iso.Hosts, sandboxbackend.HostMacOS)
			in.Host, in.Family = sandboxbackend.HostMacOS, FamilyMacOS
		}, nil, "bwrap", ClassGuide, ChNone, false},
		{"never", sandboxbackend.BackendBwrap, func(in *PlanInput) { in.Facts = map[string]Fact{"userns": {Checked: true}} }, nil, "userns", ClassNever, ChNone, false},
		{"already_guide", sandboxbackend.BackendBwrap, func(in *PlanInput) { in.Family = FamilyFedora; in.Facts = map[string]Fact{"bwrap": {Checked: true}} }, nil, "bwrap", ClassGuide, ChNone, false},
		{"kill_switch", sandboxbackend.BackendBwrap, func(in *PlanInput) { in.AllowInstall = false; in.Facts = map[string]Fact{"bwrap": {Checked: true}} }, nil, "bwrap", ClassGuide, ChNone, false},
		{"kill_switch", sandboxbackend.BackendBwrap, func(in *PlanInput) { in.AllowInstall = false; in.ComponentSelected = false }, nil, PrereqComponent, ClassGuide, ChNone, false},
		{"elevation_off", sandboxbackend.BackendBwrap, func(in *PlanInput) { in.AllowElevated = false; in.Facts = map[string]Fact{"bwrap": {Checked: true}} }, nil, "bwrap", ClassGuide, ChNone, false},
		{"managed_no_mirror", sandboxbackend.BackendCloudHypervisor, func(in *PlanInput) {
			in.Managed, in.DownloadSource = true, ""
			in.Facts = map[string]Fact{"cloud-hypervisor": {Checked: true}}
		}, []Pin{grounded}, "cloud-hypervisor", ClassAuto, ChPinned, true},
		{"pin_unavailable", sandboxbackend.BackendCloudHypervisor, func(in *PlanInput) { in.Facts = map[string]Fact{"cloud-hypervisor": {Checked: true}} }, nil, "cloud-hypervisor", ClassGuide, ChNone, false},
		{"pin_unavailable", sandboxbackend.BackendCloudHypervisor, func(in *PlanInput) { in.Facts = map[string]Fact{"cloud-hypervisor": {Checked: true}} }, []Pin{owed}, "cloud-hypervisor", ClassGuide, ChNone, false},
		{"pin_unavailable", sandboxbackend.BackendCloudHypervisor, func(in *PlanInput) {
			in.DownloadSource = ""
			in.Facts = map[string]Fact{"cloud-hypervisor": {Checked: true}}
		}, []Pin{grounded}, "cloud-hypervisor", ClassGuide, ChNone, false},
		{"pin_unavailable", sandboxbackend.BackendCloudHypervisor, func(in *PlanInput) {
			in.Arch = "arm64"
			in.Facts = map[string]Fact{"cloud-hypervisor": {Checked: true}}
		}, []Pin{grounded}, "cloud-hypervisor", ClassGuide, ChNone, false},
		{"arg_unset", sandboxbackend.BackendAppleContainer, func(in *PlanInput) {
			in.Host, in.Family = sandboxbackend.HostMacOS, FamilyMacOS
			in.Probe = &sandboxselect.Probe{Verdict: "image_missing"}
		}, nil, "apple-container-image", ClassGuide, ChNone, false},
		{"as_declared", sandboxbackend.BackendCloudHypervisor, func(in *PlanInput) { in.Facts = map[string]Fact{"cloud-hypervisor": {Checked: true}} }, []Pin{grounded}, "cloud-hypervisor", ClassAuto, ChPinned, true},
		{"as_declared", sandboxbackend.BackendBwrap, func(in *PlanInput) { in.Facts = map[string]Fact{"bwrap": {Checked: true}} }, nil, "bwrap", ClassElevated, ChPM, true},
		{"as_declared", sandboxbackend.BackendAppleContainer, func(in *PlanInput) {
			in.Host, in.Family = sandboxbackend.HostMacOS, FamilyMacOS
			in.Probe = &sandboxselect.Probe{Verdict: "engine_unreachable"}
		}, nil, "apple-container-service", ClassTerminal, ChCommand, true},
	}
	covered := map[string]bool{}
	for _, tc := range cases {
		covered[tc.rule] = true
		t.Run(tc.rule+"/"+tc.step, func(t *testing.T) {
			if !names[tc.rule] {
				t.Fatalf("no class rule %q", tc.rule)
			}
			withPins(t, tc.pins...)
			in := base(t, tc.backend)
			tc.edit(&in)
			s := stepOf(t, Build(in), tc.step)
			if s.Class != tc.class || s.Channel != tc.channel || s.CanRun != tc.canRun {
				t.Errorf("step %s = (%s, %s, canRun %v), want (%s, %s, %v); reason %q", tc.step, s.Class, s.Channel, s.CanRun, tc.class, tc.channel, tc.canRun, s.Reason)
			}
		})
	}
	for n := range names {
		if !covered[n] {
			t.Errorf("class rule %q has no test case", n)
		}
	}
}

// TestStepOutputs: what a runnable step carries for its runner, and what a
// degraded one still shows.
func TestStepOutputs(t *testing.T) {
	t.Run("pm argv derived through toolinstall", func(t *testing.T) {
		in := base(t, sandboxbackend.BackendBwrap)
		in.Facts = map[string]Fact{"bwrap": {Checked: true}}
		s := stepOf(t, Build(in), "bwrap")
		if !reflect.DeepEqual(s.Argv, []string{"sudo", "apt-get", "install", "-y", "bubblewrap"}) || s.Display != "sudo apt-get install -y bubblewrap" || s.Package != "bubblewrap" {
			t.Errorf("step = %+v", s)
		}
	})
	t.Run("degraded pm keeps the copyable command, runs nothing", func(t *testing.T) {
		in := base(t, sandboxbackend.BackendBwrap)
		in.AllowElevated = false
		in.Facts = map[string]Fact{"bwrap": {Checked: true}}
		s := stepOf(t, Build(in), "bwrap")
		if s.Argv != nil || s.Display != "sudo apt-get install -y bubblewrap" || !strings.Contains(s.Reason, "allow_elevated") {
			t.Errorf("step = %+v", s)
		}
	})
	t.Run("command argv is the remedy's constant", func(t *testing.T) {
		in := base(t, sandboxbackend.BackendOCIRunsc)
		in.Probe = &sandboxselect.Probe{Verdict: "runtime_missing", Reason: "runsc is not registered"}
		s := stepOf(t, Build(in), "runsc-registered")
		if !reflect.DeepEqual(s.Argv, []string{"sudo", "runsc", "install", "--", "--host-uds=open"}) || !s.CanRun || s.After != AfterEngineRestart || s.Disclosure == "" {
			t.Errorf("step = %+v", s)
		}
	})
	t.Run("pinned consent", func(t *testing.T) {
		p := Pin{ID: "cloud-hypervisor", Version: "54.0", GOOS: "linux", GOARCH: "amd64", URL: "https://example.invalid/ch", SHA256: strings.Repeat("b", 64), Size: 5 << 20, Status: PinGrounded}
		withPins(t, p)
		in := base(t, sandboxbackend.BackendCloudHypervisor)
		in.Facts = map[string]Fact{"cloud-hypervisor": {Checked: true}}
		s := stepOf(t, Build(in), "cloud-hypervisor")
		want := &Consent{Pin: p.ID, Version: p.Version, SHA256: p.SHA256, Bytes: p.Size, Source: SourceVendorRelease, URL: p.URL}
		if !reflect.DeepEqual(s.Consent, want) {
			t.Errorf("consent = %+v, want %+v", s.Consent, want)
		}
		in.DownloadSource = SourceOrgMirror
		if s := stepOf(t, Build(in), "cloud-hypervisor"); s.Consent == nil || s.Consent.URL != "" || s.Consent.Source != SourceOrgMirror {
			t.Errorf("mirror consent = %+v", s.Consent)
		}
	})
	t.Run("component step carries its component id", func(t *testing.T) {
		in := base(t, sandboxbackend.BackendCloudHypervisor)
		in.ComponentID, in.ComponentSelected = "terminals.sandbox.vm", false
		s := stepOf(t, Build(in), PrereqComponent)
		if s.Package != "terminals.sandbox.vm" || !s.CanRun || s.Channel != ChComponent {
			t.Errorf("step = %+v", s)
		}
	})
}

// TestGateBlockedStopsLaterRuns: rule 7, a step after a blocked one stays
// visible but cannot run; Next is the first step not done.
func TestGateBlockedStopsLaterRuns(t *testing.T) {
	in := base(t, sandboxbackend.BackendCloudHypervisor)
	in.Facts = map[string]Fact{
		"kvm-device":       {Checked: true, Reason: "no /dev/kvm"},
		"cloud-hypervisor": {Checked: true},
	}
	p := Build(in)
	kvm, ch := stepOf(t, p, "kvm-device"), stepOf(t, p, "cloud-hypervisor")
	if kvm.State != StateBlocked || ch.State != StateMissing || ch.CanRun {
		t.Errorf("kvm %s, ch %s canRun %v", kvm.State, ch.State, ch.CanRun)
	}
	if p.Next != 1 {
		t.Errorf("next = %d, want 1 (kvm-device)", p.Next)
	}
	if stepOf(t, p, PrereqEnable).CanRun {
		t.Error("enable runnable after a blocked step")
	}
}

// TestUndoRules is one test per undoRules row.
func TestUndoRules(t *testing.T) {
	names := map[string]bool{}
	for _, r := range undoRules {
		names[r.name] = true
	}
	installed := func(ch string) map[string]Record {
		return map[string]Record{"bwrap": {ID: 7, Status: toolinstall.StatusInstalled, Channel: ch, StartedAt: time.Unix(1, 0)}}
	}
	done := map[string]Fact{"bwrap": {Present: true, Version: "0.9.0"}}
	cases := []struct {
		rule string
		edit func(in *PlanInput)
		step string
		want bool
	}{
		{"not_done", func(in *PlanInput) { in.Records = installed("apt") }, "bwrap", false},
		{"live_runs", func(in *PlanInput) { in.Facts, in.Records, in.LiveRuns = done, installed("apt"), 1 }, "bwrap", false},
		{"live_runs_unknown", func(in *PlanInput) { in.Facts, in.Records, in.LiveRunsUnknown = done, installed("apt"), true }, "bwrap", false},
		{"kill_switch", func(in *PlanInput) { in.Facts, in.Records, in.AllowInstall = done, installed("apt"), false }, "bwrap", false},
		{"shared_in_use", func(in *PlanInput) {
			in.Facts, in.Records = done, installed("apt")
			in.InUseBy = map[string][]string{"bwrap": {sandboxbackend.BackendCloudHypervisor}}
		}, "bwrap", false},
		{"shared_in_use", func(in *PlanInput) {
			// The row's own enable step is never kept for another row.
			in.SandboxOn, in.Listed = true, true
			in.InUseBy = map[string][]string{PrereqEnable: {sandboxbackend.BackendCloudHypervisor}}
		}, PrereqEnable, true},
		{"default_backend", func(in *PlanInput) { in.SandboxOn, in.Listed, in.UnlistRelists = true, true, true }, PrereqEnable, false},
		{"enable", func(in *PlanInput) { in.SandboxOn, in.Listed = true, true }, PrereqEnable, true},
		{"component", func(in *PlanInput) {}, PrereqComponent, false},
		{"component", func(in *PlanInput) {
			in.Records = map[string]Record{PrereqComponent: {ID: 3, Status: toolinstall.StatusInstalled, Channel: string(ChComponent)}}
		}, PrereqComponent, true},
		{"no_record", func(in *PlanInput) { in.Facts = done }, "bwrap", false},
		{"record_settled", func(in *PlanInput) {
			in.Facts = done
			in.Records = map[string]Record{"bwrap": {Status: toolinstall.StatusUninstalled, Channel: "apt"}}
		}, "bwrap", false},
		{"elevation_off", func(in *PlanInput) {
			in.Facts, in.AllowElevated = done, false
			in.Records = map[string]Record{"bwrap": {Status: toolinstall.StatusInstalled, Channel: "apt", Elevated: true}}
		}, "bwrap", false},
		{"package", func(in *PlanInput) { in.Facts, in.Records = done, installed("apt") }, "bwrap", true},
		{"placed_file", func(in *PlanInput) {
			in.Facts = done
			in.Records = map[string]Record{"bwrap": {Status: toolinstall.StatusInstalled, Channel: string(ChPinned), PlacedPath: "/home/u/.observer/tools/x"}}
		}, "bwrap", true},
		{"config_or_content", func(in *PlanInput) {
			in.Facts = done
			in.Records = map[string]Record{"bwrap": {Status: toolinstall.StatusInstalled, Channel: string(ChContent)}}
		}, "bwrap", true},
		{"otherwise", func(in *PlanInput) {
			in.Facts = done
			in.Records = map[string]Record{"bwrap": {Status: toolinstall.StatusInstalled, Channel: string(ChCommand)}}
		}, "bwrap", false},
	}
	covered := map[string]bool{}
	for _, tc := range cases {
		covered[tc.rule] = true
		t.Run(tc.rule+"/"+tc.step, func(t *testing.T) {
			if !names[tc.rule] {
				t.Fatalf("no undo rule %q", tc.rule)
			}
			in := base(t, sandboxbackend.BackendBwrap)
			tc.edit(&in)
			if got := stepOf(t, Build(in), tc.step).CanUndo; got != tc.want {
				t.Errorf("CanUndo = %v, want %v", got, tc.want)
			}
		})
	}
	for n := range names {
		if !covered[n] {
			t.Errorf("undo rule %q has no test case", n)
		}
	}
}

// TestSharedInUseReason: a done shared prerequisite kept for another listed
// row names that row by its label, and the note leaves the fingerprint alone.
func TestSharedInUseReason(t *testing.T) {
	in := base(t, sandboxbackend.BackendBwrap)
	in.Facts = map[string]Fact{"bwrap": {Present: true, Version: "0.9.0"}}
	in.Records = map[string]Record{"bwrap": {ID: 7, Status: toolinstall.StatusInstalled, Channel: "apt", StartedAt: time.Unix(1, 0)}}
	free := Build(in)
	if s := stepOf(t, free, "bwrap"); !s.CanUndo || strings.Contains(s.Reason, "Kept:") {
		t.Fatalf("unshared bwrap: canUndo %v reason %q", s.CanUndo, s.Reason)
	}
	in.InUseBy = map[string][]string{"bwrap": {sandboxbackend.BackendCloudHypervisor}}
	kept := Build(in)
	s := stepOf(t, kept, "bwrap")
	want := "Kept: also used by " + row(t, sandboxbackend.BackendCloudHypervisor).Label + "."
	if s.CanUndo || !strings.Contains(s.Reason, want) {
		t.Errorf("shared bwrap: canUndo %v reason %q, want it to contain %q", s.CanUndo, s.Reason, want)
	}
	if kept.Fingerprint != free.Fingerprint {
		t.Error("the kept note changed the fingerprint")
	}
}

// TestFingerprint: equal plans agree, any of prereq, state, class, display
// or consent changes it, and a reason alone does not.
func TestFingerprint(t *testing.T) {
	in := base(t, sandboxbackend.BackendBwrap)
	a, b := Build(in), Build(in)
	if a.Fingerprint == "" || a.Fingerprint != b.Fingerprint || len(a.Fingerprint) != 64 {
		t.Fatalf("fingerprints %q %q", a.Fingerprint, b.Fingerprint)
	}
	steps := a.Steps
	edits := map[string]func(s *Step){
		"prereq":  func(s *Step) { s.Prereq = "x" },
		"state":   func(s *Step) { s.State = StateDone },
		"class":   func(s *Step) { s.Class = ClassNever },
		"display": func(s *Step) { s.Display = "other" },
		"consent": func(s *Step) { s.Consent = &Consent{Pin: "p", SHA256: "s"} },
	}
	for name, edit := range edits {
		cp := append([]Step(nil), steps...)
		edit(&cp[1])
		if Fingerprint(cp) == a.Fingerprint {
			t.Errorf("changing %s keeps the fingerprint", name)
		}
	}
	cp := append([]Step(nil), steps...)
	cp[1].Reason = "a different reason"
	if Fingerprint(cp) != a.Fingerprint {
		t.Error("a reason alone changed the fingerprint")
	}
	in.Facts = map[string]Fact{"bwrap": {Present: true}}
	if Build(in).Fingerprint == a.Fingerprint {
		t.Error("a fact that changes a state keeps the fingerprint")
	}
}

// TestPlanBeta: Build copies the row's SetupBeta sentence onto the plan,
// and the label never changes the Fingerprint (it is not a step).
func TestPlanBeta(t *testing.T) {
	cases := []struct {
		name string
		id   string
		host sandboxbackend.HostKind
		want string
	}{
		{"beta row", sandboxbackend.BackendHCS, sandboxbackend.HostWindows, row(t, sandboxbackend.BackendHCS).SetupBeta},
		{"non-beta row", sandboxbackend.BackendBwrap, sandboxbackend.HostLinux, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := base(t, tc.id)
			in.Host = tc.host
			if tc.want == "" && in.Row.SetupBeta != "" {
				t.Fatalf("%s carries SetupBeta %q", tc.id, in.Row.SetupBeta)
			}
			p := Build(in)
			if p.Beta != tc.want {
				t.Errorf("Beta = %q, want %q", p.Beta, tc.want)
			}
			flipped := in
			if in.Row.SetupBeta == "" {
				flipped.Row.SetupBeta = "a beta sentence"
			} else {
				flipped.Row.SetupBeta = ""
			}
			if Build(flipped).Fingerprint != p.Fingerprint {
				t.Error("the beta label changed the fingerprint")
			}
		})
	}
	if row(t, sandboxbackend.BackendHCS).SetupBeta == "" {
		t.Error("the HCS row is not beta")
	}
}

// TestEveryOfferedRowPlans: every offered row builds a plan on each of its
// hosts without a step the table does not know.
func TestEveryOfferedRowPlans(t *testing.T) {
	for _, c := range sandboxbackend.Offered() {
		for _, h := range c.Iso.Hosts {
			in := base(t, c.ID)
			in.Host = h
			p := Build(in)
			if p.Backend != c.ID || p.Label != c.Label || p.Fingerprint == "" {
				t.Errorf("%s on %s: plan %+v", c.ID, h, p)
			}
			for _, s := range p.Steps {
				if s.Reason == reasonNoRemedy {
					t.Errorf("%s on %s: step %s has no remedy", c.ID, h, s.Prereq)
				}
			}
		}
	}
}

// TestPinFor: the indirection over the pin table pins.go fills.
func TestPinFor(t *testing.T) {
	p := Pin{ID: "x", GOOS: "linux", GOARCH: "amd64", Status: PinGrounded}
	withPins(t, p, Pin{ID: "x", GOOS: "darwin", GOARCH: "arm64"})
	if got, ok := pinMatching("x", "linux", "amd64"); !ok || got != p {
		t.Errorf("pinMatching = %+v, %v", got, ok)
	}
	if _, ok := pinMatching("x", "windows", "amd64"); ok {
		t.Error("found a pin for another OS")
	}
	if _, ok := pinMatching("y", "linux", "amd64"); ok {
		t.Error("found a pin for another id")
	}
	if _, ok := PinFor("none"); ok {
		t.Error("PinFor found an absent id")
	}
}

// TestNodeWideUndo is one case per shape of the NodeWide rule (audit
// sandbox-terminal-gaps-2026-11-18, H12): the hosted custody step sets one
// value every hosted row reads, so another set-up row's use does not keep it;
// Undo is offered and names the other rows it changes. A shared step that is
// not NodeWide (the consent) is still kept, and a NodeWide step no other row
// uses carries no UndoAlso.
func TestNodeWideUndo(t *testing.T) {
	cfgRec := func(id string) map[string]Record {
		return map[string]Record{id: {ID: 9, Status: toolinstall.StatusInstalled, Channel: string(ChConfig), StartedAt: time.Unix(1, 0)}}
	}
	cases := []struct {
		name      string
		prereq    string
		others    []string
		wantUndo  bool
		wantAlso  bool
		wantKept  bool
		channelOf Channel
	}{
		{"node-wide shared: offered, names the others", "hosted-custody", []string{sandboxbackend.BackendE2B}, true, true, false, ChConfig},
		{"node-wide alone: offered, nothing else changes", "hosted-custody", nil, true, false, false, ChConfig},
		{"shared, not node-wide: kept", "hosted-consent", []string{sandboxbackend.BackendE2B}, false, false, true, ChContent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := base(t, sandboxbackend.BackendDaytona)
			in.Facts = map[string]Fact{tc.prereq: {Present: true}}
			in.Records = cfgRec(tc.prereq)
			rec := in.Records[tc.prereq]
			rec.Channel = string(tc.channelOf)
			in.Records[tc.prereq] = rec
			if tc.others != nil {
				in.InUseBy = map[string][]string{tc.prereq: tc.others}
			}
			s := stepOf(t, Build(in), tc.prereq)
			if s.State != StateDone {
				t.Fatalf("%s state = %s, want done", tc.prereq, s.State)
			}
			if s.CanUndo != tc.wantUndo {
				t.Errorf("CanUndo = %v, want %v (reason %q)", s.CanUndo, tc.wantUndo, s.Reason)
			}
			if got := s.UndoAlso != ""; got != tc.wantAlso {
				t.Errorf("UndoAlso = %q, want set %v", s.UndoAlso, tc.wantAlso)
			}
			if tc.wantAlso && !strings.Contains(s.UndoAlso, row(t, sandboxbackend.BackendE2B).Label) {
				t.Errorf("UndoAlso %q does not name %s", s.UndoAlso, row(t, sandboxbackend.BackendE2B).Label)
			}
			if got := strings.Contains(s.Reason, "Kept:"); got != tc.wantKept {
				t.Errorf("kept note = %v, want %v (reason %q)", got, tc.wantKept, s.Reason)
			}
			if got := SharedKeptByOthers(in, s); got != tc.wantKept {
				t.Errorf("SharedKeptByOthers = %v, want %v", got, tc.wantKept)
			}
		})
	}
}
