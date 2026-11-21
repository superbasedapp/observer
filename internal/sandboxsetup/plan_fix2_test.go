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

// The second live-check fix round (2026-11-07 re-runs): one test per item.

const appleImageRef = "docker.io/library/alpine@sha256:bfe7ceb9f09ec0566c48fb93356e45a47a00be5a1dd14fa5b909e7709c66b034"

// appleBase is a macOS host with Apple's CLI found and the row's module
// selected.
func appleBase(t *testing.T) PlanInput {
	t.Helper()
	in := base(t, sandboxbackend.BackendAppleContainer)
	in.Host, in.Family, in.Arch = sandboxbackend.HostMacOS, FamilyMacOS, "arm64"
	in.Facts = map[string]Fact{"apple-container-cli": {Present: true, Path: "/usr/local/bin/container", Version: "container CLI version 1.6.0"}}
	return in
}

// TestEnabledRowWithCheckOnlyStepsIsUnconfirmed (D-L5b-2, F13b): a passive
// plan of an enabled row whose remaining steps only the check can judge
// (Apple container's service and image, oci-runc's image; terminal class)
// reads unconfirmed with no Next; the same row not enabled yet is not set up
// and names its next step; a missing step is Next on an enabled row too; a
// checked plan is never unconfirmed.
func TestEnabledRowWithCheckOnlyStepsIsUnconfirmed(t *testing.T) {
	oci := base(t, sandboxbackend.BackendOCIRunc)
	oci.Facts = map[string]Fact{
		"container-engine": {Present: true, Path: "/usr/bin/podman"},
		"engine-socket":    {Present: true, Path: "/run/user/1000/podman/podman.sock"},
	}
	apple := appleBase(t)
	apple.ArgValues = map[string]string{"terminal.sandbox.apple_container.image": appleImageRef}
	cases := []struct {
		name string
		in   PlanInput
		// open is the unknown terminal step of the shape.
		open string
	}{
		{"apple container", apple, "apple-container-service"},
		{"oci-runc", oci, "oci-image"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.in
			in.SandboxOn, in.Listed = true, true
			p := Build(in)
			if st := stepOf(t, p, tc.open); st.State != StateUnknown || !runnableClass(st.Class) {
				t.Fatalf("%s = %s %s, want an unknown runnable step", tc.open, st.State, st.Class)
			}
			if p.Next != -1 || !p.Unconfirmed || p.Ready {
				t.Errorf("enabled passive = next %d unconfirmed %v ready %v, want -1 true false", p.Next, p.Unconfirmed, p.Ready)
			}
			// Not enabled yet: genuinely not set up, Next names the step.
			in.Listed = false
			q := Build(in)
			if q.Unconfirmed || q.Next < 0 || q.Steps[q.Next].Prereq != tc.open {
				t.Errorf("not enabled = unconfirmed %v next %d (%v), want next %s", q.Unconfirmed, q.Next, stepIDsOf(q), tc.open)
			}
			// A missing step on an enabled row is still Next.
			in.Listed, in.ComponentSelected = true, false
			if r := Build(in); r.Unconfirmed || r.Next < 0 || r.Steps[r.Next].Prereq != PrereqComponent {
				t.Errorf("missing component = unconfirmed %v next %d, want the component", r.Unconfirmed, r.Next)
			}
			// A checked plan that could not judge a step is not unconfirmed.
			in.ComponentSelected = true
			in.Probe = &sandboxselect.Probe{Verdict: "no_such_verdict", Reason: "the probe failed"}
			if c := Build(in); c.Unconfirmed || c.Ready {
				t.Errorf("checked = unconfirmed %v ready %v, want neither", c.Unconfirmed, c.Ready)
			}
		})
	}
}

// TestAppleImagePullStep (D-L5b-1): with the image key set to a
// digest-pinned reference the step runs `container image pull <ref>` (a
// fixed argv from the config); unset or not by digest, it is a guide that
// names the key, never a step that reads runnable and is then refused.
func TestAppleImagePullStep(t *testing.T) {
	cases := []struct {
		name   string
		value  string
		canRun bool
	}{
		{"configured by digest", appleImageRef, true},
		{"unset", "", false},
		{"a tag, not a digest", "docker.io/library/alpine:3.22", false},
		{"a flag", "--help", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := appleBase(t)
			in.ArgValues = map[string]string{"terminal.sandbox.apple_container.image": tc.value}
			in.Probe = &sandboxselect.Probe{Verdict: "image_missing", Reason: "the image is not present"}
			st := stepOf(t, Build(in), "apple-container-image")
			if st.State != StateMissing || st.CanRun != tc.canRun {
				t.Fatalf("image step = %s canRun %v, want missing canRun %v (%q)", st.State, st.CanRun, tc.canRun, st.Reason)
			}
			if tc.canRun {
				want := []string{"container", "image", "pull", appleImageRef}
				if st.Class != ClassTerminal || st.Channel != ChCommand || !reflect.DeepEqual(st.Argv, want) {
					t.Errorf("runnable step = %s %s %v, want terminal terminal_cmd %v", st.Class, st.Channel, st.Argv, want)
				}
				if st.Display != "container image pull "+appleImageRef {
					t.Errorf("display = %q", st.Display)
				}
				return
			}
			if st.Class != ClassGuide || st.Channel != ChNone || st.Argv != nil {
				t.Errorf("guide step = %s %s %v", st.Class, st.Channel, st.Argv)
			}
			if !strings.Contains(st.Reason, "[terminal.sandbox.apple_container].image") {
				t.Errorf("guide reason %q does not name the key", st.Reason)
			}
		})
	}
}

// TestUndoRefusals (F9b): a refusal row (live runs, an unanswered daemon,
// a switch) names itself and its sentence only on a step whose undo would
// otherwise be offered; on a step with nothing to undo it says nothing.
func TestUndoRefusals(t *testing.T) {
	apt := map[string]Record{"bwrap": {ID: 7, Status: toolinstall.StatusInstalled, Channel: "apt", StartedAt: time.Unix(1, 0), Elevated: true}}
	done := map[string]Fact{"bwrap": {Present: true, Version: "0.9.0"}}
	cases := []struct {
		name    string
		edit    func(in *PlanInput)
		step    string
		refused string
		note    string
	}{
		{"live run on enable", func(in *PlanInput) { in.SandboxOn, in.Listed, in.LiveRuns = true, true, 1 }, PrereqEnable, UndoRefusedLiveRuns, "1 live sandboxed run(s) use this backend"},
		{"unanswered daemon on enable", func(in *PlanInput) { in.SandboxOn, in.Listed, in.LiveRunsUnknown = true, true, true }, PrereqEnable, UndoRefusedLiveRunsUnknown, "could not ask the running daemon"},
		{"kill switch on enable", func(in *PlanInput) { in.SandboxOn, in.Listed, in.AllowInstall = true, true, false }, PrereqEnable, UndoRefusedKillSwitch, "allow_install"},
		{"elevation off on a package", func(in *PlanInput) { in.Facts, in.Records, in.AllowElevated = done, apt, false }, "bwrap", UndoRefusedElevationOff, "allow_elevated"},
		{"live run and kill switch: the first refusal names it", func(in *PlanInput) {
			in.SandboxOn, in.Listed, in.LiveRuns, in.AllowInstall = true, true, 2, false
		}, PrereqEnable, UndoRefusedLiveRuns, "2 live sandboxed run(s)"},
		{"live run on a step with nothing to undo", func(in *PlanInput) { in.Facts, in.LiveRuns = done, 1 }, "bwrap", "", ""},
		{"live run on the default backend keeps its own sentence", func(in *PlanInput) {
			in.SandboxOn, in.Listed, in.UnlistRelists, in.LiveRuns = true, true, true, 1
		}, PrereqEnable, "", "This is the default backend"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := base(t, sandboxbackend.BackendBwrap)
			tc.edit(&in)
			st := stepOf(t, Build(in), tc.step)
			if st.CanUndo {
				t.Fatal("CanUndo = true, want false")
			}
			if st.UndoRefused != tc.refused {
				t.Errorf("UndoRefused = %q, want %q", st.UndoRefused, tc.refused)
			}
			if tc.note == "" && st.UndoNote != "" {
				t.Errorf("UndoNote = %q, want none", st.UndoNote)
			}
			if tc.note != "" && !strings.Contains(st.UndoNote, tc.note) {
				t.Errorf("UndoNote = %q, want it to hold %q", st.UndoNote, tc.note)
			}
		})
	}
}

// TestEngineSocketShapes (F15, F17, F18): each socket shape the oci probe
// answers with lands on the step it is about.
func TestEngineSocketShapes(t *testing.T) {
	engineFacts := map[string]Fact{
		"container-engine": {Present: true, Path: "/usr/bin/podman"},
		"engine-socket":    {Present: true, Path: "/run/user/1000/podman/podman.sock"},
		"docker-engine":    {Present: true, Path: "/usr/bin/docker"},
	}
	cases := []struct {
		name, backend, verdict, reason string
		step                           string
		state                          StepState
		// reasonHas is a substring of the step's reason.
		reasonHas string
		done      []string
		notDone   []string
	}{
		{
			"F15 docker socket the user cannot open", sandboxbackend.BackendOCIRunc, "socket_untrusted",
			"the rootful engine socket /run/docker.sock is not group read-write for a group you are in",
			"docker-group", StateBlocked, "not group read-write",
			[]string{"container-engine", "engine-socket"},
			nil,
		},
		{
			"F15 on oci-runsc", sandboxbackend.BackendOCIRunsc, "socket_untrusted",
			"the rootful engine socket /run/docker.sock is not group read-write for a group you are in",
			"docker-group", StateBlocked, "not group read-write",
			[]string{"docker-engine"},
			nil,
		},
		{
			"oci-runsc rootful socket with allow_rootful off", sandboxbackend.BackendOCIRunsc, "socket_untrusted",
			"the engine socket /run/docker.sock belongs to root: a rootful engine socket is root-equivalent; set [terminal.sandbox.oci].allow_rootful = true to use it, or run rootless Docker or Podman",
			"oci-allow-rootful", StateMissing, "allow_rootful", nil, nil,
		},
		{
			"F17 stale socket file on oci-runc", sandboxbackend.BackendOCIRunc, "engine_unreachable",
			"the engine on /run/user/1000/podman/podman.sock did not answer: dial unix /run/user/1000/podman/podman.sock: connect: connection refused",
			"engine-socket", StateMissing, "did not answer",
			[]string{"container-engine"},
			nil,
		},
		{
			"F17 stale socket file on oci-runsc", sandboxbackend.BackendOCIRunsc, "engine_unreachable",
			"the engine on /run/docker.sock did not answer: dial unix /run/docker.sock: connect: connection refused",
			"runsc-registered", StateUnknown, "it stopped at: the engine on /run/docker.sock did not answer",
			[]string{"docker-engine"},
			nil,
		},
		{
			// Fix round 3: the shape names no step; the docker-group step is
			// judged from Docker's own socket (DockerAccessFact), so with no
			// such fact it shows the check's reason and is never passed.
			"F18 podman socket reached on oci-runsc", sandboxbackend.BackendOCIRunsc, "runtime_missing",
			"the oci-runsc row runs on docker only (its documented integration); this socket is podman",
			"docker-group", StateUnknown, "it stopped at: the oci-runsc row runs on docker only",
			[]string{"docker-engine"},
			[]string{"docker-group"},
		},
		{
			"an unmapped shape keeps the check's reason", sandboxbackend.BackendOCIRunc, "socket_untrusted",
			"the engine socket /run/docker.sock belongs to root: a rootful engine socket is root-equivalent; set [terminal.sandbox.oci].allow_rootful = true to use it",
			"docker-group", StateUnknown, "it stopped at: the engine socket /run/docker.sock belongs to root", nil, nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := base(t, tc.backend)
			in.Facts = engineFacts
			in.Probe = &sandboxselect.Probe{Verdict: tc.verdict, Reason: tc.reason}
			p := Build(in)
			st := stepOf(t, p, tc.step)
			if st.State != tc.state || !strings.Contains(st.Reason, tc.reasonHas) {
				t.Errorf("%s = %s %q, want %s holding %q", tc.step, st.State, st.Reason, tc.state, tc.reasonHas)
			}
			if strings.Contains(st.Reason, reasonNotChecked) {
				t.Errorf("%s reads not checked after a check: %q", tc.step, st.Reason)
			}
			for _, id := range tc.done {
				if s := stepOf(t, p, id); s.State != StateDone {
					t.Errorf("%s = %s, want done", id, s.State)
				}
			}
			for _, id := range tc.notDone {
				if s := stepOf(t, p, id); s.State == StateDone {
					t.Errorf("%s reads done", id)
				}
			}
			for _, engine := range []string{"container-engine", "docker-engine"} {
				if s, ok := stepOfOK(p, engine); ok && s.State != StateDone {
					t.Errorf("%s = %s %q: a socket shape must not send the plan back to the engine's install", engine, s.State, s.Reason)
				}
			}
		})
	}
}

func stepOfOK(p Plan, id string) (Step, bool) {
	for _, s := range p.Steps {
		if s.Prereq == id {
			return s, true
		}
	}
	return Step{}, false
}
