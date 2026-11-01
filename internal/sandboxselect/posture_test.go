package sandboxselect

import (
	"errors"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/postureop"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// postureTestEnv stands in a strong VM row beside the shipped bwrap row, so
// the boundary cases can show a first survivor that is weaker than the
// local first choice (no such row is offered in this build yet).
func postureTestEnv() PostureEnv {
	vm := sandboxbackend.Capability{
		ID: "test-vm", Label: "test VM", Maturity: sandboxbackend.MaturityPreview,
		Verification: []sandboxbackend.Verified{{Host: sandboxbackend.HostLinux, Kind: vocab.VerifiedLive}},
		Iso: sandboxbackend.Isolation{
			Class: vocab.ClassHWVM, ClassSource: vocab.SourceMeasured, Location: vocab.LocationLocal,
			Hosts: []sandboxbackend.HostKind{sandboxbackend.HostLinux},
		},
		Net:     sandboxbackend.Network{Egress: []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly}},
		Capture: sandboxbackend.Capture{Ceiling: vocab.CaptureFull, HookPath: sandboxbackend.HookRelay},
	}
	claimed := vm
	claimed.ID, claimed.Iso.ClassSource = "test-claimed", vocab.SourceClaimed
	return PostureEnv{
		Host: sandboxbackend.HostLinux,
		Row: func(id string) (sandboxbackend.Capability, bool) {
			switch id {
			case vm.ID:
				return vm, true
			case claimed.ID:
				return claimed, true
			}
			return sandboxbackend.Get(id)
		},
	}
}

func baseSettings() PostureSettings {
	return PostureSettings{Enabled: true, Backends: []string{"test-vm", sandboxbackend.BackendBwrap}, HomeMode: "tmpfs"}
}

// pinAfter applies one list pin with the core operator, the way the config
// overlay does, and records a skip where the overlay would skip.
func pinAfter(t *testing.T, before PostureSettings, key string, dir postureop.Direction, org []string) (PostureSettings, map[string]string) {
	t.Helper()
	after := before
	var local []string
	switch key {
	case "terminal.sandbox.backends":
		local = before.Backends
	case "terminal.sandbox.remote_allowed_hosts":
		local = before.RemoteAllowedHosts
	case "terminal.sandbox.mask_paths":
		local = before.MaskPaths
	}
	merged, err := postureop.Merge(dir, local, org)
	if err == nil && dir == postureop.DirOrderedFilter && len(merged.([]string)) == 0 { //nolint:forcetypeassert // list operator
		err = postureop.ErrEmptyIntersection
	}
	// An emptied list applies what plan 10.1 says (the overlay's
	// governanceEmptied rows): no backend, or no remote host.
	if errors.Is(err, postureop.ErrEmptyIntersection) && key == "terminal.sandbox.backends" {
		after.Backends = nil
		return after, nil
	}
	if errors.Is(err, postureop.ErrEmptyIntersection) && key == "terminal.sandbox.remote_allowed_hosts" {
		after.AllowRemoteClone = false
		return after, nil
	}
	if err != nil {
		return before, map[string]string{key: err.Error()}
	}
	l := merged.([]string) //nolint:forcetypeassert // list operator
	switch key {
	case "terminal.sandbox.backends":
		after.Backends = l
	case "terminal.sandbox.remote_allowed_hosts":
		after.RemoteAllowedHosts = l
	case "terminal.sandbox.mask_paths":
		after.MaskPaths = l
	}
	return after, nil
}

// TestPinPostureBoundaries is one boundary row per operator (sandbox plan v2
// section 13 P1b acceptance) plus the A13 case.
func TestPinPostureBoundaries(t *testing.T) {
	env := postureTestEnv()
	type row struct {
		name      string
		before    PostureSettings
		key       string
		dir       postureop.Direction
		org       []string
		wantAxis  string // "" = the pins apply
		wantSkips bool
	}
	withHosts := baseSettings()
	withHosts.RemoteAllowedHosts = []string{"git.example", "github.com"}
	withHostsCloning := withHosts
	withHostsCloning.AllowRemoteClone = true
	disabled := baseSettings()
	disabled.Enabled = false
	rows := []row{
		{
			name:   "ordered filter: removing the first preference leaves a weaker first survivor (A13)",
			before: baseSettings(), key: "terminal.sandbox.backends", dir: postureop.DirOrderedFilter,
			org: []string{sandboxbackend.BackendBwrap}, wantAxis: AxisAutoClass,
		},
		{
			name:   "ordered filter: removing a later entry is a tightening",
			before: baseSettings(), key: "terminal.sandbox.backends", dir: postureop.DirOrderedFilter,
			org: []string{"test-vm"},
		},
		{
			name:   "ordered filter: disjoint lists enable no backend, refused as a weaker auto class",
			before: baseSettings(), key: "terminal.sandbox.backends", dir: postureop.DirOrderedFilter,
			org: []string{"oci-runc"}, wantAxis: AxisAutoClass,
		},
		{
			name:   "ordered filter: removing every entry enables no backend, refused as a weaker auto class",
			before: baseSettings(), key: "terminal.sandbox.backends", dir: postureop.DirOrderedFilter,
			org: []string{"seatbelt"}, wantAxis: AxisAutoClass,
		},
		{
			name:   "ordered filter on a node with the sandbox off changes nothing it runs",
			before: disabled, key: "terminal.sandbox.backends", dir: postureop.DirOrderedFilter,
			org: []string{sandboxbackend.BackendBwrap},
		},
		{
			name:   "set intersection: an empty intersection allows no host (remote clone off), never read as any (A13)",
			before: withHostsCloning, key: "terminal.sandbox.remote_allowed_hosts", dir: postureop.DirSetIntersection,
			org: []string{"evil.example"},
		},
		{
			name:   "set intersection: a shared host narrows",
			before: withHosts, key: "terminal.sandbox.remote_allowed_hosts", dir: postureop.DirSetIntersection,
			org: []string{"github.com", "evil.example"},
		},
		{
			name:   "set intersection: an empty local list (any) narrows to the org list",
			before: baseSettings(), key: "terminal.sandbox.remote_allowed_hosts", dir: postureop.DirSetIntersection,
			org: []string{"github.com"},
		},
		{
			name:   "additive mask only hides more",
			before: baseSettings(), key: "terminal.sandbox.mask_paths", dir: postureop.DirAdditiveMask,
			org: []string{"/mnt/c"},
		},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			after, skips := pinAfter(t, r.before, r.key, r.dir, r.org)
			if (len(skips) > 0) != r.wantSkips {
				t.Fatalf("skips %v, want skips=%v", skips, r.wantSkips)
			}
			axis, err := CheckPinPosture(PinPostureInput{Before: r.before, After: after, Env: env})
			if axis != r.wantAxis || (r.wantAxis != "") != (err != nil) {
				t.Fatalf("axis %q err %v, want axis %q", axis, err, r.wantAxis)
			}
		})
	}
}

// TestRetentionPosture: retention 0 (forever) against a positive pin stays
// forever, a pin lengthens a finite value, and a shorter result is refused,
// so no pin can make the sweep delete a workspace (returned or not) earlier
// than the node's own setting.
func TestRetentionPosture(t *testing.T) {
	env := postureTestEnv()
	cases := []struct {
		name          string
		local, pin    int64
		forceAfter    int64
		useForce      bool
		wantAxis      string
		wantRetention int64
	}{
		{name: "0 against a positive pin stays forever", local: 0, pin: 30, wantRetention: 0},
		{name: "a pin lengthens", local: 7, pin: 30, wantRetention: 30},
		{name: "a shorter pin keeps the node's own", local: 90, pin: 30, wantRetention: 90},
		{name: "a result shorter than forever is refused", local: 0, useForce: true, forceAfter: 30, wantAxis: AxisRetention},
		{name: "a shortened finite result is refused", local: 90, useForce: true, forceAfter: 30, wantAxis: AxisRetention},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := baseSettings()
			before.RetentionDays = tc.local
			after := before
			if tc.useForce {
				after.RetentionDays = tc.forceAfter
			} else {
				after.RetentionDays = postureop.RaiseRetention(tc.local, tc.pin)
				if after.RetentionDays != tc.wantRetention {
					t.Fatalf("retention %d, want %d", after.RetentionDays, tc.wantRetention)
				}
			}
			axis, _ := CheckPinPosture(PinPostureInput{Before: before, After: after, Env: env})
			if axis != tc.wantAxis {
				t.Fatalf("axis %q, want %q", axis, tc.wantAxis)
			}
		})
	}
}

// TestPostureSwitchesAndClaimedClass: a restrictive-only switch can only
// tighten, an expanding one turned on is refused, and a claimed class
// counts as none.
func TestPostureSwitchesAndClaimedClass(t *testing.T) {
	env := postureTestEnv()
	before := baseSettings()
	before.AllowRemoteClone = true
	after := before
	after.AllowRemoteClone = false
	if axis, _ := CheckPinPosture(PinPostureInput{Before: before, After: after, Env: env}); axis != "" {
		t.Fatalf("turning remote clone off refused on %q", axis)
	}
	if axis, _ := CheckPinPosture(PinPostureInput{Before: after, After: before, Env: env}); axis != AxisRemoteClone {
		t.Fatalf("turning remote clone on: axis %q", axis)
	}
	claimed := PostureSettings{Enabled: true, Backends: []string{"test-claimed"}}
	if got := EvaluatePosture(claimed, env)[AxisAutoClass].S; got != string(vocab.ClassNone) {
		t.Fatalf("a claimed hw_vm row counts as %q, want none", got)
	}
	bw := PostureSettings{Enabled: true, Backends: []string{sandboxbackend.BackendBwrap}}
	if got := EvaluatePosture(bw, PostureEnv{Host: sandboxbackend.HostMacOS})[AxisAutoClass].S; got != string(vocab.ClassNone) {
		t.Fatalf("bwrap on macOS counts as %q, want none (it does not run there)", got)
	}
	if got := EvaluatePosture(bw, PostureEnv{Host: sandboxbackend.HostWSL2})[AxisAutoClass].S; got != string(vocab.ClassProcess) {
		t.Fatalf("bwrap on WSL2 counts as %q, want process", got)
	}
}

// TestPostureEnumReview: every enum value of a sandbox setting has a place on
// its axis (a value added without a direction review fails here).
func TestPostureEnumReview(t *testing.T) {
	if bad := postureop.ReviewEnums(PostureEnumKeys(), PostureAxes); len(bad) > 0 {
		t.Fatalf("enum values without a place on their axis:\n%s", strings.Join(bad, "\n"))
	}
}

// TestEnginePrivilegeFollowsThePick: the engine privilege axis is the picked
// row's (SBX-P3A merge finding F4): an engine-driven row with a rootful
// engine allowed reads rootful, the same row without it and bwrap read
// rootless, and turning allow_rootful on through a pin is a loosening.
func TestEnginePrivilegeFollowsThePick(t *testing.T) {
	oci, ok := sandboxbackend.Get(sandboxbackend.BackendOCIRunc)
	if !ok || oci.Control.Interface != sandboxbackend.InterfaceEngineAPIUDS {
		t.Fatalf("the oci-runc row is not engine-driven: %+v", oci.Control)
	}
	env := PostureEnv{Host: sandboxbackend.HostLinux}
	for _, c := range []struct {
		name     string
		backends []string
		rootful  bool
		want     string
	}{
		{"oci-runc, rootful allowed", []string{sandboxbackend.BackendOCIRunc, sandboxbackend.BackendBwrap}, true, "rootful"},
		{"oci-runc, rootless only", []string{sandboxbackend.BackendOCIRunc}, false, "rootless"},
		{"bwrap, rootful allowed", []string{sandboxbackend.BackendBwrap, sandboxbackend.BackendOCIRunc}, true, "rootless"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := PostureSettings{Enabled: true, Backends: c.backends, HomeMode: "tmpfs", RootfulEngineAllowed: c.rootful}
			if got := EvaluatePosture(s, env)[AxisEnginePrivilege].S; got != c.want {
				t.Fatalf("engine privilege %q, want %q", got, c.want)
			}
		})
	}
	off := PostureSettings{Enabled: false, Backends: []string{sandboxbackend.BackendOCIRunc}, RootfulEngineAllowed: true}
	if got := EvaluatePosture(off, env)[AxisEnginePrivilege].S; got != "rootless" {
		t.Fatalf("no pick reads %q", got)
	}
	// A driver this build does not compile is never the pick.
	notCompiled := PostureEnv{Host: sandboxbackend.HostLinux, Compiled: func(id string) bool { return id == sandboxbackend.BackendBwrap }}
	s := PostureSettings{Enabled: true, Backends: []string{sandboxbackend.BackendOCIRunc, sandboxbackend.BackendBwrap}, RootfulEngineAllowed: true}
	if got := EvaluatePosture(s, notCompiled)[AxisEnginePrivilege].S; got != "rootless" {
		t.Fatalf("an uncompiled driver set the engine privilege: %q", got)
	}
	before := PostureSettings{Enabled: true, Backends: []string{sandboxbackend.BackendOCIRunc}, HomeMode: "tmpfs"}
	after := before
	after.RootfulEngineAllowed = true
	axis, _ := CheckPinPosture(PinPostureInput{Before: before, After: after, Env: env})
	if axis != AxisEnginePrivilege {
		t.Fatalf("allowing a rootful engine is not reported as a loosening: %q", axis)
	}
}
