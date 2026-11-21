package sandboxsetup

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
)

// TestDisplayIsCommand: a step's display is a command a person can paste
// only when the planner derived it from an argv (a package-manager install, a
// remedy's constant argv, a command whose argument came from a set config
// key); a sentence is never offered as a command (the dashboard's "Copy
// command" copied prose before this flag).
func TestDisplayIsCommand(t *testing.T) {
	const image = "ghcr.io/example/box@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cases := []struct {
		name    string
		backend string
		host    sandboxbackend.HostKind
		family  string
		tweak   func(*PlanInput)
		prereq  string
		want    bool
	}{
		{"pm install on a known family", sandboxbackend.BackendBwrap, sandboxbackend.HostLinux, FamilyDebian, nil, "bwrap", true},
		{"pm install degraded to a guide keeps its command", sandboxbackend.BackendBwrap, sandboxbackend.HostLinux, FamilyDebian, func(in *PlanInput) { in.AllowElevated = false }, "bwrap", true},
		{"prose guide on an unknown family", sandboxbackend.BackendBwrap, sandboxbackend.HostLinux, FamilyFedora, nil, "bwrap", false},
		{"constant command", sandboxbackend.BackendOCIRunc, sandboxbackend.HostLinux, FamilyDebian, nil, "engine-socket", true},
		{"constant command under the kill switch", sandboxbackend.BackendOCIRunc, sandboxbackend.HostLinux, FamilyDebian, func(in *PlanInput) { in.AllowInstall = false }, "engine-socket", true},
		{"elevated constant command with elevation off", sandboxbackend.BackendOCIRunsc, sandboxbackend.HostLinux, FamilyDebian, func(in *PlanInput) { in.AllowElevated = false }, "runsc-registered", true},
		{"command whose argument key is unset", sandboxbackend.BackendAppleContainer, sandboxbackend.HostMacOS, FamilyMacOS, nil, "apple-container-image", false},
		{"command whose argument key is set", sandboxbackend.BackendAppleContainer, sandboxbackend.HostMacOS, FamilyMacOS, func(in *PlanInput) {
			in.ArgValues = map[string]string{"terminal.sandbox.apple_container.image": image}
		}, "apple-container-image", true},
		{"oci pull is a sentence", sandboxbackend.BackendOCIRunc, sandboxbackend.HostLinux, FamilyDebian, nil, "oci-image", false},
		{"hosted key is a sentence", sandboxbackend.BackendE2B, sandboxbackend.HostLinux, FamilyDebian, nil, "hosted-key", false},
		{"component is a sentence", sandboxbackend.BackendBwrap, sandboxbackend.HostLinux, FamilyDebian, nil, PrereqComponent, false},
		{"enable is a sentence", sandboxbackend.BackendBwrap, sandboxbackend.HostLinux, FamilyDebian, nil, PrereqEnable, false},
		{"never step", sandboxbackend.BackendBwrap, sandboxbackend.HostLinux, FamilyDebian, nil, "userns", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := base(t, tc.backend)
			in.Host, in.Family = tc.host, tc.family
			if tc.tweak != nil {
				tc.tweak(&in)
			}
			st := stepOf(t, Build(in), tc.prereq)
			if st.DisplayIsCommand != tc.want {
				t.Errorf("%s: DisplayIsCommand = %v, want %v (class %s, display %q)", tc.prereq, st.DisplayIsCommand, tc.want, st.Class, st.Display)
			}
			if st.DisplayIsCommand && st.Display == "" {
				t.Errorf("%s: a command flag on an empty display", tc.prereq)
			}
		})
	}
}
