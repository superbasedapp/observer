package extrun

import (
	"context"
	"reflect"
	"testing"
)

func TestContainmentRungs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		f    ContainmentFacts
		want []Rung
	}{
		{"windows: the job object first", ContainmentFacts{JobObject: true}, []Rung{RungJobObject, RungProcess}},
		{
			"linux with every mechanism: cgroup, then pid namespace, then the group",
			ContainmentFacts{Cgroup: true, PIDNamespace: true, ProcessGroup: true},
			[]Rung{RungCgroup, RungPIDNamespace, RungProcessGroup, RungProcess},
		},
		{"linux with isolation only", ContainmentFacts{PIDNamespace: true, ProcessGroup: true}, []Rung{RungPIDNamespace, RungProcessGroup, RungProcess}},
		{"macOS: the group only", ContainmentFacts{ProcessGroup: true}, []Rung{RungProcessGroup, RungProcess}},
		{"nothing at all", ContainmentFacts{}, []Rung{RungProcess}},
	}
	for _, tc := range cases {
		if got := ContainmentRungs(tc.f); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestRungContained(t *testing.T) {
	t.Parallel()
	for r, want := range map[Rung]bool{
		RungJobObject: true, RungCgroup: true, RungPIDNamespace: true,
		RungProcessGroup: false, RungProcess: false, Rung("chroot"): false,
	} {
		got, label := RungContained(r)
		if got != want || label == "" {
			t.Errorf("%s: contained %v (%q), want %v", r, got, label, want)
		}
		if !want && label[:14] != "not contained " {
			t.Errorf("%s: label %q must say not contained", r, label)
		}
	}
}

func TestContainmentLabelClaimsOnlyWhatWasDone(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		c         Containment
		contained bool
		label     string
	}{
		{"group kill without a supervisor", Containment{Rung: RungProcessGroup}, false, "not contained (process group kill only, no sweep)"},
		{"group kill with a supervisor that swept", Containment{Rung: RungProcessGroup, Supervised: true}, false, "not contained (process group kill and subreaper sweep)"},
		{"supervised never changes another rung", Containment{Rung: RungCgroup, Supervised: true}, true, "contained (per-run cgroup v2)"},
		{"the program alone", Containment{Rung: RungProcess}, false, "not contained (the program alone)"},
	}
	for _, tc := range cases {
		contained, label := ContainmentLabel(tc.c)
		if contained != tc.contained || label != tc.label {
			t.Errorf("%s: got %v %q, want %v %q", tc.name, contained, label, tc.contained, tc.label)
		}
	}
}

type namedProvider struct{}

func (namedProvider) Name() string                                 { return "p" }
func (namedProvider) Wrap(_ context.Context, p Plan) (Plan, error) { return p, nil }

type pidnsProvider struct {
	namedProvider
	v bool
}

func (p pidnsProvider) PIDNamespace() bool { return p.v }

func TestWrappedInPIDNamespace(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		prov IsolationProvider
		args []string
		want bool
	}{
		{"bwrap one-shot flags", namedProvider{}, []string{"--unshare-all", "--die-with-parent", "--", "/bin/tool", "--unshare-pid"}, true},
		{"unshare-pid spelled out", namedProvider{}, []string{"--unshare-pid", "--die-with-parent", "--", "/bin/tool"}, true},
		{"no die-with-parent: the namespace can outlive the launcher", namedProvider{}, []string{"--unshare-pid", "--", "/bin/tool"}, false},
		{"flags only after the separator belong to the program", namedProvider{}, []string{"--", "/bin/tool", "--unshare-pid", "--die-with-parent"}, false},
		{"a provider that says yes", pidnsProvider{v: true}, nil, true},
		{"a provider that says no wins over its argv", pidnsProvider{v: false}, []string{"--unshare-pid", "--die-with-parent"}, false},
	}
	for _, tc := range cases {
		if got := WrappedInPIDNamespace(tc.prov, Plan{Args: tc.args}); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
