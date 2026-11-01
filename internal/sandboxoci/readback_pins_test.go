package sandboxoci

import (
	"strings"
	"testing"
)

// readback_pins_test.go: the read-back and the plan's pins (Linux live
// re-check on the Docker sandbox 2026-10-23, N1). The create mounts each pin
// (a repository folder or .git bound onto itself) but the read-back left
// the pins out of its planned set, so every oci launch in a git repository
// was refused as "unplanned bind <ws>/.git" on both engines.

// pinCase is one engine's recorded inspect shape with its uid plan.
type pinCase struct {
	name string
	file string
	id   Identity
	user UserPlan
}

var pinCases = []pinCase{
	{"docker", "inspect_docker_v1.44.json", dockerRootful, rootfulUser},
	{"podman", "inspect_podman_libpod_v5.6.json", podmanRootless, UserPlan{Row: "rootless podman, keep-id", User: "1000:1000", UsernsMode: "keep-id", ExpectUIDMap: "1000:0:1"}},
}

// pinPlan is testPlan with the workspace's own .git pinned (inside the
// workspace's read-write bind, the shape cmd/observer's ociPinMounts plans
// for a live workspace that is a repository), plus the pins named.
func pinPlan(c pinCase, extra ...string) CreatePlan {
	p := testPlan(c.user)
	p.Engine = c.id.Engine
	p.Pins = append([]string{"/home/dev/src/app/.git"}, extra...)
	return p
}

// withBinds appends bind mounts to an inspect answer's Mounts.
func withBinds(binds ...map[string]any) func(m map[string]any) {
	return func(m map[string]any) {
		for _, b := range binds {
			m["Mounts"] = append(m["Mounts"].([]any), b)
		}
	}
}

func bindFact(src, dst string, rw bool) map[string]any {
	return map[string]any{"Type": "bind", "Source": src, "Destination": dst, "Mode": "", "RW": rw, "Propagation": "rprivate"}
}

// TestReadBackAcceptsPlannedPins: a plan with a .git pin passes the
// read-back on the recorded Docker and Podman inspect shapes when the
// engine built the pin as planned (a read-write bind of the path onto
// itself).
func TestReadBackAcceptsPlannedPins(t *testing.T) {
	for _, c := range pinCases {
		t.Run(c.name, func(t *testing.T) {
			f, err := ParseInspect(mutate(t, c.file, withBinds(bindFact("/home/dev/src/app/.git", "/home/dev/src/app/.git", true))), c.id.Engine)
			if err != nil {
				t.Fatal(err)
			}
			if v := ReadBack(ReadBackInput{Identity: c.id, Plan: pinPlan(c), Facts: f}); !v.OK() {
				t.Fatalf("a planned .git pin was refused: %v", v)
			}
		})
	}
}

// TestReadBackRefusesPinMismatches: the pins widen the planned set by
// exactly themselves. An unplanned bind beside a planned pin, a .git bound
// with no pin planned, a pin planned read-only (its nearest enclosing mount
// is a read-only bind) that came back writable, a read-write pin that came
// back read-only, a pin from another source and a missing pin each refuse
// at the mounts row, on both engines.
func TestReadBackRefusesPinMismatches(t *testing.T) {
	// /tmp/observer-sbx-<run> is a read-only bind in testPlan, so a pin
	// inside it is planned read-only.
	roPin := "/tmp/observer-sbx-" + testRun + "/.git"
	gitPin := "/home/dev/src/app/.git"
	noPins := func(c pinCase) CreatePlan {
		p := testPlan(c.user)
		p.Engine = c.id.Engine
		return p
	}
	cases := []struct {
		name string
		plan func(c pinCase) CreatePlan
		edit func(m map[string]any)
		want string
	}{
		{
			"unplanned bind beside a pin", func(c pinCase) CreatePlan { return pinPlan(c) },
			withBinds(bindFact(gitPin, gitPin, true), bindFact("/srv/other", "/srv/other", true)), "unplanned bind /srv/other",
		},
		{
			"a .git bound with no pin planned", noPins,
			withBinds(bindFact(gitPin, gitPin, true)), "unplanned bind " + gitPin,
		},
		{
			"read-only pin made writable", func(c pinCase) CreatePlan { return pinPlan(c, roPin) },
			withBinds(bindFact(gitPin, gitPin, true), bindFact(roPin, roPin, true)), "bind at " + roPin + " is writable, planned read-only",
		},
		{
			"read-write pin made read-only", func(c pinCase) CreatePlan { return pinPlan(c) },
			withBinds(bindFact(gitPin, gitPin, false)), "pin at " + gitPin + " is read-only, planned read-write",
		},
		{
			"pin from another source", func(c pinCase) CreatePlan { return pinPlan(c) },
			withBinds(bindFact("/home/dev/evil/.git", gitPin, true)), "comes from /home/dev/evil/.git",
		},
		{
			"pin missing", func(c pinCase) CreatePlan { return pinPlan(c) },
			func(map[string]any) {}, "planned binds are missing: " + gitPin,
		},
	}
	for _, c := range pinCases {
		for _, mc := range cases {
			t.Run(c.name+"/"+mc.name, func(t *testing.T) {
				f, err := ParseInspect(mutate(t, c.file, mc.edit), c.id.Engine)
				if err != nil {
					t.Fatal(err)
				}
				v := ReadBack(ReadBackInput{Identity: c.id, Plan: mc.plan(c), Facts: f})
				if v.Code != VerdictBuiltBelowPlan || !strings.HasPrefix(v.Reason, "mounts:") || !strings.Contains(v.Reason, mc.want) {
					t.Fatalf("verdict %v, want a mounts refusal naming %q", v, mc.want)
				}
			})
		}
	}
}

// TestReadBackPinsRoundTrip: what BuildCreate renders for a pins plan, read
// back as an engine reports it (each mount's ReadOnly as RW), passes on both
// engines: the create and the read-back agree on every pin and its mode.
func TestReadBackPinsRoundTrip(t *testing.T) {
	for _, c := range pinCases {
		t.Run(c.name, func(t *testing.T) {
			p := pinsPlan()
			p.Engine, p.User = c.id.Engine, c.user
			_, body, err := BuildCreate(p)
			if err != nil {
				t.Fatal(err)
			}
			f, err := ParseInspect(mutate(t, c.file, func(m map[string]any) {
				var ms []any
				for _, mt := range body.HostConfig.Mounts {
					ms = append(ms, bindFact(mt.Source, mt.Target, !mt.ReadOnly))
				}
				m["Mounts"] = ms
			}), c.id.Engine)
			if err != nil {
				t.Fatal(err)
			}
			if v := ReadBack(ReadBackInput{Identity: c.id, Plan: p, Facts: f}); !v.OK() {
				t.Fatalf("the create's own pins were refused: %v", v)
			}
		})
	}
}
