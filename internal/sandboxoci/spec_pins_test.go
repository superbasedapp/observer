package sandboxoci

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var updatePins = flag.Bool("update-pins", false, "rewrite testdata/create_pins.golden")

// pinsPlan is testPlan with an org write bind holding a repository, the
// workspace's own .git, the read-only overlays over each .git's hooks and
// config, and the pins.
func pinsPlan() CreatePlan {
	p := testPlan(rootfulUser)
	p.Binds = append(p.Binds,
		Bind{Source: "/srv/org", Target: "/srv/org"},
		Bind{Source: "/srv/org/a/repo/.git/config", Target: "/srv/org/a/repo/.git/config", ReadOnly: true},
		Bind{Source: "/srv/org/a/repo/.git/hooks", Target: "/srv/org/a/repo/.git/hooks", ReadOnly: true},
		Bind{Source: "/home/dev/src/app/.git/config", Target: "/home/dev/src/app/.git/config", ReadOnly: true},
	)
	p.Pins = []string{"/srv/org/a/repo", "/srv/org/a/repo/.git", "/home/dev/src/app/.git"}
	return p
}

// renderMounts is the golden's text: one mount per line in create order.
func renderMounts(ms []MountSpec) string {
	var b strings.Builder
	for _, m := range ms {
		mode := "rw"
		if m.ReadOnly {
			mode = "ro"
		}
		b.WriteString(m.Target + " <- " + m.Source + " " + mode + "\n")
	}
	return b.String()
}

// TestBuildCreatePinsGolden (lane SHR-FOLLOWUPS, ledger SBX-BE-10): each
// pin is a read-write bind of the path onto itself, mounted after its
// enclosing write bind and before the read-only overlays inside it, so the
// box can neither rename the .git aside nor lose the overlays. The golden
// fails with the pins removed.
func TestBuildCreatePinsGolden(t *testing.T) {
	_, body, err := BuildCreate(pinsPlan())
	if err != nil {
		t.Fatal(err)
	}
	got := renderMounts(body.HostConfig.Mounts)
	golden := filepath.Join("testdata", "create_pins.golden")
	if *updatePins {
		if err := os.WriteFile(golden, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("create mounts differ from %s:\n got:\n%s\nwant:\n%s", golden, got, want)
	}

	noPins := pinsPlan()
	noPins.Pins = nil
	_, body2, err := BuildCreate(noPins)
	if err != nil {
		t.Fatal(err)
	}
	if renderMounts(body2.HostConfig.Mounts) == string(want) {
		t.Fatal("the golden does not depend on the pins")
	}
}

// TestBuildCreateRefusesAPinOutsideAWriteBind: a pin that would make a
// read-only or unbound path writable is refused, as bwrap's plan refuses
// it.
func TestBuildCreateRefusesAPinOutsideAWriteBind(t *testing.T) {
	for _, pin := range []string{"/srv/other/.git", "/home/dev/.local/bin/observer/x", "/srv/org", "relative/.git", "/proc/self"} {
		p := pinsPlan()
		p.Pins = []string{pin}
		if _, _, err := BuildCreate(p); err == nil {
			t.Errorf("pin %s accepted", pin)
		}
	}
}

// TestBuildCreateRefusesAPinUnderANestedReadOnlyBind (lane SHR-FOLLOWUPS
// audit finding 1): a pin whose nearest enclosing mount is a read-only bind,
// a hidden directory or a tmpfs nested inside a write bind is refused, so a
// read-only repository in an org bind never has its .git reopened writable;
// a pin beside it in the write bind still builds.
func TestBuildCreateRefusesAPinUnderANestedReadOnlyBind(t *testing.T) {
	nested := func() CreatePlan {
		p := pinsPlan()
		p.Binds = append(p.Binds, Bind{Source: "/srv/org/vendor", Target: "/srv/org/vendor", ReadOnly: true})
		p.HideDirs = append(p.HideDirs, "/srv/org/secret")
		p.Tmpfs = append(p.Tmpfs, "/srv/org/scratch")
		return p
	}
	for _, pin := range []string{"/srv/org/vendor/lib/.git", "/srv/org/vendor/lib", "/srv/org/secret/repo/.git", "/srv/org/scratch/repo/.git"} {
		p := nested()
		p.Pins = []string{pin}
		_, _, err := BuildCreate(p)
		if err == nil {
			t.Errorf("pin %s under a nested read-only mount accepted", pin)
		} else if !strings.Contains(err.Error(), "read-only bind, a hidden directory or a tmpfs") {
			t.Errorf("pin %s refused for another reason: %v", pin, err)
		}
	}
	p := nested()
	p.Pins = []string{"/srv/org/a/repo/.git", "/srv/org/vendorx/.git"}
	if _, _, err := BuildCreate(p); err != nil {
		t.Fatalf("pins beside the nested read-only mount refused: %v", err)
	}
}
