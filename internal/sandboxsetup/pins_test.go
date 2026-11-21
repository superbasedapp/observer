package sandboxsetup

import (
	"encoding/hex"
	"net/url"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
)

// TestCompiledPinsShape: every grounded pin names one exact asset (a 64-hex
// sha256, a positive size, an https URL with no user info); every owed pin
// carries a version and a URL only, never a digest it did not compute.
func TestCompiledPinsShape(t *testing.T) {
	if len(compiledPins) == 0 {
		t.Fatal("no compiled pins")
	}
	seen := map[string]bool{}
	for _, p := range compiledPins {
		key := p.ID + "/" + p.GOOS + "/" + p.GOARCH
		if seen[key] {
			t.Errorf("duplicate pin %s", key)
		}
		seen[key] = true
		if p.Version == "" || strings.EqualFold(p.Version, "latest") {
			t.Errorf("%s: version %q is not exact", key, p.Version)
		}
		u, err := url.Parse(p.URL)
		if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" || strings.Contains(p.URL, "/latest/") {
			t.Errorf("%s: url %q is not an exact https asset", key, p.URL)
		}
		switch p.Status {
		case PinGrounded:
			if b, err := hex.DecodeString(p.SHA256); err != nil || len(b) != 32 || p.SHA256 != strings.ToLower(p.SHA256) {
				t.Errorf("%s: sha256 %q is not 64 lowercase hex", key, p.SHA256)
			}
			if p.Size <= 0 {
				t.Errorf("%s: size %d", key, p.Size)
			}
		case PinOwed:
			if p.SHA256 != "" || p.Size != 0 {
				t.Errorf("%s: an owed pin carries a digest or size", key)
			}
		default:
			t.Errorf("%s: status %q", key, p.Status)
		}
	}
}

// TestCompiledPinsMatchTheirPrereq: every pin id is the Package of some
// pinned_download remedy, and a pin of a driver binary carries the major
// version its registry row requires.
func TestCompiledPinsMatchTheirPrereq(t *testing.T) {
	named := map[string]bool{}
	for _, id := range IDs() {
		p, _ := Lookup(id)
		for _, r := range p.Remedies {
			if r.Channel == ChPinned {
				named[r.Package] = true
			}
		}
	}
	for _, p := range compiledPins {
		if !named[p.ID] {
			t.Errorf("pin %s is named by no pinned_download remedy", p.ID)
		}
	}
	ch, ok := sandboxbackend.Get(sandboxbackend.BackendCloudHypervisor)
	if !ok {
		t.Fatal("no cloud-hypervisor row")
	}
	min := ch.Control.Pins.RequiredMin
	for _, p := range compiledPins {
		if p.ID == pinCloudHypervisor && strings.SplitN(p.Version, ".", 2)[0] != min {
			t.Errorf("pin %s/%s version %s, the row requires %s", p.GOOS, p.GOARCH, p.Version, min)
		}
	}
}

// TestPinsIsACopy: the exported accessor cannot change the table.
func TestPinsIsACopy(t *testing.T) {
	got := Pins()
	if len(got) != len(compiledPins) {
		t.Fatalf("Pins() has %d rows, want %d", len(got), len(compiledPins))
	}
	got[0].SHA256 = "changed"
	if compiledPins[0].SHA256 == "changed" {
		t.Error("Pins() aliases the table")
	}
}

// TestCompiledPinsLoaded: init put the compiled table where the planner
// reads it.
func TestCompiledPinsLoaded(t *testing.T) {
	for _, p := range compiledPins {
		if got, ok := pinMatching(p.ID, p.GOOS, p.GOARCH); !ok || got != p {
			t.Errorf("pinMatching(%s, %s, %s) = %+v, %v", p.ID, p.GOOS, p.GOARCH, got, ok)
		}
	}
}

// TestPlannerHonoursPinStatus: through Build, the compiled grounded pin
// gives a runnable download with its consent, and the same pin marked owed
// never yields CanRun (it reads as a guide).
func TestPlannerHonoursPinStatus(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run("grounded/"+arch, func(t *testing.T) {
			in := base(t, sandboxbackend.BackendCloudHypervisor)
			in.Arch = arch
			in.Facts = map[string]Fact{pinCloudHypervisor: {Checked: true}}
			s := stepOf(t, Build(in), pinCloudHypervisor)
			p, _ := pinMatching(pinCloudHypervisor, "linux", arch)
			if !s.CanRun || s.Channel != ChPinned || s.Consent == nil || s.Consent.SHA256 != p.SHA256 || s.Consent.Bytes != p.Size {
				t.Errorf("step = %+v", s)
			}
		})
		t.Run("owed/"+arch, func(t *testing.T) {
			var owed []Pin
			for _, p := range compiledPins {
				p.Status, p.SHA256, p.Size = PinOwed, "", 0
				owed = append(owed, p)
			}
			withPins(t, owed...)
			in := base(t, sandboxbackend.BackendCloudHypervisor)
			in.Arch = arch
			in.Facts = map[string]Fact{pinCloudHypervisor: {Checked: true}}
			s := stepOf(t, Build(in), pinCloudHypervisor)
			if s.CanRun || s.Class != ClassGuide || s.Channel != ChNone {
				t.Errorf("owed pin step = %+v", s)
			}
		})
	}
}
