package sandboxsetup

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/toolinstall"
)

var (
	hLinux = sandboxbackend.HostLinux
	hWSL2  = sandboxbackend.HostWSL2
	hMac   = sandboxbackend.HostMacOS
	hWin   = sandboxbackend.HostWindows
)

// TestRemedyRows is one row per remedy row of the prerequisite table: on the
// host and family given, remedyFor picks the remedy with this class, channel
// and package. Every prerequisite id appears (TestRemedyRowsCoverTable).
var remedyCases = []struct {
	prereq  string
	kind    Kind
	host    sandboxbackend.HostKind
	family  string
	class   Class
	channel Channel
	pkg     string
	display string // a substring of the remedy's Display ("" to skip)
}{
	{"bwrap", KindProgram, hLinux, FamilyDebian, ClassElevated, ChPM, "bubblewrap", ""},
	{"bwrap", KindProgram, hWSL2, FamilyFedora, ClassGuide, ChNone, "", "bubblewrap package"},
	{"userns", KindKernel, hLinux, FamilyDebian, ClassNever, ChNone, "", "user namespaces"},
	{"landlock-abi", KindKernel, hLinux, "", ClassNever, ChNone, "", "Landlock"},
	{"kvm-device", KindKernel, hWSL2, FamilyDebian, ClassNever, ChNone, "", ".wslconfig"},
	{"kvm-device", KindKernel, hLinux, FamilyDebian, ClassNever, ChNone, "", "firmware"},
	{"kvm-group", KindGroup, hLinux, FamilyArch, ClassNever, ChNone, "", "kvm group"},
	{"cloud-hypervisor", KindProgram, hLinux, FamilyDebian, ClassAuto, ChPinned, "cloud-hypervisor", ""},
	{"virtiofsd", KindProgram, hLinux, FamilyDebian, ClassElevated, ChPM, "virtiofsd", ""},
	{"virtiofsd", KindProgram, hLinux, FamilyAlpine, ClassGuide, ChNone, "", "virtiofsd"},
	{"e2fsprogs", KindProgram, hWSL2, FamilyDebian, ClassElevated, ChPM, "e2fsprogs", ""},
	{"e2fsprogs", KindProgram, hLinux, FamilySUSE, ClassGuide, ChNone, "", "mkfs.ext4"},
	{"vm-image-set", KindContent, hLinux, "", ClassAuto, ChContent, "sandbox.rootfs,sandbox.guest_binary", ""},
	{"container-engine", KindProgram, hLinux, FamilyDebian, ClassElevated, ChPM, "podman", ""},
	{"container-engine", KindProgram, hWSL2, FamilyFedora, ClassGuide, ChNone, "", "Podman or Docker Engine"},
	{"docker-engine", KindProgram, hLinux, FamilyDebian, ClassElevated, ChPM, "docker.io", ""},
	{"docker-engine", KindProgram, hLinux, FamilyArch, ClassGuide, ChNone, "", "Docker Engine"},
	{"engine-socket", KindService, hLinux, FamilyDebian, ClassTerminal, ChCommand, "", "podman.socket"},
	{"docker-group", KindGroup, hLinux, FamilyDebian, ClassNever, ChNone, "", "docker group"},
	{"oci-allow-rootful", KindConfig, hLinux, FamilyDebian, ClassAuto, ChConfig, "terminal.sandbox.oci.allow_rootful", ""},
	{"oci-image", KindImage, hWSL2, FamilyDebian, ClassTerminal, ChOCIPull, "oci", ""},
	{"runsc", KindProgram, hLinux, FamilyDebian, ClassGuide, ChNone, "", "gVisor"},
	{"runsc-registered", KindService, hLinux, FamilyDebian, ClassElevated, ChCommand, "", "runsc install"},
	{"openshell-pkg", KindProgram, hLinux, FamilyDebian, ClassGuide, ChNone, "", "OpenShell v0.1.6"},
	{"openshell-supervisor", KindService, hLinux, FamilyDebian, ClassGuide, ChNone, "", "systemd user manager"},
	{"macos-12", KindOSVersion, hMac, FamilyMacOS, ClassNever, ChNone, "", "macOS 12"},
	{"macos-sandbox-exec", KindProgram, hMac, FamilyMacOS, ClassNever, ChNone, "", "sandbox-exec"},
	{"macos-26-arm", KindOSVersion, hMac, FamilyMacOS, ClassNever, ChNone, "", "macOS 26"},
	{"apple-container-cli", KindProgram, hMac, FamilyMacOS, ClassGuide, ChNone, "", "github.com/apple/container"},
	{"apple-container-service", KindService, hMac, FamilyMacOS, ClassTerminal, ChCommand, "", "container system start"},
	{"apple-container-image", KindImage, hMac, FamilyMacOS, ClassTerminal, ChCommand, "", "container image pull"},
	{"win-build-psec", KindOSVersion, hWin, FamilyWindows, ClassNever, ChNone, "", "Windows build"},
	{"mxc-files", KindContent, hWin, FamilyWindows, ClassAuto, ChContent, "sandbox.native_files", ""},
	{"hosted-account", KindAccount, hLinux, FamilyDebian, ClassNever, ChNone, "", "account"},
	{"hosted-key", KindCredential, hWSL2, FamilyDebian, ClassAuto, ChHostedKey, "", "API key"},
	{"hosted-custody", KindConfig, hWSL2, FamilyDebian, ClassAuto, ChConfig, "terminal.sandbox.hosted.key_custody", "API key in the box"},
	{"hosted-consent", KindConsent, hLinux, FamilyDebian, ClassAuto, ChConsent, "", "consent"},
	{"orgshell-login", KindAccount, hLinux, FamilyDebian, ClassAuto, ChOrgShell, "", "Sign in"},
}

func TestRemedyRows(t *testing.T) {
	for _, tc := range remedyCases {
		t.Run(tc.prereq+"/"+string(tc.host)+"/"+tc.family, func(t *testing.T) {
			p, ok := Lookup(tc.prereq)
			if !ok {
				t.Fatalf("no prerequisite %q", tc.prereq)
			}
			if p.Kind != tc.kind {
				t.Errorf("kind = %q, want %q", p.Kind, tc.kind)
			}
			r, ok := remedyFor(p, tc.host, tc.family)
			if !ok {
				t.Fatal("no remedy")
			}
			if r.Class != tc.class || r.Channel != tc.channel || r.Package != tc.pkg {
				t.Errorf("remedy = (%s, %s, %q), want (%s, %s, %q)", r.Class, r.Channel, r.Package, tc.class, tc.channel, tc.pkg)
			}
			if tc.display != "" && !strings.Contains(r.Display, tc.display) {
				t.Errorf("display %q lacks %q", r.Display, tc.display)
			}
		})
	}
}

// TestRemedyRowsCoverTable: one test row exists per prerequisite, and per
// remedy row (each remedy is reached by some case).
func TestRemedyRowsCoverTable(t *testing.T) {
	reached := map[string]map[int]bool{}
	for _, tc := range remedyCases {
		p, _ := Lookup(tc.prereq)
		for i, r := range p.Remedies {
			if got, ok := remedyFor(p, tc.host, tc.family); ok && sameRemedy(got, r) {
				if reached[tc.prereq] == nil {
					reached[tc.prereq] = map[int]bool{}
				}
				reached[tc.prereq][i] = true
				break
			}
		}
	}
	for _, p := range prereqTable {
		for i := range p.Remedies {
			if !reached[p.ID][i] {
				t.Errorf("%s remedy %d has no test row", p.ID, i)
			}
		}
	}
}

func sameRemedy(a, b Remedy) bool {
	return a.Class == b.Class && a.Channel == b.Channel && a.Package == b.Package && a.Display == b.Display && a.Family == b.Family
}

// TestPrereqTableShape: ids unique and not the generic ids, every row with a
// kind, a label and a remedy, Shared exactly when two or more rows list it,
// DriverBinary only on a prerequisite exactly one row lists, and every row
// used by some registry row.
func TestPrereqTableShape(t *testing.T) {
	users := map[string][]string{}
	for _, c := range sandboxbackend.Offered() {
		for _, id := range c.Setup {
			users[id] = append(users[id], c.ID)
		}
	}
	seen := map[string]bool{}
	for _, p := range prereqTable {
		if seen[p.ID] || p.ID == PrereqComponent || p.ID == PrereqEnable || p.ID == "" {
			t.Errorf("prerequisite id %q duplicated, empty or generic", p.ID)
		}
		seen[p.ID] = true
		if p.Kind == "" || p.Label == "" || len(p.Remedies) == 0 {
			t.Errorf("%s: kind, label and a remedy are required", p.ID)
		}
		if p.Kind == KindComponent || p.Kind == KindEnable {
			t.Errorf("%s: the component and enable kinds are the generic steps'", p.ID)
		}
		n := len(users[p.ID])
		if n == 0 {
			t.Errorf("%s: no registry row lists it", p.ID)
		}
		if p.Shared != (n > 1) {
			t.Errorf("%s: Shared = %v, but %d rows list it (%v)", p.ID, p.Shared, n, users[p.ID])
		}
		if p.Detect.DriverBinary && n != 1 {
			t.Errorf("%s: DriverBinary on a prerequisite %d rows list", p.ID, n)
		}
	}
	bw, _ := sandboxbackend.Get(sandboxbackend.BackendBwrap)
	if p, _ := Lookup("bwrap"); p.Detect.MinVersion != bw.Control.Pins.RequiredMin {
		t.Errorf("bwrap MinVersion %q, the bwrap row requires %q", p.Detect.MinVersion, bw.Control.Pins.RequiredMin)
	}
	if len(IDs()) != len(prereqTable) {
		t.Errorf("IDs() = %d ids, table %d", len(IDs()), len(prereqTable))
	}
}

// TestEveryOfferedRowHasSetupOrReason is the registry coverage test (plan
// section 10): every offered row lists only ids this table holds, or states
// why setup is not offered; on each host it runs on, every prerequisite it
// lists has a remedy (the family-less row is the fallback).
func TestEveryOfferedRowHasSetupOrReason(t *testing.T) {
	for _, c := range sandboxbackend.Offered() {
		if len(c.Setup) == 0 && c.SetupUnavailable == "" {
			t.Errorf("%s: offered with no Setup list and no stated reason", c.ID)
		}
		for _, id := range c.Setup {
			p, ok := index[id]
			if !ok {
				t.Errorf("%s: Setup id %q is not in the prerequisite table", c.ID, id)
				continue
			}
			for _, h := range c.Iso.Hosts {
				if _, ok := remedyFor(p, h, ""); !ok {
					t.Errorf("%s on %s: prerequisite %s has no remedy for an unknown family", c.ID, h, id)
				}
			}
		}
	}
}

// validChannels is which channels each class may use.
var validChannels = map[Class]map[Channel]bool{
	ClassAuto:     {ChComponent: true, ChEnable: true, ChConfig: true, ChPinned: true, ChContent: true, ChHostedKey: true, ChConsent: true, ChOrgShell: true},
	ClassTerminal: {ChPM: true, ChCommand: true, ChOCIPull: true},
	ClassElevated: {ChPM: true, ChCommand: true},
	ClassGuide:    {ChNone: true},
	ClassNever:    {ChNone: true},
}

// TestRemedyCoverage is the remedy half of plan section 10: no never (or
// guide) remedy has a channel other than none; each class uses only its
// channels; every pm remedy's package resolves to a toolinstall channel row
// with a derived uninstall for the family it names; every pinned remedy
// names a pin id; a command remedy carries its constant argv and no other
// remedy does.
func TestRemedyCoverage(t *testing.T) {
	all := append([]Prereq(nil), prereqTable...)
	for _, g := range genericPrereqs {
		all = append(all, g)
	}
	for _, p := range all {
		for i, r := range p.Remedies {
			where := p.ID + " remedy " + string(rune('0'+i))
			if !validChannels[r.Class][r.Channel] {
				t.Errorf("%s: class %s may not use channel %s", where, r.Class, r.Channel)
			}
			if (r.Class == ClassNever || r.Class == ClassGuide) && r.Channel != ChNone {
				t.Errorf("%s: a %s remedy has channel %s", where, r.Class, r.Channel)
			}
			if r.Class == ClassGuide || r.Class == ClassNever {
				if r.Display == "" || r.Docs == "" {
					t.Errorf("%s: a %s remedy needs its words and a docs link", where, r.Class)
				}
			}
			if r.Docs != "" && !strings.Contains(r.Docs, ".md#") {
				t.Errorf("%s: docs %q is not a doc anchor", where, r.Docs)
			}
			switch r.Channel {
			case ChPM:
				if r.Family == "" {
					t.Errorf("%s: a pm remedy names its family", where)
				}
				pm, ok := pmForFamily(r.Family)
				if !ok {
					t.Errorf("%s: family %q has no package manager", where, r.Family)
					break
				}
				ch, argv, ok := toolinstall.InstallArgvFor(pm, []string{r.Package})
				if !ok || !toolinstall.HasDefinedUninstall(ch) {
					t.Errorf("%s: %s package %q has no toolinstall channel row with a derived uninstall", where, pm.Name, r.Package)
					break
				}
				if _, err := toolinstall.PlanUninstall(ch, argv); err != nil {
					t.Errorf("%s: uninstall of %q: %v", where, argv, err)
				}
				if toolinstall.ElevatedChannel(ch) != (r.Class == ClassElevated) {
					t.Errorf("%s: class %s, channel %s elevated %v", where, r.Class, ch, toolinstall.ElevatedChannel(ch))
				}
			case ChPinned:
				if r.Package == "" {
					t.Errorf("%s: a pinned remedy names its pin id", where)
				}
			case ChCommand:
				if len(r.Argv) == 0 {
					t.Errorf("%s: a command remedy carries its argv", where)
				}
				if (r.Class == ClassElevated) != (r.Argv[0] == "sudo") {
					t.Errorf("%s: class %s with argv %q", where, r.Class, r.Argv)
				}
			case ChContent:
				if r.Package == "" {
					t.Errorf("%s: a content remedy names its kinds", where)
				}
			}
			if r.Channel != ChCommand && r.Argv != nil {
				t.Errorf("%s: only a command remedy carries an argv", where)
			}
		}
	}
}

// TestFamilyFor is one row per family key.
func TestFamilyFor(t *testing.T) {
	pm := func(n string) toolinstall.PackageManager {
		p, _ := toolinstall.PackageManagerByName(n)
		return p
	}
	cases := []struct {
		goos string
		pm   toolinstall.PackageManager
		want string
	}{
		{"linux", pm("apt"), FamilyDebian},
		{"linux", pm("dnf"), FamilyFedora},
		{"linux", pm("pacman"), FamilyArch},
		{"linux", pm("zypper"), FamilySUSE},
		{"linux", pm("apk"), FamilyAlpine},
		{"darwin", pm("brew"), FamilyMacOS},
		{"windows", toolinstall.PackageManager{}, FamilyWindows},
		{"linux", toolinstall.PackageManager{}, ""},
	}
	for _, tc := range cases {
		if got := FamilyFor(tc.goos, tc.pm); got != tc.want {
			t.Errorf("FamilyFor(%s, %q) = %q, want %q", tc.goos, tc.pm.Name, got, tc.want)
		}
		if tc.want != "" && tc.want != FamilyWindows {
			if got, ok := pmForFamily(tc.want); !ok || got.Name != tc.pm.Name {
				t.Errorf("pmForFamily(%s) = %q, %v", tc.want, got.Name, ok)
			}
		}
	}
	if _, ok := pmForFamily(FamilyWindows); ok {
		t.Error("windows has no package manager")
	}
}
