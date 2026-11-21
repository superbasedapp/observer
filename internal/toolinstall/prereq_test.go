package toolinstall

import (
	"reflect"
	"strings"
	"testing"
)

func TestMissingPrereqs(t *testing.T) {
	t.Parallel()
	has := func(present ...string) func(string) bool {
		return func(p string) bool {
			for _, x := range present {
				if x == p {
					return true
				}
			}
			return false
		}
	}
	cases := []struct {
		name     string
		requires []string
		has      func(string) bool
		want     []string
	}{
		{"all present", []string{"curl", "unzip"}, has("curl", "unzip"), nil},
		{"kiro on a box without unzip", []string{"curl", "unzip"}, has("curl", "tar"), []string{"unzip"}},
		{"order kept", []string{"curl", "tar", "bzip2"}, has(), []string{"curl", "tar", "bzip2"}},
		{"alternative satisfied by the second", []string{"sha256sum|shasum"}, has("shasum"), nil},
		{"alternative with none present", []string{"sha256sum|shasum"}, has(), []string{"sha256sum|shasum"}},
		{"blank entries ignored", []string{" ", ""}, has(), nil},
		{"nil lookup never blocks", []string{"unzip"}, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MissingPrereqs(tc.requires, tc.has); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("MissingPrereqs = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPackageManagerFor(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		goos    string
		release string
		want    string
	}{
		{"ubuntu", "linux", "ID=ubuntu\nID_LIKE=debian\n", "apt"},
		{"debian", "linux", `ID="debian"`, "apt"},
		{"mint via ID_LIKE", "linux", "ID=linuxmint\nID_LIKE=\"ubuntu debian\"", "apt"},
		{"fedora", "linux", "ID=fedora", "dnf"},
		{"rhel-like", "linux", "ID=rocky\nID_LIKE=\"rhel centos fedora\"", "dnf"},
		{"amazon linux", "linux", "ID=\"amzn\"\nID_LIKE=\"centos rhel fedora\"", "dnf"},
		{"alpine", "linux", "ID=alpine", "apk"},
		{"arch", "linux", "ID=arch", "pacman"},
		{"opensuse", "linux", "ID=opensuse-leap\nID_LIKE=\"suse opensuse\"", "zypper"},
		{"unknown distro", "linux", "ID=nixos", ""},
		{"no os-release", "linux", "", ""},
		{"macOS is Homebrew", "darwin", "", "brew"},
		{"windows has no table row", "windows", "ID=ubuntu", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PackageManagerFor(tc.goos, ParseOSRelease(tc.release)).Name; got != tc.want {
				t.Errorf("PackageManagerFor(%s) = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

func TestPrereqRemedy(t *testing.T) {
	t.Parallel()
	apt := PackageManagerFor("linux", ParseOSRelease("ID=ubuntu"))
	cases := []struct {
		name    string
		missing []string
		pm      PackageManager
		want    string
	}{
		{"nothing missing", nil, apt, ""},
		{
			"kiro on ubuntu",
			[]string{"unzip"},
			apt,
			"The installer needs unzip, which is not installed on this machine. Install it with: sudo apt-get install -y unzip (Debian/Ubuntu), then press Re-check.",
		},
		{
			"two programs",
			[]string{"tar", "bzip2"},
			apt,
			"The installer needs tar and bzip2, which are not installed on this machine. Install them with: sudo apt-get install -y tar bzip2 (Debian/Ubuntu), then press Re-check.",
		},
		{
			"alternatives map to the first program's package",
			[]string{"sha256sum|shasum"},
			PackageManagerFor("linux", ParseOSRelease("ID=alpine")),
			"The installer needs sha256sum or shasum, which is not installed on this machine. Install it with: sudo apk add coreutils (Alpine), then press Re-check.",
		},
		{
			"unknown family",
			[]string{"unzip", "curl"},
			PackageManager{},
			"The installer needs unzip and curl, which are not installed on this machine. Install unzip and curl with your system package manager, then press Re-check.",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := PrereqRemedy(tc.missing, tc.pm)
			if got != tc.want {
				t.Errorf("PrereqRemedy =\n  %q\nwant\n  %q", got, tc.want)
			}
			if strings.ContainsRune(got, '—') {
				t.Errorf("remedy carries an em-dash: %q", got)
			}
		})
	}
}

// TestInstallArgvFor is one row per builder case: each channel with a
// program, and every refusal.
func TestInstallArgvFor(t *testing.T) {
	t.Parallel()
	pm := func(name string) PackageManager {
		p, _ := PackageManagerByName(name)
		return p
	}
	cases := []struct {
		name     string
		pm       PackageManager
		packages []string
		channel  string
		argv     []string
		ok       bool
	}{
		{"apt", pm("apt"), []string{"bubblewrap"}, "apt", []string{"sudo", "apt-get", "install", "-y", "bubblewrap"}, true},
		{"dnf", pm("dnf"), []string{"bubblewrap"}, "dnf", []string{"sudo", "dnf", "install", "-y", "bubblewrap"}, true},
		{"pacman", pm("pacman"), []string{"bubblewrap"}, "pacman", []string{"sudo", "pacman", "-S", "--needed", "--noconfirm", "bubblewrap"}, true},
		{"zypper", pm("zypper"), []string{"bubblewrap"}, "zypper", []string{"sudo", "zypper", "install", "-y", "bubblewrap"}, true},
		{"apk", pm("apk"), []string{"bubblewrap"}, "apk", []string{"sudo", "apk", "add", "bubblewrap"}, true},
		{"brew runs as the user", pm("brew"), []string{"coreutils"}, "brew", []string{"brew", "install", "coreutils"}, true},
		{"apt two packages", pm("apt"), []string{"virtiofsd", "e2fsprogs"}, "apt", []string{"sudo", "apt-get", "install", "-y", "virtiofsd", "e2fsprogs"}, true},
		{"brew takes one package", pm("brew"), []string{"a", "b"}, "", nil, false},
		{"unknown family", PackageManager{}, []string{"bubblewrap"}, "", nil, false},
		{"no packages", pm("apt"), nil, "", nil, false},
		{"flag as package", pm("apt"), []string{"--allow-unauthenticated"}, "", nil, false},
		{"empty package", pm("dnf"), []string{""}, "", nil, false},
		{"whitespace", pm("apt"), []string{"bubble wrap"}, "", nil, false},
		{"shell metacharacter", pm("apt"), []string{"x;rm"}, "", nil, false},
		{"npm has no builder", PackageManager{Name: "npm"}, []string{"x"}, "", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch, argv, ok := InstallArgvFor(tc.pm, tc.packages)
			if ok != tc.ok || ch != tc.channel || !reflect.DeepEqual(argv, tc.argv) {
				t.Errorf("InstallArgvFor = (%q, %q, %v), want (%q, %q, %v)", ch, argv, ok, tc.channel, tc.argv, tc.ok)
			}
		})
	}
}

// TestPackageManagerByName: every row PackageManagerFor can answer is
// reachable by its name, and nothing else is.
func TestPackageManagerByName(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"apt", "dnf", "apk", "pacman", "zypper", "brew"} {
		pm, ok := PackageManagerByName(name)
		if !ok || pm.Name != name || pm.Install == "" || pm.Family == "" {
			t.Errorf("PackageManagerByName(%q) = %+v, %v", name, pm, ok)
		}
	}
	if got := PackageManagerFor("darwin", nil); got != mustPM(t, "brew") {
		t.Errorf("darwin = %+v", got)
	}
	for _, name := range []string{"", "npm", "winget", "choco"} {
		if _, ok := PackageManagerByName(name); ok {
			t.Errorf("PackageManagerByName(%q) found", name)
		}
	}
}

func mustPM(t *testing.T, name string) PackageManager {
	t.Helper()
	pm, ok := PackageManagerByName(name)
	if !ok {
		t.Fatalf("no %s", name)
	}
	return pm
}
