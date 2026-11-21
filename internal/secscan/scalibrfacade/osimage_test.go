//go:build !sbo_omit_security_scan_scalibr && !sbo_omit_security_scan_os

package scalibrfacade

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	rpmmeta "github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
	"github.com/google/osv-scalibr/purl"
)

// imageRoot writes a tiny extracted image root (what internal/secimage
// leaves in a run directory).
func imageRoot(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, body := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const (
	debian12 = "ID=debian\nVERSION_ID=\"12\"\nVERSION=\"12 (bookworm)\"\nVERSION_CODENAME=bookworm\n"
	noble    = "ID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION=\"24.04.1 LTS (Noble Numbat)\"\nVERSION_CODENAME=noble\n"
	nobleNoL = "ID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION=\"24.04.1 (Noble Numbat)\"\nVERSION_CODENAME=noble\n"
	alpine   = "ID=alpine\nVERSION_ID=3.20.3\n"

	debStatus = "Package: libc6\nStatus: install ok installed\nSource: glibc\nVersion: 2.36-9+deb12u2\nArchitecture: amd64\n\n" +
		"Package: zlib1g\nStatus: install ok installed\nSource: zlib\nVersion: 1:1.2.13.dfsg-1\nArchitecture: amd64\n\n"
	nobleStatus = "Package: libpcre2-8-0\nStatus: install ok installed\nSource: pcre2\nVersion: 10.42-4ubuntu2.1\nArchitecture: amd64\n\n"
	apkDB       = "P:libcrypto3\nV:3.3.0-r0\no:openssl\nA:x86_64\n\nP:musl\nV:1.2.5-r0\no:musl\nA:x86_64\n\n"

	dsa5514 = `{"id":"DSA-5514-1","modified":"2024-01-01T00:00:00Z","upstream":["CVE-2023-4911"],
"affected":[{"package":{"ecosystem":"Debian:12","name":"glibc"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.36-9+deb12u3"}]}]}]}`
	usn8974 = `{"id":"USN-8974-1","modified":"2026-01-01T00:00:00Z",
"affected":[{"package":{"ecosystem":"Ubuntu:24.04:LTS","name":"pcre2"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"10.42-4ubuntu2.2"}]}]}]}`
	alpineSSL = `{"id":"ALPINE-CVE-2024-5535","modified":"2024-07-01T00:00:00Z",
"affected":[{"package":{"ecosystem":"Alpine:v3.20","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.3.1-r1"}]}]}]}`
)

func osIndices(inv *Inventory) []int {
	out := make([]int, len(inv.Packages))
	for i := range out {
		out[i] = i
	}
	return out
}

func TestOSExtractAndMatch(t *testing.T) {
	cases := []struct {
		name        string
		files       map[string]string
		base, db    string
		canary      OSCanary
		wantEco     string
		wantVuln    []string // binary or name = id
		wantCanary  bool
		wantBinary  map[string]string // match name -> binary
		wantPackage int
	}{
		{
			name:  "Debian 12: source names and backports",
			files: map[string]string{"etc/os-release": debian12, "var/lib/dpkg/status": debStatus},
			base:  "Debian", db: dsa5514,
			canary:  OSCanary{Kind: "deb", Name: "libc6", Source: "glibc", Version: "2.36-9+deb12u2"},
			wantEco: "Debian:12", wantVuln: []string{"glibc=DSA-5514-1"}, wantCanary: true,
			wantBinary: map[string]string{"glibc": "libc6", "zlib": "zlib1g"}, wantPackage: 2,
		},
		{
			name:  "Debian 12: the fixed version is not flagged",
			files: map[string]string{"etc/os-release": debian12, "var/lib/dpkg/status": "Package: libc6\nStatus: install ok installed\nSource: glibc\nVersion: 2.36-9+deb12u3\n\n"},
			base:  "Debian", db: dsa5514,
			canary:  OSCanary{Kind: "deb", Name: "libc6", Source: "glibc", Version: "2.36-9+deb12u2"},
			wantEco: "Debian:12", wantCanary: true, wantBinary: map[string]string{"glibc": "libc6"}, wantPackage: 1,
		},
		{
			name:  "Ubuntu 24.04 LTS: the :LTS repair",
			files: map[string]string{"etc/os-release": noble, "var/lib/dpkg/status": nobleStatus},
			base:  "Ubuntu", db: usn8974,
			canary:  OSCanary{Kind: "deb", Name: "libpcre2-8-0", Source: "pcre2", Version: "10.42-4ubuntu2.1"},
			wantEco: "Ubuntu:24.04:LTS", wantVuln: []string{"pcre2=USN-8974-1"}, wantCanary: true,
			wantBinary: map[string]string{"pcre2": "libpcre2-8-0"}, wantPackage: 1,
		},
		{
			// Without "LTS" in VERSION nothing is repaired: SCALIBR's own
			// "Ubuntu:24.04" matches no record and the canary fails, which
			// is how a run catches it.
			name:  "Ubuntu without the LTS marker matches nothing",
			files: map[string]string{"etc/os-release": nobleNoL, "var/lib/dpkg/status": nobleStatus},
			base:  "Ubuntu", db: usn8974,
			canary:  OSCanary{Kind: "deb", Name: "libpcre2-8-0", Source: "pcre2", Version: "10.42-4ubuntu2.1"},
			wantEco: "Ubuntu:24.04", wantBinary: map[string]string{"pcre2": "libpcre2-8-0"}, wantPackage: 1,
		},
		{
			name:  "Alpine 3.20: origin names",
			files: map[string]string{"etc/os-release": alpine, "lib/apk/db/installed": apkDB},
			base:  "Alpine", db: alpineSSL,
			canary:  OSCanary{Kind: "apk", Name: "libcrypto3", Source: "openssl", Version: "3.3.0-r0"},
			wantEco: "Alpine:v3.20", wantVuln: []string{"openssl=ALPINE-CVE-2024-5535"}, wantCanary: true,
			wantBinary: map[string]string{"openssl": "libcrypto3"}, wantPackage: 2,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := imageRoot(t, c.files)
			inv, err := ExtractOS(context.Background(), root, OSExtractOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if len(inv.Packages) != c.wantPackage {
				t.Fatalf("packages %+v, want %d", inv.Packages, c.wantPackage)
			}
			for _, p := range inv.Packages {
				if p.OSEcosystem != c.wantEco || p.Ecosystem != c.base {
					t.Errorf("%s: ecosystem %q base %q, want %q %q", p.Name, p.OSEcosystem, p.Ecosystem, c.wantEco, c.base)
				}
				if want, ok := c.wantBinary[p.Name]; ok && p.Binary != want {
					t.Errorf("%s: binary %q, want %q", p.Name, p.Binary, want)
				}
				if !slices.Contains([]string{"os/dpkg", "os/apk"}, p.Extractor) {
					t.Errorf("%s: extractor %q", p.Name, p.Extractor)
				}
			}
			db := t.TempDir()
			writeDB(t, db, c.base, map[string]string{"a.json": c.db})
			res, err := MatchOS(context.Background(), inv, OSMatchRequest{Indices: osIndices(inv), Canary: &c.canary}, MatchOptions{DBDir: db})
			if err != nil {
				t.Fatal(err)
			}
			if res.CanaryHit != c.wantCanary {
				t.Errorf("canary hit %v, want %v", res.CanaryHit, c.wantCanary)
			}
			var got []string
			for _, v := range res.Vulns {
				got = append(got, inv.Packages[v.Index].Name+"="+v.ID)
			}
			if !slices.Equal(got, c.wantVuln) {
				t.Errorf("vulns %v, want %v", got, c.wantVuln)
			}
		})
	}
}

func TestMatchOSMissingDatabase(t *testing.T) {
	root := imageRoot(t, map[string]string{"etc/os-release": debian12, "var/lib/dpkg/status": debStatus})
	inv, err := ExtractOS(context.Background(), root, OSExtractOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MatchOS(context.Background(), inv, OSMatchRequest{Indices: osIndices(inv)}, MatchOptions{DBDir: t.TempDir()}); !errors.Is(err, ErrNoDatabase) {
		t.Fatalf("no Debian database: %v, want ErrNoDatabase", err)
	}
	if _, err := MatchOS(context.Background(), &Inventory{}, OSMatchRequest{}, MatchOptions{DBDir: t.TempDir()}); err == nil {
		t.Fatal("a project inventory is not an image inventory")
	}
}

// TestRedHatRepairKeepsAppStream decides the Red Hat repair by test (spike
// JSP-OS S4): against the stripped per-major file, a package with an EMPTY
// OSCPEName (ecosystem "Red Hat") matches both its baseos and its
// AppStream advisories through the base-only fallback; the CPE repair
// ("Red Hat:enterprise_linux:9::baseos" from CPE_NAME) would lose the
// AppStream one. So repairOS keeps OSCPEName empty. The packages are built
// directly: os/rpm does not build on Windows.
func TestRedHatRepairKeepsAppStream(t *testing.T) {
	const rhsa = `{"id":"RHSA-2024:0001","modified":"2024-01-01T00:00:00Z",
"affected":[
 {"package":{"ecosystem":"Red Hat:enterprise_linux:9::appstream","name":"nodejs"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:16.20.2-8.el9_4"}]}]},
 {"package":{"ecosystem":"Red Hat:enterprise_linux:9::baseos","name":"glib2"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"0:2.68.4-14.el9_4.1"}]}]}
]}`
	db := t.TempDir()
	writeDB(t, db, "Red Hat", map[string]string{"a.json": rhsa})
	release := map[string]string{"ID": "rhel", "VERSION_ID": "9.3", "CPE_NAME": "cpe:/o:redhat:enterprise_linux:9::baseos"}
	build := func(cpe string) *Inventory {
		mk := func(name, version string, epoch int) *extractor.Package {
			return &extractor.Package{
				Name: name, Version: version, PURLType: purl.TypeRPM, Plugins: []string{"os/rpm"},
				Metadata: &rpmmeta.Metadata{PackageName: name, Epoch: epoch, OSID: "rhel", OSVersionID: "9.3", OSCPEName: cpe},
			}
		}
		pkgs := []*extractor.Package{mk("nodejs", "16.20.2-3.el9", 1), mk("glib2", "2.68.4-11.el9", 0)}
		return &Inventory{impl: &osImpl{pkgs: pkgs, release: release}, Packages: []Package{{Name: "nodejs"}, {Name: "glib2"}}}
	}
	match := func(inv *Inventory) []string {
		res, err := MatchOS(context.Background(), inv, OSMatchRequest{Indices: []int{0, 1}}, MatchOptions{DBDir: db})
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, v := range res.Vulns {
			out = append(out, inv.Packages[v.Index].Name)
		}
		return out
	}
	if got := match(build("")); !slices.Equal(got, []string{"nodejs", "glib2"}) {
		t.Fatalf("empty CPE (the stripped file's base-only match): %v, want nodejs and glib2", got)
	}
	if got := match(build(release["CPE_NAME"])); !slices.Equal(got, []string{"glib2"}) {
		t.Fatalf("CPE repair: %v; the baseos CPE should narrow the match to glib2 (this is why it is not applied)", got)
	}
	// repairOS clears a CPE an upstream extractor might start to set.
	inv := build(release["CPE_NAME"])
	repairOS(release, inv.impl.(*osImpl).pkgs)
	if got := match(inv); !slices.Equal(got, []string{"nodejs", "glib2"}) {
		t.Fatalf("after repairOS: %v", got)
	}
	// The canary is built and repaired the same way.
	c, err := osCanaryPackage(OSCanary{Kind: "rpm", Name: "glib2", Version: "2.68.4-11.el9"}, release)
	if err != nil || c.Ecosystem().String() != "Red Hat" {
		t.Fatalf("rpm canary ecosystem %q (err %v), want bare Red Hat", c.Ecosystem().String(), err)
	}
}

func TestRepairLTSIsIdempotent(t *testing.T) {
	c, err := osCanaryPackage(OSCanary{Kind: "deb", Name: "x", Version: "1"}, map[string]string{"ID": "ubuntu", "VERSION_ID": "24.04", "VERSION": "24.04 LTS"})
	if err != nil {
		t.Fatal(err)
	}
	repairOS(map[string]string{"VERSION": "24.04 LTS"}, []*extractor.Package{c})
	if got := c.Ecosystem().String(); got != "Ubuntu:24.04:LTS" {
		t.Fatalf("ecosystem %q after two repairs, want one :LTS suffix", got)
	}
	if _, err := osCanaryPackage(OSCanary{Kind: "pkg"}, nil); err == nil {
		t.Fatal("an unknown canary kind must be refused")
	}
}
