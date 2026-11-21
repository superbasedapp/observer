//go:build !sbo_omit_security_scan_scalibr && !sbo_omit_security_scan_os

package scalibrchild

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
)

const (
	debian12Release = "ID=debian\nVERSION_ID=\"12\"\nVERSION=\"12 (bookworm)\"\nVERSION_CODENAME=bookworm\n"
	debian12Status  = "Package: libc6\nStatus: install ok installed\nSource: glibc\nVersion: 2.36-9+deb12u2\n\n" +
		"Package: linux-libc-dev\nStatus: install ok installed\nSource: linux\nVersion: 6.1.112-1\n\n" +
		"Package: zlib1g\nStatus: install ok installed\nSource: zlib\nVersion: 1:1.2.13.dfsg-1\n\n"
	dsa5514 = `{"id":"DSA-5514-1","modified":"2024-01-01T00:00:00Z","upstream":["CVE-2023-4911"],
"affected":[{"package":{"ecosystem":"Debian:12","name":"glibc"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.36-9+deb12u3"}]}]}]}`
	// A kernel advisory: never matched, since linux-libc-dev is left out.
	kernelRecord = `{"id":"DEBIAN-CVE-2024-0001","modified":"2024-01-01T00:00:00Z",
"affected":[{"package":{"ecosystem":"Debian:12","name":"linux"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`
	unrelatedDebian = `{"id":"DSA-0000-1","modified":"2024-01-01T00:00:00Z",
"affected":[{"package":{"ecosystem":"Debian:12","name":"nothing"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`
)

func writeImageRoot(t *testing.T, files map[string]string) string {
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

func TestRunOSImage(t *testing.T) {
	root := writeImageRoot(t, map[string]string{"etc/os-release": debian12Release, "var/lib/dpkg/status": debian12Status})
	good := t.TempDir()
	writeDB(t, good, "Debian", map[string]string{"a.json": dsa5514, "k.json": kernelRecord})
	stale := t.TempDir()
	writeDB(t, stale, "Debian", map[string]string{"a.json": unrelatedDebian})
	deb12 := &depscan.OSImageRequest{Ecosystem: "Debian:12", Base: "Debian", Epoch: "2026-11-04"}
	cases := []struct {
		name    string
		os      *depscan.OSImageRequest
		db      string
		goos    string
		outcome depscan.EcoOutcome
		reason  string
		advs    []string
	}{
		{"scanned, kernel left out", deb12, good, "linux", depscan.EcoScanned, "", []string{"glibc=DSA-5514-1"}},
		{"no database installed", &depscan.OSImageRequest{Ecosystem: "Debian:12", Base: "Debian"}, good, "linux", depscan.EcoNotScanned, depscan.ReasonNoDatabase, nil},
		{"database not linked", deb12, t.TempDir(), "linux", depscan.EcoNotScanned, depscan.ReasonNoDatabase, nil},
		{"database that misses its canary", deb12, stale, "linux", depscan.EcoNotScanned, depscan.ReasonSelfTestFailed, nil},
		{"release with no canary row", &depscan.OSImageRequest{Ecosystem: "Debian:11", Base: "Debian", Epoch: "e"}, good, "linux", depscan.EcoNotScanned, depscan.ReasonNoOSCanary, nil},
		{"rpm release on windows", &depscan.OSImageRequest{Ecosystem: "Rocky Linux:9", Base: "Rocky Linux", RPM: true, Epoch: "e"}, good, "windows", depscan.EcoNotScanned, depscan.ReasonRPMOnWindows, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := Run(context.Background(), depscan.ChildRequest{Version: depscan.ProtocolVersion, Kind: depscan.KindOSImage, Root: root, DBDir: c.db, OS: c.os, GOOS: c.goos}, nil)
			if resp.Error != "" || resp.Kind != depscan.KindOSImage || !resp.Compiled {
				t.Fatalf("resp %+v", resp)
			}
			if len(resp.Ecosystems) != 1 {
				t.Fatalf("ecosystems %+v, want one: the release", resp.Ecosystems)
			}
			e := resp.Ecosystems[0]
			if e.Ecosystem != c.os.Ecosystem || e.Outcome != c.outcome || e.Reason != c.reason {
				t.Fatalf("%s %s %q, want %s %q", e.Ecosystem, e.Outcome, e.Reason, c.outcome, c.reason)
			}
			var got []string
			for _, a := range e.Advisories {
				got = append(got, resp.Packages[a.Index].Name+"="+a.ID)
			}
			if len(got) != len(c.advs) || (len(got) > 0 && got[0] != c.advs[0]) {
				t.Fatalf("advisories %v, want %v", got, c.advs)
			}
			if c.reason == depscan.ReasonRPMOnWindows {
				return
			}
			if resp.Dropped[depscan.KernelDropRule] != 1 || e.Packages != 2 {
				t.Fatalf("dropped %v, packages %d: linux-libc-dev must be left out and counted", resp.Dropped, e.Packages)
			}
			for _, p := range resp.Packages {
				if p.Ecosystem != c.os.Ecosystem {
					t.Errorf("%s carries %q, want the release label", p.Name, p.Ecosystem)
				}
			}
		})
	}
}

func TestRunOSImageRefusals(t *testing.T) {
	for _, c := range []struct {
		name string
		req  depscan.ChildRequest
	}{
		{"unknown kind", depscan.ChildRequest{Version: depscan.ProtocolVersion, Kind: "registry", Root: t.TempDir()}},
		{"no release", depscan.ChildRequest{Version: depscan.ProtocolVersion, Kind: depscan.KindOSImage, Root: t.TempDir()}},
		{"no root", depscan.ChildRequest{Version: depscan.ProtocolVersion, Kind: depscan.KindOSImage, OS: &depscan.OSImageRequest{Ecosystem: "Debian:12", Base: "Debian"}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if resp := Run(context.Background(), c.req, nil); resp.Error == "" {
				t.Fatalf("resp %+v, want an error", resp)
			}
		})
	}
	// A root with no package database: no ecosystem, so "no_packages".
	resp := Run(context.Background(), depscan.ChildRequest{
		Version: depscan.ProtocolVersion, Kind: depscan.KindOSImage, Root: writeImageRoot(t, map[string]string{"etc/os-release": debian12Release}),
		OS: &depscan.OSImageRequest{Ecosystem: "Debian:12", Base: "Debian", Epoch: "e"}, DBDir: t.TempDir(),
	}, nil)
	if resp.Error != "" || len(resp.Ecosystems) != 0 || len(resp.Packages) != 0 {
		t.Fatalf("empty image: %+v", resp)
	}
}
