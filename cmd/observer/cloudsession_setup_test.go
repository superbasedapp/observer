package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudsession"
)

// TestCloudSessionSetupScriptInstallsOnlyVerified runs the generated setup
// script against a fake release (a curl stand-in on PATH serves files from a
// directory) and checks it installs a correctly signed archive and refuses a
// tampered one. It needs sh, openssl 3, sha256sum and tar.
func TestCloudSessionSetupScriptInstallsOnlyVerified(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the setup script targets Linux sandboxes")
	}
	for _, bin := range []string{"sh", "openssl", "sha256sum", "tar", "awk"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available", bin)
		}
	}
	if out, err := exec.Command("openssl", "version").Output(); err != nil || !strings.HasPrefix(string(out), "OpenSSL 3") {
		t.Skip("needs OpenSSL 3 for Ed25519")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	arch := map[string]string{"amd64": "x64", "arm64": "arm64"}[runtime.GOARCH]
	if arch == "" {
		t.Skip("unsupported test architecture")
	}
	const tag = "v9.9.9"
	asset := "observer-" + tag + "-linux-" + arch + ".tar.gz"

	build := func(t *testing.T, tamper bool) (string, string) {
		t.Helper()
		root := t.TempDir()
		rel := filepath.Join(root, "release", "download", tag)
		if err := os.MkdirAll(rel, 0o755); err != nil {
			t.Fatal(err)
		}
		archive := cloudSessionTarGz(t, "observer", "#!/bin/sh\necho 'observer version 9.9.9'\n")
		sig := ed25519.Sign(priv, archive)
		if tamper {
			archive = cloudSessionTarGz(t, "observer", "#!/bin/sh\necho evil\n")
		}
		sum := sha256.Sum256(archive)
		cloudSessionWrite(t, filepath.Join(rel, asset), archive)
		cloudSessionWrite(t, filepath.Join(rel, asset+".sig"), sig)
		cloudSessionWrite(t, filepath.Join(rel, "SHA256SUMS"), []byte(hex.EncodeToString(sum[:])+"  "+asset+"\n"))
		// A curl stand-in: map https://example.invalid/... onto the directory.
		bin := filepath.Join(root, "bin")
		if err := os.MkdirAll(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		fake := "#!/bin/sh\nout=''\nurl=''\nwhile [ $# -gt 0 ]; do case \"$1\" in -o) out=$2; shift 2;; --proto|--retry) shift 2;; -*) shift;; *) url=$1; shift;; esac; done\n" +
			"path=${url#https://example.invalid/}\n[ -f \"" + root + "/$path\" ] || exit 22\ncp \"" + root + "/$path\" \"$out\"\n"
		cloudSessionWrite(t, filepath.Join(bin, "curl"), []byte(fake))
		if err := os.Chmod(filepath.Join(bin, "curl"), 0o755); err != nil {
			t.Fatal(err)
		}
		plan, err := cloudsession.PlanInit(cloudsession.PlanOptions{
			Agent: "claude-code", Destination: cloudsession.DestOrg, ObserverVersion: tag,
			VendorKeys:     []string{base64.StdEncoding.EncodeToString(pub)},
			InstallSource:  cloudsession.InstallRelease,
			ReleaseBaseURL: "https://example.invalid/release",
			InstallDir:     filepath.Join(root, "prefix"),
		}, func(string) (string, bool, error) { return "", false, nil })
		if err != nil {
			t.Fatal(err)
		}
		var script string
		for _, c := range plan.Changes {
			if c.Path == cloudsession.SetupScriptPath {
				script = c.After
			}
		}
		cloudSessionWrite(t, filepath.Join(root, "setup.sh"), []byte(script))
		return root, bin
	}
	runScript := func(root, bin string) (string, error) {
		cmd := exec.Command("sh", filepath.Join(root, "setup.sh"))
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	t.Run("signed", func(t *testing.T) {
		root, bin := build(t, false)
		out, err := runScript(root, bin)
		if err != nil {
			t.Fatalf("setup failed: %v\n%s", err, out)
		}
		if _, err := os.Stat(filepath.Join(root, "prefix", "observer")); err != nil {
			t.Fatalf("not installed: %v\n%s", err, out)
		}
		// Idempotent: a second run finds the pinned version and stops.
		out, err = runScript(root, bin)
		if err != nil || !strings.Contains(out, "already installed") {
			t.Fatalf("second run: %v\n%s", err, out)
		}
	})
	t.Run("tampered", func(t *testing.T) {
		root, bin := build(t, true)
		out, err := runScript(root, bin)
		if err == nil {
			t.Fatalf("a tampered archive was accepted:\n%s", out)
		}
		if !strings.Contains(out, "REFUSED") || !strings.Contains(out, "signature") {
			t.Errorf("refusal does not name the signature:\n%s", out)
		}
		if _, err := os.Stat(filepath.Join(root, "prefix", "observer")); !os.IsNotExist(err) {
			t.Error("a tampered binary was installed")
		}
	})
	t.Run("unreachable", func(t *testing.T) {
		root, bin := build(t, false)
		if err := os.RemoveAll(filepath.Join(root, "release")); err != nil {
			t.Fatal(err)
		}
		out, err := runScript(root, bin)
		if err != nil || !strings.Contains(out, "WARNING") {
			t.Fatalf("an unreachable release must warn and exit 0: %v\n%s", err, out)
		}
	})
}

func cloudSessionWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func cloudSessionTarGz(t *testing.T, name, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestCloudSessionSetupScriptNpm runs the default (npm) setup script against
// a fake registry: it installs a tarball whose sha512 equals the pinned
// dist.integrity, refuses any other, checks a vendor signature shipped in
// the package when there is one, and only warns when the registry is out of
// reach (a failed setup must leave a session that still runs, CA-A2).
func TestCloudSessionSetupScriptNpm(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the setup script targets Linux sandboxes")
	}
	for _, bin := range []string{"sh", "sha512sum", "tar", "awk", "grep"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available", bin)
		}
	}
	arch := map[string]string{"amd64": "x64", "arm64": "arm64"}[runtime.GOARCH]
	if arch == "" {
		t.Skip("unsupported test architecture")
	}
	hasOpenSSL3 := false
	if out, err := exec.Command("openssl", "version").Output(); err == nil && strings.HasPrefix(string(out), "OpenSSL 3") {
		hasOpenSSL3 = true
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const tag = "v9.9.9"
	good := "#!/bin/sh\necho 'observer version 9.9.9'\n"

	type pkgOpts struct {
		body    string
		sig     []byte // nil: no observer.sig in the package
		pinBody string // the body the pin is computed for ("" = body)
		noPin   bool
		offline bool
	}
	build := func(t *testing.T, o pkgOpts) (string, string) {
		t.Helper()
		root := t.TempDir()
		pkg := "observer-linux-" + arch
		dir := filepath.Join(root, "registry", "@superbased", pkg, "-")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		files := map[string][]byte{"package/bin/observer": []byte(o.body), "package/package.json": []byte(`{"name":"@superbased/` + pkg + `"}`)}
		if o.sig != nil {
			files["package/bin/observer.sig"] = o.sig
		}
		tgz := cloudSessionTarGzFiles(t, files)
		pinBody := o.pinBody
		if pinBody == "" {
			pinBody = o.body
		}
		pinTgz := tgz
		if pinBody != o.body {
			pinFiles := map[string][]byte{"package/bin/observer": []byte(pinBody), "package/package.json": files["package/package.json"]}
			if o.sig != nil {
				pinFiles["package/bin/observer.sig"] = o.sig
			}
			pinTgz = cloudSessionTarGzFiles(t, pinFiles)
		}
		if !o.offline {
			cloudSessionWrite(t, filepath.Join(dir, pkg+"-9.9.9.tgz"), tgz)
		}
		sum := sha512.Sum512(pinTgz)
		var pins []cloudsession.NpmPin
		if !o.noPin {
			pins = []cloudsession.NpmPin{{Arch: arch, Integrity: "sha512-" + base64.StdEncoding.EncodeToString(sum[:])}}
		} else {
			other := map[string]string{"x64": "arm64", "arm64": "x64"}[arch]
			pins = []cloudsession.NpmPin{{Arch: other, Integrity: "sha512-" + base64.StdEncoding.EncodeToString(sum[:])}}
		}
		bin := filepath.Join(root, "bin")
		if err := os.MkdirAll(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		fake := "#!/bin/sh\nout=''\nurl=''\nwhile [ $# -gt 0 ]; do case \"$1\" in -o) out=$2; shift 2;; --proto|--retry) shift 2;; -*) shift;; *) url=$1; shift;; esac; done\n" +
			"path=${url#https://example.invalid/}\n[ -f \"" + root + "/$path\" ] || exit 22\ncp \"" + root + "/$path\" \"$out\"\n"
		cloudSessionWrite(t, filepath.Join(bin, "curl"), []byte(fake))
		if err := os.Chmod(filepath.Join(bin, "curl"), 0o755); err != nil {
			t.Fatal(err)
		}
		plan, err := cloudsession.PlanInit(cloudsession.PlanOptions{
			Agent: "claude-code", Destination: cloudsession.DestOrg, ObserverVersion: tag,
			VendorKeys:  []string{base64.StdEncoding.EncodeToString(pub)},
			NpmRegistry: "https://example.invalid/registry",
			NpmPins:     pins,
			InstallDir:  filepath.Join(root, "prefix"),
		}, func(string) (string, bool, error) { return "", false, nil })
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range plan.Changes {
			if c.Path == cloudsession.SetupScriptPath {
				cloudSessionWrite(t, filepath.Join(root, "setup.sh"), []byte(c.After))
			}
		}
		return root, bin
	}
	run := func(root, bin string) (string, error) {
		cmd := exec.Command("sh", filepath.Join(root, "setup.sh"))
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	installed := func(root string) bool {
		_, err := os.Stat(filepath.Join(root, "prefix", "observer"))
		return err == nil
	}

	t.Run("pinned", func(t *testing.T) {
		root, bin := build(t, pkgOpts{body: good})
		out, err := run(root, bin)
		if err != nil || !installed(root) || !strings.Contains(out, "npm dist.integrity (sha512) verified") {
			t.Fatalf("install: %v\n%s", err, out)
		}
		if out, err = run(root, bin); err != nil || !strings.Contains(out, "already installed") {
			t.Fatalf("second run: %v\n%s", err, out)
		}
	})
	t.Run("tampered", func(t *testing.T) {
		root, bin := build(t, pkgOpts{body: "#!/bin/sh\necho evil\n", pinBody: good})
		out, err := run(root, bin)
		if err == nil || installed(root) || !strings.Contains(out, "REFUSED") || !strings.Contains(out, "sha512 mismatch") {
			t.Fatalf("a tarball off its pin was accepted: %v\n%s", err, out)
		}
	})
	t.Run("unreachable registry", func(t *testing.T) {
		root, bin := build(t, pkgOpts{body: good, offline: true})
		out, err := run(root, bin)
		if err != nil || installed(root) || !strings.Contains(out, "WARNING") {
			t.Fatalf("an unreachable registry must warn and exit 0: %v\n%s", err, out)
		}
	})
	t.Run("no pin for this architecture", func(t *testing.T) {
		root, bin := build(t, pkgOpts{body: good, noPin: true})
		out, err := run(root, bin)
		if err != nil || installed(root) || !strings.Contains(out, "no npm integrity pin") {
			t.Fatalf("missing pin: %v\n%s", err, out)
		}
	})
	t.Run("vendor signature in the package", func(t *testing.T) {
		if !hasOpenSSL3 {
			t.Skip("needs OpenSSL 3 for Ed25519")
		}
		root, bin := build(t, pkgOpts{body: good, sig: ed25519.Sign(priv, []byte(good))})
		out, err := run(root, bin)
		if err != nil || !installed(root) || !strings.Contains(out, "and vendor signature verified") {
			t.Fatalf("signed package: %v\n%s", err, out)
		}
		root, bin = build(t, pkgOpts{body: good, sig: ed25519.Sign(priv, []byte("something else"))})
		out, err = run(root, bin)
		if err == nil || installed(root) || !strings.Contains(out, "vendor signature on bin/observer does not verify") {
			t.Fatalf("a bad in-package signature was accepted: %v\n%s", err, out)
		}
	})
}

func cloudSessionTarGzFiles(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o755, Size: int64(len(files[n])), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(files[n]); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
