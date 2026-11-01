package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/sandboximage"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// sandboxvm_test.go covers the sandboxrootfs and sandboxguest verbs (lane
// SBX-P4) with a TEST key generated here.

// fakeVMBuild writes a build/ directory with stand-in bulk files.
func fakeVMBuild(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"root-hash":    strings.Repeat("7", 64) + "\n",
		"kernel.tsv":   "linux-image-6.8.0-147-generic\t6.8.0-147.147\t" + strings.Repeat("0", 64) + "\n",
		"packages.tsv": "bash\t5.2.21-2ubuntu4\tamd64\ngit\t1:2.43.0-1ubuntu7.4\tamd64\n",
	}
	for _, n := range sandboximage.BulkEntries() {
		files[n] = "stand-in " + n
	}
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func writeTestKeyFile(t *testing.T) (ed25519.PublicKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, []byte(base64.StdEncoding.EncodeToString(priv.Seed())), 0o600); err != nil {
		t.Fatal(err)
	}
	return pub, p
}

func vmVerbArgs(build, out string) []string {
	return []string{"-build", build, "-recipe-dir", filepath.Join("..", "..", "deploy", "sandbox-vm-image"), "-version", "1.0.0", "-min-version", "1.0.0",
		"-commit", strings.Repeat("ab", 20), "-source-date-epoch", "1790000000", "-out", out}
}

// TestSandboxVMVerbsStopAtTheSigningSeam: without -key both verbs write
// the unsigned files and return sandbox_vm_signing_key_missing.
func TestSandboxVMVerbsStopAtTheSigningSeam(t *testing.T) {
	out := t.TempDir()
	err := run(append([]string{"sandboxrootfs"}, vmVerbArgs(fakeVMBuild(t), out)...), os.Stdout)
	if !errors.Is(err, errSandboxVMSigningKeyMissing) || !strings.Contains(err.Error(), "sandbox_vm_signing_key_missing") {
		t.Fatalf("rootfs: %v", err)
	}
	dir := filepath.Join(out, string(content.SandboxRootfs))
	if _, err := os.Stat(filepath.Join(dir, "manifest.json")); !os.IsNotExist(err) {
		t.Fatal("an unsigned run wrote a manifest")
	}
	b, err := os.ReadFile(filepath.Join(dir, sandboximage.VMDescriptorName))
	if err != nil {
		t.Fatal(err)
	}
	d, err := sandboximage.ParseVMDescriptor(b)
	if err != nil || d.VerityRootHash != strings.Repeat("7", 64) || !d.GuestUserns || d.Arch != "amd64" || d.AgentCLI {
		t.Fatalf("descriptor %+v %v", d, err)
	}
	gbin := filepath.Join(t.TempDir(), "observer")
	_ = os.WriteFile(gbin, []byte("guest"), 0o600)
	err = run([]string{"sandboxguest", "-binary", "amd64=" + gbin, "-version", "v1.40.0", "-commit", strings.Repeat("ab", 20), "-out", out}, os.Stdout)
	if !errors.Is(err, errSandboxVMSigningKeyMissing) {
		t.Fatalf("guest: %v", err)
	}
}

// TestSandboxVMVerbsSignAnImportableSet: with a test key the two manifests
// install through the node's content store and the set resolves.
func TestSandboxVMVerbsSignAnImportableSet(t *testing.T) {
	pub, key := writeTestKeyFile(t)
	out := t.TempDir()
	sign := []string{"-key", key, "-allow-unpinned-key", "-manifest-version", "1"}
	if err := run(append(append([]string{"sandboxrootfs"}, vmVerbArgs(fakeVMBuild(t), out)...), sign...), os.Stdout); err != nil {
		t.Fatal(err)
	}
	gbin := filepath.Join(t.TempDir(), "observer")
	_ = os.WriteFile(gbin, []byte("guest observer"), 0o600)
	if err := run(append([]string{"sandboxguest", "-binary", "amd64=" + gbin, "-version", "1.40.0", "-commit", strings.Repeat("ab", 20), "-out", out}, sign...), os.Stdout); err != nil {
		t.Fatal(err)
	}
	st := contentchan.Store{Root: t.TempDir(), GOOS: "linux", GOARCH: "amd64"}
	tr := contentchan.Trust{VendorKeys: []ed25519.PublicKey{pub}}
	for _, kind := range []content.Kind{content.SandboxRootfs, content.SandboxGuest} {
		dir := filepath.Join(out, string(kind))
		env, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		ents, _ := os.ReadDir(dir)
		files := map[string]string{}
		for _, e := range ents {
			if e.Name() != "manifest.json" {
				cp := filepath.Join(t.TempDir(), e.Name())
				b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
				_ = os.WriteFile(cp, b, 0o600)
				files[e.Name()] = cp
			}
		}
		if _, err := st.InstallFiles(kind, env, files, tr); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
	}
	l, err := st.Load(content.SandboxRootfs, tr, 0)
	if err != nil || l.Freshness != content.Fresh {
		t.Fatalf("load %v %s", err, l.Freshness)
	}
	if len(l.Manifest.Entries) != 6 {
		t.Fatalf("entries %+v", l.Manifest.Entries)
	}
	exp, _ := time.Parse(time.RFC3339, l.Manifest.ExpiresAt)
	if exp.Sub(time.Now()) > 91*24*time.Hour {
		t.Fatalf("validity %s", l.Manifest.ExpiresAt)
	}
}
