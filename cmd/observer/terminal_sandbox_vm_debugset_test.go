//go:build !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/sandboximage"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// TestVMSignedBytesAreTheVerifiedBytes (RERUN2 D6): the bytes a release
// signs are the bytes a node verifies, on every OS. The signer encodes the
// manifest canonically and carries it base64 inside the envelope (no text
// mode, no path separator, no line ending can change it); every file is
// covered by its sha256 over raw bytes. The set is written with CRLF and
// LF bytes and a nested entry name, imported, and each installed file and
// the envelope are compared byte for byte with what was signed. The
// Windows failure of the debug-set test was the debug key's owner-only
// check (0600 is not kept on Windows), not the signed bytes.
func TestVMSignedBytesAreTheVerifiedBytes(t *testing.T) {
	vendorPub, vendorPriv := vmTestKey(t)
	set := writeVMTestSet(t, vendorPriv, 1, "1.0.0", "1.40.0")
	rdir := filepath.Join(set.dir, string(content.SandboxRootfs))
	signed := map[string][]byte{}
	walkErr := filepath.WalkDir(rdir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		rel, _ := filepath.Rel(rdir, p)
		signed[filepath.ToSlash(rel)] = b
		return nil
	})
	if walkErr != nil {
		t.Fatal(walkErr)
	}
	var env content.Envelope
	if err := json.Unmarshal(signed[contentchan.ManifestFile], &env); err != nil {
		t.Fatalf("the envelope does not decode: %v", err)
	}
	body, err := base64.StdEncoding.DecodeString(env.ManifestB64)
	if err != nil {
		t.Fatal(err)
	}
	if content.HashBytes(body) != env.ManifestHash {
		t.Fatal("the envelope's manifest hash is not the hash of its own bytes")
	}
	if bytes.Contains(body, []byte("\r")) || bytes.Contains(body, []byte("\\\\")) {
		t.Fatalf("the signed manifest carries a CR or a backslash path: %q", body)
	}
	store := vmContentStore(t.TempDir())
	if _, err := sandboxContentImport(store, []ed25519.PublicKey{vendorPub}, set.dir); err != nil {
		t.Fatalf("a good set did not import: %v", err)
	}
	if s := loadVMImageSet(store, contentchan.Trust{VendorKeys: []ed25519.PublicKey{vendorPub}}, "", "1.40.0"); !s.res.OK {
		t.Fatalf("the imported set does not verify: %+v", s.res)
	}
	installed := filepath.Join(store.Root, string(content.SandboxRootfs))
	for name, want := range signed {
		got, err := os.ReadFile(filepath.Join(installed, filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: the installed bytes differ from the signed bytes", name)
		}
	}
}

// R-016: a debug microVM image set (never shipped) is refused by the
// content importer unless both --debug-set and --debug-key are given; with
// both it is verified against that key alone, and the driver's load boots
// it only under that key.
func TestVMDebugSetImportRefusals(t *testing.T) {
	vendorPub, vendorPriv := vmTestKey(t)
	debugPub, debugPriv := vmTestKey(t)
	vendor := []ed25519.PublicKey{vendorPub}
	debug := func(d *sandboximage.VMDescriptor) { d.Debug = true }

	t.Run("a debug set without the flags is refused, whoever signed it", func(t *testing.T) {
		for name, priv := range map[string]ed25519.PrivateKey{"vendor key": vendorPriv, "debug key": debugPriv} {
			store := vmContentStore(t.TempDir())
			_, err := sandboxContentImport(store, vendor, writeVMTestSetWith(t, priv, 1, "1.0.0", "1.40.0", debug).dir)
			if err == nil {
				t.Fatalf("%s: a debug set imported without --debug-set and --debug-key", name)
			}
			vmAssertNothingInstalled(t, store)
		}
	})
	t.Run("the flags alone are refused", func(t *testing.T) {
		if _, err := sandboxImportDebugKeyFlag(true, ""); err == nil || !strings.Contains(err.Error(), "--debug-key") {
			t.Fatalf("--debug-set without a key: %v", err)
		}
		keyFile := filepath.Join(t.TempDir(), "debug-key.pub")
		if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(debugPub)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := sandboxImportDebugKeyFlag(false, keyFile); err == nil || !strings.Contains(err.Error(), "--debug-set") {
			t.Fatalf("--debug-key without --debug-set: %v", err)
		}
		if k, err := sandboxImportDebugKeyFlag(true, keyFile); err != nil || !k.Equal(debugPub) {
			t.Fatalf("both flags: %v", err)
		}
		if err := os.WriteFile(keyFile, []byte("not a key"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := sandboxImportDebugKeyFlag(true, keyFile); err == nil {
			t.Fatal("a malformed debug key was read")
		}
	})
	t.Run("a release set under --debug-set is refused", func(t *testing.T) {
		store := vmContentStore(t.TempDir())
		if _, err := sandboxContentImportWith(store, vendor, writeVMTestSet(t, debugPriv, 1, "1.0.0", "1.40.0").dir, debugPub); err == nil || !strings.Contains(err.Error(), sandboximage.ReasonDebugSet) {
			t.Fatalf("a release set under the debug flags: %v", err)
		}
		vmAssertNothingInstalled(t, store)
	})
	t.Run("a debug set signed by another key is refused under --debug-key", func(t *testing.T) {
		store := vmContentStore(t.TempDir())
		if _, err := sandboxContentImportWith(store, vendor, writeVMTestSetWith(t, vendorPriv, 1, "1.0.0", "1.40.0", debug).dir, debugPub); err == nil {
			t.Fatal("a debug set signed by the vendor key imported under the debug key")
		}
		vmAssertNothingInstalled(t, store)
	})
	t.Run("with both flags it installs and boots only under the debug key", func(t *testing.T) {
		store := vmContentStore(t.TempDir())
		if _, err := sandboxContentImportWith(store, vendor, writeVMTestSetWith(t, debugPriv, 1, "1.0.0", "1.40.0", debug).dir, debugPub); err != nil {
			t.Fatal(err)
		}
		s := loadVMImageSet(store, contentchan.Trust{VendorKeys: vendor}, "", "1.40.0")
		if !s.res.OK || !s.res.Descriptor.Debug {
			t.Fatalf("the debug set did not load under its recorded key: %+v", s.res)
		}
		if line := sandboxContentStatusLine(store, contentchan.Trust{VendorKeys: vendor}, content.SandboxRootfs); !strings.Contains(line, "DEBUG image set") {
			t.Errorf("content status does not say debug: %s", line)
		}
		// The recorded key widened past its owner (POSIX: a group bit;
		// Windows: the default, inherited DACL of a plain write) is no key.
		kp := filepath.Join(store.Root, sandboxDebugKeyFile)
		keyText, err := os.ReadFile(kp)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(kp); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(kp, keyText, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(kp, 0o644); err != nil {
			t.Fatal(err)
		}
		if s := loadVMImageSet(store, contentchan.Trust{VendorKeys: vendor}, "", "1.40.0"); s.res.OK {
			t.Fatal("a debug key file readable past its owner was trusted")
		}
		if err := writeSandboxDebugKey(store.Root, debugPub); err != nil {
			t.Fatal(err)
		}
		if s := loadVMImageSet(store, contentchan.Trust{VendorKeys: vendor}, "", "1.40.0"); !s.res.OK {
			t.Fatalf("the rewritten owner-only debug key is not trusted: %+v", s.res)
		}
		// A release set imported later removes the debug key.
		if _, err := sandboxContentImport(store, vendor, writeVMTestSet(t, vendorPriv, 2, "1.1.0", "1.40.0").dir); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(kp); !os.IsNotExist(err) {
			t.Fatalf("the debug key outlived a release import: %v", err)
		}
	})
}
