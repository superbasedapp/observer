package main

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboximage"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// sandboxvm_debug_test.go covers the debug image set's signing step (R-016):
// -debug signs only a debug build, never with a vendor key, marks the
// descriptor debug and writes debug-key.pub; a debug build is never signed
// as a release set.
func TestSandboxVMDebugSigning(t *testing.T) {
	debugPub, debugKey := writeTestKeyFile(t)
	vendorPub, vendorKey := writeTestKeyFile(t)
	restore := acceptedVendorKeys
	acceptedVendorKeys = func() []ed25519.PublicKey { return []ed25519.PublicKey{vendorPub} }
	t.Cleanup(func() { acceptedVendorKeys = restore })
	debugBuild := func(t *testing.T) string {
		b := fakeVMBuild(t)
		if err := os.WriteFile(filepath.Join(b, vmDebugMarker), []byte("debug\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return b
	}
	rootfs := func(build, out string, extra ...string) error {
		return run(append(append([]string{"sandboxrootfs"}, vmVerbArgs(build, out)...), extra...), os.Stdout)
	}

	t.Run("a debug build with its marker deleted is still refused (LEFT2 audit S6)", func(t *testing.T) {
		b := fakeVMBuild(t)
		writeTestInitrd(t, filepath.Join(b, "initrd.img"), debugInitForTest(t))
		err := rootfs(b, t.TempDir(), "-key", vendorKey, "-manifest-version", "1")
		if err == nil || !strings.Contains(err.Error(), "debug build") {
			t.Fatalf("a debug initrd with no marker file was signed as a release set: %v", err)
		}
	})
	t.Run("a release initrd signs as a release set", func(t *testing.T) {
		b := fakeVMBuild(t)
		writeTestInitrd(t, filepath.Join(b, "initrd.img"), readRecipeFileForTest(t, "init"))
		if err := rootfs(b, t.TempDir(), "-key", vendorKey, "-manifest-version", "1"); err != nil {
			t.Fatalf("a release initrd was refused: %v", err)
		}
	})
	t.Run("a debug build is never signed as a release set", func(t *testing.T) {
		err := rootfs(debugBuild(t), t.TempDir(), "-key", vendorKey, "-manifest-version", "1")
		if err == nil || !strings.Contains(err.Error(), "debug build") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("-debug signs only a debug build", func(t *testing.T) {
		err := rootfs(fakeVMBuild(t), t.TempDir(), "-debug", "-key", debugKey, "-manifest-version", "1")
		if err == nil || !strings.Contains(err.Error(), "no debug marker") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("-debug refuses the vendor key", func(t *testing.T) {
		err := rootfs(debugBuild(t), t.TempDir(), "-debug", "-key", vendorKey, "-manifest-version", "1")
		if err == nil || !strings.Contains(err.Error(), "vendor key") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("-debug needs a key", func(t *testing.T) {
		if err := rootfs(debugBuild(t), t.TempDir(), "-debug"); err == nil || !strings.Contains(err.Error(), "-debug needs -key") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("-debug with a throwaway key", func(t *testing.T) {
		out := t.TempDir()
		if err := rootfs(debugBuild(t), out, "-debug", "-key", debugKey, "-manifest-version", "1"); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(out, string(content.SandboxRootfs), sandboximage.VMDescriptorName))
		if err != nil {
			t.Fatal(err)
		}
		d, err := sandboximage.ParseVMDescriptor(b)
		if err != nil || !d.Debug {
			t.Fatalf("descriptor %+v %v, want debug", d, err)
		}
		pub, err := os.ReadFile(filepath.Join(out, "debug-key.pub"))
		if err != nil || strings.TrimSpace(string(pub)) != hex.EncodeToString(debugPub) {
			t.Fatalf("debug-key.pub %q %v", pub, err)
		}
		release, _ := recipeDigestFor(filepath.Join("..", "..", "deploy", "sandbox-vm-image"), false)
		if d.RecipeSHA256 == release {
			t.Fatal("the debug set's recipe digest does not cover the debug variant")
		}
	})
}

// readRecipeFileForTest reads one file of the VM recipe directory.
func readRecipeFileForTest(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "sandbox-vm-image", name)) //nolint:gosec // G304: the repository's recipe
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// debugInitForTest is the debug /init build.sh --debug derives from the
// release one.
func debugInitForTest(t *testing.T) string {
	t.Helper()
	release := readRecipeFileForTest(t, "init")
	d := strings.Replace(release, "switch_root /newroot /run/observer-boot/observer-guest", "switch_root /newroot /usr/libexec/observer-debug/init-wrapper /run/observer-boot/observer-guest", 1)
	if d == release {
		t.Fatal("the release /init has no switch_root line to hand over")
	}
	return d
}

// writeTestInitrd writes a gzip newc cpio holding ".", "./bin" and "./init"
// as build.sh packs the initramfs.
func writeTestInitrd(t *testing.T, path, initBody string) {
	t.Helper()
	var raw bytes.Buffer
	entry := func(name string, mode uint32, data []byte) {
		fmt.Fprintf(&raw, "070701%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X", 1, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name)+1, 0)
		raw.WriteString(name)
		raw.WriteByte(0)
		for raw.Len()%4 != 0 {
			raw.WriteByte(0)
		}
		raw.Write(data)
		for raw.Len()%4 != 0 {
			raw.WriteByte(0)
		}
	}
	entry(".", 0o040755, nil)
	entry("./bin", 0o040755, nil)
	entry("./init", 0o100755, []byte(initBody))
	entry("TRAILER!!!", 0, nil)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(raw.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, gz.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}
