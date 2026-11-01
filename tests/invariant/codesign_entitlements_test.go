package invariant

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// TestMacOSEntitlementsAreExactlyTheWazeroOne pins the one entitlement the
// signed macOS binaries carry. Under the hardened runtime, code
// intelligence's wazero compiler maps memory writable then executable
// without MAP_JIT and is killed (Code Signature Invalid) on the first parse;
// com.apple.security.cs.allow-jit does not help and
// com.apple.security.cs.allow-unsigned-executable-memory does (MAC-8,
// 2026-10-30, P-200). Any other entitlement widens the runtime and needs its
// own ledger row (docs/security.md CODESIGN-2).
func TestMacOSEntitlementsAreExactlyTheWazeroOne(t *testing.T) {
	root := repoRoot(t)
	b, err := os.ReadFile(filepath.Join(root, "installer", "macos", "observer.entitlements"))
	if err != nil {
		t.Fatalf("installer/macos/observer.entitlements: %v (the signed build needs it, CODESIGN-2)", err)
	}
	keys := regexp.MustCompile(`<key>([^<]+)</key>`).FindAllStringSubmatch(string(b), -1)
	if len(keys) != 1 || keys[0][1] != "com.apple.security.cs.allow-unsigned-executable-memory" {
		t.Fatalf("entitlement keys = %v, want exactly com.apple.security.cs.allow-unsigned-executable-memory", keys)
	}
	if !regexp.MustCompile(`</key>\s*<true/>`).Match(b) {
		t.Fatal("the entitlement must be set to <true/>")
	}
	// The ledger is private-only (docs/); the entitlement check above runs on
	// both trees.
	t.Run("ledger names it", func(t *testing.T) {
		skipInPublicTree(t, root, "docs/security.md")
		sec, err := os.ReadFile(filepath.Join(root, "docs", "security.md"))
		if err != nil {
			t.Fatal(err)
		}
		if !regexp.MustCompile(`CODESIGN-2[^\n]*allow-unsigned-executable-memory`).Match(sec) {
			t.Fatal("docs/security.md CODESIGN-2 must name the committed entitlement")
		}
	})
}
