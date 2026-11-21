package invariant

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	agentupdate "github.com/marmutapp/superbased-observer/internal/update"
)

// TestConnectWrapperCarriesTheInstallVerifier pins scripts/connect.ps1's
// Ed25519 verifier to a byte-identical copy of scripts/install.ps1's: the
// wrapper checks the installer's signature before running it, and Windows
// PowerShell 5.1 has no Ed25519 of its own, so it carries the same pure
// PowerShell verifier. A fix to one that misses the other fails here.
func TestConnectWrapperCarriesTheInstallVerifier(t *testing.T) {
	root := repoRoot(t)
	block := func(file string) string {
		raw, err := os.ReadFile(filepath.Join(root, "scripts", file))
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		s := string(raw)
		start := strings.Index(s, "# ------------------------------------------------------------ Ed25519 (RFC 8032)")
		end := strings.Index(s, "function Test-VerifierSelfCheck {")
		if start < 0 || end < start {
			t.Fatalf("%s: no Ed25519 block", file)
		}
		rest := s[end:]
		closing := strings.Index(rest, "\n}\n")
		if closing < 0 {
			t.Fatalf("%s: Test-VerifierSelfCheck has no end", file)
		}
		return s[start : end+closing+3]
	}
	if block("install.ps1") != block("connect.ps1") {
		t.Fatal("scripts/connect.ps1's Ed25519 verifier differs from scripts/install.ps1's; copy the block again")
	}
}

// TestInstallersCarryTheVendorKeys pins the vendor verification keys the
// edition installers (scripts/install.sh, scripts/install.ps1; T-729) check
// a release archive's <archive>.sig against to the set the agent itself
// accepts (internal/update/vendorkey.go). The installers cannot import Go,
// so each carries a copy; this test makes a key rotation that forgets one
// of them fail here instead of at a customer's first install, where an
// installer holding only the retired key would refuse every new release.
//
// The accepted set is VendorPublicKeyV1 plus the rotation slot
// VendorPublicKeyV0Previous while it is set: the same two constants
// update.VendorPublicKeys reads, in the same order.
func TestInstallersCarryTheVendorKeys(t *testing.T) {
	var want []string
	for _, k := range []string{agentupdate.VendorPublicKeyV1, agentupdate.VendorPublicKeyV0Previous} {
		if k == "" {
			continue
		}
		if _, err := agentupdate.ParseVendorKey(k); err != nil {
			t.Fatalf("vendorkey.go carries an unparseable key %q: %v", k, err)
		}
		want = append(want, k)
	}
	if len(want) == 0 {
		t.Fatal("vendorkey.go accepts no key, so the installers could verify nothing")
	}

	root := repoRoot(t)
	b64 := regexp.MustCompile(`[A-Za-z0-9+/]{43}=`)
	cases := []struct {
		file string
		line *regexp.Regexp
	}{
		{"scripts/install.sh", regexp.MustCompile(`(?m)^VENDOR_KEYS="([^"]*)"$`)},
		{"scripts/install.ps1", regexp.MustCompile(`(?m)^\$VendorKeys = @\(([^)]*)\)$`)},
		// The one-step connect wrappers (Getting started v2) verify the
		// installer through the signed SHA256SUMS with the same keys.
		{"scripts/connect.sh", regexp.MustCompile(`(?m)^VENDOR_KEYS="([^"]*)"$`)},
		{"scripts/connect.ps1", regexp.MustCompile(`(?m)^\$VendorKeys = @\(([^)]*)\)$`)},
	}
	for _, c := range cases {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(c.file)))
		if err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		m := c.line.FindAllSubmatch(raw, -1)
		if len(m) != 1 {
			t.Fatalf("%s: want exactly one vendor key list line, found %d", c.file, len(m))
		}
		got := b64.FindAllString(string(m[0][1]), -1)
		if strings.Join(got, " ") != strings.Join(want, " ") {
			g, w := append([]string(nil), got...), append([]string(nil), want...)
			sort.Strings(g)
			sort.Strings(w)
			t.Errorf("%s carries vendor keys %v, want %v (newest first, as internal/update/vendorkey.go)", c.file, got, want)
			if strings.Join(g, " ") == strings.Join(w, " ") {
				t.Errorf("%s: same keys, wrong order; keep the current key first", c.file)
			}
		}
	}
}
