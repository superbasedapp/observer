//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The source scan below finds every declared keychain service, the sandbox
// drivers' among them, so it runs where the sandbox is built and the
// sandbox seam (uninstall_keystore_sandbox.go) is filled.

// keystoreServiceMark is a literal every match of the service-name regexp
// holds once its line is lower-cased. The regexp is case-insensitive, and
// while its "s" (and the "k" of KeychainID) also fold to non-ASCII letters
// (U+017F, U+212A), "b", "o" and "-" fold only to their own ASCII cases,
// which bytes.ToLower maps back: a line without the mark cannot match.
var keystoreServiceMark = []byte(`bo-`)

// TestObserverKeystoreServicesAreListed: every keychain service name the
// source declares is in observerKeystoreServices, so uninstall removes it.
func TestObserverKeystoreServicesAreListed(t *testing.T) {
	root := filepath.Join("..", "..")
	re := regexp.MustCompile(`(?i)(KeystoreService|ServiceName|KeychainID)\b[^"\n]*"(sbo-[a-z0-9-]+-v[0-9]+)"`)
	seen := map[string]string{}
	for _, dir := range []string{"cmd", "internal"} {
		_ = filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") || strings.Contains(p, "orgserver") {
				return nil
			}
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				return nil
			}
			// A match never crosses a line ([^"\n]* and the literals hold
			// no newline) and always holds keystoreServiceMark once
			// lower-cased, so the regexp runs only on the lines that do:
			// the same matches as running it on the whole file, without
			// scanning every line of the tree with a case-insensitive
			// alternation (100 s under -race).
			if !bytes.Contains(bytes.ToLower(b), keystoreServiceMark) {
				return nil
			}
			for _, line := range bytes.Split(b, []byte("\n")) {
				if !bytes.Contains(bytes.ToLower(line), keystoreServiceMark) {
					continue
				}
				for _, m := range re.FindAllSubmatch(line, -1) {
					seen[string(m[2])] = p
				}
			}
			return nil
		})
	}
	if len(seen) < 6 {
		t.Fatalf("the scan found only %v", seen)
	}
	for svc, at := range seen {
		if !slices.Contains(staticKeystoreServices(), svc) {
			t.Errorf("%s (declared in %s) is not in observerKeystoreServices or a sandbox row's KeystoreServices", svc, at)
		}
	}
}
