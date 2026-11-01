package invariant

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/keystore"
)

const goKeyringImport = "github.com/zalando/go-keyring"

// TestKeystoreTestsNeverWriteTheOSKeychain fails when a test could write to
// the user's real OS keychain (Windows 11 Pro rerun 2026-10-25, D2: the
// cloud tests wrote a device key and an API token into the real Credential
// Manager). Three rules:
//
//   - a test binary that links internal/keystore runs on the in-memory
//     keyring (keystore.OSKeyringActive is false);
//   - no non-test Go file outside internal/keystore imports go-keyring, so
//     every keychain call goes through internal/keystore's seam;
//   - a _test.go file that imports go-keyring (to simulate an unavailable
//     keychain) belongs to a package whose own code imports
//     internal/keystore, so the in-memory keyring is installed first.
func TestKeystoreTestsNeverWriteTheOSKeychain(t *testing.T) {
	if keystore.OSKeyringActive() {
		t.Fatal("a test binary reaches the real OS keychain")
	}
	root := repoRoot(t)
	type pkg struct {
		importsKeystore bool
		testsKeyring    []string
	}
	pkgs := map[string]*pkg{}
	for _, top := range []string{"cmd", "internal", "tests", "tools", "scripts"} {
		_ = filepath.WalkDir(filepath.Join(root, top), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if n := d.Name(); n == "node_modules" || n == "testdata" || strings.HasPrefix(n, ".") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, ".go") {
				return nil
			}
			src, rerr := os.ReadFile(p)
			if rerr != nil {
				return nil
			}
			f, perr := parser.ParseFile(token.NewFileSet(), p, src, parser.ImportsOnly)
			if perr != nil {
				return nil
			}
			dir := filepath.Dir(p)
			if pkgs[dir] == nil {
				pkgs[dir] = &pkg{}
			}
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			isTest := strings.HasSuffix(p, "_test.go")
			for _, im := range f.Imports {
				path, _ := strconv.Unquote(im.Path.Value)
				switch {
				case path == "github.com/marmutapp/superbased-observer/internal/keystore" && !isTest:
					pkgs[dir].importsKeystore = true
				case path == goKeyringImport && strings.HasPrefix(rel, "internal/keystore/"):
				case path == goKeyringImport && !isTest:
					t.Errorf("%s imports go-keyring directly; reach the keychain through internal/keystore", rel)
				case path == goKeyringImport:
					pkgs[dir].testsKeyring = append(pkgs[dir].testsKeyring, rel)
				}
			}
			return nil
		})
	}
	for _, p := range pkgs {
		if len(p.testsKeyring) > 0 && !p.importsKeystore {
			t.Errorf("%v import go-keyring in a package that does not link internal/keystore, so the in-memory keyring may not be installed", p.testsKeyring)
		}
	}
}
