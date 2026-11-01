package invariant

import (
	"go/ast"
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

// keystoreE2EExempt lists the test files that build an observer binary but
// never run it, each with the reason.
var keystoreE2EExempt = map[string]string{
	"tests/invariant/release_public_patch_test.go": "compiles the public tree to prove it builds; the binary is never run",
}

// TestE2EBinaryRunsUseTheMemoryKeystore (WINFIX2 audit finding 10): a test
// binary is on the in-memory keyring, but a test that builds the observer
// binary and RUNS it starts a separate process the testing.Testing() rule
// cannot reach. Every _test.go file that builds the observer binary (go
// build of ./cmd/observer, or of "." inside cmd/observer) must name
// keystore.EnvTestKeystore, the switch that puts the built process on the
// in-memory keyring; one that does not fails here, loudly, before its run
// can write to the developer's real keychain. A file that only compiles the
// binary is listed in keystoreE2EExempt with its reason.
func TestE2EBinaryRunsUseTheMemoryKeystore(t *testing.T) {
	if keystore.EnvTestKeystore != "SBO_TEST_KEYSTORE" || keystore.TestKeystoreMemory != "memory" {
		t.Fatal("the keystore switch changed; update every harness that sets it")
	}
	root := repoRoot(t)
	found := 0
	for _, top := range []string{"cmd", "internal", "tests", "tools"} {
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
			if !strings.HasSuffix(p, "_test.go") {
				return nil
			}
			src, rerr := os.ReadFile(p)
			if rerr != nil {
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			if !buildsObserverBinary(src, filepath.ToSlash(filepath.Dir(rel)) == "cmd/observer") {
				return nil
			}
			found++
			if why, ok := keystoreE2EExempt[rel]; ok && why != "" {
				return nil
			}
			if !strings.Contains(string(src), "EnvTestKeystore") {
				t.Errorf("%s builds and runs the observer binary without keystore.EnvTestKeystore: the run would reach the developer's real OS keychain", rel)
			}
			return nil
		})
	}
	if found < 4 {
		t.Fatalf("found %d test files that build the observer binary, want at least 4; the scan no longer matches how the harnesses build it", found)
	}
}

// buildsObserverBinary reports whether src runs `go build` of the observer
// command: a call whose string-literal arguments include "build" and either
// "./cmd/observer" or, inside cmd/observer itself, ".".
func buildsObserverBinary(src []byte, inCmdObserver bool) bool {
	f, err := parser.ParseFile(token.NewFileSet(), "", src, 0)
	if err != nil {
		return false
	}
	hit := false
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || hit {
			return !hit
		}
		var build, target bool
		for _, a := range call.Args {
			lit, ok := a.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			v, _ := strconv.Unquote(lit.Value)
			switch {
			case v == "build":
				build = true
			case v == "./cmd/observer", inCmdObserver && v == ".":
				target = true
			}
		}
		hit = build && target
		return !hit
	})
	return hit
}
