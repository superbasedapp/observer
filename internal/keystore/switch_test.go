package keystore

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestModeForTheTestSwitch (WINFIX2 audit finding 10): a test binary and a
// built binary a harness started with EnvTestKeystore=memory use the
// in-memory keyring; an unknown value refuses the OS keychain instead of
// reaching it; only an unset switch outside a test reaches the OS keychain.
func TestModeForTheTestSwitch(t *testing.T) {
	for _, c := range []struct {
		name  string
		test  bool
		value string
		want  keystoreMode
	}{
		{"a test binary", true, "", modeMemory},
		{"a test binary with a bad switch", true, "nope", modeMemory},
		{"a built binary under a harness", false, TestKeystoreMemory, modeMemory},
		{"a misspelt switch", false, "Memory", modeRefused},
		{"another value", false, "os", modeRefused},
		{"a real install", false, "", modeOS},
	} {
		if got := modeFor(c.test, c.value); got != c.want {
			t.Errorf("%s: modeFor = %d, want %d", c.name, got, c.want)
		}
	}
	if OSKeyringActive() {
		t.Fatal("this test binary reaches the OS keychain")
	}
}

// TestNoTestHelperInTheProductPackage (WINFIX4 audit finding 7): no
// non-test file of keystore takes a testing.TB. The keyring reset tests use
// is internal/keystore/keystoretest's, so a product binary never carries a
// function that clears the keyring.
func TestNoTestHelperInTheProductPackage(t *testing.T) {
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	scanned := 0
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name) //nolint:gosec // G304: this package's own source
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Type.Params == nil {
				continue
			}
			for _, p := range fn.Type.Params.List {
				if sel, ok := p.Type.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "testing" {
						t.Errorf("%s: %s takes testing.%s; test helpers belong in keystoretest", name, fn.Name.Name, sel.Sel.Name)
					}
				}
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no source file scanned")
	}
}
