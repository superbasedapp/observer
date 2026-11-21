package sandboxseccomp

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// xsysTable reads SYS_* from golang.org/x/sys/unix's zsysnum file for
// goarch, by source, so both tables are pinned on any host. A missing
// source FAILS (audit N2-A10, lane FU4): a skip would drop the pin of the
// non-native table in a container with an empty module cache, and a wrong
// arm64 number would then pass CI on amd64. go/build resolves the module
// through `go list`, which downloads it when the cache is empty and the
// network allows; offline, run `go mod download golang.org/x/sys` first.
func xsysTable(t *testing.T, goarch string) map[string]uint32 {
	t.Helper()
	pkg, err := build.Import("golang.org/x/sys/unix", ".", build.FindOnly)
	if err != nil || pkg.Dir == "" {
		t.Fatalf("golang.org/x/sys/unix source not found (run `go mod download golang.org/x/sys`; the pin never skips): %v", err)
	}
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(pkg.Dir, "zsysnum_linux_"+goarch+".go"), nil, 0)
	if err != nil {
		t.Fatalf("parse x/sys table: %v", err)
	}
	out := map[string]uint32{}
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}
		for _, s := range g.Specs {
			v := s.(*ast.ValueSpec)
			for i, n := range v.Names {
				if !strings.HasPrefix(n.Name, "SYS_") || i >= len(v.Values) {
					continue
				}
				lit, ok := v.Values[i].(*ast.BasicLit)
				if !ok {
					continue
				}
				x, err := strconv.ParseUint(lit.Value, 0, 32)
				if err != nil {
					continue
				}
				out[strings.ToLower(strings.TrimPrefix(n.Name, "SYS_"))] = uint32(x)
			}
		}
	}
	return out
}

// TestSysnumPinnedToXSys pins each hand-written table against x/sys.
func TestSysnumPinnedToXSys(t *testing.T) {
	for goarch, spec := range archs {
		ref := xsysTable(t, goarch)
		for name, nr := range spec.nr {
			want, ok := ref[name]
			if !ok {
				t.Errorf("%s: x/sys has no SYS_%s", goarch, strings.ToUpper(name))
				continue
			}
			if nr != want {
				t.Errorf("%s: %s is %d here, %d in x/sys", goarch, name, nr, want)
			}
		}
	}
}
