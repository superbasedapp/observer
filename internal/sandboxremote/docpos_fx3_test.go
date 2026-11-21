package sandboxremote

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestDocCommentsSitOnTheirDeclaration (FX3-A9): every documented
// top-level declaration's comment starts with its own name, so a comment
// never drifts onto the declaration below it (as BuildConsentScreen's and
// neverWorked's had).
func TestDocCommentsSitOnTheirDeclaration(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		fs := token.NewFileSet()
		af, err := parser.ParseFile(fs, f, nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range af.Decls {
			name, doc := declDoc(d)
			if doc == nil || name == "" {
				continue
			}
			if w := strings.Fields(doc.Text()); len(w) > 0 && !strings.HasPrefix(w[0], name) {
				t.Errorf("%s: the comment on %s starts %q", fs.Position(d.Pos()), name, w[0])
			}
		}
	}
}

// declDoc is a declaration's name and doc comment (a grouped const, var or
// type block has no single name and is skipped).
func declDoc(d ast.Decl) (string, *ast.CommentGroup) {
	switch d := d.(type) {
	case *ast.FuncDecl:
		return d.Name.Name, d.Doc
	case *ast.GenDecl:
		if len(d.Specs) != 1 || d.Lparen.IsValid() {
			return "", nil
		}
		switch s := d.Specs[0].(type) {
		case *ast.TypeSpec:
			return s.Name.Name, d.Doc
		case *ast.ValueSpec:
			return s.Names[0].Name, d.Doc
		}
	}
	return "", nil
}
