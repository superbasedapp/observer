package guard

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// modelsActionTypes returns every string constant named Action* that the
// models package declares: the whole action-type vocabulary, read from the
// source so a new type cannot be missed.
func modelsActionTypes(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "models", "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("glob models: %v (%d files)", err, len(files))
	}
	fset := token.NewFileSet()
	var out []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, name := range vs.Names {
					if !strings.HasPrefix(name.Name, "Action") || i >= len(vs.Values) {
						continue
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					if v, err := strconv.Unquote(lit.Value); err == nil {
						out = append(out, v)
					}
				}
			}
		}
	}
	return out
}

// TestReplayDetailActionTypesCoverEvaluation pins ReplayDetailActionTypes to
// what EvaluateActions reads: every action type it evaluates (classifyKind),
// plus the compaction and prompt rows it acts on, is in the list, and the
// list holds nothing else. A type missing from the list would replay with an
// empty target (store.LoadGuardReplayInputs) and lose its verdicts.
func TestReplayDetailActionTypesCoverEvaluation(t *testing.T) {
	t.Parallel()
	list := ReplayDetailActionTypes()
	all := modelsActionTypes(t)
	if len(all) < 20 {
		t.Fatalf("read only %d action types from internal/models; the source scan is broken", len(all))
	}
	reads := func(at string) bool {
		_, evaluable := classifyKind(at)
		return evaluable || at == models.ActionContextCompacted || at == models.ActionUserPrompt
	}
	for _, at := range all {
		if reads(at) && !slices.Contains(list, at) {
			t.Errorf("EvaluateActions reads %q but ReplayDetailActionTypes omits it", at)
		}
	}
	for _, at := range list {
		if !reads(at) {
			t.Errorf("ReplayDetailActionTypes lists %q, which EvaluateActions never reads", at)
		}
		if !slices.Contains(all, at) {
			t.Errorf("ReplayDetailActionTypes lists %q, which is not a models action type", at)
		}
	}
}
