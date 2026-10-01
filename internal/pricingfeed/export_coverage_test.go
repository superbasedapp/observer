package pricingfeed

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// exportRowSource is the Tokenomics module's feed row. It is read as source
// (the model-pricing module is a separate go.mod and absent from the public
// tree), so this test skips wherever that file does not exist.
var exportRowSource = filepath.Join("..", "..", "model-pricing", "internal", "observerexport", "observerexport.go")

// TestEveryExportedFieldHasAConsumer pins the second hop of the pricing
// chain: every JSON field the Tokenomics export can emit on a feed row must
// exist on this module's Row, so no published price dimension is dropped
// at decode (2026-09-30 finding). The first hop, catalog component -> export
// field, is model-pricing's TestEveryRateComponentReachesTheFeed.
func TestEveryExportedFieldHasAConsumer(t *testing.T) {
	src, err := os.ReadFile(exportRowSource)
	if os.IsNotExist(err) {
		t.Skip("model-pricing module not present (public tree)")
	}
	if err != nil {
		t.Fatal(err)
	}
	f, err := parser.ParseFile(token.NewFileSet(), exportRowSource, src, 0)
	if err != nil {
		t.Fatal(err)
	}
	var exported []string
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "Row" {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return false
		}
		for _, fld := range st.Fields.List {
			if fld.Tag == nil {
				continue
			}
			tag, err := strconv.Unquote(fld.Tag.Value)
			if err != nil {
				t.Fatal(err)
			}
			if name := strings.Split(reflect.StructTag(tag).Get("json"), ",")[0]; name != "" && name != "-" {
				exported = append(exported, name)
			}
		}
		return false
	})
	if len(exported) == 0 {
		t.Fatalf("no json fields found on observerexport.Row in %s", exportRowSource)
	}

	consumer := map[string]bool{}
	var walk func(rt reflect.Type)
	walk = func(rt reflect.Type) {
		for i := 0; i < rt.NumField(); i++ {
			sf := rt.Field(i)
			if sf.Anonymous && sf.Type.Kind() == reflect.Struct {
				walk(sf.Type)
				continue
			}
			if name := strings.Split(sf.Tag.Get("json"), ",")[0]; name != "" {
				consumer[name] = true
			}
		}
	}
	walk(reflect.TypeOf(Row{}))
	for _, name := range exported {
		if !consumer[name] {
			t.Errorf("the Tokenomics export emits %q but pricingfeed.Row has no field for it: the consumer would drop it", name)
		}
	}
}
