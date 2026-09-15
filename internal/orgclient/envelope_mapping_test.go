package orgclient

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestPushEnvelopeMapsEveryBatchFamily is the reflective sentinel for the
// PushBatch -> PushEnvelope mapping in PushOnce. SelectUnpushedSince composes
// a wire family into a PushBatch slice, the envelope-budget and snap-gate
// sentinels walk PushBatch by reflection, but the envelope itself is a
// hand-maintained struct literal in client.go - and twice now a family was
// composed, budgeted and then silently dropped before json.Marshal (the obs
// slices once; the W2/W3 task and tool-account wires a second time). This test
// parses client.go, finds the orgcontract.PushEnvelope composite literal, and
// requires that every PushBatch slice field whose NAME also exists on
// PushEnvelope appears as a key in that literal. A family that deliberately
// maps under a different name is not a same-name pair and is out of scope; a
// family that must not ship goes in the exception list below with a reason.
func TestPushEnvelopeMapsEveryBatchFamily(t *testing.T) {
	// Same-name PushBatch slice fields that are deliberately NOT mapped into
	// the envelope. Empty today: every composed family ships.
	exceptions := map[string]string{}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "client.go", nil, 0)
	if err != nil {
		t.Fatalf("parse client.go: %v", err)
	}
	keys := map[string]bool{}
	found := 0
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "PushEnvelope" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "orgcontract" {
			return true
		}
		found++
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if id, ok := kv.Key.(*ast.Ident); ok {
				keys[id.Name] = true
			}
		}
		return true
	})
	if found != 1 {
		t.Fatalf("expected exactly one orgcontract.PushEnvelope literal in client.go, found %d", found)
	}

	batchT := reflect.TypeOf(store.PushBatch{})
	envT := reflect.TypeOf(orgcontract.PushEnvelope{})
	checked := 0
	for i := 0; i < batchT.NumField(); i++ {
		f := batchT.Field(i)
		if f.Type.Kind() != reflect.Slice {
			continue
		}
		ef, ok := envT.FieldByName(f.Name)
		if !ok {
			continue // a differently-named family; not a same-name pair
		}
		if ef.Type != f.Type {
			t.Errorf("PushBatch.%s and PushEnvelope.%s share a name but not a type (%s vs %s)", f.Name, f.Name, f.Type, ef.Type)
			continue
		}
		checked++
		if reason, exempt := exceptions[f.Name]; exempt {
			if keys[f.Name] {
				t.Errorf("PushBatch.%s is listed as an exception (%s) but IS mapped into the envelope - remove one", f.Name, reason)
			}
			continue
		}
		if !keys[f.Name] {
			t.Errorf("PushBatch.%s is composed by SelectUnpushedSince but never mapped into the PushEnvelope literal in client.go - the rows are dropped before json.Marshal and the server ingest can never fire", f.Name)
		}
	}
	if checked < 20 {
		t.Fatalf("sentinel checked only %d same-name families; the reflection walk is broken", checked)
	}
}
