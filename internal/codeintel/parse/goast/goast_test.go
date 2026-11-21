package goast

import (
	"context"
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/codeintel"
	"github.com/marmutapp/superbased-observer/internal/codeintel/parse"
)

// sampleSrc is a representative Go file. Line numbers are 1-based and
// counted explicitly below so the test asserts exact spans.
//
//	 1: package sample
//	 2:
//	 3: import (
//	 4: 	"fmt"
//	 5: 	js "encoding/json"
//	 6: )
//	 7:
//	 8: // TopLevel is a top-level function.
//	 9: func TopLevel() string {
//	10: 	return fmt.Sprintf("hi")
//	11: }
//	12:
//	13: // Widget is a struct type.
//	14: type Widget struct {
//	15: 	Name string
//	16: }
//	17:
//	18: // Shaper is an interface type.
//	19: type Shaper interface {
//	20: 	Area() float64
//	21: }
//	22:
//	23: // ID is a type alias-ish named type.
//	24: type ID int
//	25:
//	26: // Render is a pointer-receiver method calling a func and a method.
//	27: func (w *Widget) Render() string {
//	28: 	s := TopLevel()
//	29: 	return js.Marshal(s)
//	30: }
const sampleSrc = `package sample

import (
	"fmt"
	js "encoding/json"
)

// TopLevel is a top-level function.
func TopLevel() string {
	return fmt.Sprintf("hi")
}

// Widget is a struct type.
type Widget struct {
	Name string
}

// Shaper is an interface type.
type Shaper interface {
	Area() float64
}

// ID is a type alias-ish named type.
type ID int

// Render is a pointer-receiver method calling a func and a method.
func (w *Widget) Render() string {
	s := TopLevel()
	return js.Marshal(s)
}
`

func TestCapabilities(t *testing.T) {
	p := New()
	got := p.Capabilities(parse.LangGo)
	want := codeintel.LanguageCapability{Symbols: true, ExactSpans: true, Imports: true, Calls: true}
	if got != want {
		t.Fatalf("Capabilities(go) = %+v, want %+v", got, want)
	}
	if (p.Capabilities(parse.LangPython) != codeintel.LanguageCapability{}) {
		t.Fatalf("Capabilities(python) should be zero value")
	}
	langs := p.Languages()
	if len(langs) != 1 || langs[0] != parse.LangGo {
		t.Fatalf("Languages() = %v, want [go]", langs)
	}
}

func TestParseNodes(t *testing.T) {
	p := New()
	res, err := p.Parse(context.Background(), []byte(sampleSrc), parse.LangGo, "sample.go")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if res.Parser != "goast" {
		t.Fatalf("Parser = %q, want goast", res.Parser)
	}

	type want struct {
		kind, name, fqn    string
		startLine, endLine int
	}
	wants := []want{
		{"function", "TopLevel", "TopLevel", 9, 11},
		{"class", "Widget", "Widget", 14, 16},
		{"interface", "Shaper", "Shaper", 19, 21},
		{"type", "ID", "ID", 24, 24},
		{"method", "Render", "Widget.Render", 27, 30},
	}
	if len(res.Nodes) != len(wants) {
		t.Fatalf("node count = %d, want %d; nodes=%+v", len(res.Nodes), len(wants), res.Nodes)
	}
	for i, w := range wants {
		n := res.Nodes[i]
		if n.Kind != w.kind || n.Name != w.name || n.FQN != w.fqn {
			t.Errorf("node[%d] = {kind:%q name:%q fqn:%q}, want {kind:%q name:%q fqn:%q}",
				i, n.Kind, n.Name, n.FQN, w.kind, w.name, w.fqn)
		}
		if n.StartLine != w.startLine || n.EndLine != w.endLine {
			t.Errorf("node[%d] %s span = [%d,%d], want [%d,%d]",
				i, n.Name, n.StartLine, n.EndLine, w.startLine, w.endLine)
		}
		if n.StartByte < 0 || n.EndByte <= n.StartByte {
			t.Errorf("node[%d] %s bad byte span [%d,%d]", i, n.Name, n.StartByte, n.EndByte)
		}
		if n.Signature == "" {
			t.Errorf("node[%d] %s empty signature", i, n.Name)
		}
	}
}

func TestParseImports(t *testing.T) {
	p := New()
	res, err := p.Parse(context.Background(), []byte(sampleSrc), parse.LangGo, "sample.go")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(res.Imports) != 2 {
		t.Fatalf("import count = %d, want 2; imports=%+v", len(res.Imports), res.Imports)
	}
	if res.Imports[0].Path != "fmt" || res.Imports[0].Alias != "" {
		t.Errorf("import[0] = {path:%q alias:%q}, want {fmt }", res.Imports[0].Path, res.Imports[0].Alias)
	}
	if res.Imports[0].StartLine != 4 {
		t.Errorf("import[0] StartLine = %d, want 4", res.Imports[0].StartLine)
	}
	if res.Imports[1].Path != "encoding/json" || res.Imports[1].Alias != "js" {
		t.Errorf("import[1] = {path:%q alias:%q}, want {encoding/json js}", res.Imports[1].Path, res.Imports[1].Alias)
	}
	if res.Imports[1].StartLine != 5 {
		t.Errorf("import[1] StartLine = %d, want 5", res.Imports[1].StartLine)
	}
}

func TestParseCalls(t *testing.T) {
	p := New()
	res, err := p.Parse(context.Background(), []byte(sampleSrc), parse.LangGo, "sample.go")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	// Index of Render in the (sorted) Nodes slice for Enclosing checks.
	renderIdx := -1
	for i, n := range res.Nodes {
		if n.Name == "Render" {
			renderIdx = i
		}
	}
	if renderIdx == -1 {
		t.Fatalf("Render node not found")
	}
	topLevelIdx := -1
	for i, n := range res.Nodes {
		if n.Name == "TopLevel" {
			topLevelIdx = i
		}
	}

	// Build name -> enclosing map; assert the expected calls are present.
	byName := map[string]codeintel.CallSite{}
	for _, c := range res.Calls {
		byName[c.Name] = c
	}

	for _, name := range []string{"Sprintf", "TopLevel", "Marshal"} {
		if _, ok := byName[name]; !ok {
			t.Errorf("expected call %q not found; calls=%+v", name, res.Calls)
		}
	}

	// Sprintf is called inside TopLevel's body.
	if c, ok := byName["Sprintf"]; ok && c.Enclosing != topLevelIdx {
		t.Errorf("Sprintf Enclosing = %d, want %d (TopLevel)", c.Enclosing, topLevelIdx)
	}
	// TopLevel() and Marshal() are called inside Render's body.
	if c, ok := byName["TopLevel"]; ok && c.Enclosing != renderIdx {
		t.Errorf("TopLevel call Enclosing = %d, want %d (Render)", c.Enclosing, renderIdx)
	}
	if c, ok := byName["Marshal"]; ok && c.Enclosing != renderIdx {
		t.Errorf("Marshal Enclosing = %d, want %d (Render)", c.Enclosing, renderIdx)
	}
}

// localVarSrc exercises local-variable receiver inference (W2 §4.1): each
// method call's receiver is typed from its declaration, and ambiguous /
// uninferable cases stay unbound (RecvType "").
const localVarSrc = `package sample

type Foo struct{}

func NewFoo() *Foo { return &Foo{} }

func (f *Foo) Do() {}

func viaConstructor() {
	a := NewFoo()
	a.Do()
}

func viaVar() {
	var b Foo
	b.Do()
}

func viaVarPtr() {
	var c *Foo
	c.Do()
}

func viaComposite() {
	d := Foo{}
	d.Do()
}

func viaCompositePtr() {
	e := &Foo{}
	e.Do()
}

func viaNew() {
	g := new(Foo)
	g.Do()
}

func qualifiedCtorNotInferred() {
	h := other.NewFoo()
	h.Do()
}

func conflictingReassign() {
	k := NewFoo()
	k = somethingUnknown()
	k.Do()
}
`

func TestLocalVarReceiverInference(t *testing.T) {
	p := New()
	res, err := p.Parse(context.Background(), []byte(localVarSrc), parse.LangGo, "lv.go")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// Map each Do() call to the receiver type inferred for it, keyed by the
	// enclosing function name.
	got := map[string]string{}
	for _, c := range res.Calls {
		if c.Name != "Do" {
			continue
		}
		if c.Enclosing < 0 || c.Enclosing >= len(res.Nodes) {
			t.Fatalf("Do() call has no enclosing node: %+v", c)
		}
		got[res.Nodes[c.Enclosing].Name] = c.RecvType
	}
	want := map[string]string{
		"viaConstructor":           "Foo",
		"viaVar":                   "Foo",
		"viaVarPtr":                "Foo",
		"viaComposite":             "Foo",
		"viaCompositePtr":          "Foo",
		"viaNew":                   "Foo",
		"qualifiedCtorNotInferred": "", // other.NewFoo() — another package's type
		"conflictingReassign":      "", // reassigned to an uninferable value -> dropped
	}
	for fn, wantType := range want {
		if got[fn] != wantType {
			t.Errorf("RecvType in %s = %q, want %q", fn, got[fn], wantType)
		}
	}
}

func TestDeterminism(t *testing.T) {
	p := New()
	a, err := p.Parse(context.Background(), []byte(sampleSrc), parse.LangGo, "sample.go")
	if err != nil {
		t.Fatalf("Parse #1: %v", err)
	}
	b, err := p.Parse(context.Background(), []byte(sampleSrc), parse.LangGo, "sample.go")
	if err != nil {
		t.Fatalf("Parse #2: %v", err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("Parse is not deterministic:\n#1=%+v\n#2=%+v", a, b)
	}
}

func TestMalformedNoPanic(t *testing.T) {
	p := New()
	bad := []byte("package x\nfunc Broken( {\n  this is not go\n")
	// Must not panic. Either a best-effort result or a wrapped error is
	// acceptable; what matters is no panic and a usable-or-empty result.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Parse panicked on malformed input: %v", r)
		}
	}()
	res, err := p.Parse(context.Background(), bad, parse.LangGo, "bad.go")
	_ = res
	_ = err // either nil (partial) or a wrapped goast.Parse error is fine.
}

// TestComplexityRows is one case per Go row of parse/complexity's rule
// table: each body holds exactly one decision of that row, so the function
// reads 2; the default arms read 1.
func TestComplexityRows(t *testing.T) {
	cases := []struct {
		row  string
		body string
		want int
	}{
		{"IfStmt if", "if x > 0 { return }", 2},
		{"IfStmt else-if counts once more", "if x > 0 { return } else if x < 0 { return }", 3},
		{"ForStmt for", "for i := 0; i < x; i++ {}", 2},
		{"ForStmt bare for", "for { break }", 2},
		{"RangeStmt for", "for range x {}", 2},
		{"CaseClause case", "switch x { case 1: }", 2},
		{"CaseClause default not counted", "switch x { default: }", 1},
		{"CommClause case", "var c chan int; select { case <-c: }", 2},
		{"CommClause default not counted", "select { default: }", 1},
		{"BinaryExpr &&", "_ = x > 0 && x < 9", 2},
		{"BinaryExpr ||", "_ = x > 0 || x < 9", 2},
		{"BinaryExpr + is not a decision", "_ = x + 1", 1},
		{"func literal counts toward the enclosing function", "f := func() { if x > 0 {} }; f()", 2},
	}
	for _, tc := range cases {
		t.Run(tc.row, func(t *testing.T) {
			src := "package p\n\nfunc f(x int) {\n\t" + tc.body + "\n}\n"
			res, err := New().(parse.OptionParser).ParseWith(context.Background(), []byte(src), "go", "p.go", parse.Options{Complexity: true})
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Nodes) != 1 || res.Nodes[0].Complexity != tc.want {
				t.Fatalf("nodes %+v, want one function of complexity %d", res.Nodes, tc.want)
			}
		})
	}
}

func TestComplexityPerFunctionAndKind(t *testing.T) {
	src := `package p

type T struct{}

func (T) M(x int) int {
	if x > 0 && x < 9 {
		return 1
	}
	return 0
}

func g() {}
`
	res, err := New().(parse.OptionParser).ParseWith(context.Background(), []byte(src), "go", "p.go", parse.Options{Complexity: true})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := New().Parse(context.Background(), []byte(src), "go", "p.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range plain.Nodes {
		if n.Complexity != 0 {
			t.Errorf("Parse without the option counted %s: %d", n.Name, n.Complexity)
		}
	}
	got := map[string]int{}
	for _, n := range res.Nodes {
		got[n.Kind+" "+n.Name] = n.Complexity
	}
	want := map[string]int{"class T": 0, "method M": 3, "function g": 1}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: complexity %d, want %d (all %v)", k, got[k], v, got)
		}
	}
}
