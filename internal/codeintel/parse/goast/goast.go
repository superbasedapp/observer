// Package goast implements a parse.Parser for the Go language backed by
// the standard library go/parser, go/ast, and go/token. It produces
// exact byte/line spans and is CGO-free (pure stdlib), so it satisfies
// the ExactSpans capability tier (ADR-0005) and feeds aggressive
// body-collapse.
//
// It is a pure backend (CLAUDE.md anti-spaghetti rule 1): bytes in,
// codeintel.ParseResult out. No SQL, HTTP, fsnotify, or sibling
// internal subsystems — only stdlib + the codeintel facade + the parse
// package (enforced by internal/codeintel/imports_test.go).
package goast

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/codeintel"
	"github.com/marmutapp/superbased-observer/internal/codeintel/parse"
	"github.com/marmutapp/superbased-observer/internal/codeintel/parse/complexity"
)

// parserName is the backend identity recorded on every ParseResult so a
// persisted span can be traced to its producer (and later upgraded).
const parserName = "goast"

// excerptCap bounds Signature / RawText excerpts. These are declaration
// lines or call expressions, never bodies; the cap is a defensive guard
// against pathological single-line input.
const excerptCap = 500

// goParser is the go/ast-backed parse.Parser. It is stateless; New
// returns a shareable value.
type goParser struct{}

// New returns a parse.Parser for the Go language.
func New() parse.Parser { return goParser{} }

// Languages reports that this backend serves Go.
func (goParser) Languages() []codeintel.Language {
	return []codeintel.Language{parse.LangGo}
}

// Capabilities reports full extraction with exact spans for Go, and the
// zero capability for any other language.
func (goParser) Capabilities(lang codeintel.Language) codeintel.LanguageCapability {
	if lang == parse.LangGo {
		return codeintel.LanguageCapability{
			Symbols:    true,
			ExactSpans: true,
			Imports:    true,
			Calls:      true,
		}
	}
	return codeintel.LanguageCapability{}
}

// Parse turns Go source into a ParseResult. It parses with
// parser.SkipObjectResolution (spans only; no scope wiring needed) and
// is best-effort: a recoverable parse error still yields whatever the
// AST contains, with a nil error. Only when ParseFile returns no usable
// file at all does Parse return the wrapped error. It never panics. It
// extracts the base set; ParseWith adds the optional extractions.
func (p goParser) Parse(ctx context.Context, src []byte, lang codeintel.Language, filename string) (codeintel.ParseResult, error) {
	return p.ParseWith(ctx, src, lang, filename, parse.Options{})
}

// ParseWith is Parse under opts (parse.OptionParser): complexity is counted
// only when opts.Complexity is set.
func (p goParser) ParseWith(_ context.Context, src []byte, lang codeintel.Language, filename string, opts parse.Options) (codeintel.ParseResult, error) {
	result := codeintel.ParseResult{
		Lang:       lang,
		Capability: p.Capabilities(lang),
		Parser:     parserName,
	}
	if lang != parse.LangGo {
		return result, nil
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, parser.SkipObjectResolution)
	if file == nil {
		// No usable AST: surface the wrapped error so the caller can fail
		// open with context.
		if err != nil {
			return result, fmt.Errorf("goast.Parse: %w", err)
		}
		return result, nil
	}

	// Best-effort: parse errors with a partial AST are tolerated — we
	// extract what we can and return a nil error so downstream still
	// benefits. (Callers fail open on a non-nil error anyway.)
	result.Nodes = extractNodes(fset, file, src)
	result.Imports = extractImports(fset, file, src)
	// Nodes must be in their FINAL order before call Enclosing indices are
	// computed — Enclosing is an index into result.Nodes, so sorting Nodes
	// afterward would invalidate it. Sort Nodes + Imports first, resolve
	// calls against the sorted slice, then sort the calls themselves.
	sort.SliceStable(result.Nodes, func(i, j int) bool {
		if result.Nodes[i].StartLine != result.Nodes[j].StartLine {
			return result.Nodes[i].StartLine < result.Nodes[j].StartLine
		}
		return result.Nodes[i].Name < result.Nodes[j].Name
	})
	sort.SliceStable(result.Imports, func(i, j int) bool {
		return result.Imports[i].StartLine < result.Imports[j].StartLine
	})
	// Complexity: every decision point's offset, attributed to its
	// innermost function or method by exact span (parse/complexity).
	if opts.Complexity {
		complexity.Count(result.Nodes, decisionOffsets(fset, file))
	}
	result.Calls = extractCalls(fset, file, src, result.Nodes)
	sort.SliceStable(result.Calls, func(i, j int) bool {
		if result.Calls[i].StartLine != result.Calls[j].StartLine {
			return result.Calls[i].StartLine < result.Calls[j].StartLine
		}
		return result.Calls[i].StartByte < result.Calls[j].StartByte
	})
	return result, nil
}

// extractNodes walks the top-level declarations and emits one Node per
// func / method / type spec with an exact span.
func extractNodes(fset *token.FileSet, file *ast.File, src []byte) []codeintel.Node {
	var nodes []codeintel.Node
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if n, ok := nodeFromFunc(fset, d, src); ok {
				nodes = append(nodes, n)
			}
		case *ast.GenDecl:
			if d.Tok != token.TYPE {
				continue
			}
			for _, spec := range d.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				nodes = append(nodes, nodeFromType(fset, ts, src))
			}
		}
	}
	return nodes
}

// decisionOffsets returns the byte offset of every decision point in file,
// as Go's rows in parse/complexity's rule table define one: the go/ast type
// name and the keyword or operator are looked up in the table, never
// decided here. A default case or select clause reports "default" and so is
// not a row.
func decisionOffsets(fset *token.FileSet, file *ast.File) []int {
	var offs []int
	add := func(kind, tok string, pos token.Pos) {
		if pos.IsValid() && complexity.GoDecision(kind, tok) {
			offs = append(offs, fset.Position(pos).Offset)
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.IfStmt:
			add("IfStmt", "if", x.If)
		case *ast.ForStmt:
			add("ForStmt", "for", x.For)
		case *ast.RangeStmt:
			add("RangeStmt", "for", x.For)
		case *ast.CaseClause:
			add("CaseClause", caseToken(x.List == nil), x.Case)
		case *ast.CommClause:
			add("CommClause", caseToken(x.Comm == nil), x.Case)
		case *ast.BinaryExpr:
			add("BinaryExpr", x.Op.String(), x.OpPos)
		}
		return true
	})
	return offs
}

// caseToken is the keyword a case or select clause starts with.
func caseToken(isDefault bool) string {
	if isDefault {
		return "default"
	}
	return "case"
}

// nodeFromFunc builds a Node for a func or method declaration. The
// signature excerpt runs from the decl start up to (but excluding) the
// body's opening brace; for a bodiless declaration it runs to the end of
// the type. ok is false only for a degenerate decl with no name.
func nodeFromFunc(fset *token.FileSet, d *ast.FuncDecl, src []byte) (codeintel.Node, bool) {
	if d.Name == nil {
		return codeintel.Node{}, false
	}
	name := d.Name.Name
	kind := "function"
	fqn := name
	if recv := receiverType(d); recv != "" {
		kind = "method"
		fqn = recv + "." + name
	}

	startPos := d.Pos()
	endPos := d.End()
	// Signature ends at the body brace when there is a body.
	sigEnd := d.Type.End()
	if d.Body != nil {
		sigEnd = d.Body.Lbrace
	}

	startOff := fset.Position(startPos).Offset
	endOff := fset.Position(endPos).Offset
	sigOff := fset.Position(sigEnd).Offset

	return codeintel.Node{
		Kind:      kind,
		Name:      name,
		FQN:       fqn,
		StartLine: fset.Position(startPos).Line,
		EndLine:   fset.Position(endPos).Line,
		StartByte: startOff,
		EndByte:   endOff,
		Signature: excerpt(src, startOff, sigOff),
	}, true
}

// nodeFromType builds a Node for a single type spec. struct -> class,
// interface -> interface, anything else (alias / named) -> type. The
// signature excerpt is the declaration head (e.g. "type T struct"),
// running up to the opening brace where one exists.
func nodeFromType(fset *token.FileSet, ts *ast.TypeSpec, src []byte) codeintel.Node {
	name := ts.Name.Name
	kind := "type"
	var sigEnd token.Pos
	switch t := ts.Type.(type) {
	case *ast.StructType:
		kind = "class"
		sigEnd = t.Fields.Opening // the '{'
	case *ast.InterfaceType:
		kind = "interface"
		sigEnd = t.Methods.Opening // the '{'
	default:
		sigEnd = ts.End()
	}
	if !sigEnd.IsValid() {
		sigEnd = ts.End()
	}

	startPos := ts.Pos()
	endPos := ts.End()
	startOff := fset.Position(startPos).Offset
	endOff := fset.Position(endPos).Offset
	sigOff := fset.Position(sigEnd).Offset

	return codeintel.Node{
		Kind:      kind,
		Name:      name,
		FQN:       name,
		StartLine: fset.Position(startPos).Line,
		EndLine:   fset.Position(endPos).Line,
		StartByte: startOff,
		EndByte:   endOff,
		Signature: excerpt(src, startOff, sigOff),
	}
}

// receiverType returns the bare receiver type name for a method (leading
// '*' stripped, type parameters dropped), or "" for a plain function.
func receiverType(d *ast.FuncDecl) string {
	if d.Recv == nil || len(d.Recv.List) == 0 {
		return ""
	}
	return baseTypeName(d.Recv.List[0].Type)
}

// baseTypeName extracts the identifier name from a receiver type
// expression, unwrapping a pointer and any generic instantiation.
func baseTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return baseTypeName(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr: // generic receiver: T[P]
		return baseTypeName(t.X)
	case *ast.IndexListExpr: // generic receiver: T[P, Q]
		return baseTypeName(t.X)
	case *ast.SelectorExpr:
		return t.Sel.Name
	}
	return ""
}

// extractImports emits one Import per import spec.
func extractImports(fset *token.FileSet, file *ast.File, src []byte) []codeintel.Import {
	var imps []codeintel.Import
	for _, spec := range file.Imports {
		path := importPath(spec)
		alias := ""
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		startPos := spec.Pos()
		startOff := fset.Position(startPos).Offset
		endOff := fset.Position(spec.End()).Offset
		imps = append(imps, codeintel.Import{
			Path:      path,
			Alias:     alias,
			StartLine: fset.Position(startPos).Line,
			StartByte: startOff,
			RawText:   excerpt(src, startOff, endOff),
		})
	}
	return imps
}

// importPath returns the unquoted import path of a spec.
func importPath(spec *ast.ImportSpec) string {
	if spec.Path == nil {
		return ""
	}
	return strings.Trim(spec.Path.Value, "`\"")
}

// extractCalls walks the AST for call expressions and emits one CallSite
// per resolvable callee (a bare ident or the trailing segment of a
// selector). Calls whose callee is neither (func-literal calls,
// type conversions on composite types, etc.) are skipped.
//
// For a method call x.M() whose receiver x is a local variable whose type
// is evident from its declaration (the easy intra-package shapes — see
// inferLocalVarTypes), the CallSite carries RecvType so the scoped
// resolver can bind it to T.M (W2 §4.1). funcScopes maps each function
// body's byte range to that body's var->type map; a call outside every
// body (a package-level initializer) has no locals.
func extractCalls(fset *token.FileSet, file *ast.File, src []byte, nodes []codeintel.Node) []codeintel.CallSite {
	scopes := buildFuncScopes(fset, file)
	var calls []codeintel.CallSite
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := calleeName(call.Fun)
		if name == "" {
			return true
		}
		startPos := call.Pos()
		startOff := fset.Position(startPos).Offset
		endOff := fset.Position(call.End()).Offset
		calls = append(calls, codeintel.CallSite{
			Name:      name,
			Enclosing: enclosingNode(nodes, startOff, endOff),
			StartLine: fset.Position(startPos).Line,
			StartByte: startOff,
			RawText:   excerpt(src, startOff, endOff),
			RecvType:  localReceiverType(call.Fun, scopes, startOff),
		})
		return true
	})
	return calls
}

// funcScope is one function body's byte span paired with the var->type map
// inferred from its declarations. Go function declarations do not nest, so
// at most one scope contains any given call offset.
type funcScope struct {
	startByte, endByte int
	vars               map[string]string
}

// buildFuncScopes builds a funcScope (body byte range + inferred local
// var->type map) for every function/method declaration with a body.
func buildFuncScopes(fset *token.FileSet, file *ast.File) []funcScope {
	var scopes []funcScope
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		vars := inferLocalVarTypes(fn)
		if len(vars) == 0 {
			continue
		}
		scopes = append(scopes, funcScope{
			startByte: fset.Position(fn.Body.Pos()).Offset,
			endByte:   fset.Position(fn.Body.End()).Offset,
			vars:      vars,
		})
	}
	return scopes
}

// localReceiverType returns the inferred receiver type for a method call
// fun = x.M() when x is a local variable of a known same-package type in
// the function body containing offset. It returns "" for any other callee
// shape (bare call, pkg-qualified call, chained receiver) or an unknown
// variable — those stay name-matched / are handled by the other scoped
// rules.
func localReceiverType(fun ast.Expr, scopes []funcScope, offset int) string {
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	recv, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	for _, sc := range scopes {
		if sc.startByte <= offset && offset < sc.endByte {
			return sc.vars[recv.Name]
		}
	}
	return ""
}

// inferLocalVarTypes builds a conservative var->type map for the easy,
// intra-package shapes where a local variable's type is evident from its
// declaration alone — no cross-file or toolchain type info (W2 §4.1):
//
//	x := NewFoo()              constructor-naming convention (New<Type>)
//	var x Foo / var x *Foo     explicit declared type
//	x := Foo{} / x := &Foo{}   composite literal
//	x := new(Foo)              builtin new
//
// Only a same-package type identifier is recorded; a package-qualified
// type (other.Foo) is skipped because its methods live in another package.
// A name bound to two DIFFERENT inferred types, or reassigned to a value
// whose type cannot be inferred, is dropped (ambiguous -> stays
// name-matched). Receiver and parameter variables are not in the map (the
// self-receiver case is handled separately, from the signature).
func inferLocalVarTypes(fn *ast.FuncDecl) map[string]string {
	types := map[string]string{}
	poisoned := map[string]bool{}
	record := func(name, typ string) {
		if name == "" || name == "_" || poisoned[name] {
			return
		}
		if typ == "" {
			// An assignment whose type we cannot infer: if we had a type for
			// this name, we no longer trust it.
			if _, ok := types[name]; ok {
				delete(types, name)
				poisoned[name] = true
			}
			return
		}
		if prev, ok := types[name]; ok && prev != typ {
			delete(types, name)
			poisoned[name] = true
			return
		}
		types[name] = typ
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			// x := rhs or x = rhs (single binding only — multi-value
			// assignments need return-type info we do not resolve here).
			if len(s.Lhs) == 1 && len(s.Rhs) == 1 {
				if id, ok := s.Lhs[0].(*ast.Ident); ok {
					record(id.Name, typeOfExpr(s.Rhs[0]))
				}
			}
		case *ast.DeclStmt:
			gd, ok := s.Decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				return true
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				switch {
				case vs.Type != nil: // var x[, y] Foo
					typ := localTypeName(vs.Type)
					for _, nm := range vs.Names {
						record(nm.Name, typ)
					}
				case len(vs.Names) == 1 && len(vs.Values) == 1: // var x = NewFoo()
					record(vs.Names[0].Name, typeOfExpr(vs.Values[0]))
				}
			}
		}
		return true
	})
	return types
}

// typeOfExpr infers a same-package type name from a value expression for
// the easy shapes: composite literals (Foo{} / &Foo{}), new(Foo), and
// constructor-convention calls (NewFoo()). Anything else (a
// package-qualified constructor, a method call, a plain value) yields "".
func typeOfExpr(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.CompositeLit: // Foo{...}
		return localTypeName(x.Type)
	case *ast.UnaryExpr: // &Foo{...}
		if x.Op == token.AND {
			return typeOfExpr(x.X)
		}
	case *ast.CallExpr:
		if id, ok := x.Fun.(*ast.Ident); ok {
			if id.Name == "new" && len(x.Args) == 1 { // new(Foo)
				return localTypeName(x.Args[0])
			}
			return constructorType(id.Name) // NewFoo()
		}
		// A package-qualified constructor (pkg.NewFoo()) targets another
		// package's type — not inferable as same-package; leave unbound.
	}
	return ""
}

// localTypeName extracts a same-package type identifier from a type
// expression, unwrapping a pointer and a generic instantiation. A
// package-qualified type (pkg.Foo), map/slice/etc. yields "".
func localTypeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return localTypeName(t.X)
	case *ast.IndexExpr: // Foo[T]
		return localTypeName(t.X)
	case *ast.IndexListExpr: // Foo[T, U]
		return localTypeName(t.X)
	}
	return ""
}

// constructorType maps a Go constructor name to the type it constructs by
// the New<Type> naming convention: "NewFoo" -> "Foo". It requires the
// character after "New" to be upper-case so "Newton" / "Newest" are not
// mistaken for constructors. Returns "" when the name is not a New<Type>.
func constructorType(name string) string {
	const prefix = "New"
	if !strings.HasPrefix(name, prefix) || len(name) <= len(prefix) {
		return ""
	}
	rest := name[len(prefix):]
	if c := rest[0]; c < 'A' || c > 'Z' {
		return ""
	}
	return rest
}

// calleeName returns the trailing identifier of a callee expression:
// "Foo" for Foo(), "Foo" for pkg.Foo(), "Z" for x.y.Z(). Returns "" for
// any callee that is not an identifier or selector (e.g. a func literal
// invoked inline).
func calleeName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	case *ast.IndexExpr: // generic call: Foo[T]()
		return calleeName(f.X)
	case *ast.IndexListExpr: // generic call: Foo[T, U]()
		return calleeName(f.X)
	}
	return ""
}

// enclosingNode returns the index of the smallest node whose byte span
// contains [startOff, endOff], or -1 when the call is top-level /
// outside every node. "Smallest" keeps a call attributed to the inner
// func rather than an outer type when spans nest.
func enclosingNode(nodes []codeintel.Node, startOff, endOff int) int {
	best := -1
	bestSize := -1
	for i, nd := range nodes {
		if nd.StartByte <= startOff && endOff <= nd.EndByte {
			size := nd.EndByte - nd.StartByte
			if best == -1 || size < bestSize {
				best = i
				bestSize = size
			}
		}
	}
	return best
}

// excerpt returns src[start:end] as a string, clamped to valid bounds
// and capped at excerptCap bytes. It never returns a body — callers pass
// declaration-line / call-expression spans.
func excerpt(src []byte, start, end int) string {
	if start < 0 {
		start = 0
	}
	if end > len(src) {
		end = len(src)
	}
	if start >= end {
		return ""
	}
	if end-start > excerptCap {
		end = start + excerptCap
	}
	return string(src[start:end])
}
