package resolve

import (
	"reflect"
	"testing"
)

func TestModuleRulesForRegistry(t *testing.T) {
	for _, lang := range []string{"typescript", "tsx", "python"} {
		if _, ok := ModuleRulesFor(lang); !ok {
			t.Errorf("expected module rules for %s", lang)
		}
	}
	if _, ok := ModuleRulesFor("go"); ok {
		t.Error("go must use the package-dir model, not the module model")
	}
	if got := ModuleScopedLangs(); !reflect.DeepEqual(got, []string{"python", "tsx", "typescript"}) {
		t.Errorf("ModuleScopedLangs() = %v", got)
	}
}

func TestTSParseImport(t *testing.T) {
	r := tsModuleRules{}
	cases := []struct {
		raw, path    string
		wantOK       bool
		wantMembers  map[string]string
		wantNamespac []string
	}{
		{`import { foo } from './x'`, "./x", true, map[string]string{"foo": "foo"}, nil},
		{`import { a, b as c } from './x'`, "./x", true, map[string]string{"a": "a", "c": "b"}, nil},
		{`import * as ns from './x'`, "./x", true, map[string]string{}, []string{"ns"}},
		{`import type { T } from './x'`, "./x", true, map[string]string{"T": "T"}, nil},
		{`import def from './x'`, "./x", false, nil, nil}, // default-only: unresolvable
		{`import './x'`, "./x", false, nil, nil},          // side-effect: nothing
		{`import foo from "react"`, "react", false, nil, nil},
	}
	for _, c := range cases {
		pi, ok := r.ParseImport(c.raw, c.path)
		if ok != c.wantOK {
			t.Errorf("ParseImport(%q) ok=%v want %v", c.raw, ok, c.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if !reflect.DeepEqual(pi.Members, c.wantMembers) {
			t.Errorf("ParseImport(%q) members=%v want %v", c.raw, pi.Members, c.wantMembers)
		}
		if !reflect.DeepEqual(pi.Namespaces, c.wantNamespac) {
			t.Errorf("ParseImport(%q) namespaces=%v want %v", c.raw, pi.Namespaces, c.wantNamespac)
		}
	}
}

func TestPyParseImport(t *testing.T) {
	r := pyModuleRules{}
	cases := []struct {
		raw, path    string
		wantOK       bool
		wantMembers  map[string]string
		wantNamespac []string
	}{
		{`from utils import foo`, "utils", true, map[string]string{"foo": "foo"}, nil},
		{`from .utils import a, b as c`, ".utils", true, map[string]string{"a": "a", "c": "b"}, nil},
		{`import utils`, "utils", true, map[string]string{}, []string{"utils"}},
		{`import numpy as np`, "numpy", true, map[string]string{}, []string{"np"}},
		{`from utils import *`, "utils", false, nil, nil}, // wildcard: unknown names
	}
	for _, c := range cases {
		pi, ok := r.ParseImport(c.raw, c.path)
		if ok != c.wantOK {
			t.Errorf("ParseImport(%q) ok=%v want %v", c.raw, ok, c.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if !reflect.DeepEqual(pi.Members, c.wantMembers) {
			t.Errorf("ParseImport(%q) members=%v want %v", c.raw, pi.Members, c.wantMembers)
		}
		if !reflect.DeepEqual(pi.Namespaces, c.wantNamespac) {
			t.Errorf("ParseImport(%q) namespaces=%v want %v", c.raw, pi.Namespaces, c.wantNamespac)
		}
	}
}

func TestSplitCallGeneric(t *testing.T) {
	cases := []struct {
		raw, callee string
		wantQual    string
		wantQuald   bool
	}{
		{"foo(x)", "foo", "", false},        // bare
		{"ns.foo(x)", "foo", "ns", true},    // namespace-qualified
		{"a.b.foo()", "foo", "a.b", true},   // dotted namespace (Python import a.b)
		{"this.foo()", "foo", "this", true}, // qualified (won't match any ns -> no bind)
		{"a().foo()", "foo", "_complex", false},
		{"arr[i].foo()", "foo", "_complex", false},
		// The tree-sitter excerpt shapes for a non-identifier receiver
		// (treesitter.callQualifier keeps only its closing character) and
		// optional chaining: both complex, never bare.
		{").foo(x)", "foo", "_complex", false},
		{"].foo(x)", "foo", "_complex", false},
		{"ns?.foo(x)", "foo", "_complex", false},
	}
	for _, c := range cases {
		q, ok := splitCallGeneric(c.callee, c.raw)
		if q != c.wantQual || ok != c.wantQuald {
			t.Errorf("splitCallGeneric(%q,%q) = (%q,%v), want (%q,%v)", c.callee, c.raw, q, ok, c.wantQual, c.wantQuald)
		}
	}
}

func TestTSResolveModule(t *testing.T) {
	r := tsModuleRules{}
	files := []string{"/r/x.ts", "/r/sub/y.tsx", "/r/sub/index.ts", "/r/main.ts"}
	fset := map[string]bool{}
	for _, f := range files {
		fset[f] = true
	}
	cases := []struct {
		module, importer string
		want             []string
	}{
		{"./x", "/r/main.ts", []string{"/r/x.ts"}},
		{"./sub/y", "/r/main.ts", []string{"/r/sub/y.tsx"}},
		{"./sub", "/r/main.ts", []string{"/r/sub/index.ts"}}, // directory index
		{"react", "/r/main.ts", nil},                         // external
		{"@/x", "/r/main.ts", nil},                           // tsconfig alias (unresolved)
	}
	for _, c := range cases {
		got := r.ResolveModule(c.module, c.importer, fset, files)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("ResolveModule(%q,%q) = %v, want %v", c.module, c.importer, got, c.want)
		}
	}
}

func TestPyResolveModule(t *testing.T) {
	r := pyModuleRules{}
	files := []string{"/r/pkg/utils.py", "/r/pkg/sub/__init__.py", "/r/pkg/main.py", "/r/other.py"}
	fset := map[string]bool{}
	for _, f := range files {
		fset[f] = true
	}
	cases := []struct {
		module, importer string
		want             []string
	}{
		{".utils", "/r/pkg/main.py", []string{"/r/pkg/utils.py"}},
		{".sub", "/r/pkg/main.py", []string{"/r/pkg/sub/__init__.py"}},
		{"pkg.utils", "/r/pkg/main.py", []string{"/r/pkg/utils.py"}}, // absolute suffix match
		{"os", "/r/pkg/main.py", nil},                                // stdlib / external
	}
	for _, c := range cases {
		got := r.ResolveModule(c.module, c.importer, fset, files)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("ResolveModule(%q,%q) = %v, want %v", c.module, c.importer, got, c.want)
		}
	}
}

func TestModuleResolveTSBindsImportedMember(t *testing.T) {
	rules, _ := ModuleRulesFor("typescript")
	nodes := []ScopedNodeRef{
		{ID: 1, Name: "foo", Pkg: "/r/x.ts", FileID: 10},
		{ID: 2, Name: "foo", Pkg: "/r/other.ts", FileID: 20}, // the over-link trap
	}
	imports := map[int64][]RawImport{
		30: {{Path: "./x", RawText: `import { foo } from './x'`}},
	}
	calls := []ScopedCall{
		{EdgeID: 100, CallerFile: 30, CallerPkg: "/r/main.ts", Callee: "foo", RawText: "foo(a)"},
	}
	files := []string{"/r/x.ts", "/r/other.ts", "/r/main.ts"}
	got := ModuleResolve(rules, nodes, imports, calls, files)
	if len(got) != 1 || got[0].DstID != 1 {
		t.Fatalf("imported foo() -> %+v, want bind to id 1 (./x), not the other file", got)
	}
}

func TestModuleResolveTSNamespace(t *testing.T) {
	rules, _ := ModuleRulesFor("tsx")
	nodes := []ScopedNodeRef{{ID: 1, Name: "render", Pkg: "/r/ui.ts", FileID: 10}}
	imports := map[int64][]RawImport{
		30: {{Path: "./ui", RawText: `import * as ui from './ui'`}},
	}
	calls := []ScopedCall{
		{EdgeID: 100, CallerFile: 30, CallerPkg: "/r/app.tsx", Callee: "render", RawText: "ui.render(x)"},
	}
	files := []string{"/r/ui.ts", "/r/app.tsx"}
	got := ModuleResolve(rules, nodes, imports, calls, files)
	if len(got) != 1 || got[0].DstID != 1 {
		t.Fatalf("ui.render() -> %+v, want bind to id 1", got)
	}
}

func TestModuleResolvePythonFromImport(t *testing.T) {
	rules, _ := ModuleRulesFor("python")
	nodes := []ScopedNodeRef{
		{ID: 1, Name: "foo", Pkg: "/r/pkg/utils.py", FileID: 10},
		{ID: 2, Name: "foo", Pkg: "/r/other.py", FileID: 20},
	}
	imports := map[int64][]RawImport{
		30: {{Path: ".utils", RawText: `from .utils import foo`}},
	}
	calls := []ScopedCall{
		{EdgeID: 100, CallerFile: 30, CallerPkg: "/r/pkg/main.py", Callee: "foo", RawText: "foo(a)"},
	}
	files := []string{"/r/pkg/utils.py", "/r/other.py", "/r/pkg/main.py"}
	got := ModuleResolve(rules, nodes, imports, calls, files)
	if len(got) != 1 || got[0].DstID != 1 {
		t.Fatalf("from .utils import foo; foo() -> %+v, want bind to id 1", got)
	}
}

func TestModuleResolveExternalImportLeftNameMatched(t *testing.T) {
	rules, _ := ModuleRulesFor("typescript")
	nodes := []ScopedNodeRef{{ID: 1, Name: "useState", Pkg: "/r/x.ts", FileID: 10}}
	imports := map[int64][]RawImport{
		30: {{Path: "react", RawText: `import { useState } from 'react'`}},
	}
	calls := []ScopedCall{
		{EdgeID: 100, CallerFile: 30, CallerPkg: "/r/app.ts", Callee: "useState", RawText: "useState(0)"},
	}
	files := []string{"/r/x.ts", "/r/app.ts"}
	// react does not resolve to an indexed file -> no scoped bind (the
	// coincidental same-named local must NOT be bound).
	if got := ModuleResolve(rules, nodes, imports, calls, files); len(got) != 0 {
		t.Errorf("external import should stay name-matched, got %+v", got)
	}
}

func TestModuleResolveAmbiguousMemberLeftNameMatched(t *testing.T) {
	rules, _ := ModuleRulesFor("python")
	nodes := []ScopedNodeRef{
		{ID: 1, Name: "foo", Pkg: "/r/a.py", FileID: 10},
		{ID: 2, Name: "foo", Pkg: "/r/a.py", FileID: 10}, // two foo in the SAME target file
	}
	imports := map[int64][]RawImport{
		30: {{Path: ".a", RawText: `from .a import foo`}},
	}
	calls := []ScopedCall{
		{EdgeID: 100, CallerFile: 30, CallerPkg: "/r/main.py", Callee: "foo", RawText: "foo()"},
	}
	files := []string{"/r/a.py", "/r/main.py"}
	if got := ModuleResolve(rules, nodes, imports, calls, files); len(got) != 0 {
		t.Errorf("two foo in target file is ambiguous -> name-matched, got %+v", got)
	}
}
