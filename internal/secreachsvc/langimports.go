package secreachsvc

import (
	"context"
	"path"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/secreach"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// CodeIntelCallReader is the codeintel index's call-site read (*store.Store
// satisfies it). A CodeIntelReader that does not also implement it gets no
// call level: the Rust tier stays at import level.
type CodeIntelCallReader interface {
	CodeIntelProjectCalls(ctx context.Context, project, lang string, names []string, limit int) (store.CodeIntelCalls, error)
}

// codeIntelLangRow is one language whose import list comes from the
// codeintel index only: the codeintel language keys of its files and
// whether the per-file import keys are kept (the Rust call rule reads
// them).
type codeIntelLangRow struct {
	Lang      string
	Keys      []string
	PerFile   bool
	CallLevel bool
}

// codeIntelLangRows is the table of codeintel-only languages.
var codeIntelLangRows = []codeIntelLangRow{
	{Lang: secreach.LangJS, Keys: []string{"javascript", "jsx", "typescript", "tsx"}},
	{Lang: secreach.LangPython, Keys: []string{"python"}},
	{Lang: secreach.LangRust, Keys: []string{"rust"}, PerFile: true, CallLevel: true},
}

func codeIntelLangRowFor(lang string) (codeIntelLangRow, bool) {
	for _, r := range codeIntelLangRows {
		if r.Lang == lang {
			return r, true
		}
	}
	return codeIntelLangRow{}, false
}

// dependencyDir reports a directory element whose files are dependency
// code, never the project's own (codeintel skips them; a site under one is
// left out regardless).
func dependencyDir(seg string) bool {
	switch seg {
	case "node_modules", ".venv", "venv", "site-packages", "vendor", "__pycache__":
		return true
	}
	return false
}

func inDependencyDir(rel string) bool {
	dir, _ := path.Split(rel)
	for _, seg := range strings.Split(strings.TrimSuffix(dir, "/"), "/") {
		if dependencyDir(seg) {
			return true
		}
	}
	return false
}

// CodeIntelLangImports builds a JavaScript/TypeScript, Python or Rust
// import list (secreach.LangJS, LangPython, LangRust) from the codeintel
// index of project root, keyed by secreach.ImportKey. ok is false when the
// index holds no file of the language (codeintel off, the project not
// indexed, no such file) or a read fails: the tier is then unknown. The
// list is complete only when every file of the language is indexed, no
// read hit its cap and every site lies under root.
func CodeIntelLangImports(ctx context.Context, r CodeIntelReader, root, lang string) (*secreach.ImportSet, bool) {
	row, ok := codeIntelLangRowFor(lang)
	if r == nil || root == "" || !ok {
		return nil, false
	}
	set := &secreach.ImportSet{Source: secreach.SourceCodeIntel, Complete: true, Uses: map[string]secreach.Use{}}
	if row.PerFile {
		set.FileImports = map[string][]string{}
	}
	files := 0
	for _, key := range row.Keys {
		got, err := r.CodeIntelProjectImports(ctx, root, key, 0)
		if err != nil {
			return nil, false
		}
		files += got.Files
		if got.Indexed != got.Files || got.Truncated {
			set.Complete = false
		}
		for _, site := range got.Sites {
			rel, ok := relUnder(root, site.File)
			if !ok {
				set.Complete = false
				continue
			}
			if inDependencyDir(rel) {
				continue
			}
			k, ok := secreach.ImportKey(lang, site.Spec)
			if !ok {
				continue
			}
			u := set.Uses[k]
			if secreach.IsTestFile(lang, rel) {
				u.Test = true
			} else {
				u.NonTest = true
			}
			set.Uses[k] = u
			if row.PerFile && !contains(set.FileImports[rel], k) {
				set.FileImports[rel] = append(set.FileImports[rel], k)
			}
		}
	}
	if files == 0 {
		return nil, false
	}
	return set, true
}

// CodeIntelRustCalls reads the Rust call sites whose callee name is one of
// names, project-relative and tagged test or not; ok false when r has no
// call read, names is empty or the read fails (the call level is then not
// checked). A capped read still proves the calls it holds.
func CodeIntelRustCalls(ctx context.Context, r CodeIntelReader, root string, names []string) ([]secreach.Call, bool) {
	cr, ok := r.(CodeIntelCallReader)
	if !ok || root == "" || len(names) == 0 {
		return nil, false
	}
	got, err := cr.CodeIntelProjectCalls(ctx, root, "rust", names, 0)
	if err != nil {
		return nil, false
	}
	calls := make([]secreach.Call, 0, len(got.Sites))
	for _, site := range got.Sites {
		rel, ok := relUnder(root, site.File)
		if !ok || inDependencyDir(rel) {
			continue
		}
		calls = append(calls, secreach.Call{File: rel, Name: site.Name, Text: site.Text, Test: secreach.IsTestFile(secreach.LangRust, rel)})
	}
	return calls, true
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
