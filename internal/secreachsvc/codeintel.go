package secreachsvc

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secreach"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// CodeIntelReader is the codeintel index read (*store.Store satisfies it).
type CodeIntelReader interface {
	CodeIntelProjectImports(ctx context.Context, project, lang string, limit int) (store.CodeIntelImports, error)
}

// codeIntelLang is the codeintel language key of Go files.
const codeIntelLang = "go"

// CodeIntelGoImports builds the Go import list from the codeintel index of
// project root. ok is false when the index does not hold every Go file of
// the project (no rows, a file not yet indexed, the site cap hit) or the
// read fails: the index then cannot stand in for the parse. A site the
// root does not contain, or under a directory the parse skips, is left
// out (and a site the root does not contain makes its module incomplete).
func CodeIntelGoImports(ctx context.Context, r CodeIntelReader, root string) (*GoImports, bool) {
	start := time.Now()
	if r == nil || root == "" {
		return nil, false
	}
	got, err := r.CodeIntelProjectImports(ctx, root, codeIntelLang, 0)
	if err != nil || got.Files == 0 || got.Indexed != got.Files || got.Truncated {
		return nil, false
	}
	out := &GoImports{Source: secreach.SourceCodeIntel, Root: root, Modules: map[string]*ModuleImports{}}
	out.module("")
	mods := moduleFinder{root: root, known: map[string]string{}}
	files := map[string]bool{}
	for _, site := range got.Sites {
		rel, ok := relUnder(root, site.File)
		if !ok {
			out.module("").Incomplete = true
			continue
		}
		dir, name := path.Split(rel)
		dir = strings.TrimSuffix(dir, "/")
		if skippedPath(dir) || !goSourceFile(name) {
			continue
		}
		m := out.module(mods.moduleOf(dir))
		if !files[rel] {
			files[rel] = true
			out.Stats.Files++
			if isTestFile(name) {
				out.Stats.TestFiles++
			}
		}
		u := m.Uses[site.Spec]
		if isTestFile(name) {
			u.Test = true
		} else {
			u.NonTest = true
		}
		m.Uses[site.Spec] = u
	}
	for dir, m := range out.Modules {
		m.Modules = readModulePaths(filepath.Join(root, filepath.FromSlash(dir)))
	}
	out.Stats.Elapsed = time.Since(start)
	return out, true
}

// relUnder returns file relative to root (slash form), ok false when root
// does not contain it. Both sides are compared in slash form.
func relUnder(root, file string) (string, bool) {
	r := strings.TrimSuffix(filepath.ToSlash(root), "/")
	f := filepath.ToSlash(file)
	rest, ok := strings.CutPrefix(f, r+"/")
	if !ok || rest == "" {
		return "", false
	}
	for _, seg := range strings.Split(rest, "/") {
		if seg == ".." || seg == "" {
			return "", false
		}
	}
	return rest, true
}

// skippedPath reports a project-relative directory the parse would not
// enter (any element skipDir names).
func skippedPath(dir string) bool {
	if dir == "" {
		return false
	}
	for _, seg := range strings.Split(dir, "/") {
		if skipDir(seg) {
			return true
		}
	}
	return false
}

// moduleFinder resolves the module directory of a project-relative
// directory: the nearest ancestor (itself included) holding a go.mod, ""
// (the root) when none.
type moduleFinder struct {
	root  string
	known map[string]string
}

func (mf moduleFinder) moduleOf(dir string) string {
	if dir == "" {
		return ""
	}
	if m, ok := mf.known[dir]; ok {
		return m
	}
	var m string
	if st, err := os.Stat(filepath.Join(mf.root, filepath.FromSlash(dir), "go.mod")); err == nil && st.Mode().IsRegular() {
		m = dir
	} else {
		parent := path.Dir(dir)
		if parent == "." {
			parent = ""
		}
		m = mf.moduleOf(parent)
	}
	mf.known[dir] = m
	return m
}
