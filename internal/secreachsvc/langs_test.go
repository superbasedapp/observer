package secreachsvc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secreach"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// fakeLangIndex is a codeintel index read keyed by codeintel language,
// with the call read.
type fakeLangIndex struct {
	imports   map[string]store.CodeIntelImports
	err       error
	calls     store.CodeIntelCalls
	callErr   error
	callNames []string
	callReads int
}

func (f *fakeLangIndex) CodeIntelProjectImports(_ context.Context, _, lang string, _ int) (store.CodeIntelImports, error) {
	return f.imports[lang], f.err
}

func (f *fakeLangIndex) CodeIntelProjectCalls(_ context.Context, _, _ string, names []string, _ int) (store.CodeIntelCalls, error) {
	f.callReads++
	f.callNames = names
	return f.calls, f.callErr
}

// importsOnly hides the call read.
type importsOnly struct{ f *fakeLangIndex }

func (i importsOnly) CodeIntelProjectImports(ctx context.Context, p, l string, n int) (store.CodeIntelImports, error) {
	return i.f.CodeIntelProjectImports(ctx, p, l, n)
}

func abs(root, rel string) string { return filepath.Join(root, filepath.FromSlash(rel)) }

func sites(root string, pairs ...string) []store.CodeIntelImportSite {
	var out []store.CodeIntelImportSite
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, store.CodeIntelImportSite{File: abs(root, pairs[i]), Spec: pairs[i+1]})
	}
	return out
}

func advLookup(advs map[string]secreach.Advisory) Lookup {
	return func(id string) (secreach.Advisory, bool) {
		a, ok := advs[id]
		return a, ok
	}
}

func dep(id, rel string) secfinding.Finding {
	return secfinding.Finding{ID: id, Category: policy.FindingVulnerableDependency, Location: secfinding.Location{RelPath: rel}}
}

func TestTiersJS(t *testing.T) {
	root := t.TempDir()
	full := &fakeLangIndex{imports: map[string]store.CodeIntelImports{
		"typescript": {Files: 2, Indexed: 2, Sites: sites(root,
			"src/a.ts", "lodash/fp", "src/a.ts", "./x", "src/a.ts", "node:fs", "src/a.ts", "@babel/core/lib/x",
			"node_modules/dep/index.ts", "evil-pkg")},
		"javascript": {Files: 1, Indexed: 1, Sites: sites(root, "src/a.test.js", "left-pad")},
	}}
	partial := &fakeLangIndex{imports: map[string]store.CodeIntelImports{
		"typescript": {Files: 2, Indexed: 1, Sites: sites(root, "src/a.ts", "lodash")},
	}}
	empty := &fakeLangIndex{imports: map[string]store.CodeIntelImports{}}
	advs := map[string]secreach.Advisory{
		"lodash": {Ecosystem: "npm", Package: "lodash"},
		"babel":  {Ecosystem: "npm", Package: "@babel/core", Records: []secreach.Record{{ID: "GHSA-1"}}},
		"pad":    {Ecosystem: "npm", Package: "left-pad"},
		"react":  {Ecosystem: "npm", Package: "react"},
		"evil":   {Ecosystem: "npm", Package: "evil-pkg"},
	}
	findings := []secfinding.Finding{dep("lodash", "package-lock.json"), dep("babel", "package-lock.json"), dep("pad", "package-lock.json"), dep("react", "package-lock.json"), dep("evil", "package-lock.json")}
	ci := secreach.SourceCodeIntel
	cases := []struct {
		name string
		opts []Option
		want map[string]secreach.Tier
	}{
		{"a complete index", []Option{WithCodeIntel(full)}, map[string]secreach.Tier{
			"lodash": {Level: secreach.Imported, Source: ci, Match: "lodash"},
			"babel":  {Level: secreach.Imported, Source: ci, Match: "@babel/core"},
			"pad":    {Level: secreach.Imported, Source: ci, TestsOnly: true, Match: "left-pad"},
			"react":  {Level: secreach.NotImportedDirectly, Source: ci},
			"evil":   {Level: secreach.NotImportedDirectly, Source: ci},
		}},
		{"a partial index proves only presence", []Option{WithCodeIntel(partial)}, map[string]secreach.Tier{
			"lodash": {Level: secreach.Imported, Source: ci, Match: "lodash"},
			"babel":  secreach.UnknownTier(secreach.ReasonIncomplete),
			"pad":    secreach.UnknownTier(secreach.ReasonIncomplete),
			"react":  secreach.UnknownTier(secreach.ReasonIncomplete),
			"evil":   secreach.UnknownTier(secreach.ReasonIncomplete),
		}},
		{"no file of the language indexed", []Option{WithCodeIntel(empty)}, allUnknown(findings, secreach.ReasonNoCodeIntel)},
		{"codeintel off", nil, allUnknown(findings, secreach.ReasonNoCodeIntel)},
		{"an index read error", []Option{WithCodeIntel(&fakeLangIndex{err: errors.New("boom")})}, allUnknown(findings, secreach.ReasonNoCodeIntel)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Tiers(context.Background(), root, findings, advLookup(advs), tc.opts...)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Tiers =\n%+v\nwant\n%+v", got, tc.want)
			}
		})
	}
}

func allUnknown(fs []secfinding.Finding, r secreach.Reason) map[string]secreach.Tier {
	out := map[string]secreach.Tier{}
	for _, f := range fs {
		out[f.ID] = secreach.UnknownTier(r)
	}
	return out
}

// sitePackages makes root/<venv>/lib/python3.12/site-packages.
func sitePackages(t *testing.T, root, venv string) string {
	t.Helper()
	sp := filepath.Join(root, venv, "lib", "python3.12", "site-packages")
	if err := os.MkdirAll(sp, 0o755); err != nil {
		t.Fatal(err)
	}
	return sp
}

func writeFile(t *testing.T, name, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestTiersPython(t *testing.T) {
	root := t.TempDir()
	sp := sitePackages(t, root, ".venv")
	writeFile(t, filepath.Join(sp, "odd_dist-1.0.dist-info", "RECORD"), "oddmod/__init__.py,,\noddmod/core.py,,\nodd_dist-1.0.dist-info/METADATA,,\n")
	writeFile(t, filepath.Join(sp, "Legacy-2.0-py3.12.egg-info", "top_level.txt"), "legacymod\n")
	// A sub-project's own environment wins for its lockfile.
	subSP := sitePackages(t, filepath.Join(root, "svc"), "venv")
	writeFile(t, filepath.Join(subSP, "odd_dist-2.0.dist-info", "RECORD"), "othermod.py,,\n")

	idx := &fakeLangIndex{imports: map[string]store.CodeIntelImports{
		"python": {Files: 3, Indexed: 3, Sites: sites(root,
			"app/main.py", "yaml", "app/main.py", "oddmod.core", "app/main.py", ".local", "app/main.py", "requests.adapters",
			"tests/test_x.py", "legacymod", ".venv/lib/python3.12/site-packages/x.py", "secret_dep")},
	}}
	advs := map[string]secreach.Advisory{
		"yaml":     {Ecosystem: "PyPI", Package: "PyYAML"},
		"odd":      {Ecosystem: "PyPI", Package: "Odd-Dist"},
		"odd-sub":  {Ecosystem: "PyPI", Package: "odd.dist"},
		"legacy":   {Ecosystem: "PyPI", Package: "legacy"},
		"requests": {Ecosystem: "PyPI", Package: "requests"},
		"unknown":  {Ecosystem: "PyPI", Package: "secret-dep"},
		"bs4":      {Ecosystem: "PyPI", Package: "beautifulsoup4"},
	}
	findings := []secfinding.Finding{
		dep("yaml", "requirements.txt"), dep("odd", "poetry.lock"), dep("odd-sub", "svc/requirements.txt"), dep("legacy", "requirements.txt"),
		dep("requests", "requirements.txt"), dep("unknown", "requirements.txt"), dep("bs4", "requirements.txt"),
	}
	ci := secreach.SourceCodeIntel
	got := Tiers(context.Background(), root, findings, advLookup(advs), WithCodeIntel(idx), WithCache(NewCache(0)))
	want := map[string]secreach.Tier{
		"yaml":     {Level: secreach.Imported, Source: ci, Match: "yaml"},
		"odd":      {Level: secreach.Imported, Source: ci, Match: "oddmod.core"},
		"odd-sub":  {Level: secreach.NotImportedDirectly, Source: ci},
		"legacy":   {Level: secreach.Imported, Source: ci, TestsOnly: true, Match: "legacymod"},
		"requests": {Level: secreach.Imported, Source: ci, Approximate: true, Match: "requests.adapters"},
		"unknown":  secreach.UnknownTier(secreach.ReasonNoNameMapping),
		"bs4":      {Level: secreach.NotImportedDirectly, Source: ci},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Tiers =\n%+v\nwant\n%+v", got, want)
	}
}

func TestReadPythonMeta(t *testing.T) {
	root := t.TempDir()
	sp := sitePackages(t, root, ".venv")
	writeFile(t, filepath.Join(sp, "a_dist-1.dist-info", "RECORD"), "amod.py,,\n")
	writeFile(t, filepath.Join(sp, "b_dist-1.dist-info", "RECORD"), "not a module\n")
	writeFile(t, filepath.Join(sp, "b_dist-1.dist-info", "top_level.txt"), "bmod\n")
	writeFile(t, filepath.Join(sp, "c_dist-1.dist-info", "RECORD"), "")
	writeFile(t, filepath.Join(sp, "notmeta", "RECORD"), "zmod.py,,\n")
	writeFile(t, filepath.Join(root, "venv", "Lib", "site-packages", "w_dist-1.dist-info", "top_level.txt"), "wmod\n")

	m := ReadPythonMeta(context.Background(), root)
	want := map[string][]string{"a-dist": {"amod"}, "b-dist": {"bmod"}, "w-dist": {"wmod"}}
	if !reflect.DeepEqual(m.Provides, want) || m.Stopped != "" || m.Dists != 3 {
		t.Fatalf("ReadPythonMeta = %+v, want %v", m, want)
	}
	if got := ReadPythonMeta(context.Background(), t.TempDir()); len(got.Provides) != 0 || got.Stopped != "" {
		t.Fatalf("no venv = %+v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := ReadPythonMeta(ctx, root); got.Stopped != StoppedCanceled {
		t.Fatalf("canceled read = %+v", got)
	}
}

func TestReadPythonMetaRefusesLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need privileges on Windows")
	}
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "lib", "python3.12", "site-packages", "x_dist-1.dist-info", "RECORD"), "xmod.py,,\n")
	writeFile(t, filepath.Join(outside, "RECORD"), "ymod.py,,\n")

	// A linked .venv is not followed.
	root := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, ".venv")); err != nil {
		t.Fatal(err)
	}
	if got := ReadPythonMeta(context.Background(), root); len(got.Provides) != 0 {
		t.Fatalf("a linked venv was read: %+v", got.Provides)
	}

	// Nor a linked metadata directory or a linked RECORD.
	root2 := t.TempDir()
	sp := sitePackages(t, root2, ".venv")
	if err := os.Symlink(filepath.Join(outside, "lib", "python3.12", "site-packages", "x_dist-1.dist-info"), filepath.Join(sp, "x_dist-1.dist-info")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(sp, "y_dist-1.dist-info"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "RECORD"), filepath.Join(sp, "y_dist-1.dist-info", "RECORD")); err != nil {
		t.Fatal(err)
	}
	if got := ReadPythonMeta(context.Background(), root2); len(got.Provides) != 0 {
		t.Fatalf("a linked metadata file was read: %+v", got.Provides)
	}
}

func TestReadRegularCapped(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "f")
	writeFile(t, name, "12345")
	if b, err := readRegularCapped(name, 5); err != nil || string(b) != "12345" {
		t.Fatalf("at the cap: %q, %v", b, err)
	}
	if _, err := readRegularCapped(name, 4); err == nil {
		t.Fatal("over the cap: want an error")
	}
	if _, err := readRegularCapped(dir, 100); err == nil {
		t.Fatal("a directory: want an error")
	}
}

func TestTiersRust(t *testing.T) {
	root := t.TempDir()
	idx := &fakeLangIndex{
		imports: map[string]store.CodeIntelImports{
			"rust": {Files: 2, Indexed: 2, Sites: sites(root, "src/main.rs", "smallvec::SmallVec", "src/main.rs", "crate::db", "src/lib.rs", "std::io")},
		},
		calls: store.CodeIntelCalls{Sites: []store.CodeIntelCallSite{
			{File: abs(root, "src/main.rs"), Name: "insert_many", Text: "v.insert_many(0, it)"},
			{File: abs(root, "src/lib.rs"), Name: "from_slice", Text: "serde_json::from_slice(&b)"},
		}},
	}
	advs := map[string]secreach.Advisory{
		"smallvec": {Ecosystem: "crates.io", Package: "smallvec", Records: []secreach.Record{{ID: "RUSTSEC-1", Functions: []string{"smallvec::SmallVec::insert_many"}}}},
		"serde":    {Ecosystem: "crates.io", Package: "serde-json", Records: []secreach.Record{{ID: "RUSTSEC-2", Functions: []string{"serde_json::from_slice"}}}},
		"tokio":    {Ecosystem: "crates.io", Package: "tokio"},
	}
	findings := []secfinding.Finding{dep("smallvec", "Cargo.lock"), dep("serde", "Cargo.lock"), dep("tokio", "Cargo.lock")}
	got := Tiers(context.Background(), root, findings, advLookup(advs), WithCodeIntel(idx))
	want := map[string]secreach.Tier{
		"smallvec": {Level: secreach.Called, Source: secreach.SourceRustCallSite, Approximate: true, Match: "smallvec::SmallVec::insert_many"},
		"serde":    {Level: secreach.Called, Source: secreach.SourceRustCallSite, Approximate: true, Match: "serde_json::from_slice"},
		"tokio":    secreach.UnknownTier(secreach.ReasonUseOnly),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Tiers =\n%+v\nwant\n%+v", got, want)
	}
	if idx.callReads != 1 || !reflect.DeepEqual(idx.callNames, []string{"insert_many", "from_slice"}) {
		t.Fatalf("call reads = %d of %v; want one read of both names", idx.callReads, idx.callNames)
	}

	// Without the call read: the import level, never "not called".
	got = Tiers(context.Background(), root, findings, advLookup(advs), WithCodeIntel(importsOnly{idx}))
	want = map[string]secreach.Tier{
		"smallvec": {Level: secreach.Imported, Source: secreach.SourceCodeIntel, Match: "smallvec"},
		"serde":    secreach.UnknownTier(secreach.ReasonUseOnly),
		"tokio":    secreach.UnknownTier(secreach.ReasonUseOnly),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("import level =\n%+v\nwant\n%+v", got, want)
	}

	// A failed call read is the same.
	idx.callErr = errors.New("boom")
	if got := Tiers(context.Background(), root, findings[:1], advLookup(advs), WithCodeIntel(idx)); got["smallvec"].Level != secreach.Imported {
		t.Fatalf("a failed call read = %+v", got["smallvec"])
	}
}

func TestMetaDirs(t *testing.T) {
	root := filepath.FromSlash("/p")
	cases := map[string][]string{
		"requirements.txt":          {root},
		"svc/requirements.txt":      {filepath.Join(root, "svc"), root},
		"./svc/api/poetry.lock":     {filepath.Join(root, "svc", "api"), root},
		"../other/requirements.txt": {root},
		"/abs/requirements.txt":     {root},
		"":                          {root},
	}
	for rel, want := range cases {
		if got := metaDirs(root, rel); !reflect.DeepEqual(got, want) {
			t.Errorf("metaDirs(%q) = %v, want %v", rel, got, want)
		}
	}
}
