package secreach

import (
	"reflect"
	"testing"
)

// TestJSKeyRules has one case per jsKeyRules row, in table order.
func TestJSKeyRules(t *testing.T) {
	cases := []struct {
		spec string
		want string
		ok   bool
	}{
		// Row 1: empty or a loader chain.
		{"", "", false},
		{"style-loader!css-loader!./a.css", "", false},
		// Row 2: relative path.
		{"./util", "", false},
		{"../lib/x.js", "", false},
		{".", "", false},
		// Row 3: absolute path.
		{"/abs/path.js", "", false},
		{`\\server\share`, "", false},
		// Row 4: package.json subpath import.
		{"#internal/db", "", false},
		// Row 5: npm: specifier.
		{"npm:lodash@4.17.21", "lodash", true},
		{"npm:@scope/pkg@^1/sub", "@scope/pkg", true},
		// Row 6: node: builtin or another scheme.
		{"node:fs", "", false},
		{"https://cdn.example/x.js", "", false},
		{"C:/x.js", "", false},
		// Row 7: scoped or bare package.
		{"lodash", "lodash", true},
		{"lodash/fp/map", "lodash", true},
		{"@babel/core", "@babel/core", true},
		{"@babel/core/lib/x", "@babel/core", true},
		{"vue?raw", "vue", true},
		{"JSONStream", "JSONStream", true},
		{"fs", "fs", true},
		{"@scope", "", false},
		{"@/components/x", "", false},
		{"~/x", "", false},
		{"_private", "", false},
	}
	for _, tc := range cases {
		got, ok := ImportKey(LangJS, tc.spec)
		if got != tc.want || ok != tc.ok {
			t.Errorf("ImportKey(js, %q) = %q, %v; want %q, %v", tc.spec, got, ok, tc.want, tc.ok)
		}
	}
}

// TestPythonKeyRules has one case per pythonKeyRules row.
func TestPythonKeyRules(t *testing.T) {
	cases := []struct {
		spec, want string
		ok         bool
	}{
		{".", "", false},
		{".models", "", false},
		{"__future__", "", false},
		{"yaml", "yaml", true},
		{"google.cloud.storage", "google.cloud.storage", true},
		{"a.b-c", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := ImportKey(LangPython, tc.spec)
		if got != tc.want || ok != tc.ok {
			t.Errorf("ImportKey(python, %q) = %q, %v; want %q, %v", tc.spec, got, ok, tc.want, tc.ok)
		}
	}
}

// TestRustKeyRules has one case per rustKeyRules row.
func TestRustKeyRules(t *testing.T) {
	cases := []struct {
		spec, want string
		ok         bool
	}{
		{"", "", false},
		{"::", "", false},
		{"serde::Deserialize", "serde", true},
		{"::tokio::io", "tokio", true},
		{"tokio", "tokio", true},
		{"Serde_JSON::Value", "serde_json", true},
		{"r#async_trait::x", "async_trait", true},
		{"crate::db", "", false},
		{"self::x", "", false},
		{"super::y", "", false},
		{"std::io", "", false},
		{"core::fmt", "", false},
		{"alloc::vec", "", false},
	}
	for _, tc := range cases {
		got, ok := ImportKey(LangRust, tc.spec)
		if got != tc.want || ok != tc.ok {
			t.Errorf("ImportKey(rust, %q) = %q, %v; want %q, %v", tc.spec, got, ok, tc.want, tc.ok)
		}
	}
	if _, ok := ImportKey("cobol", "x"); ok {
		t.Error("a language without a table maps nothing")
	}
	if got, ok := ImportKey(LangGo, "net/http"); !ok || got != "net/http" {
		t.Errorf("go key = %q, %v", got, ok)
	}
}

// TestIsTestFile has one case per testFileRows row (and its negative).
func TestIsTestFile(t *testing.T) {
	cases := []struct {
		lang, rel string
		want      bool
	}{
		{LangGo, "a/b_test.go", true},
		{LangGo, "a/test/b.go", false},
		{LangJS, "src/a.test.ts", true},
		{LangJS, "src/a.spec.jsx", true},
		{LangJS, "src/__tests__/a.js", true},
		{LangJS, "test/a.mjs", true},
		{LangJS, "src/latest.js", false},
		{LangPython, "pkg/test_a.py", true},
		{LangPython, "pkg/a_test.py", true},
		{LangPython, "conftest.py", true},
		{LangPython, "tests/helpers.py", true},
		{LangPython, "pkg/contest.py", false},
		{LangRust, "tests/it.rs", true},
		{LangRust, "benches/b.rs", true},
		{LangRust, "src/tests.rs", true},
		{LangRust, "src/lib.rs", false},
	}
	for _, tc := range cases {
		if got := IsTestFile(tc.lang, tc.rel); got != tc.want {
			t.Errorf("IsTestFile(%s, %q) = %v, want %v", tc.lang, tc.rel, got, tc.want)
		}
	}
}

func set(lang, src string, complete bool, uses map[string]Use) map[string]ImportSet {
	return map[string]ImportSet{lang: {Source: src, Complete: complete, Uses: uses}}
}

// TestNPM covers the npm matcher's decided and undecided outcomes.
func TestNPM(t *testing.T) {
	adv := func(name string, recs ...Record) Advisory {
		return Advisory{Ecosystem: "npm", Package: name, Records: recs}
	}
	cases := []struct {
		name    string
		adv     Advisory
		imports map[string]ImportSet
		want    Tier
	}{
		{
			"imported by production code", adv("lodash", Record{ID: "GHSA-1"}), set(LangJS, SourceCodeIntel, true, map[string]Use{"lodash": both}),
			Tier{Level: Imported, Source: SourceCodeIntel, Match: "lodash"},
		},
		{
			"imported by tests only", adv("@babel/core"), set(LangJS, SourceCodeIntel, true, map[string]Use{"@babel/core": test}),
			Tier{Level: Imported, Source: SourceCodeIntel, TestsOnly: true, Match: "@babel/core"},
		},
		{
			"no record still decides by name", adv("left-pad"), set(LangJS, SourceCodeIntel, true, map[string]Use{"lodash": prod}),
			Tier{Level: NotImportedDirectly, Source: SourceCodeIntel},
		},
		{
			"an incomplete list proves nothing absent", adv("left-pad"), set(LangJS, SourceCodeIntel, false, map[string]Use{}),
			UnknownTier(ReasonIncomplete),
		},
		{"no index", adv("left-pad"), nil, UnknownTier(ReasonNoCodeIntel)},
		{
			"names are compared exactly", adv("JSONStream"), set(LangJS, SourceCodeIntel, true, map[string]Use{"jsonstream": prod}),
			Tier{Level: NotImportedDirectly, Source: SourceCodeIntel},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.adv, tc.imports); got != tc.want {
				t.Fatalf("Classify = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestPyPI covers the mapping ladder: installed metadata, the built-in
// table, the approximate own-name rule, and an unknown mapping.
func TestPyPI(t *testing.T) {
	adv := func(name string) Advisory { return Advisory{Ecosystem: "PyPI", Package: name} }
	withProvides := func(s map[string]ImportSet, p map[string][]string) map[string]ImportSet {
		v := s[LangPython]
		v.Provides = p
		s[LangPython] = v
		return s
	}
	cases := []struct {
		name    string
		adv     Advisory
		imports map[string]ImportSet
		want    Tier
	}{
		{
			"metadata maps the distribution", adv("my_dist"),
			withProvides(set(LangPython, SourceCodeIntel, true, map[string]Use{"odd_name.sub": prod}), map[string][]string{"my-dist": {"odd_name"}}),
			Tier{Level: Imported, Source: SourceCodeIntel, Match: "odd_name.sub"},
		},
		{
			"metadata wins over the table", adv("PyYAML"),
			withProvides(set(LangPython, SourceCodeIntel, true, map[string]Use{"yaml": prod}), map[string][]string{"pyyaml": {"ruamel_fork"}}),
			Tier{Level: NotImportedDirectly, Source: SourceCodeIntel},
		},
		{
			"the built-in table: PyYAML is yaml", adv("PyYAML"), set(LangPython, SourceCodeIntel, true, map[string]Use{"yaml": prod}),
			Tier{Level: Imported, Source: SourceCodeIntel, Match: "yaml"},
		},
		{
			"the built-in table: Pillow is PIL, tests only", adv("Pillow"), set(LangPython, SourceCodeIntel, true, map[string]Use{"PIL.Image": test}),
			Tier{Level: Imported, Source: SourceCodeIntel, TestsOnly: true, Match: "PIL.Image"},
		},
		{
			"the built-in table: a module beside the prefix is not under it", adv("protobuf"), set(LangPython, SourceCodeIntel, true, map[string]Use{"google.protobufx": prod, "google.cloud": prod}),
			Tier{Level: NotImportedDirectly, Source: SourceCodeIntel},
		},
		{
			"own name, approximate", adv("Typing-Extensions"), set(LangPython, SourceCodeIntel, true, map[string]Use{"typing_extensions": prod}),
			Tier{Level: Imported, Source: SourceCodeIntel, Approximate: true, Match: "typing_extensions"},
		},
		{
			"own name, case folded", adv("PyInstaller"), set(LangPython, SourceCodeIntel, true, map[string]Use{"PyInstaller.utils": prod}),
			Tier{Level: Imported, Source: SourceCodeIntel, Approximate: true, Match: "PyInstaller.utils"},
		},
		{
			"unknown mapping is unknown, never not imported", adv("some-dist"), set(LangPython, SourceCodeIntel, true, map[string]Use{"requests": prod}),
			UnknownTier(ReasonNoNameMapping),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.adv, tc.imports); got != tc.want {
				t.Fatalf("Classify = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestNormalizePEP503(t *testing.T) {
	for in, want := range map[string]string{"PyYAML": "pyyaml", "python_dateutil": "python-dateutil", "ruamel.yaml": "ruamel-yaml", "a--_.b": "a-b", "-x-": "x", "": ""} {
		if got := NormalizePEP503(in); got != want {
			t.Errorf("NormalizePEP503(%q) = %q, want %q", in, got, want)
		}
	}
	for dist := range pythonDistModules {
		if NormalizePEP503(dist) != dist {
			t.Errorf("table row %q is not normalised", dist)
		}
	}
}

func TestPythonDistOfMetadataDir(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"PyYAML-6.0.1.dist-info", "pyyaml", true},
		{"python_dateutil-2.9.0.dist-info", "python-dateutil", true},
		{"requests-2.31.0-py3.11.egg-info", "requests", true},
		{"mypkg.egg-info", "mypkg", true},
		{"yaml", "", false},
		{"-1.0.dist-info", "", false},
		{"bad name-1.dist-info", "", false},
	}
	for _, tc := range cases {
		got, ok := PythonDistOfMetadataDir(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("PythonDistOfMetadataDir(%q) = %q, %v", tc.in, got, ok)
		}
	}
}

func TestPythonModulesFromRecord(t *testing.T) {
	record := `yaml/__init__.py,sha256=x,1
yaml/composer.py,sha256=x,1
_yaml/__init__.py,sha256=x,1
yaml/_yaml.cpython-311-x86_64-linux-gnu.so,sha256=x,1
six.py,sha256=x,1
google/cloud/storage/__init__.py,sha256=x,1
google/cloud/storage/blob.py,sha256=x,1
azure/thing.py,,
"odd,name/__init__.py",,
PyYAML-6.0.1.dist-info/RECORD,,
PyYAML-6.0.1.data/scripts/x.py,,
yaml/__pycache__/composer.cpython-311.pyc,,
../../../bin/tool,,
/abs/x.py,,
README.md,,
__init__.py,,
`
	got := PythonModulesFromRecord([]byte(record))
	want := []string{"_yaml", "azure.thing", "google.cloud.storage", "six", "yaml"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("PythonModulesFromRecord = %v, want %v", got, want)
	}
	if got := PythonModulesFromTopLevel([]byte("yaml\n_yaml\n\nbad-name\ngoogle/protobuf\n")); !reflect.DeepEqual(got, []string{"_yaml", "google.protobuf", "yaml"}) {
		t.Fatalf("PythonModulesFromTopLevel = %v", got)
	}
}

// TestRustCallRules has one case per rustCallRules row, plus the import
// level that decides when no call matches.
func TestRustCallRules(t *testing.T) {
	rec := Record{ID: "RUSTSEC-1", Functions: []string{"smallvec::SmallVec::insert_many"}}
	adv := Advisory{Ecosystem: "crates.io", Package: "smallvec", Records: []Record{rec}}
	rust := func(complete bool, uses map[string]Use, calls []Call, files map[string][]string) map[string]ImportSet {
		return map[string]ImportSet{LangRust: {Source: SourceCodeIntel, Complete: complete, Uses: uses, Calls: calls, CallsRead: calls != nil, FileImports: files}}
	}
	called := Tier{Level: Called, Source: SourceRustCallSite, Approximate: true, Match: "smallvec::SmallVec::insert_many"}
	cases := []struct {
		name    string
		adv     Advisory
		imports map[string]ImportSet
		want    Tier
	}{
		// Row 1: qualified path.
		{"fully qualified call, no use", adv, rust(true, map[string]Use{},
			[]Call{{File: "src/a.rs", Name: "insert_many", Text: "smallvec::SmallVec::insert_many(&mut v, 0, it)"}}, nil), called},
		{"type-qualified call in a file that uses the crate", adv, rust(true, map[string]Use{"smallvec": prod},
			[]Call{{File: "src/a.rs", Name: "insert_many", Text: "SmallVec::<[u8; 4]>::insert_many(&mut v, 0, it)"}}, map[string][]string{"src/a.rs": {"smallvec"}}), called},
		{
			"type-qualified call in a file that does not use the crate", adv, rust(true, map[string]Use{"smallvec": prod},
				[]Call{{File: "src/b.rs", Name: "insert_many", Text: "SmallVec::insert_many(&mut v, 0, it)"}}, map[string][]string{"src/a.rs": {"smallvec"}}),
			Tier{Level: Imported, Source: SourceCodeIntel, Match: "smallvec"},
		},
		{
			"another type's function of that name", adv, rust(true, map[string]Use{"smallvec": prod},
				[]Call{{File: "src/a.rs", Name: "insert_many", Text: "OtherVec::insert_many(&mut v)"}}, map[string][]string{"src/a.rs": {"smallvec"}}),
			Tier{Level: Imported, Source: SourceCodeIntel, Match: "smallvec"},
		},
		// Row 2: callee name in a file that uses the crate.
		{"method call in a file that uses the crate", adv, rust(true, map[string]Use{"smallvec": prod},
			[]Call{{File: "src/a.rs", Name: "insert_many", Text: "v.insert_many(0, it)"}}, map[string][]string{"src/a.rs": {"smallvec"}}), called},
		{
			"method call in tests only", adv, rust(true, map[string]Use{"smallvec": prod},
				[]Call{{File: "tests/t.rs", Name: "insert_many", Text: "v.insert_many(0, it)", Test: true}}, map[string][]string{"tests/t.rs": {"smallvec"}}),
			Tier{Level: Imported, Source: SourceCodeIntel, Match: "smallvec"},
		},
		{
			"called in tests only beats imported in tests only", adv, rust(true, map[string]Use{"smallvec": test},
				[]Call{{File: "tests/t.rs", Name: "insert_many", Text: "v.insert_many(0, it)", Test: true}}, map[string][]string{"tests/t.rs": {"smallvec"}}),
			Tier{Level: Called, Source: SourceRustCallSite, Approximate: true, TestsOnly: true, Match: "smallvec::SmallVec::insert_many"},
		},
		{"a production call wins over a test call", adv, rust(true, map[string]Use{"smallvec": both}, []Call{
			{File: "tests/t.rs", Name: "insert_many", Text: "v.insert_many(0, it)", Test: true},
			{File: "src/a.rs", Name: "insert_many", Text: "w.insert_many(0, it)"},
		}, map[string][]string{"tests/t.rs": {"smallvec"}, "src/a.rs": {"smallvec"}}), called},
		{
			"method call in a file that does not use the crate", adv, rust(true, map[string]Use{"smallvec": prod},
				[]Call{{File: "src/b.rs", Name: "insert_many", Text: "v.insert_many(0, it)"}}, map[string][]string{}),
			Tier{Level: Imported, Source: SourceCodeIntel, Match: "smallvec"},
		},
		// The import level; never "not called", never "not imported".
		{"no matching call and no use is unknown", adv, rust(true, map[string]Use{"serde": prod}, []Call{}, nil), UnknownTier(ReasonUseOnly)},
		{
			"call sites not read: the import level", adv, rust(true, map[string]Use{"smallvec": prod}, nil, nil),
			Tier{Level: Imported, Source: SourceCodeIntel, Match: "smallvec"},
		},
		{
			"a record without functions: the import level",
			Advisory{Ecosystem: "crates.io", Package: "smallvec"},
			rust(false, map[string]Use{}, []Call{}, nil), UnknownTier(ReasonIncomplete),
		},
		{
			"a dashed crate name",
			Advisory{Ecosystem: "crates.io", Package: "serde-json"},
			rust(true, map[string]Use{"serde_json": prod}, nil, nil),
			Tier{Level: Imported, Source: SourceCodeIntel, Match: "serde_json"},
		},
		{"no index", adv, nil, UnknownTier(ReasonNoCodeIntel)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.adv, tc.imports); got != tc.want {
				t.Fatalf("Classify = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestRustCallPath(t *testing.T) {
	cases := []struct {
		text, name string
		want       []string
	}{
		{"smallvec::SmallVec::insert_many(&mut v)", "insert_many", []string{"smallvec", "SmallVec"}},
		{"::smallvec::SmallVec::insert_many(x)", "insert_many", []string{"smallvec", "SmallVec"}},
		{"Vec::<u8>::with_capacity(4)", "with_capacity", []string{"Vec"}},
		{"SmallVec::<[u8; 4]>::new()", "new", []string{"SmallVec"}},
		{"x.insert_many(0)", "insert_many", nil},
		{"insert_many(0)", "insert_many", nil},
		{"self.inner.insert_many(0)", "insert_many", nil},
		{"foo::bar::<T>(x)", "bar", []string{"foo"}},
		{"reinsert_many(0)", "insert_many", nil},
		{"insert_many_x(0); a::insert_many(1)", "insert_many", []string{"a"}},
		{"", "x", nil},
		{"a::b()", "", nil},
	}
	for _, tc := range cases {
		if got := RustCallPath(tc.text, tc.name); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("RustCallPath(%q, %q) = %v, want %v", tc.text, tc.name, got, tc.want)
		}
	}
}

func TestCallNames(t *testing.T) {
	adv := Advisory{Ecosystem: "crates.io", Package: "smallvec", Records: []Record{
		{Functions: []string{"smallvec::SmallVec::insert_many", "smallvec::SmallVec::insert_many", "other::f", "bad"}},
		{Functions: []string{"smallvec::from_buf"}},
	}}
	if got := CallNames(adv); !reflect.DeepEqual(got, []string{"insert_many", "from_buf"}) {
		t.Fatalf("CallNames = %v", got)
	}
}
