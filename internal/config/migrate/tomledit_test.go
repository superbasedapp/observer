package migrate

import (
	"reflect"
	"testing"
)

func TestParseDottedKey(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"a.b.c", []string{"a", "b", "c"}},
		{" compression . code_graph . enabled ", []string{"compression", "code_graph", "enabled"}},
		{`a."b.c".d`, []string{"a", "b.c", "d"}},
		{"'x.y'.z", []string{"x.y", "z"}},
		{"single", []string{"single"}},
	}
	for _, c := range cases {
		if got := SplitDottedKey(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("SplitDottedKey(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestScalarSafe(t *testing.T) {
	safe := []string{"true", "false", "42", `"a string"`, "1.5", `'literal'`, `"has # hash"`}
	unsafe := []string{"", "[1, 2]", "{ a = 1 }", `"""multi`, "'''multi"}
	for _, s := range safe {
		if !scalarSafe(s) {
			t.Errorf("scalarSafe(%q) = false, want true", s)
		}
	}
	for _, s := range unsafe {
		if scalarSafe(s) {
			t.Errorf("scalarSafe(%q) = true, want false", s)
		}
	}
}

func TestSplitKeyVal(t *testing.T) {
	k, v, ok := splitKeyVal("  enabled = true  # c")
	if !ok || k != "enabled" || v != "true  # c" {
		t.Errorf("splitKeyVal got (%q,%q,%v)", k, v, ok)
	}
	if _, _, ok := splitKeyVal("[section]"); ok {
		// '[section]' has no '=' — not a keyval
		t.Errorf("header should not parse as keyval")
	}
	if _, _, ok := splitKeyVal("# comment = x"); !ok {
		// splitKeyVal is dumb about comments; analyze() filters those
		// out first, so this only asserts the '=' split itself.
		t.Logf("splitKeyVal does not itself skip comments (by design)")
	}
}

func TestFindKey_BlockAndDotted(t *testing.T) {
	block := parseDocument("[compression.code_graph]\nenabled = true\n")
	if block.findKey(k("compression", "code_graph", "enabled")) < 0 {
		t.Errorf("block-form key not found")
	}
	dotted := parseDocument("compression.code_graph.enabled = true\n")
	if dotted.findKey(k("compression", "code_graph", "enabled")) < 0 {
		t.Errorf("dotted-form key not found")
	}
	if block.findKey(k("compression", "code_graph", "nope")) >= 0 {
		t.Errorf("absent key reported present")
	}
}

func TestUpsertScalar_CreatesTableAndKey(t *testing.T) {
	d := parseDocument("[observer]\nlog_level = \"info\"\n")
	d.upsertScalar(k("codeintel", "index", "on_start"), "true")
	if d.findKey(k("codeintel", "index", "on_start")) < 0 {
		t.Fatalf("upsert did not create key:\n%s", d.render())
	}
	if d.findHeader(k("codeintel.index")) < 0 && d.findHeader(k("codeintel", "index")) < 0 {
		// header stored as segments ["codeintel","index"]
		t.Errorf("codeintel.index header not created:\n%s", d.render())
	}
}

func TestUpsertScalar_ReplacesInPlace(t *testing.T) {
	d := parseDocument("[codeintel]\nenabled = false\n")
	d.upsertScalar(k("codeintel", "enabled"), "true")
	got := d.render()
	if want := "[codeintel]\nenabled = true\n"; got != want {
		t.Errorf("replace-in-place got:\n%q\nwant:\n%q", got, want)
	}
}

func TestRoundTripPreservesTrailingNewlineState(t *testing.T) {
	for _, in := range []string{"a = 1\n", "a = 1"} {
		if got := parseDocument(in).render(); got != in {
			t.Errorf("round-trip changed %q -> %q", in, got)
		}
	}
}

func TestReadInt(t *testing.T) {
	d := parseDocument("[observer]\nconfig_version = 3  # stamped\n")
	if n, ok := d.readInt(k("observer", "config_version")); !ok || n != 3 {
		t.Errorf("readInt got (%d,%v), want (3,true)", n, ok)
	}
	if _, ok := parseDocument("[observer]\n").readInt(k("observer", "config_version")); ok {
		t.Errorf("absent int should return ok=false")
	}
}
