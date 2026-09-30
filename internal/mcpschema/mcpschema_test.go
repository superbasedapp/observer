package mcpschema

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func mustHash(t *testing.T, tools []Tool) string {
	t.Helper()
	h, err := SchemaHash(tools, Options{})
	if err != nil {
		t.Fatalf("SchemaHash: %v", err)
	}
	return h
}

func TestCanonicalizeStableUnderReorderAndWhitespace(t *testing.T) {
	cases := []struct {
		name string
		a, b string
	}{
		{"key order", `{"b":1,"a":{"d":true,"c":null}}`, `{ "a" : { "c" : null , "d" : true } , "b" : 1 }`},
		{"float form", `{"x":1.0,"y":1e2,"z":-0.5}`, `{"z":-0.50,"y":100,"x":1}`},
		{"nested arrays keep order", `{"enum":["b","a"]}`, `{ "enum" : [ "b" , "a" ] }`},
		{"unicode not html-escaped", `{"d":"a<b>&cé"}`, "{\"d\":\"a<b>&cé\"}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca, err := Canonicalize([]byte(tc.a), Options{})
			if err != nil {
				t.Fatalf("a: %v", err)
			}
			cb, err := Canonicalize([]byte(tc.b), Options{})
			if err != nil {
				t.Fatalf("b: %v", err)
			}
			if string(ca) != string(cb) {
				t.Fatalf("canonical forms differ:\n a=%s\n b=%s", ca, cb)
			}
			if strings.ContainsAny(string(ca), " \n\t") && !strings.Contains(tc.a, `"a<b>`) {
				t.Fatalf("canonical form carries whitespace: %s", ca)
			}
		})
	}
	// Array order IS significant.
	ca, _ := Canonicalize([]byte(`["a","b"]`), Options{})
	cb, _ := Canonicalize([]byte(`["b","a"]`), Options{})
	if string(ca) == string(cb) {
		t.Fatal("array reorder canonicalized equal")
	}
	if _, err := Canonicalize([]byte(`{"a":`), Options{}); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("truncated JSON err = %v", err)
	}
	if _, err := Canonicalize([]byte(`{} {}`), Options{}); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("trailing data err = %v", err)
	}
	if c, _ := Canonicalize(nil, Options{}); string(c) != "null" {
		t.Fatalf("nil -> %s", c)
	}
}

func TestCanonicalizeResolvesLocalRefsBounded(t *testing.T) {
	withRef := `{"type":"object","properties":{"who":{"$ref":"#/$defs/person"}},"$defs":{"person":{"type":"string","minLength":1}}}`
	inline := `{"type":"object","properties":{"who":{"type":"string","minLength":1}},"$defs":{"person":{"type":"string","minLength":1}}}`
	a, err := Canonicalize([]byte(withRef), Options{})
	if err != nil {
		t.Fatalf("withRef: %v", err)
	}
	b, _ := Canonicalize([]byte(inline), Options{})
	if string(a) != string(b) {
		t.Fatalf("$ref not inlined:\n got=%s\nwant=%s", a, b)
	}

	// Sibling keyword merges over the target (sibling wins on conflict).
	sib := `{"x":{"$ref":"#/d","minLength":5},"d":{"type":"string","minLength":1}}`
	c, err := Canonicalize([]byte(sib), Options{})
	if err != nil {
		t.Fatalf("sibling: %v", err)
	}
	if want := `{"d":{"minLength":1,"type":"string"},"x":{"minLength":5,"type":"string"}}`; string(c) != want {
		t.Fatalf("sibling merge = %s, want %s", c, want)
	}

	// Pointer escapes and array indices.
	esc := `{"x":{"$ref":"#/a~1b/1"},"a/b":[0,{"ok":true}]}`
	c, err = Canonicalize([]byte(esc), Options{})
	if err != nil || !strings.Contains(string(c), `"x":{"ok":true}`) {
		t.Fatalf("escaped pointer: %s %v", c, err)
	}

	// A remote $ref is kept verbatim and never fetched.
	remote := `{"x":{"$ref":"https://example.com/schema.json"}}`
	c, err = Canonicalize([]byte(remote), Options{})
	if err != nil || string(c) != `{"x":{"$ref":"https://example.com/schema.json"}}` {
		t.Fatalf("remote ref: %s %v", c, err)
	}

	errCases := []struct {
		name string
		doc  string
		opts Options
		want error
	}{
		{"cycle", `{"a":{"$ref":"#/b"},"b":{"$ref":"#/a"}}`, Options{}, ErrRefCycle},
		{"self cycle", `{"a":{"$ref":"#/a"}}`, Options{}, ErrRefCycle},
		{"missing target", `{"a":{"$ref":"#/nope"}}`, Options{}, ErrRefTarget},
		{"depth", `{"a":{"$ref":"#/b"},"b":{"$ref":"#/c"},"c":{"$ref":"#/d"},"d":{"v":1}}`, Options{MaxRefDepth: 2}, ErrRefDepth},
		{"budget", `{"a":[{"$ref":"#/d"},{"$ref":"#/d"},{"$ref":"#/d"}],"d":{"v":1}}`, Options{MaxRefExpansions: 2}, ErrRefBudget},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Canonicalize([]byte(tc.doc), tc.opts)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestSchemaHashAndCanonicalTool(t *testing.T) {
	t1 := Tool{Name: "create_issue", Description: "Create", InputSchema: json.RawMessage(`{"type":"object","properties":{"title":{"type":"string"}}}`), Annotations: json.RawMessage(`{"destructiveHint":false}`)}
	t2 := Tool{Name: "delete_repo", Description: "Delete", InputSchema: json.RawMessage(`{"type":"object"}`)}
	h1 := mustHash(t, []Tool{t1, t2})
	h2 := mustHash(t, []Tool{t2, t1}) // order-independent
	if h1 != h2 {
		t.Fatal("hash depends on tool order")
	}
	reformatted := t1
	reformatted.InputSchema = json.RawMessage(`{ "properties" : { "title" : { "type" : "string" } } , "type" : "object" }`)
	if mustHash(t, []Tool{reformatted, t2}) != h1 {
		t.Fatal("hash depends on schema whitespace/key order")
	}
	nested := t1
	nested.InputSchema = json.RawMessage(`{"type":"object","properties":{"title":{"type":"string","maxLength":9}}}`)
	if mustHash(t, []Tool{nested, t2}) == h1 {
		t.Fatal("a nested schema change did not change the hash (depth-1 pin regression)")
	}
	ann := t1
	ann.Annotations = json.RawMessage(`{"destructiveHint":true}`)
	if mustHash(t, []Tool{ann, t2}) == h1 {
		t.Fatal("an annotation change did not change the hash")
	}
	if _, err := SchemaHash([]Tool{t1, t1}, Options{}); !errors.Is(err, ErrDuplicateTool) {
		t.Fatalf("duplicate err = %v", err)
	}
	if _, err := SchemaHash([]Tool{{Name: "bad name"}}, Options{}); !errors.Is(err, ErrToolName) {
		t.Fatalf("bad name err = %v", err)
	}
	if empty := mustHash(t, nil); len(empty) != 64 {
		t.Fatalf("empty set hash = %q", empty)
	}
	c, err := CanonicalTool(t1, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"annotations":{"destructiveHint":false},"description":"Create","inputSchema":{"properties":{"title":{"type":"string"}},"type":"object"},"name":"create_issue"}`
	if string(c) != want {
		t.Fatalf("CanonicalTool = %s\nwant %s", c, want)
	}
	arr, err := MarshalTools([]Tool{t2, t1}, Options{})
	if err != nil || !strings.HasPrefix(string(arr), `[{"annotations"`) || !strings.HasSuffix(string(arr), `"name":"delete_repo"}]`) {
		t.Fatalf("MarshalTools = %s %v", arr, err)
	}
	back, err := ParseTools(arr)
	if err != nil || len(back) != 2 || back[0].Name != "create_issue" {
		t.Fatalf("ParseTools round trip = %+v %v", back, err)
	}
	if mustHash(t, back) != h1 {
		t.Fatal("round-tripped tools_json hashes differently")
	}
}

func TestParseToolsListResult(t *testing.T) {
	tools, cursor, err := ParseToolsListResult([]byte(`{"tools":[{"name":"a","inputSchema":{"type":"object"}}],"nextCursor":"c2"}`))
	if err != nil || len(tools) != 1 || tools[0].Name != "a" || cursor != "c2" {
		t.Fatalf("got %+v %q %v", tools, cursor, err)
	}
	if _, _, err := ParseToolsListResult([]byte(`nope`)); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("err = %v", err)
	}
}

func TestCfgHash(t *testing.T) {
	a := LaunchShape{Transport: "streamable_http", URL: "https://mcp.example.com/mcp", HeaderNames: []string{"X-B", "X-A"}}
	b := a
	b.HeaderNames = []string{"X-A", "X-B"}
	if CfgHash(a) != CfgHash(b) {
		t.Fatal("header-name order changed the cfg hash")
	}
	c := a
	c.URL = "https://mcp.example.com/mcp2"
	if CfgHash(a) == CfgHash(c) {
		t.Fatal("URL change did not change the cfg hash")
	}
	d := LaunchShape{Transport: "node_local_stdio", Command: "npx", Args: []string{"-y", "srv"}}
	e := d
	e.Args = []string{"srv", "-y"}
	if CfgHash(d) == CfgHash(e) {
		t.Fatal("arg order is significant and must change the hash")
	}
}

func TestAnnotationsDefaults(t *testing.T) {
	cases := []struct {
		raw             string
		destructive, ro bool
		idem, openWorld bool
	}{
		{"", true, false, false, true},
		{`{}`, true, false, false, true},
		{`{"destructiveHint":false}`, false, false, false, true},
		{`{"readOnlyHint":true}`, false, true, false, true},
		{`{"readOnlyHint":true,"destructiveHint":true}`, false, true, false, true},
		{`{"idempotentHint":true,"openWorldHint":false}`, true, false, true, false},
	}
	for _, tc := range cases {
		a, err := ParseAnnotations(json.RawMessage(tc.raw))
		if err != nil {
			t.Fatalf("%s: %v", tc.raw, err)
		}
		if a.Destructive() != tc.destructive || a.ReadOnly() != tc.ro || a.Idempotent() != tc.idem || a.OpenWorld() != tc.openWorld {
			t.Fatalf("%s: got d=%t ro=%t i=%t ow=%t", tc.raw, a.Destructive(), a.ReadOnly(), a.Idempotent(), a.OpenWorld())
		}
	}
	if _, err := ParseAnnotations(json.RawMessage(`[1]`)); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("err = %v", err)
	}
}

func TestDiffTools(t *testing.T) {
	create := Tool{Name: "create_issue", Description: "Create", InputSchema: json.RawMessage(`{"type":"object"}`), Annotations: json.RawMessage(`{"destructiveHint":false}`)}
	del := Tool{Name: "delete_repo", Description: "Delete", InputSchema: json.RawMessage(`{"type":"object"}`)}
	list := Tool{Name: "list_repos", Description: "List", Annotations: json.RawMessage(`{"readOnlyHint":true}`)}

	d, err := DiffTools([]Tool{create, del}, []Tool{del, create}, Options{})
	if err != nil || !d.Empty() || d.Summary() != "no drift" {
		t.Fatalf("identical sets: %+v %v", d, err)
	}

	changedDel := del
	changedDel.InputSchema = json.RawMessage(`{"type":"object","properties":{"force":{"type":"boolean"}}}`)
	changedCreate := create
	changedCreate.Description = "Create an issue"
	d, err = DiffTools([]Tool{create, del}, []Tool{changedDel, changedCreate, list}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Added) != 1 || d.Added[0] != "list_repos" {
		t.Fatalf("Added = %v", d.Added)
	}
	if len(d.Removed) != 0 {
		t.Fatalf("Removed = %v", d.Removed)
	}
	if len(d.Changed) != 2 || d.Changed[0].Name != "create_issue" || d.Changed[0].Fields[0] != "description" ||
		d.Changed[1].Name != "delete_repo" || d.Changed[1].Fields[0] != "inputSchema" {
		t.Fatalf("Changed = %+v", d.Changed)
	}
	// delete_repo has no annotations -> destructive by default; create_issue
	// says false; list_repos is read-only.
	if len(d.DestructiveTouched) != 1 || d.DestructiveTouched[0] != "delete_repo" {
		t.Fatalf("DestructiveTouched = %v", d.DestructiveTouched)
	}
	if d.OldHash == d.NewHash || d.OldHash != mustHash(t, []Tool{create, del}) {
		t.Fatal("hashes not carried")
	}
	if !strings.Contains(d.Summary(), "added=1") || !strings.Contains(d.Summary(), "changed=2") || !strings.Contains(d.Summary(), "destructive_touched=1") {
		t.Fatalf("Summary = %q", d.Summary())
	}
	b, err := json.Marshal(Diff{OldHash: "a", NewHash: "b"})
	if err != nil || !strings.Contains(string(b), `"added":[]`) || !strings.Contains(string(b), `"changed":[]`) {
		t.Fatalf("empty diff JSON = %s %v", b, err)
	}
	d, _ = DiffTools([]Tool{create, del}, []Tool{create}, Options{})
	if len(d.Removed) != 1 || d.Removed[0] != "delete_repo" {
		t.Fatalf("Removed = %v", d.Removed)
	}
}

func TestNameMap(t *testing.T) {
	tools := []Tool{{Name: "create_issue"}, {Name: "delete_repo"}, {Name: "list"}}
	cases := []struct {
		name string
		m    NameMap
		ok   bool
	}{
		{"empty", NameMap{}, true},
		{"rename one", NameMap{"create_issue": "gh_create_issue"}, true},
		{"swap is fine", NameMap{"create_issue": "delete_repo", "delete_repo": "create_issue"}, true},
		{"unknown native", NameMap{"nope": "x"}, false},
		{"invalid exposed", NameMap{"create_issue": "has space"}, false},
		{"duplicate exposed", NameMap{"create_issue": "x", "delete_repo": "x"}, false},
		{"collides with unmapped native", NameMap{"create_issue": "list"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateNameMap(tc.m, tools)
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, ok %t", err, tc.ok)
			}
			if err != nil && !errors.Is(err, ErrNameMap) {
				t.Fatalf("does not wrap ErrNameMap: %v", err)
			}
		})
	}
	m := NameMap{"create_issue": "gh_create_issue"}
	if m.Exposed("create_issue") != "gh_create_issue" || m.Exposed("list") != "list" {
		t.Fatal("Exposed")
	}
	if n, ok := m.Native("gh_create_issue", tools); !ok || n != "create_issue" {
		t.Fatal("Native mapped")
	}
	if _, ok := m.Native("create_issue", tools); ok {
		t.Fatal("a renamed-away native name must not be exposed")
	}
	if n, ok := m.Native("list", tools); !ok || n != "list" {
		t.Fatal("Native unmapped")
	}
	if _, ok := m.Native("ghost", tools); ok {
		t.Fatal("unknown exposed name resolved")
	}
	b, _ := json.Marshal(NameMap{"b": "2", "a": "1"})
	if string(b) != `{"a":"1","b":"2"}` {
		t.Fatalf("MarshalJSON = %s", b)
	}
	back, err := ParseNameMap(b)
	if err != nil || back["a"] != "1" {
		t.Fatalf("ParseNameMap = %v %v", back, err)
	}
	if e, err := ParseNameMap(nil); err != nil || len(e) != 0 {
		t.Fatalf("empty = %v %v", e, err)
	}
}
