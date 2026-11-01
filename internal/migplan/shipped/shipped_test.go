package shipped

import (
	"strings"
	"testing"
)

const (
	blobA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	blobB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	blobC = "cccccccccccccccccccccccccccccccccccccccc"
	blobD = "dddddddddddddddddddddddddddddddddddddddd"
	sha   = "0123456789abcdef0123456789abcdef01234567"
)

func nodeEntry() Lineage {
	return Lineage{
		Name: "node", Dir: "internal/db/migrations", Head: 5, Ref: "v1.0.0", Commit: sha,
		Steps: []Step{{File: "001_initial.sql", Blob: blobA}, {File: "002_more.sql", Blob: blobB}, {File: "005_last.sql", Blob: blobD}},
	}
}

func TestBlobIDMatchesGit(t *testing.T) {
	// `printf 'hello\n' | git hash-object --stdin`
	if got, want := BlobID([]byte("hello\n")), "ce013625030ba8dba906f756967f9e9ca394464a"; got != want {
		t.Fatalf("BlobID = %s, want %s", got, want)
	}
	// The empty blob.
	if got, want := BlobID(nil), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"; got != want {
		t.Fatalf("BlobID(empty) = %s, want %s", got, want)
	}
}

func TestStepNumber(t *testing.T) {
	cases := []struct {
		file string
		n    int
		ok   bool
	}{
		{"001_initial.sql", 1, true},
		{"0108_org_member.sql", 108, true},
		{"241_x.sql", 241, true},
		{"migrations.go", 0, false},
		{"001_initial.go", 0, false},
		{"abc_x.sql", 0, false},
		{"_x.sql", 0, false},
		{"001.sql", 0, false},
		{"001_.sql", 0, false},
		{"gen/001_x.sql", 0, false},
		{"-01_x.sql", 0, false},
	}
	for _, c := range cases {
		n, ok := StepNumber(c.file)
		if n != c.n || ok != c.ok {
			t.Errorf("StepNumber(%q) = %d,%v want %d,%v", c.file, n, ok, c.n, c.ok)
		}
	}
}

func TestCheck(t *testing.T) {
	cases := []struct {
		name  string
		tree  []Step
		kinds []ViolationKind
		files []string
		want  []string // substrings of the joined messages
	}{
		{
			name: "unchanged tree passes",
			tree: []Step{{"001_initial.sql", blobA}, {"002_more.sql", blobB}, {"005_last.sql", blobD}, {"migrations.go", blobC}},
		},
		{
			name: "new step above head accepted",
			tree: []Step{{"001_initial.sql", blobA}, {"002_more.sql", blobB}, {"005_last.sql", blobD}, {"006_new.sql", blobC}},
		},
		{
			name:  "late step in a gap below head rejected",
			tree:  []Step{{"001_initial.sql", blobA}, {"002_more.sql", blobB}, {"003_late.sql", blobC}, {"005_last.sql", blobD}},
			kinds: []ViolationKind{Late},
			files: []string{"003_late.sql"},
			want: []string{
				"internal/db/migrations/003_late.sql is numbered 3, at or below the shipped head 5 of the node lineage (shipped in v1.0.0)",
				"It is unshipped, so renumbering is safe: renumber the new step above 5 (next free number: 006)",
				"Never edit a shipped step",
			},
		},
		{
			name:  "next free number clears unshipped steps above head and keeps the padding",
			tree:  []Step{{"001_initial.sql", blobA}, {"002_more.sql", blobB}, {"0004_late.sql", blobC}, {"005_last.sql", blobD}, {"007_new.sql", blobC}},
			kinds: []ViolationKind{Late},
			files: []string{"0004_late.sql"},
			want:  []string{"next free number: 0008"},
		},
		{
			name:  "late step reusing the head number rejected",
			tree:  []Step{{"001_initial.sql", blobA}, {"002_more.sql", blobB}, {"005_last.sql", blobD}, {"005_other.sql", blobC}},
			kinds: []ViolationKind{Late},
			files: []string{"005_other.sql"},
			want:  []string{"numbered 5, at or below the shipped head 5", "next free number: 006"},
		},
		{
			name:  "shipped blob changed rejected",
			tree:  []Step{{"001_initial.sql", blobA}, {"002_more.sql", blobC}, {"005_last.sql", blobD}},
			kinds: []ViolationKind{Changed},
			files: []string{"002_more.sql"},
			want:  []string{"shipped in v1.0.0", "blob " + blobB + ", but the tree has blob " + blobC, "git checkout v1.0.0 -- internal/db/migrations/002_more.sql", "new step above 5"},
		},
		{
			name:  "shipped step vanished rejected",
			tree:  []Step{{"001_initial.sql", blobA}, {"005_last.sql", blobD}},
			kinds: []ViolationKind{Vanished},
			files: []string{"002_more.sql"},
			want:  []string{"is missing from the tree", "never removed or renamed"},
		},
		{
			name:  "renamed shipped step is vanished plus late",
			tree:  []Step{{"001_initial.sql", blobA}, {"002_renamed.sql", blobB}, {"005_last.sql", blobD}},
			kinds: []ViolationKind{Vanished, Late},
			files: []string{"002_more.sql", "002_renamed.sql"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vs := Check(nodeEntry(), c.tree)
			if len(vs) != len(c.kinds) {
				t.Fatalf("got %d violations %v, want %d", len(vs), vs, len(c.kinds))
			}
			var msgs []string
			for i, v := range vs {
				if v.Kind != c.kinds[i] || v.File != c.files[i] {
					t.Errorf("violation %d = %s %s, want %s %s", i, v.Kind, v.File, c.kinds[i], c.files[i])
				}
				msgs = append(msgs, v.String())
			}
			joined := strings.Join(msgs, "\n")
			for _, w := range c.want {
				if !strings.Contains(joined, w) {
					t.Errorf("message lacks %q:\n%s", w, joined)
				}
			}
		})
	}
}

func validRecord() Record {
	r := Record{Schema: SchemaVersion}
	for _, def := range Lineages() {
		r.Lineages = append(r.Lineages, Lineage{
			Name: def.Name, Dir: def.Dir, Head: 1, Ref: "v1.0.0", Commit: sha,
			Steps: []Step{{File: "001_initial.sql", Blob: blobA}},
		})
	}
	return r
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Record)
		want   string // "" = valid
	}{
		{"valid", func(*Record) {}, ""},
		{"wrong schema", func(r *Record) { r.Schema = 2 }, "schema is 2"},
		{"lineage missing", func(r *Record) { r.Lineages = r.Lineages[1:] }, `lineage "archive" is missing`},
		{"lineage twice", func(r *Record) { r.Lineages = append(r.Lineages, r.Lineages[0]) }, "appears twice"},
		{"unknown lineage", func(r *Record) { r.Lineages[0].Name = "mystery" }, "not a known lineage"},
		{"wrong dir", func(r *Record) { r.Lineages[0].Dir = "elsewhere" }, `dir is "elsewhere"`},
		{"empty ref", func(r *Record) { r.Lineages[0].Ref = " " }, "ref is empty"},
		{"bad commit", func(r *Record) { r.Lineages[0].Commit = "abc" }, "not a 40-hex commit id"},
		{"no steps", func(r *Record) { r.Lineages[0].Steps = nil }, "no steps"},
		{"bad step name", func(r *Record) { r.Lineages[0].Steps[0].File = "initial.sql" }, "not a NNN_name.sql step file"},
		{"bad blob", func(r *Record) { r.Lineages[0].Steps[0].Blob = "XYZ" }, "not a 40-hex blob id"},
		{"head not max", func(r *Record) { r.Lineages[0].Head = 7 }, "head is 7 but the highest step is 1"},
		{"number used twice", func(r *Record) {
			r.Lineages[0].Steps = append(r.Lineages[0].Steps, Step{File: "001_other.sql", Blob: blobB})
		}, "number 1 is used by both"},
		{"step twice", func(r *Record) {
			r.Lineages[0].Steps = append(r.Lineages[0].Steps, r.Lineages[0].Steps[0])
		}, "appears twice"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := validRecord()
			c.mutate(&r)
			err := r.Validate()
			if c.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error = %v, want it to contain %q", err, c.want)
			}
		})
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	good, err := Encode(validRecord())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(good); err != nil {
		t.Fatalf("Parse(valid): %v", err)
	}
	cases := []struct {
		name string
		data string
		want string
	}{
		{"not json", "{", "shipped.Parse"},
		{"unknown field", `{"schema":1,"lineages":[],"extra":true}`, "unknown field"},
		{"trailing data", string(good) + "{}", "trailing data"},
		{"empty record", `{"schema":1,"lineages":[]}`, "is missing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Parse([]byte(c.data)); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Parse error = %v, want %q", err, c.want)
			}
		})
	}
}

func TestEncodeIsDeterministicAndSorted(t *testing.T) {
	r := validRecord()
	r.Lineages[0].Steps = []Step{{File: "002_b.sql", Blob: blobB}, {File: "001_initial.sql", Blob: blobA}}
	r.Lineages[0].Head = 2
	// Reverse the lineage order.
	for i, j := 0, len(r.Lineages)-1; i < j; i, j = i+1, j-1 {
		r.Lineages[i], r.Lineages[j] = r.Lineages[j], r.Lineages[i]
	}
	a, err := Encode(r)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(a)
	if err != nil {
		t.Fatalf("Parse(Encode): %v", err)
	}
	b, err := Encode(back)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("Encode is not stable:\n%s\n---\n%s", a, b)
	}
	if back.Lineages[0].Name != "archive" || back.Lineages[len(back.Lineages)-1].Name != "org-sqlite" {
		t.Fatalf("lineages not sorted: %+v", back.Lineages)
	}
	arch := back.Lineages[0]
	if arch.Name == "archive" && len(arch.Steps) == 2 && arch.Steps[0].File != "001_initial.sql" {
		t.Fatalf("steps not sorted: %+v", arch.Steps)
	}
	if !strings.HasSuffix(string(a), "}\n") {
		t.Fatal("record must end with a newline")
	}
}

func TestMerge(t *testing.T) {
	def, _ := LookupLineage("node")
	prev := nodeEntry()
	cases := []struct {
		name     string
		prev     *Lineage
		tree     []Step
		wantHead int
		wantErr  string
	}{
		{"first record", nil, []Step{{"001_initial.sql", blobA}, {"migrations.go", blobD}}, 1, ""},
		{"append above head", &prev, []Step{{"001_initial.sql", blobA}, {"002_more.sql", blobB}, {"005_last.sql", blobD}, {"006_new.sql", blobC}}, 6, ""},
		{"same tree again", &prev, []Step{{"001_initial.sql", blobA}, {"002_more.sql", blobB}, {"005_last.sql", blobD}}, 5, ""},
		{"late step refused", &prev, []Step{{"001_initial.sql", blobA}, {"003_late.sql", blobC}, {"002_more.sql", blobB}, {"005_last.sql", blobD}}, 0, "breaks the released-step rule"},
		{"edited step refused", &prev, []Step{{"001_initial.sql", blobC}, {"002_more.sql", blobB}, {"005_last.sql", blobD}}, 0, "never edit a shipped step"},
		{"vanished step refused", &prev, []Step{{"001_initial.sql", blobA}, {"005_last.sql", blobD}}, 0, "is missing from the tree"},
		{"no steps refused", nil, []Step{{"migrations.go", blobD}}, 0, "no migration steps"},
		{"duplicate number refused", nil, []Step{{"001_a.sql", blobA}, {"001_b.sql", blobB}}, 0, "number 1 is used by both"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Merge(c.prev, def, "v2.0.0", sha, c.tree)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(c.wantErr)) {
					t.Fatalf("err = %v, want %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Merge: %v", err)
			}
			if got.Head != c.wantHead || got.Ref != "v2.0.0" || got.Commit != sha || got.Dir != def.Dir {
				t.Fatalf("got %+v", got)
			}
			for _, s := range got.Steps {
				if _, ok := StepNumber(s.File); !ok {
					t.Fatalf("non-step file recorded: %s", s.File)
				}
			}
		})
	}
}
