package agentconfig

import (
	"sort"
	"strings"
	"sync"
)

// SchemaPin records the pinned vendor schema a generated row set came from
// (written by catgen into catalog_index.gen.go).
type SchemaPin struct {
	Tool      string `json:"tool"`
	Shape     string `json:"shape"`
	File      string `json:"file"` // under testdata/agentconfig/schemas
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	FetchedOn string `json:"fetched_on"`
}

// SchemaPins returns the pins, sorted by tool.
func SchemaPins() []SchemaPin { return append([]SchemaPin(nil), schemaPins...) }

// Overlay amends a generated row with what a schema cannot know. Zero
// fields leave the generated value alone. Source is required: every
// overlay fact is grounded (vendor doc URL or the audit section).
type Overlay struct {
	// ID is the setting id; with Prefix set it matches every row whose id
	// starts with ID + "." (a whole sub-tree, e.g. Gemini "admin").
	ID     string
	Prefix bool

	Owner    Owner
	Danger   DangerClass
	Secret   *bool
	Type     ValueType
	Enum     []string
	Scopes   []Scope
	Verified Verified
	Note     string
	Source   string
}

// toolCatalog is the hand-written part of one tool's catalogue.
type toolCatalog struct {
	Tool string
	// VerifiedAgainst names the vendor version / schema revision the rows
	// were checked against.
	VerifiedAgainst string
	Overlays        []Overlay
	// Extra rows the schema omits (env-backed keys, documented keys the
	// published schema lags behind). For a doc-authored tool (phase P2,
	// no schema) these are ALL of its rows. Each carries its own Source.
	Extra []SettingRow
	// Map is the tool's common-vocabulary mapping (vocab_map.go).
	Map []MapRow
	// Files are the tool's settings-kind Files rows (doc-authored tools
	// declare them beside their rows; schema tools keep theirs in
	// files.go). Instruction-kind rows still come from internal/guidance.
	Files []FileRow
}

// toolCatalogs is the registry of hand-written catalogues: one entry per
// schema-generated tool (overlay_<tool>.go) and one per doc-authored tool
// (catalog_<tool>.go, phase P2).
var toolCatalogs = []toolCatalog{
	claudeCodeCatalog,
	codexCatalog,
	openInterpreterCatalog,
	geminiCLICatalog,
	opencodeCatalog,
	kiloCodeCatalog,
	kiloCodeCLICatalog,
	crushCatalog,

	// Doc-authored (phase P2), catalog_<tool>.go.
	aiderCatalog,
	antigravityCatalog,
	antigravityCLICatalog,
	clineCatalog,
	clineCLICatalog,
	commandCodeCatalog,
	copilotCatalog,
	copilotCLICatalog,
	coworkCatalog,
	cursorCatalog,
	deepseekCatalog,
	devinCatalog,
	droidCatalog,
	freebuffCatalog,
	gooseCatalog,
	grokCatalog,
	hermesCatalog,
	junieCatalog,
	kimiCodeCatalog,
	kiroCLICatalog,
	kiroCrewCatalog,
	mistralCodeCatalog,
	museCatalog,
	openclawCatalog,
	piCatalog,
	poolsideCatalog,
	primeAgentCatalog,
	qoderCatalog,
	qwenCodeCatalog,
	zcodeCatalog,
	zedCatalog,

	// The 2026-10-21 capture-only wave (surface-gap lane w4-catalog).
	autohandCatalog,
	ibmBobCatalog,
	cortexCodeCatalog,
	codebuddyCatalog,
	deepAgentsCodeCatalog,
	dimcodeCatalog,
	diracCatalog,
	kimchiCatalog,
	stakpakCatalog,
	vtcodeCatalog,
}

var (
	catalogOnce     sync.Once
	catalogRows     []SettingRow
	catalogProblems []string
)

// Catalog returns every setting row of every catalogued tool, sorted by
// id. The slice and its rows are copies the caller may keep.
func Catalog() []SettingRow {
	catalogOnce.Do(build)
	out := make([]SettingRow, len(catalogRows))
	for i, r := range catalogRows {
		out[i] = cloneRow(r)
	}
	return out
}

// Setting returns one row by id.
func Setting(id string) (SettingRow, bool) {
	catalogOnce.Do(build)
	i := sort.Search(len(catalogRows), func(i int) bool { return catalogRows[i].ID >= id })
	if i < len(catalogRows) && catalogRows[i].ID == id {
		return cloneRow(catalogRows[i]), true
	}
	return SettingRow{}, false
}

// SettingsFor returns one tool's rows, sorted by id.
func SettingsFor(tool string) []SettingRow {
	var out []SettingRow
	for _, r := range Catalog() {
		if r.Tool == tool {
			out = append(out, r)
		}
	}
	return out
}

// buildProblems returns the inconsistencies found while assembling the
// catalogue (an overlay that matches no row, an extra row that collides
// with a generated one). Empty in a healthy build; pinned by the tests.
func buildProblems() []string {
	catalogOnce.Do(build)
	return append([]string(nil), catalogProblems...)
}

func cloneRow(r SettingRow) SettingRow {
	r.Path = append(KeyPath(nil), r.Path...)
	r.Scopes = append([]Scope(nil), r.Scopes...)
	r.Enum = append([]string(nil), r.Enum...)
	if r.Min != nil {
		r.Min = f64(*r.Min)
	}
	if r.Max != nil {
		r.Max = f64(*r.Max)
	}
	return r
}

func build() {
	shapes := shapeIndex()
	var rows []SettingRow
	var problems []string
	for _, tc := range toolCatalogs {
		gen := generatedRows[tc.Tool]
		byID := make(map[string]int, len(gen))
		tool := make([]SettingRow, 0, len(gen)+len(tc.Extra))
		for _, r := range gen {
			byID[r.ID] = len(tool)
			tool = append(tool, cloneRow(r))
		}
		for _, x := range tc.Extra {
			if _, dup := byID[x.ID]; dup {
				problems = append(problems, "extra row "+x.ID+" duplicates a generated row: drop the extra")
				continue
			}
			byID[x.ID] = len(tool)
			tool = append(tool, cloneRow(x))
		}
		for _, o := range tc.Overlays {
			matched := 0
			for i := range tool {
				match := tool[i].ID == o.ID
				if o.Prefix {
					match = strings.HasPrefix(tool[i].ID, o.ID+".")
				}
				if match {
					applyOverlay(&tool[i], o)
					matched++
				}
			}
			if matched == 0 {
				problems = append(problems, "overlay "+o.ID+" matches no row")
			}
		}
		rows = append(rows, tool...)
	}
	spans, unresolved := computeSpans(filesTable())
	stampOwnedRows(rows, spans)
	spansCache, spansUnresolved = spans, unresolved
	for i := range rows {
		r := &rows[i]
		files := shapes[r.FileID]
		if len(r.Scopes) == 0 {
			r.Scopes = shapeScopes(files)
		} else {
			// An overlay names the vendor's scope rule; keep the scopes
			// this tool actually has a file for.
			r.Scopes = intersectScopes(r.Scopes, shapeScopes(files))
		}
		r.Writable = r.Owner == OwnerUser && shapeWritable(files, r.Scopes)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	catalogRows, catalogProblems = rows, problems
}

func applyOverlay(r *SettingRow, o Overlay) {
	if o.Owner != "" {
		r.Owner = o.Owner
	}
	if o.Danger != DangerNone {
		r.Danger = o.Danger
	}
	if o.Secret != nil {
		r.Secret = *o.Secret
		if r.Secret {
			r.Default = ""
		}
	}
	if o.Type != "" {
		r.Type = o.Type
	}
	if o.Enum != nil {
		r.Enum = append([]string(nil), o.Enum...)
	}
	if o.Scopes != nil {
		r.Scopes = append([]Scope(nil), o.Scopes...)
	}
	if o.Verified != "" {
		r.Verified = o.Verified
	}
	if o.Note != "" {
		if r.Note != "" {
			r.Note += " "
		}
		r.Note += o.Note
	}
}

// shapeIndex groups the Files table by shape.
func shapeIndex() map[string][]FileRow {
	out := map[string][]FileRow{}
	for _, f := range filesTable() {
		out[f.Shape] = append(out[f.Shape], f)
	}
	return out
}

func shapeScopes(files []FileRow) []Scope {
	seen := map[Scope]bool{}
	for _, f := range files {
		seen[f.Scope] = true
	}
	var out []Scope
	for _, s := range Scopes() {
		if seen[s] {
			out = append(out, s)
		}
	}
	return out
}

func intersectScopes(want, have []Scope) []Scope {
	ok := map[Scope]bool{}
	for _, s := range have {
		ok[s] = true
	}
	var out []Scope
	for _, s := range want {
		if ok[s] {
			out = append(out, s)
		}
	}
	return out
}

// shapeWritable reports whether some file of the shape at one of the
// row's scopes is writable with the user's own rights.
func shapeWritable(files []FileRow, scopes []Scope) bool {
	want := map[Scope]bool{}
	for _, s := range scopes {
		want[s] = true
	}
	for _, f := range files {
		if want[f.Scope] && f.WriteNeeds == PrivUser {
			return true
		}
	}
	return false
}

func boolp(v bool) *bool { return &v }
