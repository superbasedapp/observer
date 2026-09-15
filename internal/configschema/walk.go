package configschema

import (
	"reflect"
	"strings"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// Kind is the settable shape of a leaf. The first six are the kinds the
// generic write route can set; KindTable is an opaque compound (a map of
// structs, an array of tables, a map of lists) that has its own editor or
// stays file-only — it is described so the UI can SAY so, never edited
// through the generic route.
type Kind string

// Leaf kinds.
const (
	KindBool       Kind = "bool"
	KindInt        Kind = "int"
	KindFloat      Kind = "float"
	KindString     Kind = "string"
	KindStringList Kind = "string_list"
	KindStringMap  Kind = "string_map"
	KindTable      Kind = "table"
)

// Scalar reports whether the kind is a single-line TOML scalar the surgical
// editor can rewrite in place (plan §2.3 Tier A). Lists and maps re-serialize
// the file (Tier B).
func (k Kind) Scalar() bool {
	switch k {
	case KindBool, KindInt, KindFloat, KindString:
		return true
	}
	return false
}

// Writable reports whether the generic write route can set a leaf of this
// kind at all (KindTable cannot).
func (k Kind) Writable() bool { return k != KindTable }

// Leaf is one settable config key, fully described. The structural fields
// come from the reflect walk; the classification fields from the annotation
// table; Doc is filled only by the generator (from the Go comment), never
// at runtime.
type Leaf struct {
	// Path is the dotted TOML path ("observer.watch.poll_interval_seconds").
	Path string `json:"path"`
	// FieldPath is the dotted JSON path of the same value in GET /api/config's
	// `config` object, which encoding/json renders with Go field names (or
	// `json` tags where a struct declares them).
	FieldPath string `json:"field_path"`
	// Kind is the settable shape.
	Kind Kind `json:"kind"`
	// GoType is the Go type string, informational (drives the "table" copy).
	GoType string `json:"go_type"`
	// Owner is the package-qualified struct type declaring the field
	// ("github.com/…/internal/config.WatchConfig"); Field its Go name. The
	// generator uses the pair to attach the field's doc comment.
	Owner string `json:"owner"`
	Field string `json:"field"`
	// Block is the top-level [table] the key lives under.
	Block string `json:"block"`
	// Table is the dotted path of the enclosing table ("" for a root key).
	Table string `json:"table"`

	Tier       Tier       `json:"tier"`
	Restart    Restart    `json:"restart"`
	Section    string     `json:"section"`
	Prominence Prominence `json:"prominence"`
	// Secret is true for T2 leaves — redacted on read, refused on write.
	Secret bool `json:"secret"`
	// Deprecated carries the migration hint for a legacy alias ("" otherwise).
	// Deprecated leaves render read-only; writing one would re-create the
	// loader's deprecation warning on the next start.
	Deprecated string `json:"deprecated,omitempty"`
	// OwnedBy names the command or surface that owns a T3 leaf.
	OwnedBy string `json:"owned_by,omitempty"`
	// Enum is the closed vocabulary for a string leaf, when one exists.
	Enum []string `json:"enum,omitempty"`
	// Min / Max bound numeric leaves when set.
	Min *float64 `json:"min,omitempty"`
	Max *float64 `json:"max,omitempty"`
	// Doc is the field's Go doc comment. Generator-only.
	Doc string `json:"doc,omitempty"`

	// index is the reflect FieldByIndex chain from config.Config to the
	// leaf, used by the value accessors. Not serialized.
	index []int
}

// Table is one enclosing [table] the walk passed through, so the UI can
// group leaves and the generator can attach the struct's doc comment.
type Table struct {
	Path      string `json:"path"`
	FieldPath string `json:"field_path"`
	Owner     string `json:"owner"`
	Block     string `json:"block"`
	Doc       string `json:"doc,omitempty"`
}

var (
	walkOnce   sync.Once
	walkLeaves []Leaf
	walkTables []Table
	walkByPath map[string]int
)

// ensureWalked runs the reflect walk exactly once per process. The walk is
// over the TYPE, so it needs no config value and cannot fail.
func ensureWalked() {
	walkOnce.Do(func() {
		w := &walker{byPath: map[string]int{}}
		w.walk(reflect.TypeOf(config.Config{}), nil, nil, nil, "")
		for i := range w.leaves {
			annotate(&w.leaves[i])
		}
		walkLeaves, walkTables, walkByPath = w.leaves, w.tables, w.byPath
	})
}

type walker struct {
	leaves []Leaf
	tables []Table
	byPath map[string]int
}

// walk descends t, appending one Leaf per settable field. path is the TOML
// path so far, fpath the JSON field path, index the reflect index chain.
func (w *walker) walk(t reflect.Type, path, fpath []string, index []int, block string) {
	for i := range t.NumField() {
		f := t.Field(i)
		if f.PkgPath != "" { // unexported
			continue
		}
		name := tomlName(f)
		if name == "-" {
			continue
		}
		idx := append(append([]int{}, index...), i)
		if f.Anonymous && name == "" {
			// Promoted embedded struct: its fields belong to the enclosing
			// table (BurntSushi semantics).
			w.walk(f.Type, path, fpath, idx, block)
			continue
		}
		if name == "" {
			name = f.Name
		}
		p := append(append([]string{}, path...), name)
		fp := append(append([]string{}, fpath...), jsonName(f))
		b := block
		if b == "" {
			b = name
		}
		if f.Type.Kind() == reflect.Struct {
			w.tables = append(w.tables, Table{
				Path:      strings.Join(p, "."),
				FieldPath: strings.Join(fp, "."),
				Owner:     qualifiedName(f.Type),
				Block:     b,
			})
			w.walk(f.Type, p, fp, idx, b)
			continue
		}
		leaf := Leaf{
			Path:      strings.Join(p, "."),
			FieldPath: strings.Join(fp, "."),
			Kind:      kindOf(f.Type),
			GoType:    f.Type.String(),
			Owner:     qualifiedName(t),
			Field:     f.Name,
			Block:     b,
			Table:     strings.Join(path, "."),
			index:     idx,
		}
		w.byPath[leaf.Path] = len(w.leaves)
		w.leaves = append(w.leaves, leaf)
	}
}

func tomlName(f reflect.StructField) string {
	return strings.Split(f.Tag.Get("toml"), ",")[0]
}

// jsonName mirrors encoding/json's field naming: the `json` tag name when
// declared, else the Go field name.
func jsonName(f reflect.StructField) string {
	if tag := strings.Split(f.Tag.Get("json"), ",")[0]; tag != "" && tag != "-" {
		return tag
	}
	return f.Name
}

func qualifiedName(t reflect.Type) string {
	if t.PkgPath() == "" {
		return t.Name()
	}
	return t.PkgPath() + "." + t.Name()
}

// kindOf maps a Go leaf type onto a Kind. Anything the generic setter
// cannot express as one of the six writable kinds is KindTable.
func kindOf(t reflect.Type) Kind {
	switch t.Kind() {
	case reflect.Bool:
		return KindBool
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return KindInt
	case reflect.Float32, reflect.Float64:
		return KindFloat
	case reflect.String:
		return KindString
	case reflect.Slice:
		if t.Elem().Kind() == reflect.String {
			return KindStringList
		}
	case reflect.Map:
		if t.Key().Kind() == reflect.String && t.Elem().Kind() == reflect.String {
			return KindStringMap
		}
	}
	return KindTable
}

// Leaves returns every leaf of config.Config in struct-declaration order —
// the order the generator emits and the UI renders. The slice is shared;
// callers must not mutate it.
func Leaves() []Leaf {
	ensureWalked()
	return walkLeaves
}

// Tables returns every enclosing [table] in walk order.
func Tables() []Table {
	ensureWalked()
	return walkTables
}

// Lookup resolves a dotted TOML path to its leaf.
func Lookup(dotted string) (Leaf, bool) {
	ensureWalked()
	i, ok := walkByPath[dotted]
	if !ok {
		return Leaf{}, false
	}
	return walkLeaves[i], true
}

// Blocks returns the top-level block names in declaration order.
func Blocks() []string {
	ensureWalked()
	var out []string
	seen := map[string]bool{}
	for _, l := range walkLeaves {
		if !seen[l.Block] {
			seen[l.Block] = true
			out = append(out, l.Block)
		}
	}
	return out
}
