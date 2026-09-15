// Command cfgschema emits the config-schema artifacts the dashboard's
// Settings page reads — the serialization of internal/configschema (the one
// owner of config.Config's structure + classification) plus the Go doc
// comment of every field, harvested with go/ast.
//
// # Why this exists (docs/plans/dashboard-config-management-plan-2026-08-28.md §1)
//
// The dashboard carried a hand-maintained TypeScript mirror of the config
// surface (web/src/pages/settings/sectionSpecs.ts: 22 sections, ~144 fields
// of ~525 leaf keys — 27%, drifting). web/taxgen already showed the fix for
// that failure mode: generate from the Go owner, byte-diff in CI, make the
// TypeScript side a compile-time consumer of a generated literal union.
// cfgschema is the same shape for config.
//
// # What it writes
//
//   - internal/config/schema/schema.gen.json — the DATA: a
//     configschema.Descriptor (blocks, tables, leaves with tier / restart /
//     section / prominence / enum / bounds) where every leaf and table also
//     carries its Go doc comment. go:embed'd by internal/config/schema and
//     served at runtime by GET /api/config/schema, so the schema always
//     describes THIS daemon's build.
//   - web/src/lib/configschema.gen.ts — the TYPES only: the ConfigKeyPath
//     literal union plus the row shapes. Erased at build, so a key removed
//     in Go becomes a `tsc --noEmit` error in any TypeScript that names it.
//
// # Doc harvest
//
// The generator parses the packages that declare config structs
// (internal/config, internal/notify/email, internal/notify/digest) with
// go/parser and indexes `<import path>.<Type>.<Field>` → the field's doc
// comment (Doc, falling back to the trailing line Comment). A leaf's Owner +
// Field (recorded by the reflect walk) selects its comment; a table's Owner
// selects the struct's type-level comment. Nothing is transcribed by hand.
//
// # Determinism contract
//
// Generation is pure: no clock, no environment, no filesystem reads beyond
// the named source directories, no map iteration order (leaves and tables
// are emitted in struct-declaration order; the TS union in the same order).
// That is what makes the byte-diff drift gate (`make verify-config-schema`)
// meaningful rather than flaky.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/configschema"
)

const (
	defaultJSONOut  = "internal/config/schema/schema.gen.json"
	defaultTypesOut = "web/src/lib/configschema.gen.ts"
	// The module path prefix every config-declaring package shares.
	modulePrefix = "github.com/marmutapp/superbased-observer/"
)

// docSources are the packages whose exported structs may appear as config
// tables. Order is irrelevant (the index is keyed by full import path), but
// the list is explicit so the generator reads nothing it was not told to.
var docSources = []string{
	"internal/config",
	"internal/notify/email",
	"internal/notify/digest",
}

// keyPattern is what a dotted key must look like to be emitted into a
// TypeScript literal union; a key with other punctuation is a mistake
// upstream, not something to render faithfully.
var keyPattern = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)*$`)

func main() {
	jsonOut := flag.String("json", defaultJSONOut, "path of the generated schema JSON")
	typesOut := flag.String("types", defaultTypesOut, "path of the generated TypeScript types")
	root := flag.String("root", ".", "repository root (the doc sources are resolved under it)")
	flag.Parse()

	docs, err := harvestDocs(*root)
	if err != nil {
		log.Fatalf("cfgschema: harvest docs: %v", err)
	}
	desc := configschema.Describe()
	for i := range desc.Leaves {
		l := &desc.Leaves[i]
		l.Doc = docs[l.Owner+"."+l.Field]
	}
	for i := range desc.Tables {
		t := &desc.Tables[i]
		t.Doc = docs[t.Owner]
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(desc); err != nil {
		log.Fatalf("cfgschema: encode: %v", err)
	}
	if err := writeFile(*jsonOut, buf.Bytes()); err != nil {
		log.Fatal(err)
	}
	ts, err := renderTypes(desc)
	if err != nil {
		log.Fatalf("cfgschema: types: %v", err)
	}
	if err := writeFile(*typesOut, ts); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("cfgschema: %d leaves, %d tables → %s, %s\n", len(desc.Leaves), len(desc.Tables), *jsonOut, *typesOut)
}

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("cfgschema: mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil { //nolint:gosec // G306: generated source artifact, readable like the rest of the tree.
		return fmt.Errorf("cfgschema: write %s: %w", path, err)
	}
	return nil
}

// harvestDocs indexes doc comments for every exported struct + field in the
// docSources packages: "<importPath>.<Type>" → type doc, and
// "<importPath>.<Type>.<Field>" → field doc.
func harvestDocs(root string) (map[string]string, error) {
	out := map[string]string{}
	fset := token.NewFileSet()
	for _, rel := range docSources {
		dir := filepath.Join(root, rel)
		importPath := modulePrefix + rel
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", dir, err)
		}
		// Deterministic file order (ReadDir sorts, but be explicit).
		var names []string
		for _, e := range entries {
			n := e.Name()
			if strings.HasSuffix(n, ".go") && !strings.HasSuffix(n, "_test.go") {
				names = append(names, n)
			}
		}
		sort.Strings(names)
		for _, n := range names {
			f, err := parser.ParseFile(fset, filepath.Join(dir, n), nil, parser.ParseComments)
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w", n, err)
			}
			for _, decl := range f.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.TYPE {
					continue
				}
				for _, spec := range gd.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok {
						continue
					}
					st, ok := ts.Type.(*ast.StructType)
					if !ok {
						continue
					}
					typeKey := importPath + "." + ts.Name.Name
					if d := commentText(ts.Doc, gd.Doc); d != "" {
						out[typeKey] = d
					}
					for _, field := range st.Fields.List {
						d := commentText(field.Doc, field.Comment)
						if d == "" {
							continue
						}
						for _, name := range field.Names {
							out[typeKey+"."+name.Name] = d
						}
					}
				}
			}
		}
	}
	return out, nil
}

// commentText returns the first non-empty comment group's text, trimmed.
func commentText(groups ...*ast.CommentGroup) string {
	for _, g := range groups {
		if g == nil {
			continue
		}
		if t := strings.TrimSpace(g.Text()); t != "" {
			return t
		}
	}
	return ""
}

// renderTypes emits the TypeScript types artifact.
func renderTypes(desc configschema.Descriptor) ([]byte, error) {
	var b strings.Builder
	b.WriteString("// GENERATED by web/cfgschema from internal/configschema — DO NOT EDIT.\n")
	b.WriteString("// Regenerate with `make config-schema-build`; `make verify-config-schema` is the drift gate.\n")
	b.WriteString("//\n")
	b.WriteString("// TYPES ONLY. The schema DATA (kinds, tiers, restart classes, docs) is served\n")
	b.WriteString("// at runtime by GET /api/config/schema so it always describes the daemon the\n")
	b.WriteString("// dashboard is talking to. This union exists so that a config key removed in\n")
	b.WriteString("// Go becomes a tsc error in any TypeScript that names it.\n\n")

	b.WriteString("export type ConfigKeyPath =\n")
	for i, l := range desc.Leaves {
		if !keyPattern.MatchString(l.Path) {
			return nil, fmt.Errorf("leaf path %q is not a plain dotted key", l.Path)
		}
		sep := " |"
		if i == len(desc.Leaves)-1 {
			sep = ";"
		}
		fmt.Fprintf(&b, "  %s%s\n", strconv.Quote(l.Path), sep)
	}
	b.WriteString("\n")
	b.WriteString("export type ConfigSchemaKind = \"bool\" | \"int\" | \"float\" | \"string\" | \"string_list\" | \"string_map\" | \"table\";\n")
	b.WriteString("export type ConfigSchemaTier = \"plain\" | \"sensitive\" | \"secret\" | \"owner_elsewhere\";\n")
	b.WriteString("export type ConfigSchemaRestart = \"live\" | \"live_persist\" | \"next_spawn\" | \"restart\";\n")
	b.WriteString("export type ConfigSchemaProminence = \"primary\" | \"advanced\" | \"expert\";\n\n")
	b.WriteString("export type ConfigSchemaLeaf = {\n")
	b.WriteString("  path: ConfigKeyPath;\n")
	b.WriteString("  field_path: string;\n")
	b.WriteString("  kind: ConfigSchemaKind;\n")
	b.WriteString("  go_type: string;\n")
	b.WriteString("  owner: string;\n")
	b.WriteString("  field: string;\n")
	b.WriteString("  block: string;\n")
	b.WriteString("  table: string;\n")
	b.WriteString("  tier: ConfigSchemaTier;\n")
	b.WriteString("  restart: ConfigSchemaRestart;\n")
	b.WriteString("  section: string;\n")
	b.WriteString("  prominence: ConfigSchemaProminence;\n")
	b.WriteString("  secret: boolean;\n")
	b.WriteString("  deprecated?: string;\n")
	b.WriteString("  owned_by?: string;\n")
	b.WriteString("  enum?: string[];\n")
	b.WriteString("  min?: number;\n")
	b.WriteString("  max?: number;\n")
	b.WriteString("  doc?: string;\n")
	b.WriteString("};\n\n")
	b.WriteString("export type ConfigSchemaTable = {\n")
	b.WriteString("  path: string;\n")
	b.WriteString("  field_path: string;\n")
	b.WriteString("  owner: string;\n")
	b.WriteString("  block: string;\n")
	b.WriteString("  doc?: string;\n")
	b.WriteString("};\n\n")
	b.WriteString("export type ConfigSchemaDescriptor = {\n")
	b.WriteString("  schema_version: number;\n")
	b.WriteString("  blocks: string[];\n")
	b.WriteString("  tables: ConfigSchemaTable[];\n")
	b.WriteString("  leaves: ConfigSchemaLeaf[];\n")
	b.WriteString("};\n")
	return []byte(b.String()), nil
}
