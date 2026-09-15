package loc

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// updateTables regenerates the committed classifier-table JSON instead of
// asserting against it:
//
//	go test ./internal/loc/ -run TestClassifierTablesJSONIsCurrent -update
var updateTables = flag.Bool("update", false,
	"regenerate vscode/src/loc/classifier-tables.json from the Go tables")

// classifierTablesPath is where the VS Code extension reads the exported
// tables from. It is a RELATIVE path out of this package so the test is
// the thing that knows about the coupling — nothing in the extension has
// to know it was generated, and nothing in internal/loc has to import it.
var classifierTablesPath = filepath.Join("..", "..", "vscode", "src", "loc", "classifier-tables.json")

// TestClassifierTablesJSONIsCurrent is the DRIFT GATE between the Go
// classifier and the VS Code extension's copy of its tables.
//
// The extension classifies a human's saved lines; the daemon classifies
// an agent's. If the two use different tables, "AI vs human" is measured
// with two different rulers and the comparison is worthless. This test
// fails the moment the Go tables change without the exported JSON being
// regenerated, so the drift is loud here instead of silent in the
// numbers.
//
// Regenerate with `-update` after any change to the language table, the
// denylists or the lexer token table.
func TestClassifierTablesJSONIsCurrent(t *testing.T) {
	want, err := MarshalTables()
	if err != nil {
		t.Fatalf("MarshalTables: %v", err)
	}
	if *updateTables {
		if err := os.MkdirAll(filepath.Dir(classifierTablesPath), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(classifierTablesPath, want, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		t.Logf("regenerated %s (%d bytes)", classifierTablesPath, len(want))
		return
	}
	got, err := os.ReadFile(classifierTablesPath)
	if err != nil {
		t.Fatalf("read %s: %v\nRegenerate with: go test ./internal/loc/ -run %s -update",
			classifierTablesPath, err, t.Name())
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s is stale — the Go classifier tables changed but the exported JSON "+
			"the VS Code extension reads did not.\n"+
			"Regenerate with: go test ./internal/loc/ -run %s -update\n"+
			"(committed %d bytes, generated %d bytes)",
			classifierTablesPath, t.Name(), len(got), len(want))
	}
}

// TestTablesRoundTrip pins that the exported shape survives JSON and
// keeps the facts a consumer depends on: every language that has a lexer
// row is present, and every extension resolves to a language/category
// pair the Go side agrees with.
func TestTablesRoundTrip(t *testing.T) {
	t.Parallel()
	body, err := MarshalTables()
	if err != nil {
		t.Fatalf("MarshalTables: %v", err)
	}
	var decoded ExportedTables
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.TablesVersion != TablesVersion {
		t.Errorf("tables_version = %d, want %d", decoded.TablesVersion, TablesVersion)
	}
	if decoded.ClassifierVersion != Version {
		t.Errorf("classifier_version = %d, want %d", decoded.ClassifierVersion, Version)
	}
	if len(decoded.Lex) != len(lexTable) {
		t.Errorf("lex rows = %d, want %d", len(decoded.Lex), len(lexTable))
	}
	// Spot-check the pairs a consumer would break on first.
	for ext, want := range map[string]ExportedLangEntry{
		"go":   {Lang: string(LangGo), Category: string(CategoryCode)},
		"md":   {Lang: string(LangMarkdown), Category: string(CategoryDocs)},
		"yaml": {Lang: string(LangYAML), Category: string(CategoryConfig)},
	} {
		if got := decoded.Extensions[ext]; got != want {
			t.Errorf("extension %q = %+v, want %+v", ext, got, want)
		}
	}
	// The denylists a consumer must apply BEFORE the language table.
	if !contains(decoded.VendoredSegments, "node_modules") {
		t.Error("vendored_segments is missing node_modules")
	}
	if !contains(decoded.LockfileBasenames, "package-lock.json") {
		t.Error("lockfile_basenames is missing package-lock.json")
	}
	// Acceptance criterion 5: testdata / build / bin / target must NOT be
	// on any denylist, in the export just as in the Go tables.
	for _, never := range []string{"testdata", "build", "bin", "target"} {
		if contains(decoded.GeneratedSegments, never) || contains(decoded.VendoredSegments, never) {
			t.Errorf("%q is denylisted in the export — loc deliberately counts these "+
				"(codeintel excludes them; loc does not)", never)
		}
	}
}

// contains reports whether a slice holds a value.
func contains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}
