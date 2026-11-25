package sdkcatalog

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestEmbeddedCatalogParses: the shipped catalog is valid and keeps the
// order the surfaces show (Python first).
func TestEmbeddedCatalogParses(t *testing.T) {
	rows, err := All()
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].ID != "python" {
		t.Fatalf("first row %q, want python", rows[0].ID)
	}
	// The setup field reaches the Go reader: Python and TypeScript have one
	// (the SDK quickstart), Go and Java do not.
	setup := map[string]string{}
	for _, r := range rows {
		setup[r.ID] = r.Setup
	}
	want := map[string]string{"python": "uvx superbased-sdk setup", "typescript": "npx @superbased/sdk setup", "go": "", "java": ""}
	for id, w := range want {
		if setup[id] != w {
			t.Errorf("%s: Setup = %q, want %q", id, setup[id], w)
		}
	}
	for _, r := range rows {
		want := r.InstallCheckout
		if r.Published {
			want = r.InstallPublished
		}
		if r.Install() != want {
			t.Fatalf("%s: Install() = %q", r.ID, r.Install())
		}
	}
}

// TestFixtureRowReachesTheReader: a new row is one more catalog entry and
// nothing else (the C0 fixture row, appended).
func TestFixtureRowReachesTheReader(t *testing.T) {
	fx, err := os.ReadFile("sdkCatalog.fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Row json.RawMessage `json:"row"`
	}
	if err := json.Unmarshal(fx, &fixture); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(catalogJSON, &doc); err != nil {
		t.Fatal(err)
	}
	var row any
	if err := json.Unmarshal(fixture.Row, &row); err != nil {
		t.Fatal(err)
	}
	doc["sdks"] = append(doc["sdks"].([]any), row)
	merged, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := Parse(merged)
	if err != nil {
		t.Fatal(err)
	}
	if rows[len(rows)-1].ID != "fixturelang" {
		t.Fatalf("last row %q, want fixturelang", rows[len(rows)-1].ID)
	}
}

// TestParseRefusals: one case per rule.
func TestParseRefusals(t *testing.T) {
	ok := `{"id":"x","label":"X","package":"p","registry":"r","docs":"/d","published":false,"release":"none","install_checkout":"a","install_published":"b","snippet":["s"]}`
	cases := map[string]string{
		"no rows":         `{"sdks":[]}`,
		"upper id":        `{"sdks":[` + strings.Replace(ok, `"id":"x"`, `"id":"X"`, 1) + `]}`,
		"repeated id":     `{"sdks":[` + ok + `,` + ok + `]}`,
		"no label":        `{"sdks":[` + strings.Replace(ok, `"label":"X"`, `"label":""`, 1) + `]}`,
		"docs not a path": `{"sdks":[` + strings.Replace(ok, `"docs":"/d"`, `"docs":"d"`, 1) + `]}`,
		"no install":      `{"sdks":[` + strings.Replace(ok, `"install_checkout":"a"`, `"install_checkout":""`, 1) + `]}`,
		"bad release":     `{"sdks":[` + strings.Replace(ok, `"release":"none"`, `"release":"x"`, 1) + `]}`,
		"no snippet":      `{"sdks":[` + strings.Replace(ok, `"snippet":["s"]`, `"snippet":[]`, 1) + `]}`,
		"two-line setup":  `{"sdks":[` + strings.Replace(ok, `"snippet"`, `"setup":"a\nb","snippet"`, 1) + `]}`,
		"untrimmed setup": `{"sdks":[` + strings.Replace(ok, `"snippet"`, `"setup":" a setup","snippet"`, 1) + `]}`,
		"not json":        `{`,
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Parse([]byte(`{"sdks":[` + ok + `]}`)); err != nil {
		t.Fatalf("valid row refused: %v", err)
	}
	withSetup := strings.Replace(ok, `"snippet"`, `"setup":"x setup","snippet"`, 1)
	if rows, err := Parse([]byte(`{"sdks":[` + withSetup + `]}`)); err != nil || rows[0].Setup != "x setup" {
		t.Fatalf("a row with setup: %+v %v", rows, err)
	}
}
