package sbom

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

type invDoc struct {
	BOMFormat    string `json:"bomFormat"`
	SpecVersion  string `json:"specVersion"`
	SerialNumber string `json:"serialNumber"`
	Metadata     struct {
		Timestamp  string              `json:"timestamp"`
		Lifecycles []map[string]string `json:"lifecycles"`
		Tools      map[string][]tool   `json:"tools"`
		Component  component           `json:"component"`
		Properties []property          `json:"properties"`
	} `json:"metadata"`
	Components   []component       `json:"components"`
	Dependencies []json.RawMessage `json:"dependencies"`
}

func renderInv(t *testing.T, m InventoryMeta, pkgs []InventoryPackage) (invDoc, []byte) {
	t.Helper()
	out, err := RenderInventory(m, pkgs)
	if err != nil {
		t.Fatal(err)
	}
	var d invDoc
	if err := json.Unmarshal(out, &d); err != nil {
		t.Fatal(err)
	}
	return d, out
}

func samplePkgs() []InventoryPackage {
	return []InventoryPackage{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.20", Purl: "pkg:npm/lodash@4.17.20", Path: "web/package-lock.json", Licenses: []string{"MIT"}},
		{Ecosystem: "GIT", Name: "vendor/lib", Version: "abc123", Path: ".gitmodules"},
		{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.5", Purl: "pkg:golang/golang.org/x/text@v0.3.5", Path: "go.mod"},
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.20", Purl: "pkg:npm/lodash@4.17.20", Path: "package-lock.json", Licenses: []string{"MIT", "CC0-1.0"}},
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.20", Purl: "pkg:npm/lodash@4.17.20", Path: "package-lock.json"},
	}
}

// TestRenderInventoryShape pins the inventory document: the project as
// the root, sorted and collapsed components, a no-purl package with its
// ecosystem property, paths as properties, the discovery lifecycle, the
// scan time and no claimed dependency graph.
func TestRenderInventoryShape(t *testing.T) {
	scan := time.Date(2026, 11, 13, 10, 0, 0, 0, time.FixedZone("x", 3600))
	d, _ := renderInv(t, InventoryMeta{ProjectName: "myproj", ScanTime: scan}, samplePkgs())
	if d.BOMFormat != "CycloneDX" || d.SpecVersion != SpecVersion || !strings.HasPrefix(d.SerialNumber, "urn:uuid:") {
		t.Fatalf("header %q %q %q", d.BOMFormat, d.SpecVersion, d.SerialNumber)
	}
	if d.Metadata.Timestamp != "2026-11-13T09:00:00Z" {
		t.Errorf("timestamp %q", d.Metadata.Timestamp)
	}
	if !reflect.DeepEqual(d.Metadata.Lifecycles, []map[string]string{{"phase": "discovery"}}) {
		t.Errorf("lifecycles %v", d.Metadata.Lifecycles)
	}
	if got := d.Metadata.Tools["components"]; len(got) != 1 || got[0].Name != "observer" {
		t.Errorf("tools %v", d.Metadata.Tools)
	}
	root := d.Metadata.Component
	if root.Type != "application" || root.Name != "myproj" || root.BOMRef != "project:myproj" {
		t.Errorf("root %+v", root)
	}
	if len(d.Metadata.Properties) != 0 || len(d.Dependencies) != 0 {
		t.Errorf("properties %v dependencies %v", d.Metadata.Properties, d.Dependencies)
	}
	want := []component{
		{
			Type: "library", BOMRef: "inventory:GIT/vendor/lib@abc123", Name: "vendor/lib", Version: "abc123",
			Properties: []property{{Name: "superbased:ecosystem", Value: "GIT"}, {Name: "superbased:path", Value: ".gitmodules"}},
		},
		{
			Type: "library", BOMRef: "pkg:golang/golang.org/x/text@v0.3.5", Name: "golang.org/x/text", Version: "v0.3.5", Purl: "pkg:golang/golang.org/x/text@v0.3.5",
			Properties: []property{{Name: "superbased:path", Value: "go.mod"}},
		},
		{
			Type: "library", BOMRef: "pkg:npm/lodash@4.17.20", Name: "lodash", Version: "4.17.20", Purl: "pkg:npm/lodash@4.17.20",
			Licenses:   []licenseChoice{{License: &licenseRef{ID: "MIT"}}, {License: &licenseRef{ID: "CC0-1.0"}}},
			Properties: []property{{Name: "superbased:path", Value: "package-lock.json"}, {Name: "superbased:path", Value: "web/package-lock.json"}},
		},
	}
	if !reflect.DeepEqual(d.Components, want) {
		gotJSON, _ := json.Marshal(d.Components)
		wantJSON, _ := json.Marshal(want)
		t.Errorf("components\n got %s\nwant %s", gotJSON, wantJSON)
	}
}

// TestRenderInventoryStableSerial pins the serial to the inventory: input
// order and scan time do not change it, a different inventory or project
// does, and the same input renders the same bytes.
func TestRenderInventoryStableSerial(t *testing.T) {
	m := InventoryMeta{ProjectName: "p", ScanTime: time.Unix(1700000000, 0)}
	a, ab := renderInv(t, m, samplePkgs())
	_, ab2 := renderInv(t, m, samplePkgs())
	if !bytes.Equal(ab, ab2) {
		t.Error("two renders of the same inventory differ")
	}
	rev := samplePkgs()
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	later := m
	later.ScanTime = m.ScanTime.Add(time.Hour)
	b, _ := renderInv(t, later, rev)
	if a.SerialNumber != b.SerialNumber {
		t.Errorf("reordered/later scan serial %s != %s", b.SerialNumber, a.SerialNumber)
	}
	c, _ := renderInv(t, m, samplePkgs()[:2])
	other := m
	other.ProjectName = "q"
	d, _ := renderInv(t, other, samplePkgs())
	tr := m
	tr.Truncated = true
	e, _ := renderInv(t, tr, samplePkgs())
	for name, s := range map[string]string{"fewer packages": c.SerialNumber, "other project": d.SerialNumber, "truncated": e.SerialNumber} {
		if s == a.SerialNumber {
			t.Errorf("%s kept the serial", name)
		}
	}
	if len(e.Metadata.Properties) != 1 || e.Metadata.Properties[0] != (property{Name: "superbased:truncated", Value: "true"}) {
		t.Errorf("truncated properties %v", e.Metadata.Properties)
	}
}

// TestRenderInventoryLicences pins the licence rendering rules, one case
// per shape.
func TestRenderInventoryLicences(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{"none", nil, ``},
		{"one id", []string{"MIT"}, `[{"license":{"id":"MIT"}}]`},
		{"lone expression", []string{"MIT OR Apache-2.0"}, `[{"expression":"MIT OR Apache-2.0"}]`},
		{"parenthesised expression", []string{"(MIT)"}, `[{"expression":"(MIT)"}]`},
		{"licence ref", []string{"LicenseRef-acme"}, `[{"license":{"name":"LicenseRef-acme"}}]`},
		{"free text", []string{"Custom Licence"}, `[{"license":{"name":"Custom Licence"}}]`},
		{"expression among several", []string{"GPL-2.0-only", "MIT OR Apache-2.0"}, `[{"license":{"id":"GPL-2.0-only"}},{"license":{"name":"MIT OR Apache-2.0"}}]`},
		{"blank and duplicate dropped", []string{"MIT", " ", "MIT"}, `[{"license":{"id":"MIT"}}]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, out := renderInv(t, InventoryMeta{ProjectName: "p"}, []InventoryPackage{{Ecosystem: "npm", Name: "a", Version: "1", Purl: "pkg:npm/a@1", Licenses: c.in}})
			var raw struct {
				Components []map[string]json.RawMessage `json:"components"`
			}
			if err := json.Unmarshal(out, &raw); err != nil {
				t.Fatal(err)
			}
			got := raw.Components[0]["licenses"]
			var compact bytes.Buffer
			if len(got) > 0 {
				if err := json.Compact(&compact, got); err != nil {
					t.Fatal(err)
				}
			}
			if compact.String() != c.want {
				t.Errorf("licenses = %s, want %s", compact.String(), c.want)
			}
		})
	}
}

// TestRenderInventoryEdges pins the empty project name refusal, the zero
// scan time and an empty inventory.
func TestRenderInventoryEdges(t *testing.T) {
	if _, err := RenderInventory(InventoryMeta{ProjectName: " "}, nil); err == nil {
		t.Error("an empty project name must be refused")
	}
	d, out := renderInv(t, InventoryMeta{ProjectName: "p", Tool: "sbo"}, nil)
	if strings.Contains(string(out), `"timestamp"`) {
		t.Error("a zero scan time must omit the timestamp")
	}
	if d.Components == nil || len(d.Components) != 0 || d.Metadata.Tools["components"][0].Name != "sbo" {
		t.Errorf("empty inventory %+v", d)
	}
	if !strings.Contains(string(out), `"components": []`) {
		t.Error("an empty inventory must render an empty components array")
	}
}
