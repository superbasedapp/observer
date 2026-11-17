package secsbom

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const cdxNested = `{
  "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
  "metadata": {"component": {"type": "application", "name": "app", "purl": "pkg:npm/app@0.0.1"}},
  "components": [
    {"type": "library", "name": "lodash", "purl": "pkg:npm/lodash@4.17.20",
     "licenses": [{"license": {"id": "MIT"}}],
     "components": [
       {"type": "library", "purl": "pkg:npm/%40scope/inner@1.0.0",
        "licenses": [{"expression": "Apache-2.0 OR MIT"}],
        "components": [{"type": "library", "purl": "pkg:pypi/Requests@2.19.0", "licenses": [{"license": {"name": "Custom Licence"}}]}]}
     ]},
    {"type": "library", "name": "no purl"},
    {"type": "library", "purl": "pkg:generic/openssl@3.0.0"},
    {"type": "library", "purl": "pkg:npm/lodash@4.17.20", "licenses": [{"license": {"id": "MIT"}}, {"license": {"id": "CC0-1.0"}}]}
  ]
}`

const spdxDoc = `{
  "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
  "packages": [
    {"name": "serde", "licenseConcluded": "MIT OR Apache-2.0", "licenseDeclared": "NOASSERTION",
     "externalRefs": [
       {"referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"},
       {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:cargo/serde@1.0.0"}]},
    {"name": "gin", "licenseConcluded": "NONE", "licenseDeclared": "MIT",
     "externalRefs": [{"referenceCategory": "PACKAGE_MANAGER", "referenceType": "purl", "referenceLocator": "pkg:golang/github.com/gin-gonic/gin@v1.9.0"}]},
    {"name": "no refs"},
    {"name": "maven", "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:maven/org.yaml/snakeyaml@1.33"}]}
  ]
}`

// TestRead pins the reader per document shape.
func TestRead(t *testing.T) {
	cases := []struct {
		name      string
		in        string
		format    string
		pkgs      []Package
		skipped   int
		truncated bool
		err       error
	}{
		{
			name: "cyclonedx nested with licences and dedup", in: cdxNested, format: FormatCycloneDX,
			pkgs: []Package{
				{Ecosystem: "npm", Name: "lodash", Version: "4.17.20", Licenses: []string{"MIT", "CC0-1.0"}},
				{Ecosystem: "npm", Name: "@scope/inner", Version: "1.0.0", Licenses: []string{"Apache-2.0 OR MIT"}},
				{Ecosystem: "PyPI", Name: "requests", Version: "2.19.0", Licenses: []string{"Custom Licence"}},
			},
			skipped: 2,
		},
		{
			name: "spdx", in: spdxDoc, format: FormatSPDX,
			pkgs: []Package{
				{Ecosystem: "crates.io", Name: "serde", Version: "1.0.0", Licenses: []string{"MIT OR Apache-2.0"}},
				{Ecosystem: "Go", Name: "github.com/gin-gonic/gin", Version: "v1.9.0", Licenses: []string{"MIT"}},
				{Ecosystem: "Maven", Name: "org.yaml:snakeyaml", Version: "1.33"},
			},
			skipped: 1,
		},
		{name: "cyclonedx 1.4 empty", in: `{"bomFormat":"CycloneDX","specVersion":"1.4"}`, format: FormatCycloneDX, pkgs: []Package{}},
		{name: "cyclonedx 1.6 unknown type only", in: `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"purl":"pkg:deb/debian/curl@7"}]}`, format: FormatCycloneDX, pkgs: []Package{}, skipped: 1},
		{name: "cyclonedx 1.3", in: `{"bomFormat":"CycloneDX","specVersion":"1.3"}`, err: ErrUnsupportedVersion},
		{name: "spdx 3", in: `{"spdxVersion":"SPDX-3.0"}`, err: ErrUnsupportedVersion},
		{name: "not json", in: `<bom/>`, err: ErrNotJSON},
		{name: "json array", in: `[1,2]`, err: ErrNotJSON},
		{name: "unknown format", in: `{"hello":"world"}`, err: ErrUnknownFormat},
		{name: "malformed purl type", in: `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"purl":7}]}`, err: ErrMalformed},
		{name: "malformed spdx packages", in: `{"spdxVersion":"SPDX-2.3","packages":{}}`, err: ErrMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := Read([]byte(c.in))
			if c.err != nil {
				if !errors.Is(err, c.err) {
					t.Fatalf("err = %v, want %v", err, c.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if res.Format != c.format || res.Skipped != c.skipped || res.Truncated != c.truncated {
				t.Errorf("format %q skipped %d truncated %v; want %q %d %v", res.Format, res.Skipped, res.Truncated, c.format, c.skipped, c.truncated)
			}
			if !reflect.DeepEqual(res.Packages, c.pkgs) {
				t.Errorf("packages\n got %#v\nwant %#v", res.Packages, c.pkgs)
			}
		})
	}
}

// TestReadCaps pins the size and package caps.
func TestReadCaps(t *testing.T) {
	big := make([]byte, MaxSBOMBytes+1)
	if _, err := Read(big); !errors.Is(err, ErrTooLarge) {
		t.Errorf("over-size err = %v", err)
	}
	var b strings.Builder
	b.WriteString(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[`)
	n := MaxSBOMPackages + 5
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"purl":"pkg:npm/p%d@1.0.0"}`, i)
	}
	b.WriteString(`]}`)
	res, err := Read([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || len(res.Packages) != MaxSBOMPackages {
		t.Errorf("truncated %v, %d packages; want true, %d", res.Truncated, len(res.Packages), MaxSBOMPackages)
	}
	if ExtractorFor(res.Format) != "sbom:cyclonedx" || ExtractorFor(FormatSPDX) != "sbom:spdx" {
		t.Error("extractor labels")
	}
}
