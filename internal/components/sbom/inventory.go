package sbom

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// InventoryMeta is what the caller knows about a project inventory beyond
// its packages.
type InventoryMeta struct {
	// ProjectName names the root component: the project directory's base
	// name, never an absolute path.
	ProjectName string
	// Tool names the generator; "" means "observer".
	Tool string
	// ScanTime is the scan the inventory came from; the zero value omits
	// the document timestamp.
	ScanTime time.Time
	// Truncated marks an inventory cut at its package cap.
	Truncated bool
}

// InventoryPackage is one package of a project inventory, in plain terms
// (this package imports neither depscan nor secsbom, so it stays linked
// into every edition).
type InventoryPackage struct {
	// Ecosystem is the OSV ecosystem name ("npm", "PyPI", ...).
	Ecosystem string
	// Name is the package name as the ecosystem spells it.
	Name string
	// Version is the package version.
	Version string
	// Purl is the package URL the caller computed through the one purl
	// table (internal/secsbom); "" when the ecosystem has no purl type.
	Purl string
	// Path is the dependency file the package came from, project-relative.
	Path string
	// Licenses are licence SPDX ids or expressions, when known.
	Licenses []string
}

// inventoryEntry is one collapsed component before rendering.
type inventoryEntry struct {
	key      string
	pkg      InventoryPackage
	paths    []string
	licenses []string
}

// RenderInventory returns the CycloneDX JSON document for one project's
// dependency inventory: the project as the root application component and
// one library component per distinct package, sorted by purl (or by
// ecosystem/name@version for a package with no purl), with duplicates
// collapsed and every dependency file path kept as a superbased:path
// property. The serial number is derived from the inventory, so the same
// inventory renders the same serial; the timestamp is the scan time. The
// dependency graph is not known to an inventory, so no dependencies are
// claimed.
func RenderInventory(m InventoryMeta, pkgs []InventoryPackage) ([]byte, error) {
	if strings.TrimSpace(m.ProjectName) == "" {
		return nil, errors.New("sbom.RenderInventory: no project name")
	}
	entries := collapseInventory(pkgs)
	rootRef := "project:" + m.ProjectName
	toolName := m.Tool
	if toolName == "" {
		toolName = "observer"
	}
	props := []property{}
	if m.Truncated {
		props = append(props, property{Name: "superbased:truncated", Value: "true"})
	}
	doc := document{
		BOMFormat:   "CycloneDX",
		SpecVersion: SpecVersion,
		Version:     1,
		Metadata: metadata{
			Tools:      map[string][]tool{"components": {{Type: "application", Name: toolName}}},
			Component:  component{Type: "application", BOMRef: rootRef, Name: m.ProjectName},
			Properties: props,
			Lifecycles: []map[string]string{{"phase": "discovery"}},
		},
		Components:   make([]component, 0, len(entries)),
		Dependencies: []dependency{},
	}
	if !m.ScanTime.IsZero() {
		doc.Metadata.Timestamp = m.ScanTime.UTC().Format(time.RFC3339)
	}
	for _, e := range entries {
		c := component{
			Type: "library", Name: e.pkg.Name, Version: e.pkg.Version, Purl: e.pkg.Purl,
			Licenses: licenseChoices(e.licenses),
		}
		if c.Purl != "" {
			c.BOMRef = c.Purl
		} else {
			c.BOMRef = "inventory:" + e.key
			c.Properties = append(c.Properties, property{Name: "superbased:ecosystem", Value: e.pkg.Ecosystem})
		}
		for _, p := range e.paths {
			c.Properties = append(c.Properties, property{Name: "superbased:path", Value: p})
		}
		doc.Components = append(doc.Components, c)
	}
	doc.SerialNumber = inventorySerial(m, entries)
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("sbom.RenderInventory: %w", err)
	}
	return append(out, '\n'), nil
}

// inventoryKey is a package's sort and identity key.
func inventoryKey(p InventoryPackage) string {
	if p.Purl != "" {
		return p.Purl
	}
	return p.Ecosystem + "/" + p.Name + "@" + p.Version
}

// collapseInventory sorts the packages and folds those with the same key
// into one entry, keeping every distinct path (sorted) and licence (first
// seen order).
func collapseInventory(pkgs []InventoryPackage) []inventoryEntry {
	sorted := append([]InventoryPackage(nil), pkgs...)
	sort.SliceStable(sorted, func(i, j int) bool {
		ki, kj := inventoryKey(sorted[i]), inventoryKey(sorted[j])
		if ki != kj {
			return ki < kj
		}
		return sorted[i].Path < sorted[j].Path
	})
	var out []inventoryEntry
	for _, p := range sorted {
		k := inventoryKey(p)
		if n := len(out); n == 0 || out[n-1].key != k {
			out = append(out, inventoryEntry{key: k, pkg: p})
		}
		e := &out[len(out)-1]
		if p.Path != "" && (len(e.paths) == 0 || e.paths[len(e.paths)-1] != p.Path) {
			e.paths = append(e.paths, p.Path)
		}
		e.licenses = appendNew(e.licenses, p.Licenses)
	}
	return out
}

// appendNew appends the non-empty values of add not already in have.
func appendNew(have, add []string) []string {
	for _, v := range add {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		dup := false
		for _, h := range have {
			if h == v {
				dup = true
				break
			}
		}
		if !dup {
			have = append(have, v)
		}
	}
	return have
}

// licenseKind is how one licence string renders.
type licenseKind int

const (
	licenseID licenseKind = iota
	licenseName
	licenseExpression
)

// licenseRules classify a licence string, first match wins: an SPDX
// expression (an operator or parentheses), a LicenseRef/DocumentRef (not in
// the SPDX id list the CycloneDX schema validates license.id against, so a
// name), an SPDX-id-shaped token, else free text as a name.
var licenseRules = []struct {
	match func(string) bool
	kind  licenseKind
}{
	{func(s string) bool {
		return strings.ContainsAny(s, "()") || strings.Contains(s, " AND ") ||
			strings.Contains(s, " OR ") || strings.Contains(s, " WITH ")
	}, licenseExpression},
	{func(s string) bool {
		return strings.HasPrefix(s, "LicenseRef-") || strings.HasPrefix(s, "DocumentRef-")
	}, licenseName},
	{isSPDXIDShape, licenseID},
	{func(string) bool { return true }, licenseName},
}

func classifyLicense(s string) licenseKind {
	for _, r := range licenseRules {
		if r.match(s) {
			return r.kind
		}
	}
	return licenseName
}

// isSPDXIDShape reports an SPDX short identifier's character set.
func isSPDXIDShape(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '+') {
			return false
		}
	}
	return true
}

// licenseChoices renders licences as CycloneDX 1.5 licenses[]: a lone
// expression as [{"expression"}]; otherwise one license object each, an
// SPDX id as license.id and anything else (an expression among several
// licences included, since the schema forbids mixing an expression with
// license objects) as license.name.
func licenseChoices(ls []string) []licenseChoice {
	if len(ls) == 0 {
		return nil
	}
	if len(ls) == 1 && classifyLicense(ls[0]) == licenseExpression {
		return []licenseChoice{{Expression: ls[0]}}
	}
	out := make([]licenseChoice, 0, len(ls))
	for _, l := range ls {
		if classifyLicense(l) == licenseID {
			out = append(out, licenseChoice{License: &licenseRef{ID: l}})
		} else {
			out = append(out, licenseChoice{License: &licenseRef{Name: l}})
		}
	}
	return out
}

// inventorySerial derives a stable urn:uuid from the project name and the
// collapsed, sorted inventory (keys, paths, licences, truncation). The
// scan time is not part of it, so the same inventory keeps its serial.
func inventorySerial(m InventoryMeta, entries []inventoryEntry) string {
	h := sha256.New()
	h.Write([]byte("inventory\nproject=" + m.ProjectName + "\n"))
	if m.Truncated {
		h.Write([]byte("truncated\n"))
	}
	for _, e := range entries {
		h.Write([]byte(e.key + "\n"))
		for _, p := range e.paths {
			h.Write([]byte("\tpath=" + p + "\n"))
		}
		for _, l := range e.licenses {
			h.Write([]byte("\tlicense=" + l + "\n"))
		}
	}
	return urnUUID(h.Sum(nil))
}
