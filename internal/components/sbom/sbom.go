package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SpecVersion is the CycloneDX specification version Render emits.
const SpecVersion = "1.5"

// Meta is what the caller knows about the binary beyond its build info.
type Meta struct {
	// Distro is the prebuilt distro the binary was built as ("minimal",
	// "developer", "managed", "full") or "custom".
	Distro string
	// CatalogVersion is the component catalog version.
	CatalogVersion int
	// ComponentsDigest is the components digest of the binary's compiled set.
	ComponentsDigest string
	// BinarySHA256 is the hex SHA-256 of the binary file, "" when unknown
	// (a running process does not hash itself).
	BinarySHA256 string
	// Timestamp is the document time; the zero value omits it, which keeps
	// a release SBOM byte-reproducible (the release passes SOURCE_DATE_EPOCH).
	Timestamp time.Time
	// Tool names the generator ("sbo-components" or "observer").
	Tool string
}

// Setting returns one build setting of bi ("" when absent).
func Setting(bi *debug.BuildInfo, key string) string {
	if bi == nil {
		return ""
	}
	for _, s := range bi.Settings {
		if s.Key == key {
			return s.Value
		}
	}
	return ""
}

// Tags returns the binary's build tags (the -tags setting), sorted.
func Tags(bi *debug.BuildInfo) []string {
	raw := Setting(bi, "-tags")
	if raw == "" {
		return []string{}
	}
	var out []string
	for _, t := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' }) {
		if t != "" {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// Modules returns "path@version" for every dependency module the binary
// links (a replaced module reports its replacement), sorted.
func Modules(bi *debug.BuildInfo) []string {
	if bi == nil {
		return nil
	}
	var out []string
	for _, d := range bi.Deps {
		m := effective(d)
		out = append(out, m.Path+"@"+m.Version)
	}
	sort.Strings(out)
	return out
}

func effective(m *debug.Module) *debug.Module {
	if m.Replace != nil {
		return m.Replace
	}
	return m
}

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// licenseRef is a CycloneDX license object: an SPDX id or a free-text name.
type licenseRef struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// licenseChoice is one CycloneDX licenses[] entry: a license or an SPDX
// expression (never both).
type licenseChoice struct {
	License    *licenseRef `json:"license,omitempty"`
	Expression string      `json:"expression,omitempty"`
}

type component struct {
	Type       string          `json:"type"`
	BOMRef     string          `json:"bom-ref"`
	Name       string          `json:"name"`
	Version    string          `json:"version,omitempty"`
	Purl       string          `json:"purl,omitempty"`
	Hashes     []hash          `json:"hashes,omitempty"`
	Licenses   []licenseChoice `json:"licenses,omitempty"`
	Properties []property      `json:"properties,omitempty"`
}

type tool struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type metadata struct {
	Timestamp  string              `json:"timestamp,omitempty"`
	Lifecycles []map[string]string `json:"lifecycles"`
	Tools      map[string][]tool   `json:"tools"`
	Component  component           `json:"component"`
	Properties []property          `json:"properties"`
}

type dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type document struct {
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber"`
	Version      int          `json:"version"`
	Metadata     metadata     `json:"metadata"`
	Components   []component  `json:"components"`
	Dependencies []dependency `json:"dependencies"`
}

// purl returns the package URL of a Go module version.
func purl(path, version string) string {
	if version == "" {
		return "pkg:golang/" + path
	}
	return "pkg:golang/" + path + "@" + version
}

// Render returns the CycloneDX JSON document for bi.
func Render(bi *debug.BuildInfo, m Meta) ([]byte, error) {
	if bi == nil {
		return nil, errors.New("sbom.Render: no build info (the binary was not built with module support)")
	}
	tags := Tags(bi)
	mainVersion := bi.Main.Version
	mainRef := purl(bi.Main.Path, mainVersion)
	root := component{
		Type: "application", BOMRef: mainRef, Name: bi.Path, Version: mainVersion,
		Purl: mainRef,
	}
	if m.BinarySHA256 != "" {
		root.Hashes = []hash{{Alg: "SHA-256", Content: m.BinarySHA256}}
	}
	props := []property{
		{Name: "superbased:distro", Value: m.Distro},
		{Name: "superbased:build_tags", Value: strings.Join(tags, ",")},
		{Name: "superbased:catalog_version", Value: strconv.Itoa(m.CatalogVersion)},
		{Name: "superbased:components_digest", Value: m.ComponentsDigest},
		{Name: "superbased:go_version", Value: bi.GoVersion},
		{Name: "superbased:goos", Value: Setting(bi, "GOOS")},
		{Name: "superbased:goarch", Value: Setting(bi, "GOARCH")},
		{Name: "superbased:cgo_enabled", Value: Setting(bi, "CGO_ENABLED")},
		{Name: "superbased:vcs_revision", Value: Setting(bi, "vcs.revision")},
	}
	toolName := m.Tool
	if toolName == "" {
		toolName = "sbo-components"
	}
	doc := document{
		BOMFormat:   "CycloneDX",
		SpecVersion: SpecVersion,
		Version:     1,
		Metadata: metadata{
			Tools:      map[string][]tool{"components": {{Type: "application", Name: toolName}}},
			Component:  root,
			Properties: props,
			Lifecycles: []map[string]string{{"phase": "build"}},
		},
		Components:   []component{},
		Dependencies: []dependency{},
	}
	if !m.Timestamp.IsZero() {
		doc.Metadata.Timestamp = m.Timestamp.UTC().Format(time.RFC3339)
	}
	deps := make([]*debug.Module, 0, len(bi.Deps))
	for _, d := range bi.Deps {
		deps = append(deps, effective(d))
	}
	sort.Slice(deps, func(i, j int) bool { return deps[i].Path < deps[j].Path })
	rootDeps := []string{}
	std := component{Type: "library", Name: "std", Version: bi.GoVersion, Purl: purl("std", strings.TrimPrefix(bi.GoVersion, "go"))}
	std.BOMRef = std.Purl
	doc.Components = append(doc.Components, std)
	rootDeps = append(rootDeps, std.BOMRef)
	for _, d := range deps {
		c := component{Type: "library", Name: d.Path, Version: d.Version, Purl: purl(d.Path, d.Version)}
		c.BOMRef = c.Purl
		if d.Sum != "" {
			c.Properties = []property{{Name: "superbased:go_sum", Value: d.Sum}}
		}
		doc.Components = append(doc.Components, c)
		rootDeps = append(rootDeps, c.BOMRef)
	}
	doc.Dependencies = append(doc.Dependencies, dependency{Ref: mainRef, DependsOn: rootDeps})
	doc.SerialNumber = serial(bi, m)
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("sbom.Render: %w", err)
	}
	return append(out, '\n'), nil
}

// serial derives a stable urn:uuid from the binary's identity: its hash
// when known, otherwise its main module, Go version, settings and module
// list. The same binary always gets the same serial number.
func serial(bi *debug.BuildInfo, m Meta) string {
	h := sha256.New()
	if m.BinarySHA256 != "" {
		h.Write([]byte("sha256:" + m.BinarySHA256))
	} else {
		h.Write([]byte(bi.Path + "\n" + bi.Main.Path + "@" + bi.Main.Version + "\n" + bi.GoVersion + "\n"))
		for _, s := range bi.Settings {
			h.Write([]byte(s.Key + "=" + s.Value + "\n"))
		}
		for _, mod := range Modules(bi) {
			h.Write([]byte(mod + "\n"))
		}
	}
	h.Write([]byte("\ndistro=" + m.Distro + "\ndigest=" + m.ComponentsDigest))
	return urnUUID(h.Sum(nil))
}

// urnUUID shapes the first 16 bytes of a SHA-256 sum as a name-based
// urn:uuid (the serial number shape both Render and RenderInventory use).
func urnUUID(sum []byte) string {
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50 // version 5 shape (name-based, SHA)
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	s := hex.EncodeToString(b)
	return "urn:uuid:" + s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}
