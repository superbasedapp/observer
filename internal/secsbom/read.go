package secsbom

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// MaxSBOMBytes is the largest SBOM document Read accepts (64 MiB).
const MaxSBOMBytes = 64 << 20

// MaxSBOMPackages is the most packages Read returns; beyond it the result
// is marked Truncated.
const MaxSBOMPackages = 100_000

// The formats Read detects.
const (
	// FormatCycloneDX is a CycloneDX JSON document.
	FormatCycloneDX = "cyclonedx"
	// FormatSPDX is an SPDX 2.x JSON document.
	FormatSPDX = "spdx"
)

// Sentinel errors Read returns (wrapped; test with errors.Is).
var (
	// ErrTooLarge: the input is over MaxSBOMBytes.
	ErrTooLarge = errors.New("secsbom: SBOM is larger than the 64 MiB cap")
	// ErrNotJSON: the input is not a JSON object.
	ErrNotJSON = errors.New("secsbom: SBOM is not a JSON object")
	// ErrMalformed: a CycloneDX or SPDX document whose fields have the
	// wrong JSON shape (a purl that is not a string, components that are
	// not an array).
	ErrMalformed = errors.New("secsbom: malformed SBOM document")
	// ErrUnknownFormat: JSON that is neither CycloneDX nor SPDX 2.x.
	ErrUnknownFormat = errors.New("secsbom: not a CycloneDX or SPDX JSON document")
	// ErrUnsupportedVersion: a known format at a spec version this reader
	// does not read (CycloneDX outside 1.4 to 1.6, SPDX other than 2.x).
	ErrUnsupportedVersion = errors.New("secsbom: unsupported SBOM spec version")
)

// Package is one package an SBOM lists, in OSV ecosystem terms.
type Package struct {
	// Ecosystem is the OSV ecosystem name (the purl table's left column).
	Ecosystem string
	// Name is the package name as the ecosystem spells it.
	Name string
	// Version is the version, "" when the purl carries none.
	Version string
	// Licenses are the licence ids or expressions the SBOM states, in
	// document order without duplicates.
	Licenses []string
}

// Result is what Read found in one SBOM.
type Result struct {
	// Format is FormatCycloneDX or FormatSPDX.
	Format string
	// SpecVersion is the document's spec version ("1.5", "SPDX-2.3").
	SpecVersion string
	// Packages are the deduplicated packages, in document order.
	Packages []Package
	// Skipped counts components with no usable purl or a purl type with no
	// ecosystem row.
	Skipped int
	// Truncated is set when the document lists more than MaxSBOMPackages
	// packages; the rest are not returned.
	Truncated bool
}

// ExtractorFor returns the extractor label rows read from an SBOM of the
// given format carry ("sbom:cyclonedx", "sbom:spdx").
func ExtractorFor(format string) string {
	return "sbom:" + format
}

// probe is the top-level shape Read detects the format from.
type probe struct {
	BOMFormat   string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
	SPDXVersion string `json:"spdxVersion"`
}

// cyclonedxVersions are the CycloneDX spec versions Read reads.
var cyclonedxVersions = map[string]bool{"1.4": true, "1.5": true, "1.6": true}

// Read parses an SBOM document: CycloneDX 1.4 to 1.6 JSON (components[]
// with their nested components, by purl) or SPDX 2.x JSON (packages[] by
// their purl external reference). Packages map to OSV ecosystems through
// the purl table; anything else is counted in Skipped.
func Read(data []byte) (Result, error) {
	if len(data) > MaxSBOMBytes {
		return Result{}, fmt.Errorf("secsbom.Read: %w", ErrTooLarge)
	}
	var p probe
	if err := json.Unmarshal(data, &p); err != nil {
		return Result{}, fmt.Errorf("secsbom.Read: %w: %w", ErrNotJSON, err)
	}
	switch {
	case strings.EqualFold(p.BOMFormat, "CycloneDX"):
		if !cyclonedxVersions[p.SpecVersion] {
			return Result{}, fmt.Errorf("secsbom.Read: %w: CycloneDX %q", ErrUnsupportedVersion, p.SpecVersion)
		}
		return readCycloneDX(data, p.SpecVersion)
	case p.SPDXVersion != "":
		if !strings.HasPrefix(p.SPDXVersion, "SPDX-2.") {
			return Result{}, fmt.Errorf("secsbom.Read: %w: %q", ErrUnsupportedVersion, p.SPDXVersion)
		}
		return readSPDX(data, p.SPDXVersion)
	}
	return Result{}, fmt.Errorf("secsbom.Read: %w", ErrUnknownFormat)
}

// cdxLicense is one CycloneDX licenses[] entry: a license (id or name) or
// an expression.
type cdxLicense struct {
	License *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"license"`
	Expression string `json:"expression"`
}

type cdxComponent struct {
	Purl       string         `json:"purl"`
	Licenses   []cdxLicense   `json:"licenses"`
	Components []cdxComponent `json:"components"`
}

type cdxDocument struct {
	Components []cdxComponent `json:"components"`
}

func readCycloneDX(data []byte, spec string) (Result, error) {
	var doc cdxDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return Result{}, fmt.Errorf("secsbom.Read: %w: %w", ErrMalformed, err)
	}
	acc := newAccumulator(FormatCycloneDX, spec)
	// Iterative walk, depth first in document order.
	stack := make([]*cdxComponent, 0, len(doc.Components))
	for i := len(doc.Components) - 1; i >= 0; i-- {
		stack = append(stack, &doc.Components[i])
	}
	for len(stack) > 0 && !acc.res.Truncated {
		c := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		var lic []string
		for _, l := range c.Licenses {
			switch {
			case l.Expression != "":
				lic = append(lic, l.Expression)
			case l.License != nil && l.License.ID != "":
				lic = append(lic, l.License.ID)
			case l.License != nil && l.License.Name != "":
				lic = append(lic, l.License.Name)
			}
		}
		acc.add(c.Purl, lic)
		for i := len(c.Components) - 1; i >= 0; i-- {
			stack = append(stack, &c.Components[i])
		}
	}
	return acc.res, nil
}

type spdxRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxPackage struct {
	LicenseConcluded string    `json:"licenseConcluded"`
	LicenseDeclared  string    `json:"licenseDeclared"`
	ExternalRefs     []spdxRef `json:"externalRefs"`
}

type spdxDocument struct {
	Packages []spdxPackage `json:"packages"`
}

// spdxPackageManager reports a package-manager reference category (SPDX
// 2.2 spells it PACKAGE_MANAGER, 2.3 PACKAGE-MANAGER).
func spdxPackageManager(cat string) bool {
	c := strings.ToUpper(cat)
	return c == "PACKAGE-MANAGER" || c == "PACKAGE_MANAGER"
}

// spdxLicense reports whether an SPDX licence field states a licence.
func spdxLicense(v string) bool {
	v = strings.TrimSpace(v)
	return v != "" && v != "NOASSERTION" && v != "NONE"
}

func readSPDX(data []byte, spec string) (Result, error) {
	var doc spdxDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return Result{}, fmt.Errorf("secsbom.Read: %w: %w", ErrMalformed, err)
	}
	acc := newAccumulator(FormatSPDX, spec)
	for _, p := range doc.Packages {
		if acc.res.Truncated {
			break
		}
		var purl string
		for _, r := range p.ExternalRefs {
			if spdxPackageManager(r.ReferenceCategory) && strings.EqualFold(r.ReferenceType, "purl") && r.ReferenceLocator != "" {
				purl = r.ReferenceLocator
				break
			}
		}
		var lic []string
		for _, l := range []string{p.LicenseConcluded, p.LicenseDeclared} {
			if spdxLicense(l) {
				lic = append(lic, strings.TrimSpace(l))
			}
		}
		acc.add(purl, lic)
	}
	return acc.res, nil
}

// pkgKey is the deduplication identity.
type pkgKey struct{ eco, name, version string }

// accumulator collects packages with dedup, licence merge and the cap.
type accumulator struct {
	res Result
	at  map[pkgKey]int
}

func newAccumulator(format, spec string) *accumulator {
	return &accumulator{res: Result{Format: format, SpecVersion: spec, Packages: []Package{}}, at: map[pkgKey]int{}}
}

// add records one component's purl and licences.
func (a *accumulator) add(purl string, licenses []string) {
	eco, name, version, ok := ParsePurl(strings.TrimSpace(purl))
	if !ok {
		a.res.Skipped++
		return
	}
	k := pkgKey{eco, name, version}
	if i, seen := a.at[k]; seen {
		a.res.Packages[i].Licenses = mergeLicenses(a.res.Packages[i].Licenses, licenses)
		return
	}
	if len(a.res.Packages) >= MaxSBOMPackages {
		a.res.Truncated = true
		return
	}
	a.at[k] = len(a.res.Packages)
	a.res.Packages = append(a.res.Packages, Package{Ecosystem: eco, Name: name, Version: version, Licenses: mergeLicenses(nil, licenses)})
}

// mergeLicenses appends the licences of add not already in have.
func mergeLicenses(have, add []string) []string {
	for _, l := range add {
		dup := false
		for _, h := range have {
			if h == l {
				dup = true
				break
			}
		}
		if !dup {
			have = append(have, l)
		}
	}
	return have
}
