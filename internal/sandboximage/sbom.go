package sandboximage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// sbom.go turns the image's Debian package list (dpkg-query output the
// recipe writes, one "name\tversion\tarch" line per package) into an SPDX
// 2.3 JSON document, deterministically, and checks one back. It never reads
// the image: the build script hands it the list.

// Package is one installed Debian package.
type Package struct {
	Name, Version, Arch string
}

// maxSBOMBytes caps the SBOM.
const maxSBOMBytes = 4 << 20

var (
	debNameRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)
	debVersionRE = regexp.MustCompile(`^[A-Za-z0-9.+~:-]+$`)
	debArchRE    = regexp.MustCompile(`^(all|amd64|arm64)$`)
	spdxIDRE     = regexp.MustCompile(`[^A-Za-z0-9.-]`)
)

// agentMarkers are package names an agent CLI ships under; the SBOM check
// and the recipe test refuse any of them (plan I9, SBX-IMG-1). A closed
// table: one row per known agent package name.
var agentMarkers = []string{
	"claude", "claude-code", "codex", "gemini-cli", "copilot", "github-copilot-cli",
	"aider", "aider-chat", "cursor", "cursor-agent", "opencode", "goose", "qwen-code",
	"kimi-cli", "crush", "amp", "droid", "kiro-cli", "cline",
}

// IsAgentPackage reports whether a package name is a known agent CLI.
func IsAgentPackage(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.TrimPrefix(n, "@")
	if i := strings.LastIndex(n, "/"); i >= 0 {
		n = n[i+1:]
	}
	for _, m := range agentMarkers {
		if n == m {
			return true
		}
	}
	return false
}

// ParsePackagesTSV reads dpkg-query's "name\tversion\tarch" lines.
func ParsePackagesTSV(b []byte) ([]Package, error) {
	var out []Package
	for i, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 3 || !debNameRE.MatchString(f[0]) || !debVersionRE.MatchString(f[1]) || !debArchRE.MatchString(f[2]) {
			return nil, fmt.Errorf("sandboximage: package list line %d is not name<TAB>version<TAB>arch", i+1)
		}
		out = append(out, Package{Name: f[0], Version: f[1], Arch: f[2]})
	}
	if len(out) == 0 {
		return nil, errors.New("sandboximage: the package list is empty")
	}
	return out, nil
}

// SBOMInput is one SBOM.
type SBOMInput struct {
	// Descriptor names the image (repository, version, digest).
	Descriptor Descriptor
	// Created is the build time (SOURCE_DATE_EPOCH), so the same build
	// yields the same bytes.
	Created time.Time
	// Packages are the installed packages per platform ("linux/amd64").
	Packages map[string][]Package
}

type spdxDoc struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreation       `json:"creationInfo"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type spdxCreation struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	Name             string        `json:"name"`
	SPDXID           string        `json:"SPDXID"`
	VersionInfo      string        `json:"versionInfo"`
	DownloadLocation string        `json:"downloadLocation"`
	FilesAnalyzed    bool          `json:"filesAnalyzed"`
	LicenseConcluded string        `json:"licenseConcluded"`
	LicenseDeclared  string        `json:"licenseDeclared"`
	CopyrightText    string        `json:"copyrightText"`
	ExternalRefs     []spdxExtRef  `json:"externalRefs,omitempty"`
	Checksums        []spdxSumWrap `json:"checksums,omitempty"`
}

type spdxSumWrap struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type spdxExtRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	Element string `json:"spdxElementId"`
	Type    string `json:"relationshipType"`
	Related string `json:"relatedSpdxElement"`
}

const (
	spdxVersion  = "SPDX-2.3"
	spdxLicense  = "CC0-1.0"
	spdxDocID    = "SPDXRef-DOCUMENT"
	spdxImageID  = "SPDXRef-image"
	spdxNoAssert = "NOASSERTION"
	spdxCreator  = "Tool: observer-vendorsign-sandboximage"
)

// SPDX renders the SBOM. The same input always yields the same bytes.
func SPDX(in SBOMInput) ([]byte, error) {
	d := in.Descriptor
	if d.Repository == "" || d.Version == "" || !digestRE.MatchString(d.Digest) {
		return nil, errors.New("sandboximage: the SBOM needs the descriptor's repository, version and digest")
	}
	if len(in.Packages) == 0 {
		return nil, errors.New("sandboximage: the SBOM needs at least one platform's packages")
	}
	doc := spdxDoc{
		SPDXVersion: spdxVersion, DataLicense: spdxLicense, SPDXID: spdxDocID,
		Name:              d.Repository + "@" + d.Version,
		DocumentNamespace: "https://superbased.app/spdx/sandbox-image/" + url.PathEscape(d.Version) + "/" + strings.TrimPrefix(d.Digest, "sha256:"),
		CreationInfo:      spdxCreation{Created: in.Created.UTC().Format(time.RFC3339), Creators: []string{spdxCreator}},
	}
	doc.Packages = append(doc.Packages, spdxPackage{
		Name: d.Repository, SPDXID: spdxImageID, VersionInfo: d.Version, DownloadLocation: spdxNoAssert,
		LicenseConcluded: spdxNoAssert, LicenseDeclared: spdxNoAssert, CopyrightText: spdxNoAssert,
		Checksums: []spdxSumWrap{{Algorithm: "SHA256", ChecksumValue: strings.TrimPrefix(d.Digest, "sha256:")}},
		ExternalRefs: []spdxExtRef{{
			ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl",
			ReferenceLocator: "pkg:oci/" + url.PathEscape(lastSegment(d.Repository)) + "@" + url.QueryEscape(d.Digest) + "?repository_url=" + url.QueryEscape(d.Repository),
		}},
	})
	doc.Relationships = append(doc.Relationships, spdxRelationship{Element: spdxDocID, Type: "DESCRIBES", Related: spdxImageID})
	platforms := make([]string, 0, len(in.Packages))
	for p := range in.Packages {
		platforms = append(platforms, p)
	}
	sort.Strings(platforms)
	for _, plat := range platforms {
		pkgs := append([]Package(nil), in.Packages[plat]...)
		sort.Slice(pkgs, func(i, j int) bool {
			if pkgs[i].Name != pkgs[j].Name {
				return pkgs[i].Name < pkgs[j].Name
			}
			return pkgs[i].Arch < pkgs[j].Arch
		})
		for i, pk := range pkgs {
			if IsAgentPackage(pk.Name) {
				return nil, fmt.Errorf("sandboximage: package %s is an agent CLI; the image never carries one (SBX-IMG-1)", pk.Name)
			}
			id := fmt.Sprintf("SPDXRef-deb-%s-%d-%s", spdxIDRE.ReplaceAllString(plat, "-"), i, spdxIDRE.ReplaceAllString(pk.Name, "-"))
			doc.Packages = append(doc.Packages, spdxPackage{
				Name: pk.Name, SPDXID: id, VersionInfo: pk.Version, DownloadLocation: spdxNoAssert,
				LicenseConcluded: spdxNoAssert, LicenseDeclared: spdxNoAssert, CopyrightText: spdxNoAssert,
				ExternalRefs: []spdxExtRef{{
					ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl",
					ReferenceLocator: "pkg:deb/debian/" + pk.Name + "@" + url.PathEscape(pk.Version) + "?arch=" + pk.Arch,
				}},
			})
			doc.Relationships = append(doc.Relationships, spdxRelationship{Element: spdxImageID, Type: "CONTAINS", Related: id})
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("sandboximage: sbom: %w", err)
	}
	return buf.Bytes(), nil
}

func lastSegment(repo string) string {
	if i := strings.LastIndex(repo, "/"); i >= 0 {
		return repo[i+1:]
	}
	return repo
}

// CheckSBOM reads an SBOM back: SPDX 2.3, CC0 data licence, the image
// package described, at least one contained package, none an agent CLI.
func CheckSBOM(b []byte) error {
	if len(b) == 0 || len(b) > maxSBOMBytes {
		return fmt.Errorf("sandboximage: the SBOM is empty or over %d bytes", maxSBOMBytes)
	}
	var doc spdxDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("sandboximage: sbom: %w", err)
	}
	switch {
	case doc.SPDXVersion != spdxVersion || doc.DataLicense != spdxLicense || doc.SPDXID != spdxDocID:
		return errors.New("sandboximage: the SBOM is not an SPDX 2.3 document under CC0-1.0")
	case len(doc.Packages) < 2:
		return errors.New("sandboximage: the SBOM lists no packages")
	}
	described := false
	for _, r := range doc.Relationships {
		if r.Element == spdxDocID && r.Type == "DESCRIBES" && r.Related == spdxImageID {
			described = true
		}
	}
	if !described {
		return errors.New("sandboximage: the SBOM does not describe the image")
	}
	for _, p := range doc.Packages {
		if IsAgentPackage(p.Name) {
			return fmt.Errorf("sandboximage: the SBOM lists %s, an agent CLI (SBX-IMG-1)", p.Name)
		}
	}
	return nil
}
