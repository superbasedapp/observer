package sandboximage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"time"
)

// vmsbom.go renders the guest image set's SPDX 2.3 SBOM: the set as the
// described package (its checksum the verity root hash), the pinned kernel
// package and every Debian package installed in the rootfs. The same input
// always yields the same bytes, and CheckSBOM reads it back like the
// default image's.

// VMSBOMInput is one SBOM.
type VMSBOMInput struct {
	Descriptor VMDescriptor
	Created    time.Time
	// Packages are the rootfs's installed packages (packages.tsv).
	Packages []Package
}

// VMSPDX renders the set's SBOM.
func VMSPDX(in VMSBOMInput) ([]byte, error) {
	d := in.Descriptor
	if err := d.Validate(); err != nil {
		return nil, err
	}
	if len(in.Packages) == 0 {
		return nil, errors.New("sandboximage: the VM SBOM needs the rootfs's packages")
	}
	name := "observer-sandbox-vm"
	doc := spdxDoc{
		SPDXVersion: spdxVersion, DataLicense: spdxLicense, SPDXID: spdxDocID,
		Name:              name + "@" + d.Version,
		DocumentNamespace: "https://superbased.app/spdx/sandbox-vm/" + url.PathEscape(d.Version) + "/" + d.VerityRootHash,
		CreationInfo:      spdxCreation{Created: in.Created.UTC().Format(time.RFC3339), Creators: []string{"Tool: observer-vendorsign-sandboxrootfs"}},
	}
	doc.Packages = append(doc.Packages, spdxPackage{
		Name: name, SPDXID: spdxImageID, VersionInfo: d.Version, DownloadLocation: spdxNoAssert,
		LicenseConcluded: spdxNoAssert, LicenseDeclared: spdxNoAssert, CopyrightText: spdxNoAssert,
		Checksums: []spdxSumWrap{{Algorithm: "SHA256", ChecksumValue: d.VerityRootHash}},
	}, spdxPackage{
		Name: d.Kernel.Package, SPDXID: "SPDXRef-kernel", VersionInfo: d.Kernel.Version, DownloadLocation: spdxNoAssert,
		LicenseConcluded: spdxNoAssert, LicenseDeclared: "GPL-2.0-only", CopyrightText: spdxNoAssert,
		Checksums: []spdxSumWrap{{Algorithm: "SHA256", ChecksumValue: d.Kernel.SHA256}},
		ExternalRefs: []spdxExtRef{{
			ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl",
			ReferenceLocator: "pkg:deb/ubuntu/" + d.Kernel.Package + "@" + url.PathEscape(d.Kernel.Version) + "?arch=" + d.Arch,
		}},
	})
	doc.Relationships = append(doc.Relationships,
		spdxRelationship{Element: spdxDocID, Type: "DESCRIBES", Related: spdxImageID},
		spdxRelationship{Element: spdxImageID, Type: "CONTAINS", Related: "SPDXRef-kernel"})
	pkgs := append([]Package(nil), in.Packages...)
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Name != pkgs[j].Name {
			return pkgs[i].Name < pkgs[j].Name
		}
		return pkgs[i].Arch < pkgs[j].Arch
	})
	for i, pk := range pkgs {
		if IsAgentPackage(pk.Name) {
			return nil, fmt.Errorf("sandboximage: package %s is an agent CLI; a guest image never carries one (D-751 Q38)", pk.Name)
		}
		id := fmt.Sprintf("SPDXRef-deb-%d-%s", i, spdxIDRE.ReplaceAllString(pk.Name, "-"))
		doc.Packages = append(doc.Packages, spdxPackage{
			Name: pk.Name, SPDXID: id, VersionInfo: pk.Version, DownloadLocation: spdxNoAssert,
			LicenseConcluded: spdxNoAssert, LicenseDeclared: spdxNoAssert, CopyrightText: spdxNoAssert,
			ExternalRefs: []spdxExtRef{{
				ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl",
				ReferenceLocator: "pkg:deb/ubuntu/" + pk.Name + "@" + url.PathEscape(pk.Version) + "?arch=" + pk.Arch,
			}},
		})
		doc.Relationships = append(doc.Relationships, spdxRelationship{Element: spdxImageID, Type: "CONTAINS", Related: id})
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("sandboximage: VM sbom: %w", err)
	}
	return buf.Bytes(), nil
}
