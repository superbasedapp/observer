// Package secsbom is the pure core of the project SBOM work (security
// coverage gaps plan 2026-11-13, section 3 "Item 2").
//
// It owns two things:
//
//   - THE one ecosystem <-> package-URL type table (purl.go). An OSV
//     ecosystem name as internal/secscan/depscan spells it ("npm", "PyPI",
//     "Go", "crates.io", "GitHub Actions", ...) maps to exactly one purl
//     type, with the per-type name encoding (npm scopes, Maven
//     group:artifact, PyPI name normalisation, Go module paths, GitHub
//     Actions owner/repo). PurlFor renders a purl and ParsePurl reads one
//     back; an ecosystem with no row has no purl, and a purl type with no
//     row has no ecosystem. The SBOM renderer in internal/components/sbom
//     takes purls already computed by its caller through this table, so the
//     renderer stays edition-wide and never imports this package.
//   - The SBOM input reader (read.go): CycloneDX 1.4 to 1.6 JSON and SPDX
//     2.x JSON bytes to plain Package rows through the same table, capped
//     (MaxSBOMBytes, MaxSBOMPackages), deduplicated, with typed sentinel
//     errors for input that is not JSON, not a known format, or a spec
//     version this reader does not support.
//
// It is pure: no file, network, database, process or fsnotify import, and
// no store (pinned by imports_test.go). The caller reads the file and
// converts rows to depscan packages at its own seam.
package secsbom
