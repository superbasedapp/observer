// Package sbom renders a CycloneDX 1.5 software bill of materials for one
// observer binary from its Go build information (modular packaging plan
// 5.5, lane MP-REL).
//
// It is pure: it takes a *debug.BuildInfo (read from a file by
// debug/buildinfo.ReadFile in cmd/sbo-components, or from the running
// process by debug.ReadBuildInfo in the dashboard) plus the distro facts
// the caller already knows, and returns JSON bytes. No SQL, HTTP, file or
// process I/O happens here, so the release pipeline's per-artifact SBOM and
// the Components page's download (T-670) are the same document for the
// same binary.
//
// The generation context names the distro, its build tags and the catalog
// version (CISA 2025 draft minimum elements). The document is deterministic
// for a given binary: no wall-clock timestamp unless the caller passes one
// (the release passes SOURCE_DATE_EPOCH), and a serial number derived from
// the binary's own content.
//
// RenderInventory (inventory.go) is the second document this package owns,
// the project SBOM export (security coverage gaps plan 2026-11-13, section
// 3): a CycloneDX 1.5 document for one project's dependency inventory,
// sharing the document types above. It takes plain InventoryPackage rows
// with their purls already computed by the caller through the one purl
// table in internal/secsbom; this package imports neither secsbom nor
// depscan, so it stays pure and linked into every edition.
package sbom
