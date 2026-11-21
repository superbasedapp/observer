// Package secinventory is the one owner of the per-project package
// inventory snapshots (security coverage gaps plan item 2): the packages
// the last dependency scan of a project found, kept so the project's SBOM
// (CycloneDX, internal/components/sbom.RenderInventory) and the licence
// join can be built without scanning again.
//
// A snapshot is one owner-only JSON file per project,
// <security dir>/inventory/<project_root_hash>.json, written atomically
// (temp file, rename), capped at MaxPackages. It holds ecosystems, names,
// versions, the project-relative dependency file path and the extractor:
// never a file's contents. It is node-local: nothing here reaches the org
// push wire.
//
// Two feed paths, one owner, one precedence rule (CLAUDE.md module rule 4):
// both dependency drivers report their inventory, and Supersedes decides
// whether an incoming snapshot replaces the stored one (the linked SCALIBR
// driver's inventory wins over osv-scanner's, which replaces it only when
// it is osv-scanner's own or older than StaleAfter). Supersedes is pure;
// Replace and Load are the file I/O.
package secinventory
