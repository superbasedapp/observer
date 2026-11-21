// Package secreachsvc is the one I/O seam of the reachability tier
// (security plan 2026-11-04 section 14.5 items 3a and 3c; the pure rules
// are internal/secreach). Tiers is the single entry function a surface
// calls: it reads each dependency finding's advisory data through an
// injected Lookup (NewLookup builds one over secdepdetail's local OSV
// record read), builds each import list it needs once (langBuilders), and
// returns a secreach.Tier per finding.
//
// JavaScript/TypeScript, Python and Rust lists come from the codeintel
// index only (CodeIntelLangImports over store.CodeIntelProjectImports,
// codeIntelLangRows), project-wide; no index, no list ("unknown"). A
// Python finding adds the installed metadata of the virtual environments
// under its lockfile directory and the project root (ReadPythonMeta:
// capped, symlink-refusing, read-only); a Rust finding adds the call sites
// of its listed functions' names (CodeIntelRustCalls over
// store.CodeIntelProjectCalls, one read per Tiers call, only when the
// reader also implements CodeIntelCallReader).
//
// The Go import list has two sources, walked in order (sourceLadder):
//
//   - "go imports": an imports-only parse (go/parser ImportsOnly) of the
//     project's .go files. It skips what the go command skips (vendor/,
//     testdata/, directories and files whose name starts with "_" or "."),
//     node_modules/, and symlinks; it does NOT read .gitignore. It is
//     bounded (Limits: files, bytes per file, total time) and reads only a
//     file's head unless the imports run past it. Test files (_test.go) are
//     counted separately so a package only tests import is labelled "tests
//     only".
//   - "codeintel": the IMPORTS sites the project's codeintel index holds
//     (store.CodeIntelProjectImports, the only SQL), used only when the
//     index holds every Go file of the project (codeintel is off by
//     default, D-307). It is as fresh as the index.
//
// A source that hit a bound or failed to parse a file yields an incomplete
// list: it can still prove "imported", never "not_imported_directly".
//
// Imports are scoped to the Go module the finding's lockfile belongs to
// (a finding on sub/go.mod is decided against the files of module sub/,
// nested modules excluded); a finding whose lockfile is not a module's
// go.mod or go.sum is decided against every module of the project.
//
// It is also the one owner of the Go symbol checks' node-local record
// (symbolstore.go, plan section 14.5 item 3b): <security dir>/reach/<project
// root hash>.json, written after each dependency scan
// (ReplaceSymbolRuns) and read at view time (LoadSymbolRuns).
//
// Ruling Q14-4: the tier ranks and labels only. Nothing here closes, hides
// or re-grades a finding, and nothing leaves the node (no network, no
// process; the one write is the symbol checks' record).
package secreachsvc
