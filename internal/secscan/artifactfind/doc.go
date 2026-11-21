// Package artifactfind discovers the candidate build-artifact folders of a
// project (OS and CI vulnerability scanning plan section 14.6, M3L-2 item
// 4, operator ruling 2026-11-05 "Item 4 folders"): the folders a developer
// may turn artifact scanning on for, each shown with what its file headers
// say it holds ("2 ELF executables, 1 JAR").
//
// Discovery is deliberately shallow and blind to contents: it lists
// directory names, to two levels below the project root, matches them
// against a table (candidateRules: the default list bin/, dist/ and
// target/release/, a cargo profile, and the common build output names), and
// reads the first HeaderBytes of the files inside a candidate to count
// executables (ELF, PE, Mach-O, WebAssembly), JARs and wheels. It parses
// nothing, never follows a symbolic link and stops at fixed bounds.
// Nothing under a folder is scanned for packages until the developer turns
// that folder on (depscan.ArtifactDirs); discovery is only the offer.
//
// The package is pure (CLAUDE.md "Module Boundaries" rule 1): the project
// is an injected io/fs.FS, no os, no network, no database (imports_test.go).
package artifactfind
