// Package docpos holds the doc-position check (FX3-A9): every documented
// top-level declaration's comment starts with its own name, so a comment
// never drifts onto the declaration below it. A package runs it from its
// own test with docpos.Check(t).
//
// The check and its declDoc helper were byte-identical copies in two
// packages before they moved here.
//
// TEST SUPPORT ONLY: no production command or package may import it
// (tests/invariant/vendormock_boundary_test.go).
package docpos
