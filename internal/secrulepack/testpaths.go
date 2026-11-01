package secrulepack

import "github.com/marmutapp/superbased-observer/internal/sectestpath"

// testpaths.go re-exports the closed test-path class table, which lives in
// the pure package internal/sectestpath since lane SEC-P4 (one table, read
// by the per-rule test exclusion here and by the diff observations).

// TestPathClass returns the class of a test path and true, or "" and false
// (sectestpath.Class).
func TestPathClass(rel string) (string, bool) { return sectestpath.Class(rel) }

// TestPathClasses returns the class names, in table order
// (sectestpath.Classes).
func TestPathClasses() []string { return sectestpath.Classes() }
