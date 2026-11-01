// Package sandboxselect is the sandbox module's single decision point
// (sandbox plan v2 sections 4.4 and 4.5, phase P1a): the capture
// computation table C1 to C8, the selection rule table S0 to S13 with S1b,
// S2b, S4b, S6b, S7b to S7d, S11b and S12b, the nesting table for stacks,
// and the post-build re-check parser for bwrap.
//
// Every decision is an ordered data table walked top-down, one test per row
// (CLAUDE.md rule 5). Nothing branches on a backend name: rows are judged
// by their capability columns from internal/sandboxbackend. Inputs are
// plain data (the request, the per-backend probe facts, the local config's
// enabled list, the floors, the tool's facts); the package does no I/O
// (imports_test.go pins it).
package sandboxselect
