// Package sandboxbackend is the isolation backend registry of the sandbox
// module (sandbox plan v2 section 4.2, phase P1a): one data row per
// backend, modelled on internal/integration. Closed enums with an honest
// zero ("not grounded", never "supported"), computed predicates instead of
// stored flags, and coverage tests that keep the rows honest.
//
// Only the bwrap row is selectable in P1a; every other supported row of
// section 4.9 is present as Maturity planned with a note naming the phase
// that builds it, and a planned row is never offered by a picker, a probe
// or the selector. A connector (section 4.1, D-751 Q37: a way of reaching a
// backend with no isolation class of its own, the SSH connector today) is a
// row of a separate table and never a Capability.
//
// The package is pure data: it imports only the neutral vocabulary leaf
// internal/sandboxvocab (imports_test.go pins it).
package sandboxbackend
