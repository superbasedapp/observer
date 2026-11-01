// Package sandboxvocab holds the closed vocabularies of the sandbox module
// that core packages read whether or not the module is compiled in or
// active (sandbox plan v2 section 11.1, "What stays in core"): the
// isolation class ladder, the capture levels and their origin, the
// verification kinds, the key custody modes, the native-sandbox states, the
// egress tier spellings and the model-provider host set (section 7.3).
//
// The execution evidence envelope (internal/execevidence, roadmap F0-13),
// the terminal_run evidence columns, the org wire posture row and the
// module's own registry (internal/sandboxbackend) and selection
// (internal/sandboxselect) all read these spellings from here, so a value
// has one owner and a build without the module still reads old history.
//
// The package is a pure leaf: no observer-internal imports, no I/O.
package sandboxvocab
