// Package devcontainer is the one reader of a repository's
// .devcontainer/devcontainer.json (sandbox plan v2 section 13 P3, N2). The
// container sandbox driver's planner (internal/sandboxoci) adopts its image
// and allow-listed containerEnv from what this package reads, and the
// repository trust check reports the host-executing and privilege-raising
// fields from the same result, so the two can never disagree.
//
// It is a leaf of its own, outside the container sandbox component, so the
// trust check's unconditional initializeCommand row (the N2 ruling) is
// built into every install, with or without the container driver.
//
// The package is pure and standard-library only (imports_test.go pins it).
package devcontainer
