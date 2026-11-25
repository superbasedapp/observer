// Package codequalitysvc is the I/O boundary of the Projects page's quality
// metrics (docs/projects-page.md "Quality metrics"): it finds and reads a
// project's coverage report files through an fs.FS, reads the codeintel
// duplication and complexity facts and the daily trend through the store
// seam, and hands them to the pure internal/codequality, which decides every number and
// state. It also runs the daemon pass that records one daily point per
// active project (cmd/observer/codequality_wire.go).
//
// It never runs a project's tests or any other process, never writes into
// a project, and makes no network call. A report file is read under a byte
// cap, never followed through a symbolic link, and only its numbers reach
// the database.
package codequalitysvc
