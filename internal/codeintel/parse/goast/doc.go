// Package goast implements a parse.Parser for the Go language backed by
// the standard library go/parser, go/ast, and go/token. It produces
// exact byte/line spans and is CGO-free (pure stdlib), so it satisfies
// the ExactSpans capability tier (ADR-0005) and feeds aggressive
// body-collapse.
//
// It is a pure backend (CLAUDE.md anti-spaghetti rule 1): bytes in,
// codeintel.ParseResult out. No SQL, HTTP, fsnotify, or sibling
// internal subsystems — only stdlib + the codeintel facade + the parse
// package (enforced by internal/codeintel/imports_test.go).
package goast
