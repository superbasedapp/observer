// Package cloudevidence is the pure node-side builder that turns normalized
// session data into a cloudcontract.Envelope, and the ONE serializer that
// produces both the literal preview and the upload bytes (plan §6 CI-P1;
// telemetry plan §6).
//
// It does no I/O. The caller (a later phase) maps store rows into the plain
// input DTOs defined here; this package bounds the arrays, defaults paths to
// extension/category, emits per-account-salted path hashes only under the
// path-correlation grant, runs internal/scrub over every optional excerpt,
// gates fields by consent purpose, refuses to build anything whose
// data-authority classification is not eligible for personal enrichment, and
// serializes deterministically so preview == upload.
//
// Purity discipline (plan §6 CI-P1 / CLAUDE.md §1): imports are limited to
// internal/cloudcontract, internal/scrub, internal/dataauthority, and stdlib.
// NO os, io/fs, database/sql, net/http, fsnotify, config, store, client, or
// server package — pinned by imports_test.go. The reverse-boundary pin keeps
// hosted packages out of node ingest by keeping this package's import set
// closed.
package cloudevidence
