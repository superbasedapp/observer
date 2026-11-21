// Package seclang is the one table that names the language or file format
// of a security finding's file (the Code security page's Language filter,
// its facet counts and each findings row's language label; redesign plan
// docs/plans/code-security-page-redesign-plan-2026-11-06.md section 4.4).
//
// One row per language id: a label, the file suffixes ("." included) and
// the exact base names (Dockerfile, Makefile) that name it, all lower case.
// It covers code languages and the config and infrastructure formats the
// scanners read (YAML, JSON, TOML, Terraform/HCL, Dockerfile, shell,
// Markdown and the rest). Language answers a path by base name first, then
// by suffix; a path no row names is "" (unknown), never a guess.
//
// The table is built so that a SQL filter made of each row's own patterns
// (store.SecFindingFilter.Languages) selects exactly the paths Language
// names that row: no suffix is the tail of another row's suffix, and no
// base name ends with another row's suffix (TestRowsDoNotOverlap). So the
// filter, the facet and the row label never disagree.
//
// It is PURE (CLAUDE.md "Module Boundaries" rule 1): no database/sql, no
// net/http, no os, no fsnotify (imports_test.go). The SQL that reads the
// table lives in the store.
package seclang
