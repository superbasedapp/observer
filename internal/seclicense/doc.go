// Package seclicense is the pure core of Observer's local licence
// compliance check (security coverage gaps plan, section 5, "Item 4:
// licence compliance, local first").
//
// Four tables decide and nothing else does:
//
//   - the SPDX normaliser (Normalize): common aliases such as "Apache 2.0",
//     "GPLv3" or "MIT License" map to SPDX ids through aliasTable, deprecated
//     SPDX ids (GPL-2.0, LGPL-2.1, AGPL-3.0, ...) map to their -only forms,
//     and an expression with OR, AND, WITH and parentheses is kept as an
//     expression with each id normalized;
//   - the class table (classTable, Classify): one row per SPDX id giving its
//     Class (permissive, weak copyleft, strong copyleft, network copyleft,
//     source-available, proprietary); anything else is ClassUnknown. For an
//     expression, OR takes the most permissive alternative and AND the least
//     permissive part; WITH keeps the base id's class;
//   - the reader table (ReaderFor): one row per dependency file pattern
//     (package-lock.json, node_modules/<name>/package.json, composer.lock,
//     *.dist-info/METADATA, vendor/<crate>/Cargo.toml), each reading bytes
//     the caller supplies into Entry rows;
//   - the policy table (Evaluate, Findings): deny, then not allowed, then
//     unknown, walked top-down. Every licence finding is capped at medium
//     severity and recorded with baseline unknown, so it can never enter the
//     commit gate's blocking set (plan section 12, finding 5).
//
// The package is PURE (CLAUDE.md "Module Boundaries" rule 1): no file,
// network, database, process or fsnotify import (imports_test.go). The
// walk over a project and the recording of findings belong to the caller.
package seclicense
