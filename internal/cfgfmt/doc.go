// Package cfgfmt holds the comment-preserving format engines the adapter
// config editor uses to read and surgically edit vendor configuration files
// (docs/plans/adapter-config-and-common-vocabulary-plan-2026-10-03.md
// section 2.6, phase P0).
//
// One engine per format, one surface:
//
//	doc, err := cfgfmt.Parse(cfgfmt.FormatTOML, raw)
//	v, found, err := doc.Get(cfgfmt.Path{"tui", "theme"})
//	err = doc.Set(cfgfmt.Path{"model"}, "gpt-6")
//	found, err = doc.Delete(cfgfmt.Path{"notify"})
//	out := doc.Bytes()
//
// # Guarantees
//
//   - Byte-stable round trip: Bytes() of a document nobody edited is the
//     input, byte for byte (BOM, CRLF, mixed line endings, trailing
//     whitespace and a missing final newline included).
//   - Single-key edits: Set and Delete change only the bytes of the edited
//     entry. Comments, key order, blank lines and formatting elsewhere in
//     the file are kept. A new key is appended at the end of its parent
//     table / object / mapping. In TOML, deleting the last child of an
//     implicit table (one with no [header] of its own, only the
//     super-table of [a.b.c] headers or dotted keys) also removes that
//     table, because TOML cannot spell it empty; an explicit [header]
//     is kept.
//   - Self-verified: after every edit the engine re-decodes the result and
//     compares it with the expected tree (the old tree with exactly that
//     one change). A surgical edit that does not produce exactly the
//     expected tree is never returned silently.
//   - Disclosed fallback: where the surgical editor cannot express an edit
//     (TOML arrays of tables, inline tables on the path; YAML flow
//     collections), the engine re-serializes the document from its parsed
//     form and records a Disclosure naming what was lost. Parse with
//     Options.ForbidReserialize to turn that into ErrNeedsReserialize
//     instead (the hygiene pipeline's preview shows the disclosure; the
//     `PatchFile` precedent in internal/config).
//   - Fail closed on hostile input: oversize input, excessive nesting,
//     NUL bytes, invalid UTF-8, duplicate keys, multi-document YAML and
//     anchored / aliased YAML targets are refused with a typed error.
//
// The Markdown engine (FormatMarkdown, FormatMDC) edits the YAML front
// matter through the same Get / Set / Delete surface and adds marked-block
// upsert for org instruction blocks (plan section 6.4), byte-exact outside
// the edited block.
//
// # Purity
//
// No os, database/sql, net/http or fsnotify import (pinned by
// imports_test.go). Callers own the I/O: they read the bytes, hand them to
// Parse and write Bytes() back through their own lock / backup / atomic
// write seam (plan section 5.2 step 8).
package cfgfmt
