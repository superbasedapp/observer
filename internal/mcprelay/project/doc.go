// Package project projects the relay's desired state into every VERIFIED
// AI client's MCP config (doc3 §11.7 W4c, §12.1/§12.2): every existing
// stdio `{command,args}` entry is replaced by the relay's TRUE stdio wrapper
// (`observer mcp-relay wrap --client <tool> --server <key>`) with the
// original launch journaled first, and the org-approved remote entries are
// projected through the relay's loopback listener. It is the ONE owner of
// the launch-journal SEQUENCE (parking decision B5, Sol P3+P4 findings 2 +
// 7): stage -> verbatim backup fsync -> journal rows with the applied
// digest -> atomic rewrite (doc3 §12.1 R8.28.i ordering), idempotent
// re-apply, and the table-driven restore (byte-identical whole-file under a
// CAS on the applied digest, else the format-aware reversal of only the
// relay-owned entries). The per-format writers are internal/mcp's
// Registrar (pure write primitives reached through the Writer seam) and the
// durable journal is Lane N-M's mcp_relay_launch_spec store + the backup
// file half in internal/mcprelay/journal.go (reached through the Journal
// seam).
//
// Pure package (CLAUDE.md §1, pinned by imports_test.go): no database/sql,
// net/http, fsnotify, os, store, orgclient, config or mcp import. Every
// decision that is a rule (which client is projected, which entry is
// refused, what makes a re-apply a no-op, which restore mode a group
// takes) is a table walked top-down.
package project
