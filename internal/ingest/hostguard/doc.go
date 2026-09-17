// Package hostguard is the ONE owner of the Host-header loopback predicate the
// node's ingest listeners share.
//
// Two listeners need it: internal/ingest/browser (the browser-capture rail,
// which has applied it since it shipped) and internal/ingest/otlp (which did
// not, NODE-OTLP-1 of the 2026-09-16 codebase audit — a rebinding page could
// inject spans into the node's OTLP/HTTP receiver, drive the billable judge, or
// simply fabricate telemetry). Rather than copy the predicate into the second
// listener, it moved here and both call it, per CLAUDE.md module boundary #4
// (one owner per piece of logic).
//
// It is a PURE package: net only. No database/sql, no net/http, no fsnotify —
// it takes a string and returns a bool, and each listener decides at its own
// boundary WHEN to apply it (the browser rail always, because it is by
// definition same-machine; the OTLP receiver only when it is bound
// loopback-only, because an operator who set allow_non_loopback deliberately
// opened it to remote collectors whose Host header is a real name).
package hostguard
