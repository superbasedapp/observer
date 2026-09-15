// Package telemetrylog is the PURE contract for the org server's shared durable
// log (plan of record docs/plans/stateless-collectors-durable-log-plan-2026-09-08.md,
// decision D1; ADR-0006). It is the seam between the stateless collectors (the
// publish side: HTTP push + OTLP handlers, which ack a node or an edge ONLY after
// the log's PubAck) and the consumers (the apply worker, the SoR writer, the OTLP
// hot writer), so the P0-9 "WAL before ack" contract survives with the WAL moved
// from a per-process SQLite table to a replicated log.
//
// This package holds ONLY types, interfaces, errors and pure helpers. It never
// imports database/sql, net/http, fsnotify or any broker client; those live in
// the adapters (memlog for tests, natslog for NATS JetStream, kafkalog later),
// and logtest is the conformance suite every adapter must pass (the waltest
// precedent). The node binary (cmd/observer, internal/store, internal/orgclient)
// must never import this package or any broker module; tests/invariant pins it.
//
// Contract in one paragraph: a Record is ONE push envelope or ONE mapped OTLP
// batch (never chunked, D6); its DedupID is derived from the content so a node
// retry re-publishes the same id and the log drops it inside the duplicate
// window; outside the window the duplicate is applied and is a no-op because
// every family is idempotent by natural key. At-least-once delivery plus
// natural-key idempotency is the guarantee; broker dedup is an optimization.
package telemetrylog
