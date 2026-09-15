// Package memlog is an in-memory implementation of telemetrylog.Log for unit
// tests. It is a full, faithful implementation of the log contract — durable
// sequences, a content-derived duplicate window, durable pull consumers that
// reattach by name, at-least-once delivery with AckWait redelivery, Nak backoff,
// Term quarantine and a MaxDeliver budget — kept entirely in memory behind one
// mutex, so a test that would otherwise need an embedded NATS server (natslog)
// can pin the same behaviour in microseconds.
//
// It passes telemetrylog/logtest.RunConformance, the shared suite every adapter
// must pass, and adds two test-only hooks the suite and the collector tests
// need: New's Options carry an injectable clock (Now) so a test can prove the
// duplicate window expires without sleeping, and FailNextPublish arms the next
// Publish to return a chosen error so the collector's "WAL before ack" 503 path
// (plan §6 criterion 2) can be pinned deterministically.
//
// memlog is a TEST adapter: it has no persistence, no replication and no size
// eviction beyond the configured caps (its Discard policy is Discard: New, like
// JetStream). Production runs against natslog.
package memlog
