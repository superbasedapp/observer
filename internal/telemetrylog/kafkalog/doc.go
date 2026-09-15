// Package kafkalog implements the telemetry log on a dedicated, pre-provisioned
// Kafka topic using franz-go. The topic must have exactly one partition: the
// shared sequence is its offset+1, never an ambiguous cross-partition number.
// Publishers use idempotent transport retries and acks=all; Connect verifies the
// configured minimum replication, min.insync.replicas and clean-leader policy.
// This is not content-DedupID deduplication or a discard-new capacity limit.
//
// Each durable consumer uses a Kafka group. Offset-commit metadata preserves
// outstanding offsets, attempts and redelivery deadlines; the committed offset
// never passes an unfinished record. Filtered/acked holes are represented by the
// durable scan cursor, not silently skipped by committing the latest Ack.
// At most 64 unfinished records are tracked, bounded by Kafka's 4 KiB metadata
// limit. Exhausted MaxDeliver records remain parked until their final delivery
// is Term'd by the caller's quarantine path. Keep group-offset retention longer
// than the maximum worker outage; deleting/expiring a group loses its cursor.
//
// Kafka exposes offset ranges and consumer lag, not the interface's exact
// record/byte/backlog counts. Stats returns telemetrylog.ErrStatsUnavailable;
// Probe performs real broker/topic checks and marks stats unavailable. Topic
// retention is broker-managed; operators must retain data beyond consumer lag
// and configure broker maximum record size for the selected MaxMsgBytes.
package kafkalog
