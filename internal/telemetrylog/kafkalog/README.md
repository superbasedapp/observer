# Kafka telemetry log

`Connect(ctx, Options)` attaches to an existing dedicated Kafka topic.
`ValidateOptions` performs defaulted structural validation only (no files or
network), so the org configuration loader can use it too. `Connect` and `Probe`
read metadata/configuration; they never create or alter a topic.

The package uses franz-go 1.20.7 / kmsg 1.12.0 (Go 1.24 minimum, compatible with
the repository's pinned Go 1.25.13). It is pure Go; no librdkafka/CGO dependency.

## Required broker contract

- Exactly **one** topic partition. `Sequence = Kafka offset + 1`; offsets may
  contain gaps but are ordered and unambiguous. Do not add partitions to a live
  topic. Parallel collectors may publish safely, but throughput remains bounded
  by one partition. Multiple independently numbered partitions need a future
  interface change, not a synthesized global counter in this adapter.
- Default minimums: 3 replicas and 2 in-sync replicas. `Connect` checks actual
  replicas/ISR, effective `min.insync.replicas`,
  `unclean.leader.election.enable=false`, and `cleanup.policy=delete`.
  `RequiredReplicas=1, MinInSyncReplicas=1` is explicit dev-only durability.
- Publishing uses franz-go's idempotent producer and `acks=all`. Success is
  reported only after broker acknowledgment; an ambiguous timeout is an error,
  never an invented PubAck. Idempotence protects transport retries within the
  producer session, not repeated content-DedupID calls across collectors.
- Configure topic/broker maximum message and replica-fetch sizes to fit the
  selected payload cap plus headers/batch overhead. For the 32 MiB default,
  40 MiB broker limits provide headroom. The adapter caps producer batches at
  payload cap + 64 KiB; excessive attributes are also rejected by the producer.
- Keep record retention longer than the maximum consumer lag. Keep consumer
  group-offset retention longer than the maximum worker outage. Secure and
  replicate `__consumer_offsets` as well as the data topic; group deletion or
  offset expiry deletes attempt/cursor state. These operator lifecycle settings
  are not auto-modified by the adapter.
- Restrict topic writes and group-offset mutation to authorized adapter clients;
  record values/headers have this package's schema. Invalid external records or
  corrupted/incompatible cursor metadata stop consumption for investigation.

TLS is required outside loopback, including advertised broker addresses. The
plain loopback exception exists for disposable local tests. Optional CA/mTLS
files and SASL `PLAIN`, `SCRAM-SHA-256`, or `SCRAM-SHA-512` are supported.
Credentials are runtime-only; Options formatting and transport failures redact
them. Kafka ACLs must allow metadata/configuration reads, data-topic publish and
consume, and group join/fetch/commit operations for the chosen group prefix.

## Durable consumer behavior

Each `(topic, ConsumerSpec.Name)` maps to one stable Kafka consumer group. Group
assignment fences acknowledgment writers by member/generation. Subscription
waits for initial group attachment/cursor restoration; a standby member with no
assigned partition is valid and waits for ownership. No auto-commit runs.

Every delivery is persisted in group offset metadata **before Fetch returns**.
The metadata holds a version, policy fingerprint, scan cursor and up to 64
unfinished `(offset, attempt, retry-deadline)` entries. It is bounded below
Kafka's standard 4 KiB offset-metadata limit; a lower broker limit fails closed.
The committed offset is the earliest unfinished record, or the scan cursor if
none remain. Later Ack/Term calls cannot skip an earlier unacknowledged record.
Filtered and already-completed offsets are represented by the scan cursor and
absence from unfinished entries, so they do not replay after restart.

Ack and Term persist completion; the caller must write quarantine evidence
before Term. Nak persists its requested delay (zero uses one second). AckWait
expiry increments the durable attempt on redelivery. MaxDeliver parks the
record; production consumers should quarantine+Term on their final attempt.
A parked record retains its gap and consumes an outstanding slot. Sixty-four
parked records stop further delivery until operator recovery, rather than
discarding records to unblock the stream. Stale deliveries cannot acknowledge
a newer attempt or a new group assignment.

Restarts may rescan completed holes from the earliest unfinished offset to the
scan cursor; this trades extra reads for bounded durable metadata. Broker
retention that removes an unfinished record is an error: automatic reset to
latest/earliest is disabled. Filter/AckWait/MaxDeliver changes on an already-used
durable name are refused because inheriting its cursor could skip newly matched
records. Make policy/group changes as a planned replay/migration operation.

## Deliberately unavailable conveniences

`Capabilities()` returns false for content-window deduplication, discard-new
capacity and exact stats. Kafka does not provide JetStream-style MaxMessages
rejection or exact filtered Pending/AckPending counters. `Stats` returns
`telemetrylog.ErrStatsUnavailable`; `Probe` validates actual broker/topic health
and sets `StatsUnavailable=true`. Do not label offset distance as message depth,
or render the zero-valued stats fields as an empty healthy queue.

## Focused verification

```bash
# Unit tests (live cases skip without the explicit broker variable).
GOTOOLCHAIN=go1.25.13 go test ./internal/telemetrylog/kafkalog
# Disposable Apache Kafka 3.9.1, loopback-only listeners, no external service.
bash internal/telemetrylog/kafkalog/test-kafka.sh -race -v
```

The harness runs only this package, captures broker logs in a temporary
directory and removes its container. Conformance uses the shared capability
seam: all mandatory publish/delivery/ack tests remain, unsupported optional
capabilities have explicit assertions instead of fabricated implementations.
Single-broker test success is not a three-failure-domain or broker-crash proof.
