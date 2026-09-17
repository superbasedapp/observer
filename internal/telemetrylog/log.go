package telemetrylog

import (
	"context"
	"errors"
	"time"
)

// Attribute keys carried on a Record. They are the ONLY out-of-band facts a
// consumer may rely on; everything else is inside Payload. Adapters transport
// them as message headers (or their engine's equivalent) and must round-trip
// every key verbatim.
const (
	// AttrUserID is the pushing node's authenticated subject (bearer claims.Sub)
	// for a push record. The apply worker hands it to ingest.PushWithControl as
	// userID; a record without it is quarantined, never applied under a guess.
	AttrUserID = "user_id"
	// AttrPushedAt is the RFC3339 UTC instant the collector accepted the push;
	// it becomes the pushed_at stamp on every ingested row, exactly as the
	// synchronous handler stamped it before the arc.
	AttrPushedAt = "pushed_at"
	// AttrCollector identifies the collector instance that published the
	// record (hostname or an operator-set instance id). Diagnostic only.
	AttrCollector = "collector"
	// AttrSignal is the OTLP signal ("traces" | "logs" | "metrics") of an OTLP
	// record; absent on push records. The OTLP applier switches on it to pick
	// the decoder, the same way gateway.WALRecord.Signal did.
	AttrSignal = "signal"
	// AttrSourceIP is the remote address of the publishing request, kept for
	// ingest health's per-source view. Diagnostic only.
	AttrSourceIP = "source_ip"
)

// Record kinds, one per subject family (plan §4.3). A record's Kind is derived
// from its Subject by KindOf; adapters never persist it separately.
const (
	// KindPush is one complete node push envelope (orgcontract.PushEnvelope),
	// published as the EXACT decoded (post-gunzip) JSON bytes the collector
	// verified. Subject "sbo.push.<org>".
	KindPush = "push"
	// KindOTLP is one mapped OTLP batch (the gateway's Mapped* payload in its
	// existing WAL codec), subject "sbo.otlp.<org>.<signal>".
	KindOTLP = "otlp"
)

// Record is ONE durable log record: exactly one push envelope or one mapped
// OTLP batch. It is a plain value; adapters serialize it however their engine
// needs and must hand a consumer back an equal Record.
type Record struct {
	// Org is the org id the record belongs to. Every subject, dedup id and
	// SoR partition is org-keyed by construction (plan §4.6).
	Org string
	// Subject is the log subject the record is published on: PushSubject(org)
	// or OTLPSubject(org, signal). Adapters route and filter on it.
	Subject string
	// DedupID is the content-derived duplicate id: DedupID(org, subject,
	// payload). Adapters use it as their engine's message id (NATS
	// Nats-Msg-Id) so a retry inside the duplicate window is dropped at the
	// broker. It is an optimization, never the idempotency guarantee.
	DedupID string
	// PayloadVer is the codec version of Payload (the gateway WAL codec's
	// version for OTLP records; PushPayloadVer for push records) so a consumer
	// built against a newer codec can still decode an older record.
	PayloadVer int
	// Payload is the record body. For a push record it is the decoded envelope
	// JSON; for an OTLP record it is the gateway WAL-codec bytes.
	Payload []byte
	// Attrs are the out-of-band facts listed above (AttrUserID, AttrPushedAt,
	// ...). nil and empty are equivalent.
	Attrs map[string]string
}

// PushPayloadVer is the codec version stamped on every push record: 1 = the
// decoded orgcontract.PushEnvelope JSON exactly as received after gunzip.
const PushPayloadVer = 1

// PubResult is what a successful Publish returns. Sequence is the engine's
// stream sequence (0 when the engine has none); Duplicate reports that the
// engine recognized DedupID inside its duplicate window and stored nothing new,
// which is still a SUCCESS for the collector (the record is durably held).
type PubResult struct {
	Sequence  uint64
	Duplicate bool
}

// ConsumerSpec names a durable consumer and its delivery policy. A consumer
// with the same Name reattaches to the same durable cursor across process
// restarts (that is what makes a worker crash between Fetch and Ack a
// redelivery, never a loss).
type ConsumerSpec struct {
	// Name is the durable consumer name, unique per log (e.g. "applyworker",
	// "sorwriter", "otlpapplier").
	Name string
	// FilterSubjects restricts delivery to these subjects (wildcards allowed by
	// the engine: "sbo.push.*", "sbo.otlp.>"). Empty means every subject.
	FilterSubjects []string
	// MaxDeliver is the delivery budget per record; when a record has been
	// delivered this many times without an Ack the engine stops redelivering
	// it and the consumer Term's it into quarantine. <= 0 means the adapter's
	// pinned default.
	MaxDeliver int
	// AckWait is how long the engine waits for an Ack/Nak before it redelivers
	// a fetched record on its own. <= 0 means the adapter's pinned default.
	AckWait time.Duration
	// MaxAckPending bounds globally outstanding records for this durable
	// consumer, including NAKed deliveries. One preserves stream order across
	// retries and worker replicas. Zero selects the adapter default.
	MaxAckPending int
}

// OrderPosition identifies one stored occurrence, not merely its content hash.
// Generation must change when the stream is recreated; Sequence never resets
// within a generation. Unsupported adapters do not implement OrderedDelivery.
type OrderPosition struct {
	Generation string
	Sequence   uint64
}

// OrderedDelivery is optional trusted provenance for ordered archive recovery.
// Callers must not manufacture it from payload attributes or wall-clock time.
type OrderedDelivery interface {
	OrderPosition() (OrderPosition, bool)
}

// Delivered is one fetched record with its acknowledgement handle. Exactly one
// of Ack, Nak or Term is called per delivery; a delivery that is neither acked
// nor nakked within AckWait is redelivered by the engine (at-least-once).
type Delivered interface {
	// Record returns the record as published (equal to the Record passed to
	// Publish, Attrs included).
	Record() Record
	// Sequence is the engine's stream sequence for this record (0 when none).
	Sequence() uint64
	// Attempt is the 1-based delivery count of this record to this consumer.
	Attempt() int
	// Ack marks the record consumed; the engine never redelivers it.
	Ack(ctx context.Context) error
	// Nak asks for redelivery after delay (0 = the engine's default backoff).
	Nak(ctx context.Context, delay time.Duration) error
	// Term stops redelivery permanently (the poison-record path); the caller
	// records reason in the quarantine table BEFORE calling Term so the record
	// is never lost silently.
	Term(ctx context.Context, reason string) error
}

// Consumer is a durable pull consumer. Fetch blocks up to wait for at least
// one record and returns at most max; an empty slice with a nil error means
// nothing was available within wait (never an error). Close releases the
// subscription without deleting the durable cursor.
//
// Fetch may return ErrReattachRequired; only the natslog engine reports it
// today (memlog and kafkalog have no re-creatable broker-side durable), so a
// caller must treat it as possible but never assume every engine raises it.
type Consumer interface {
	Fetch(ctx context.Context, max int, wait time.Duration) ([]Delivered, error)
	Close() error
}

// StreamStats is the log's own depth read for ingest health and the doctor.
// Every count is engine-reported, never estimated.
type StreamStats struct {
	// Messages is the number of records the stream currently holds.
	Messages uint64
	// Bytes is the stream's stored size.
	Bytes uint64
	// FirstSequence / LastSequence bound the retained range (0 when empty).
	FirstSequence uint64
	LastSequence  uint64
	// Consumers is the per-durable-consumer backlog: records delivered but
	// not yet acked plus records not yet delivered.
	Consumers []ConsumerStats
}

// ConsumerStats is one durable consumer's backlog.
type ConsumerStats struct {
	Name string
	// Pending is the number of records not yet delivered to this consumer.
	Pending uint64
	// AckPending is the number delivered and awaiting Ack/Nak/Term.
	AckPending uint64
	// Redelivered is the number of records currently in a redelivery cycle.
	Redelivered uint64
}

// Report is the doctor / health probe result for one log engine, the
// telemetry capability Report's shape transposed onto the log.
type Report struct {
	// Engine is the adapter name ("memory", "nats", "kafka").
	Engine string `json:"engine"`
	// Configured is false when the adapter has no backend to reach.
	Configured bool `json:"configured"`
	// Healthy is true when a round trip to the backend succeeded.
	Healthy bool `json:"healthy"`
	// Replicas is the stream replication factor the backend reports (1 for the
	// embedded single-node server, 3 for an HA cluster, 0 when not applicable).
	Replicas int `json:"replicas"`
	// Stats is the depth read; zero when Healthy is false.
	Stats StreamStats `json:"stats"`
	// StatsUnavailable distinguishes unsupported exact counters from an empty
	// log. Healthy is still based on a real broker connectivity probe.
	StatsUnavailable bool `json:"stats_unavailable,omitempty"`
	// Detail is a one-line human explanation (the error text when unhealthy).
	Detail string `json:"detail,omitempty"`
}

// Log is the durable log every collector publishes into and every consumer
// pulls from. Implementations must pass logtest.RunConformance.
type Log interface {
	// Publish appends rec and returns only after the engine has durably
	// acknowledged it (the PubAck). ErrFull when the stream is at capacity
	// (the collector answers 503 + Retry-After), ErrTooLarge when the payload
	// exceeds the engine's per-record cap, ErrUnavailable when the backend
	// cannot be reached, ErrClosed after Close. A duplicate inside the window
	// is a SUCCESS with PubResult.Duplicate = true.
	Publish(ctx context.Context, rec Record) (PubResult, error)
	// Subscribe attaches (creating it when absent) the durable consumer spec
	// names and returns its pull handle.
	Subscribe(ctx context.Context, spec ConsumerSpec) (Consumer, error)
	// Stats is the engine-reported depth read.
	Stats(ctx context.Context) (StreamStats, error)
	// Probe is the doctor / health round trip; it never returns an error, it
	// reports one.
	Probe(ctx context.Context) Report
	// Close releases the adapter's connections (and, for an embedded engine,
	// stops the in-process server). Idempotent.
	Close() error
}

// Sentinel errors every adapter maps its engine's failures onto. Callers use
// errors.Is; adapters wrap with context.
var (
	// ErrFull is returned by Publish when the stream is at its configured
	// capacity and discards new records (the ingest depth cap of P0-9, now the
	// log's Discard: New policy). The collector maps it to 503 + Retry-After.
	ErrFull = errors.New("telemetrylog: log full")
	// ErrTooLarge is returned by Publish when the record exceeds the engine's
	// per-record byte cap (D6: 32 MiB on JetStream, above the node's 16 MiB
	// push ceiling, so a legal push never trips it).
	ErrTooLarge = errors.New("telemetrylog: record too large")
	// ErrUnavailable is returned when the backend cannot be reached or did not
	// acknowledge within the adapter's timeout. The collector maps it to 503;
	// it never acks the node on it.
	ErrUnavailable = errors.New("telemetrylog: log unavailable")
	// ErrClosed is returned after Close.
	ErrClosed = errors.New("telemetrylog: log closed")
	// ErrStatsUnavailable means the backend cannot report exact record counts;
	// callers must show unavailable, never treat the zero value as zero backlog.
	ErrStatsUnavailable = errors.New("telemetrylog: exact statistics unavailable")
	// ErrInvalidRecord is returned by Publish for a record with an empty Org,
	// Subject, DedupID or Payload, or whose Subject does not belong to Org.
	ErrInvalidRecord = errors.New("telemetrylog: invalid record")
	// ErrReattachRequired is returned by Consumer.Fetch when the live durable
	// consumer is no longer the one this handle attached to — the engine
	// recreated the same-name durable (a broker restart that re-created the
	// consumer during store recovery), moved it to another stream, or another
	// subscriber relaxed the global credit this handle promised. The handle is
	// permanently stale: the ONLY recovery is Close + Subscribe by the SAME
	// ConsumerSpec.Name, which reattaches the durable cursor and redelivers
	// every unacked record. Callers branch on errors.Is, never on message text
	// (incident ORG-NATS-REATTACH-1: the runner logged "reattach required"
	// every second for 10+ minutes and nothing reattached).
	ErrReattachRequired = errors.New("telemetrylog: reattach required")
	// ErrReconnectRequired is returned by Log.Subscribe when the STREAM behind
	// this Log handle is no longer the stream it was constructed against (it was
	// deleted and re-created, so its immutable identity and ordering generation
	// changed). Unlike ErrReattachRequired, re-Subscribing by the same durable
	// name can never heal it: the refusal is deliberate and fail-closed, because
	// silently following a re-created stream would let a handle inherit ordering
	// provenance it never earned. The ONLY recovery is to re-establish what a
	// fresh process boot establishes — a restart, or the optional Reconnector
	// capability when the engine implements it. Callers branch on errors.Is,
	// never on message text (incident ORG-NATS-REATTACH-1, residual 4).
	ErrReconnectRequired = errors.New("telemetrylog: reconnect required")
)

// Reconnector is an OPTIONAL capability a Log implements when it can
// re-establish, in-process, exactly what a fresh process boot establishes —
// re-reading the stream's current immutable identity (its creation stamp and
// ordering generation) and re-provisioning whatever a boot provisions.
//
// It exists for the one failure the durable-name reattach cannot heal: the
// STREAM itself was re-created, so every Subscribe on the running process is
// refused with ErrReconnectRequired while a fresh boot against the same broker
// succeeds (incident ORG-NATS-REATTACH-1, residual 4). A caller branches on the
// CAPABILITY — a type assertion on this interface — never on the engine name
// (CLAUDE.md rule #3); a Log that cannot do it simply does not implement it and
// the caller stays fail-closed.
//
// Reconnect must be safe to call concurrently with Publish/Subscribe/Stats and
// must leave the Log usable (or return an error and leave it unchanged). It
// never resurrects data the re-created stream lost, and it never certifies the
// old generation: deliveries after a successful Reconnect carry the NEW
// OrderPosition.Generation, exactly as they would after a restart.
type Reconnector interface {
	Reconnect(ctx context.Context) error
}
