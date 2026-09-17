package natslog

import (
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// Default* are the adapter's pinned defaults (plan O4). A zero value in the
// corresponding Options field is normalised to these by withDefaults.
const (
	// DefaultStream is the JetStream stream name.
	DefaultStream = "SBO_TELEMETRY"
	// DefaultMaxAge is the stream retention horizon (plan O4: 72 h).
	DefaultMaxAge = 72 * time.Hour
	// DefaultMaxBytes is the stream storage cap: 10 GiB, the value the
	// production estate actually runs. Lowered from the plan O4 default of
	// 250 GiB (JetStream error 10047 against a 35 GB broker broke the
	// estate; see docs/teams-operations.md "Durable log capacity"). Also
	// checked proactively at connect time against the broker's advertised
	// JetStream account storage limit — see preflightCapacityErr in
	// errors.go — so a cap configured above what the broker can actually
	// provide is refused with an actionable message before ever attempting
	// to create the stream, not just reactively on first publish.
	DefaultMaxBytes int64 = 10 << 30
	// DefaultMaxMsgBytes is the per-record cap (D6: 32 MiB, above the node's
	// 16 MiB push ceiling so a legal push never trips ErrTooLarge).
	DefaultMaxMsgBytes int32 = 32 << 20
	// DefaultDuplicateWindow is the Nats-Msg-Id dedup window (plan O4: 2 h).
	DefaultDuplicateWindow = 2 * time.Hour
	// DefaultMaxDeliver is the per-record delivery budget before quarantine.
	DefaultMaxDeliver = 10
	// DefaultAckWait is how long the engine waits for an Ack before redelivery.
	DefaultAckWait = 30 * time.Second
	// DefaultConnectTimeout bounds one connect attempt.
	DefaultConnectTimeout = 5 * time.Second
	// DefaultPublishTimeout bounds one publish / info round trip.
	DefaultPublishTimeout = 10 * time.Second
)

// unlimited is the JetStream "no limit" sentinel for MaxMsgs / MaxBytes.
const unlimited int64 = -1

// DefaultSubjects is the subject set the stream binds when Options.Subjects is
// empty: one wildcard family per record kind (plan §4.3).
func DefaultSubjects() []string { return []string{"sbo.push.>", "sbo.otlp.>"} }

// Options configures the JetStream adapter. It is a PLAIN struct with no TOML
// tags (the gateway.WALConfig precedent): the orgserver config package mirrors
// it and translates into this shape at the construction site, so natslog stays
// config-free and can never import internal/orgserver/config.
type Options struct {
	// URL is the nats-server URL (ignored by Embedded, which dials its own
	// in-process server). A tls:// or nats+tls:// scheme implies TLS.
	URL string
	// Stream is the stream name (default DefaultStream).
	Stream string
	// Subjects is the stream's bound subject set (default DefaultSubjects).
	Subjects []string
	// Replicas is the stream replication factor (default 1; forced to 1 for
	// Embedded). An existing stream with a different count is kept as-is.
	Replicas int
	// MaxAge is the retention horizon (default DefaultMaxAge).
	MaxAge time.Duration
	// MaxBytes is the storage cap (default DefaultMaxBytes; -1 = unlimited).
	MaxBytes int64
	// EmbeddedMaxStore caps the IN-PROCESS server's whole JetStream file-store
	// pool (Embedded only; ignored by Connect). Zero — the production default —
	// leaves the server deriving its pool from the host's free disk exactly as
	// before. It exists so a caller that must be hermetic about its footprint,
	// above all the test broker, can pin a small explicit pool instead of
	// inheriting whatever the machine happens to have free: a stream MaxBytes
	// reservation the host cannot back is refused by the broker at create time
	// (JetStream 10047), which is precisely how the 10 GiB production default
	// turned a small CI runner into a total natslog-test failure.
	EmbeddedMaxStore int64
	// MaxMsgBytes is the per-record cap (default DefaultMaxMsgBytes).
	MaxMsgBytes int32
	// MaxMessages is the ErrFull message-count cap (0 or -1 = unlimited).
	MaxMessages int64
	// DuplicateWindow is the Nats-Msg-Id dedup window (default
	// DefaultDuplicateWindow); clamped to MaxAge, which it must not exceed.
	DuplicateWindow time.Duration
	// MaxDeliver is the per-consumer delivery budget (default DefaultMaxDeliver).
	MaxDeliver int
	// AckWait is the per-consumer redelivery timeout (default DefaultAckWait).
	AckWait time.Duration
	// ConnectTimeout bounds one connect / ready attempt (default 5s).
	ConnectTimeout time.Duration
	// PublishTimeout bounds one publish / info round trip (default 10s).
	PublishTimeout time.Duration
	// Name is the NATS client name (diagnostic).
	Name string

	// CredsFile is a NATS credentials file (JWT + nkey seed).
	CredsFile string
	// NKeySeedFile is a bare nkey seed file (used when CredsFile is empty).
	NKeySeedFile string
	// Token is a connection token (used when the above are empty).
	Token string
	// User / Password are basic-auth credentials (used when the above are empty).
	User     string
	Password string

	// CAFile / CertFile / KeyFile are optional TLS material. A tls:// or
	// nats+tls:// URL implies TLS even with none of these set.
	CAFile   string
	CertFile string
	KeyFile  string

	// EmbeddedListen, for Embedded only, is the loopback bind for the
	// in-process server. "" means a random loopback port; a host:port lets an
	// operator point the nats CLI at the embedded server.
	EmbeddedListen string
}

// withDefaults returns a copy with every zero-valued field normalised to its
// pinned default, mirroring config.EffectiveWAL's "<=0 => default" rule. It is
// the ONE place the defaults live, so Connect and Embedded agree.
func (o Options) withDefaults() Options {
	if o.Stream == "" {
		o.Stream = DefaultStream
	}
	if len(o.Subjects) == 0 {
		o.Subjects = DefaultSubjects()
	}
	if o.Replicas <= 0 {
		o.Replicas = 1
	}
	if o.MaxAge <= 0 {
		o.MaxAge = DefaultMaxAge
	}
	if o.MaxBytes == 0 {
		o.MaxBytes = DefaultMaxBytes
	}
	if o.MaxMsgBytes <= 0 {
		o.MaxMsgBytes = DefaultMaxMsgBytes
	}
	if o.MaxMessages == 0 {
		// 0 and -1 both mean unlimited; normalise to the JetStream sentinel.
		o.MaxMessages = unlimited
	}
	if o.DuplicateWindow <= 0 {
		o.DuplicateWindow = DefaultDuplicateWindow
	}
	if o.DuplicateWindow > o.MaxAge {
		// JetStream refuses a duplicate window longer than MaxAge; clamp it.
		o.DuplicateWindow = o.MaxAge
	}
	if o.MaxDeliver <= 0 {
		o.MaxDeliver = DefaultMaxDeliver
	}
	if o.AckWait <= 0 {
		o.AckWait = DefaultAckWait
	}
	if o.ConnectTimeout <= 0 {
		o.ConnectTimeout = DefaultConnectTimeout
	}
	if o.PublishTimeout <= 0 {
		o.PublishTimeout = DefaultPublishTimeout
	}
	return o
}

// streamConfig builds the JetStream stream configuration from o (already
// defaulted): Limits retention, File storage, Discard:New (so a full stream
// rejects net-new records with ErrFull rather than evicting), plus the caps
// and the duplicate window.
func (o Options) streamConfig() jetstream.StreamConfig {
	return jetstream.StreamConfig{
		Name:       o.Stream,
		Subjects:   o.Subjects,
		Retention:  jetstream.LimitsPolicy,
		Storage:    jetstream.FileStorage,
		Discard:    jetstream.DiscardNew,
		MaxAge:     o.MaxAge,
		MaxBytes:   o.MaxBytes,
		MaxMsgSize: o.MaxMsgBytes,
		MaxMsgs:    o.MaxMessages,
		Replicas:   o.Replicas,
		Duplicates: o.DuplicateWindow,
	}
}
