package natslog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/marmutapp/superbased-observer/internal/telemetrylog"
)

// Message header names the adapter transports a Record's out-of-band facts on.
// Nats-Msg-Id is the engine's dedup key; the Sbo-* names carry the rest.
const (
	// headerMsgID is the JetStream dedup header (Record.DedupID).
	headerMsgID = jetstream.MsgIDHeader // "Nats-Msg-Id"
	// headerOrg carries Record.Org.
	headerOrg = "Sbo-Org"
	// headerPayloadVer carries Record.PayloadVer.
	headerPayloadVer = "Sbo-Payload-Ver"
	// headerAttrPrefix prefixes one header per Record.Attrs entry.
	headerAttrPrefix = "Sbo-Attr-"
)

// ErrDurableIncompatible is the fail-closed refusal for a live durable whose
// configuration this adapter can neither honour NOR repair. JetStream refuses
// to update a consumer's start position, so a durable created with
// DeliverLast/DeliverNew (or an explicit start sequence/time) can only be
// attached to as-is — and attaching pins that start position silently: Fetch
// returns empty batches forever while the backlog behind it is never delivered,
// and an empty SUCCESSFUL Fetch even keeps the dead-handle clock clear. The
// wrapped text names the offending field; the operator's remedy is to delete
// the durable so the adapter re-creates it with DeliverAllPolicy.
var ErrDurableIncompatible = errors.New("natslog: durable consumer configuration cannot be reconciled")

// engineName is the Report.Engine value for this adapter.
const engineName = "nats"

// Only creation by the upgraded adapter establishes this durable boundary.
// An existing unmarked stream must never be retroactively certified.
const (
	orderingMetadataKey     = "sbo.telemetry.ordering"
	orderingMetadataVersion = "1"
)

// Log is the JetStream implementation of telemetrylog.Log. Construct it with
// Connect (external server) or Embedded (in-process server). It is safe for
// concurrent Publish/Subscribe/Stats calls; Close is idempotent.
type Log struct {
	nc   *nats.Conn
	js   jetstream.JetStream
	srv  embeddedServer // non-nil only for Embedded
	opts Options

	// mu guards the closed flag AND the stream identity below, which Reconnect
	// replaces in place. Read the identity through identity(), never directly,
	// so a concurrent Reconnect cannot be observed half-applied.
	mu     sync.Mutex
	closed bool
	// stream / streamCreated / orderGeneration are the provisioned stream and
	// the immutable identity Subscribe fences every handle against.
	stream          jetstream.Stream
	streamCreated   time.Time
	orderGeneration string
	// note carries a non-fatal provisioning remark (e.g. a kept-existing
	// replica count) surfaced on Probe.Detail even while healthy.
	note string
}

// embeddedServer is the slice of *server.Server the adapter drives; it lives
// behind an interface so log.go need not import nats-server (embedded.go does).
type embeddedServer interface {
	Shutdown()
	WaitForShutdown()
}

// Connect wires the adapter to an external nats-server at opts.URL, creating or
// updating the stream, and returns a ready Log. A connection failure is
// reported as ErrUnavailable within opts.ConnectTimeout.
func Connect(ctx context.Context, opts Options) (*Log, error) {
	o := opts.withDefaults()
	nc, err := connectNATS(o)
	if err != nil {
		return nil, fmt.Errorf("natslog.Connect: %w: %w", err, telemetrylog.ErrUnavailable)
	}
	l, err := newLog(ctx, nc, o, nil)
	if err != nil {
		nc.Close()
		return nil, err
	}
	return l, nil
}

// connectNATS dials the server with the credential and TLS options set on o.
func connectNATS(o Options) (*nats.Conn, error) {
	natsOpts := []nats.Option{
		nats.Timeout(o.ConnectTimeout),
		// The default async error handler prints "connection reset by peer"
		// to stderr when the embedded server shuts down under a live client;
		// the adapter reports transport failures through error returns, so the
		// handler is silenced (a nil handler restores the noisy default).
		nats.ErrorHandler(func(*nats.Conn, *nats.Subscription, error) {}),
	}
	if o.Name != "" {
		natsOpts = append(natsOpts, nats.Name(o.Name))
	}
	switch {
	case o.CredsFile != "":
		natsOpts = append(natsOpts, nats.UserCredentials(o.CredsFile))
	case o.NKeySeedFile != "":
		opt, err := nats.NkeyOptionFromSeed(o.NKeySeedFile)
		if err != nil {
			return nil, fmt.Errorf("nkey seed %q: %w", o.NKeySeedFile, err)
		}
		natsOpts = append(natsOpts, opt)
	case o.Token != "":
		natsOpts = append(natsOpts, nats.Token(o.Token))
	case o.User != "":
		natsOpts = append(natsOpts, nats.UserInfo(o.User, o.Password))
	}
	if o.CAFile != "" {
		natsOpts = append(natsOpts, nats.RootCAs(o.CAFile))
	}
	if o.CertFile != "" && o.KeyFile != "" {
		natsOpts = append(natsOpts, nats.ClientCert(o.CertFile, o.KeyFile))
	}
	nc, err := nats.Connect(o.URL, natsOpts...)
	if err != nil {
		return nil, err
	}
	return nc, nil
}

// newLog builds the JetStream context, provisions the stream, and returns the
// Log. srv is non-nil only for the embedded engine.
func newLog(ctx context.Context, nc *nats.Conn, o Options, srv embeddedServer) (*Log, error) {
	js, err := jetstream.New(nc)
	if err != nil {
		return nil, fmt.Errorf("natslog: jetstream context: %w", err)
	}
	provCtx, cancel := context.WithTimeout(ctx, o.PublishTimeout)
	defer cancel()
	if err := preflightCapacityErr(provCtx, js, o.MaxBytes); err != nil {
		return nil, err
	}
	stream, note, err := ensureStream(provCtx, js, o)
	if err != nil {
		return nil, streamProvisionErr(err, o.MaxBytes)
	}
	info := stream.CachedInfo()
	if info == nil || info.Config.Name != o.Stream || info.Created.IsZero() {
		return nil, fmt.Errorf("natslog: provisioned stream has no immutable identity")
	}
	return &Log{
		nc: nc, js: js, stream: stream, srv: srv, opts: o, note: note,
		streamCreated: info.Created, orderGeneration: streamOrderGeneration(info),
	}, nil
}

func streamOrderGeneration(info *jetstream.StreamInfo) string {
	if info == nil || info.Created.IsZero() || info.Config.Name == "" || info.Config.Metadata[orderingMetadataKey] != orderingMetadataVersion {
		return ""
	}
	identity := "nats-order-v1\x00" + info.Config.Name + "\x00" + info.Created.UTC().Format(time.RFC3339Nano)
	sum := sha256.Sum256([]byte(identity))
	return "nats-v1-" + hex.EncodeToString(sum[:])
}

// ensureStream creates or updates the stream. When an existing stream has a
// different Replicas count, it keeps the existing one and returns an
// explanatory note rather than failing (an operator cannot re-replicate a
// single-node stream by editing config).
func ensureStream(ctx context.Context, js jetstream.JetStream, o Options) (jetstream.Stream, string, error) {
	cfg := o.streamConfig()
	existing, err := js.Stream(ctx, o.Stream)
	if errors.Is(err, jetstream.ErrStreamNotFound) {
		cfg.Metadata = map[string]string{orderingMetadataKey: orderingMetadataVersion}
		created, createErr := js.CreateStream(ctx, cfg)
		if createErr == nil {
			return created, "", nil
		}
		if !errors.Is(createErr, jetstream.ErrStreamNameAlreadyInUse) {
			return nil, "", fmt.Errorf("natslog: create stream %q: %w", o.Stream, mapTransportErr(createErr))
		}
		// A competing creator won. Read its actual metadata; do not add the
		// marker to an unmarked stream that appeared between lookup/create.
		existing, err = js.Stream(ctx, o.Stream)
	}
	if err != nil {
		return nil, "", fmt.Errorf("natslog: inspect stream %q: %w", o.Stream, mapTransportErr(err))
	}
	info := existing.CachedInfo()
	if info == nil {
		return nil, "", fmt.Errorf("natslog: existing stream has no configuration")
	}
	// Metadata is durable provenance plus operator-owned extensions. Every
	// restart preserves it, including the absence of an ordering marker.
	cfg.Metadata = make(map[string]string, len(info.Config.Metadata))
	for key, value := range info.Config.Metadata {
		cfg.Metadata[key] = value
	}
	stream, err := js.UpdateStream(ctx, cfg)
	if err == nil {
		return stream, "", nil
	}
	// The update may have been refused only because Replicas differs; fall
	// back to the existing replication factor and retry.
	if info.Config.Replicas == cfg.Replicas {
		// Replicas match, so the update failed for another reason; surface it.
		return nil, "", fmt.Errorf("natslog: create/update stream %q: %w", o.Stream, mapTransportErr(err))
	}
	note := fmt.Sprintf("stream %q exists with replicas=%d (requested %d); keeping the existing replication factor",
		o.Stream, info.Config.Replicas, cfg.Replicas)
	cfg.Replicas = info.Config.Replicas
	stream, err = js.UpdateStream(ctx, cfg)
	if err != nil {
		return nil, "", fmt.Errorf("natslog: reconcile stream %q: %w", o.Stream, mapTransportErr(err))
	}
	return stream, note, nil
}

// identity returns the stream handle and the immutable identity every
// Subscribe fences against, read under the lock so a concurrent Reconnect is
// never observed half-applied.
func (l *Log) identity() (jetstream.Stream, time.Time, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.stream, l.streamCreated, l.orderGeneration
}

// Reconnect implements telemetrylog.Reconnector: it re-establishes EXACTLY what
// a fresh process boot establishes — the capacity preflight, the stream
// provisioning, and the immutable identity (creation stamp + ordering
// generation) that Subscribe fences handles against — without dropping the
// process.
//
// It is the recovery for the one failure a durable-name reattach can never heal
// (incident ORG-NATS-REATTACH-1, residual 4): the STREAM was deleted and
// re-created, so every Subscribe on this Log is refused with
// telemetrylog.ErrReconnectRequired while a fresh boot against the same broker
// succeeds. Nothing here is a shortcut past that refusal's purpose: the
// re-read generation is a NEW one, so deliveries after a Reconnect carry the new
// OrderPosition.Generation and the old generation is never retroactively
// certified — the same honest outcome as a restart, which is why doing it
// in-process is safe. Records the re-created stream lost are not resurrected;
// consumer handles taken before the Reconnect stay stale and must be replaced by
// a Subscribe (the Runner's reattach does exactly that).
//
// On any failure the Log is left exactly as it was, still refusing Subscribe.
func (l *Log) Reconnect(ctx context.Context) error {
	if l.isClosed() {
		return fmt.Errorf("natslog.Reconnect: %w", telemetrylog.ErrClosed)
	}
	provCtx, cancel := context.WithTimeout(ctx, l.opts.PublishTimeout)
	defer cancel()
	if err := preflightCapacityErr(provCtx, l.js, l.opts.MaxBytes); err != nil {
		return fmt.Errorf("natslog.Reconnect: %w", err)
	}
	stream, note, err := ensureStream(provCtx, l.js, l.opts)
	if err != nil {
		return fmt.Errorf("natslog.Reconnect: %w", streamProvisionErr(err, l.opts.MaxBytes))
	}
	info := stream.CachedInfo()
	if info == nil || info.Config.Name != l.opts.Stream || info.Created.IsZero() {
		return fmt.Errorf("natslog.Reconnect: re-provisioned stream has no immutable identity")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return fmt.Errorf("natslog.Reconnect: %w", telemetrylog.ErrClosed)
	}
	l.stream, l.streamCreated, l.orderGeneration, l.note = stream, info.Created, streamOrderGeneration(info), note
	return nil
}

// Publish appends rec, returning after the engine's PubAck. See the package
// doc for the error mapping.
func (l *Log) Publish(ctx context.Context, rec telemetrylog.Record) (telemetrylog.PubResult, error) {
	if l.isClosed() {
		return telemetrylog.PubResult{}, telemetrylog.ErrClosed
	}
	if err := validateRecord(rec); err != nil {
		return telemetrylog.PubResult{}, err
	}
	msg := nats.NewMsg(rec.Subject)
	msg.Data = rec.Payload
	msg.Header.Set(headerMsgID, rec.DedupID)
	msg.Header.Set(headerOrg, rec.Org)
	msg.Header.Set(headerPayloadVer, strconv.Itoa(rec.PayloadVer))
	for k, v := range rec.Attrs {
		msg.Header.Set(headerAttrPrefix+k, v)
	}
	pubCtx, cancel := context.WithTimeout(ctx, l.opts.PublishTimeout)
	defer cancel()
	ack, err := l.js.PublishMsg(pubCtx, msg)
	if err != nil {
		return telemetrylog.PubResult{}, fmt.Errorf("natslog.Publish: %w", classifyPublishErr(err))
	}
	return telemetrylog.PubResult{Sequence: ack.Sequence, Duplicate: ack.Duplicate}, nil
}

// Subscribe creates or reattaches the durable pull consumer named by spec.
func (l *Log) Subscribe(ctx context.Context, spec telemetrylog.ConsumerSpec) (telemetrylog.Consumer, error) {
	if l.isClosed() {
		return nil, telemetrylog.ErrClosed
	}
	if strings.TrimSpace(spec.Name) == "" {
		return nil, fmt.Errorf("natslog.Subscribe: consumer name is required: %w", telemetrylog.ErrInvalidRecord)
	}
	if spec.MaxAckPending < 0 {
		return nil, fmt.Errorf("natslog.Subscribe: MaxAckPending must be non-negative: %w", telemetrylog.ErrInvalidRecord)
	}
	maxDeliver := spec.MaxDeliver
	if maxDeliver <= 0 {
		maxDeliver = l.opts.MaxDeliver
	}
	ackWait := spec.AckWait
	if ackWait <= 0 {
		ackWait = l.opts.AckWait
	}
	cfg := jetstream.ConsumerConfig{
		Name:          spec.Name,
		Durable:       spec.Name,
		AckPolicy:     jetstream.AckExplicitPolicy,
		MaxDeliver:    maxDeliver,
		AckWait:       ackWait,
		DeliverPolicy: jetstream.DeliverAllPolicy,
		ReplayPolicy:  jetstream.ReplayInstantPolicy,
		MaxAckPending: spec.MaxAckPending,
	}
	switch {
	case len(spec.FilterSubjects) == 1:
		cfg.FilterSubject = spec.FilterSubjects[0]
	case len(spec.FilterSubjects) > 1:
		cfg.FilterSubjects = spec.FilterSubjects
	}
	subCtx, cancel := context.WithTimeout(ctx, l.opts.PublishTimeout)
	defer cancel()
	stream, streamCreated, generation := l.identity()
	current, err := stream.Info(subCtx)
	if err != nil {
		if isStreamGone(err) {
			// The stream is not merely DIFFERENT, it is GONE — the shape a
			// broker whose store does not survive a restart actually takes
			// (the estate's sidecar runs on emptyDir, R=1). It is the same
			// class of failure as a re-created stream and takes the same
			// recovery: Reconnect's ensureStream re-creates it and derives a
			// FRESH generation, so fail-closed ordering is preserved. Without
			// this the error is untyped, the Runner never reaches its Reconnect
			// branch, and every consumer backs off forever.
			return nil, fmt.Errorf("natslog.Subscribe: stream %q no longer exists; reconnect before subscribing: %w",
				l.opts.Stream, telemetrylog.ErrReconnectRequired)
		}
		return nil, fmt.Errorf("natslog.Subscribe: stream identity: %w", mapTransportErr(err))
	}
	if !current.Created.Equal(streamCreated) || streamOrderGeneration(current) != generation {
		// Fail closed: this Log handle is pinned to a stream that no longer
		// exists under that identity. The TYPED sentinel is what lets a caller
		// reach for the optional telemetrylog.Reconnector capability instead of
		// matching the message text (the incident's residual 4).
		return nil, fmt.Errorf("natslog.Subscribe: stream generation changed; reconnect before subscribing: %w",
			telemetrylog.ErrReconnectRequired)
	}
	cons, err := l.attachOrCreateConsumer(subCtx, cfg)
	if err != nil {
		return nil, fmt.Errorf("natslog.Subscribe: %w", err)
	}
	ci := cons.CachedInfo()
	if ci == nil || ci.Created.IsZero() || ci.Stream != l.opts.Stream || (spec.MaxAckPending > 0 && ci.Config.MaxAckPending != spec.MaxAckPending) {
		return nil, fmt.Errorf("natslog.Subscribe: durable identity/credit read-back differs")
	}
	return &natsConsumer{
		cons: cons, name: spec.Name, streamName: l.opts.Stream, streamCreated: streamCreated,
		consumerCreated: ci.Created, orderGeneration: generation, maxAckPending: spec.MaxAckPending,
	}, nil
}

// attachOrCreateConsumer resolves the durable named by cfg.Durable WITHOUT
// racing JetStream's store recovery — the root cause of incident
// ORG-NATS-REATTACH-1. The create-if-absent shortcut it replaces
// (CreateOrUpdateConsumer) could run while the broker was still recovering its
// consumer store: it created a brand-new durable, this process cached that
// durable's Created stamp, and when recovery finished and the REAL durable came
// back every Fetch on the cached identity failed ErrReattachRequired forever.
//
// So: probe first and ATTACH to whatever durable is already there, without
// rewriting a config that matches (a rewrite is what moves the identity a live
// handle must match); create ONLY when the probe says absent; and, because
// probe-then-create is not atomic, attach to the WINNER when the create loses
// the race rather than overwriting it.
func (l *Log) attachOrCreateConsumer(ctx context.Context, cfg jetstream.ConsumerConfig) (jetstream.Consumer, error) {
	existing, err := l.js.Consumer(ctx, l.opts.Stream, cfg.Durable)
	switch {
	case err == nil:
		// A field an UpdateConsumer cannot repair is checked FIRST, because the
		// two alternatives are both wrong: rewriting is refused by the server,
		// and attaching silently pins a start position this spec never asked
		// for. Refuse, named.
		if why := consumerUnfixableDrift(existing.CachedInfo(), cfg); why != "" {
			return nil, fmt.Errorf("durable %q cannot be reconciled (%s); delete it so it is re-created: %w",
				cfg.Durable, why, ErrDurableIncompatible)
		}
		drift := consumerConfigDrift(existing.CachedInfo(), cfg)
		if drift == "" {
			return existing, nil
		}
		// The live durable does not carry the delivery config this spec
		// promises (an operator edit, or an older release's defaults). Reconcile
		// it with an UPDATE, which keeps the durable AND its cursor, so the
		// handle still pins the same consumer identity.
		updated, uerr := l.js.UpdateConsumer(ctx, l.opts.Stream, cfg)
		if uerr != nil {
			return nil, fmt.Errorf("reconcile durable %q (%s): %w", cfg.Durable, drift, mapTransportErr(uerr))
		}
		return updated, nil
	case !isConsumerGone(err):
		return nil, fmt.Errorf("probe durable %q: %w", cfg.Durable, mapTransportErr(err))
	}
	created, cerr := l.js.CreateConsumer(ctx, l.opts.Stream, cfg)
	if cerr == nil {
		return created, nil
	}
	if !isConsumerExists(cerr) {
		return nil, fmt.Errorf("create durable %q: %w", cfg.Durable, mapTransportErr(cerr))
	}
	winner, werr := l.js.Consumer(ctx, l.opts.Stream, cfg.Durable)
	if werr != nil {
		return nil, fmt.Errorf("attach durable %q after create race: %w", cfg.Durable, mapTransportErr(werr))
	}
	return winner, nil
}

// consumerConfigDrift reports, for the reconcile log line, WHICH delivery
// promise the live durable does not carry — empty when attaching to it as-is
// honours the spec. Only the fields the adapter deliberately sets are compared;
// server-defaulted fields are never a reason to rewrite a healthy durable.
func consumerConfigDrift(info *jetstream.ConsumerInfo, want jetstream.ConsumerConfig) string {
	if info == nil {
		return "no consumer info"
	}
	got := info.Config
	switch {
	// MaxAckPending is compared only when the spec actually asked for a credit:
	// a zero request means "the engine's default", and the server resolves that
	// to its own non-zero value — comparing against 0 would call every healthy
	// durable drifted and reintroduce a write on every single Subscribe.
	case want.MaxAckPending > 0 && got.MaxAckPending != want.MaxAckPending:
		return fmt.Sprintf("max_ack_pending %d != %d", got.MaxAckPending, want.MaxAckPending)
	case got.MaxDeliver != want.MaxDeliver:
		return fmt.Sprintf("max_deliver %d != %d", got.MaxDeliver, want.MaxDeliver)
	case got.AckWait != want.AckWait:
		return fmt.Sprintf("ack_wait %s != %s", got.AckWait, want.AckWait)
	case got.AckPolicy != want.AckPolicy:
		return fmt.Sprintf("ack_policy %s != %s", got.AckPolicy, want.AckPolicy)
	case got.FilterSubject != want.FilterSubject:
		return fmt.Sprintf("filter_subject %q != %q", got.FilterSubject, want.FilterSubject)
	case !equalSubjects(got.FilterSubjects, want.FilterSubjects):
		return fmt.Sprintf("filter_subjects %v != %v", got.FilterSubjects, want.FilterSubjects)
	}
	return ""
}

// consumerUnfixableDrift reports WHICH non-updatable field of the live durable
// contradicts the spec — empty when there is none. These are the fields
// JetStream refuses to change on an existing consumer (its START POSITION), so
// unlike consumerConfigDrift's fields they can never be reconciled by an
// UpdateConsumer: the only honest outcomes are refuse or silently deliver
// nothing. It is a table walked top-down, one row per field (CLAUDE.md #5).
//
// A start sequence/time is compared only when the SPEC sets one: the adapter
// leaves both zero, and a server-defaulted zero must never be called drift.
func consumerUnfixableDrift(info *jetstream.ConsumerInfo, want jetstream.ConsumerConfig) string {
	if info == nil {
		return ""
	}
	got := info.Config
	for _, row := range []struct {
		differs bool
		detail  func() string
	}{
		{
			differs: got.DeliverPolicy != want.DeliverPolicy,
			detail:  func() string { return fmt.Sprintf("deliver_policy %s != %s", got.DeliverPolicy, want.DeliverPolicy) },
		},
		{
			differs: want.OptStartSeq > 0 && got.OptStartSeq != want.OptStartSeq,
			detail:  func() string { return fmt.Sprintf("opt_start_seq %d != %d", got.OptStartSeq, want.OptStartSeq) },
		},
		{
			differs: want.OptStartTime != nil && (got.OptStartTime == nil || !got.OptStartTime.Equal(*want.OptStartTime)),
			detail:  func() string { return fmt.Sprintf("opt_start_time %v != %v", got.OptStartTime, *want.OptStartTime) },
		},
	} {
		if row.differs {
			return row.detail()
		}
	}
	return ""
}

// equalSubjects reports SET equality of two filter-subject lists, treating nil
// and empty as equal. Order is deliberately not significant: the server may
// return a multi-subject filter in its own order, and judging that drifted
// would rewrite a healthy durable on every single reattach — the consumer-API
// churn attach-as-is exists to stop.
func equalSubjects(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// Stats is the engine-reported depth read.
func (l *Log) Stats(ctx context.Context) (telemetrylog.StreamStats, error) {
	if l.isClosed() {
		return telemetrylog.StreamStats{}, telemetrylog.ErrClosed
	}
	stats, _, err := l.loadStats(ctx)
	if err != nil {
		return telemetrylog.StreamStats{}, fmt.Errorf("natslog.Stats: %w", mapTransportErr(err))
	}
	return stats, nil
}

// loadStats reads the stream state plus every durable consumer's backlog. It
// returns the stats and the stream config's Replicas count (for Probe).
func (l *Log) loadStats(ctx context.Context) (telemetrylog.StreamStats, int, error) {
	stream, _, _ := l.identity()
	info, err := stream.Info(ctx)
	if err != nil {
		return telemetrylog.StreamStats{}, 0, err
	}
	stats := telemetrylog.StreamStats{
		Messages:      info.State.Msgs,
		Bytes:         info.State.Bytes,
		FirstSequence: info.State.FirstSeq,
		LastSequence:  info.State.LastSeq,
	}
	lister := stream.ListConsumers(ctx)
	for ci := range lister.Info() {
		stats.Consumers = append(stats.Consumers, telemetrylog.ConsumerStats{
			Name:        ci.Name,
			Pending:     ci.NumPending,
			AckPending:  uint64(ci.NumAckPending),
			Redelivered: uint64(ci.NumRedelivered),
		})
	}
	if err := lister.Err(); err != nil {
		return stats, info.Config.Replicas, err
	}
	return stats, info.Config.Replicas, nil
}

// Probe is the doctor / health round trip; it never returns an error, it
// reports one.
func (l *Log) Probe(ctx context.Context) telemetrylog.Report {
	rep := telemetrylog.Report{Engine: engineName, Configured: true}
	if l.isClosed() {
		rep.Detail = "log closed"
		return rep
	}
	probeCtx, cancel := context.WithTimeout(ctx, l.opts.PublishTimeout)
	defer cancel()
	stats, replicas, err := l.loadStats(probeCtx)
	if err != nil {
		rep.Detail = err.Error()
		return rep
	}
	rep.Healthy = true
	rep.Replicas = replicas
	rep.Stats = stats
	if note := l.provisionNote(); note != "" {
		rep.Detail = note
	}
	return rep
}

// Close drains the connection once and, for the embedded engine, stops the
// in-process server after the drain. It is idempotent.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.nc != nil {
		_ = l.nc.Drain()
	}
	if l.srv != nil {
		l.srv.Shutdown()
		l.srv.WaitForShutdown()
	}
	return nil
}

// provisionNote returns the non-fatal provisioning remark under the lock
// (Reconnect may replace it).
func (l *Log) provisionNote() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.note
}

// isClosed reports whether Close has run.
func (l *Log) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}

// validateRecord is the adapter's own minimal check: an empty Org, Subject,
// DedupID or Payload is ErrInvalidRecord. (The pure telemetrylog.ValidateRecord
// does the full check; the mainline calls it before this adapter, and the
// conformance suite reaches Publish through it.)
func validateRecord(rec telemetrylog.Record) error {
	if rec.Org == "" || rec.Subject == "" || rec.DedupID == "" || len(rec.Payload) == 0 {
		return fmt.Errorf("natslog: empty org/subject/dedup_id/payload: %w", telemetrylog.ErrInvalidRecord)
	}
	return nil
}
