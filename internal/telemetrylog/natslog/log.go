package natslog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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
	nc              *nats.Conn
	js              jetstream.JetStream
	stream          jetstream.Stream
	srv             embeddedServer // non-nil only for Embedded
	opts            Options
	streamCreated   time.Time
	orderGeneration string

	mu     sync.Mutex
	closed bool
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
	current, err := l.stream.Info(subCtx)
	if err != nil {
		return nil, fmt.Errorf("natslog.Subscribe: stream identity: %w", mapTransportErr(err))
	}
	if !current.Created.Equal(l.streamCreated) || streamOrderGeneration(current) != l.orderGeneration {
		return nil, fmt.Errorf("natslog.Subscribe: stream generation changed; reconnect before subscribing")
	}
	cons, err := l.js.CreateOrUpdateConsumer(subCtx, l.opts.Stream, cfg)
	if err != nil {
		return nil, fmt.Errorf("natslog.Subscribe: %w", mapTransportErr(err))
	}
	ci := cons.CachedInfo()
	if ci == nil || ci.Created.IsZero() || ci.Stream != l.opts.Stream || (spec.MaxAckPending > 0 && ci.Config.MaxAckPending != spec.MaxAckPending) {
		return nil, fmt.Errorf("natslog.Subscribe: durable identity/credit read-back differs")
	}
	return &natsConsumer{
		cons: cons, streamName: l.opts.Stream, streamCreated: l.streamCreated,
		consumerCreated: ci.Created, orderGeneration: l.orderGeneration, maxAckPending: spec.MaxAckPending,
	}, nil
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
	info, err := l.stream.Info(ctx)
	if err != nil {
		return telemetrylog.StreamStats{}, 0, err
	}
	stats := telemetrylog.StreamStats{
		Messages:      info.State.Msgs,
		Bytes:         info.State.Bytes,
		FirstSequence: info.State.FirstSeq,
		LastSequence:  info.State.LastSeq,
	}
	lister := l.stream.ListConsumers(ctx)
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
	if l.note != "" {
		rep.Detail = l.note
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
