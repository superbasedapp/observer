// Package natslog is the NATS JetStream adapter for the pure
// internal/telemetrylog contract (plan of record
// docs/plans/stateless-collectors-durable-log-plan-2026-09-08.md, decision D1;
// ADR-0006). It is one of the interchangeable log engines the stateless
// collectors publish into and the durable consumers pull from; it passes the
// same logtest.RunConformance suite every adapter must.
//
// Two constructors:
//
//   - Connect wires the adapter to an EXTERNAL nats-server (the HA profile: a
//     3-node cluster URL, R>=3, file store on local NVMe).
//   - Embedded starts an IN-PROCESS nats-server with JetStream on a local
//     directory (the single-node `observer-org --role all` profile, R=1). The
//     directory MUST be a LOCAL disk — never Azure Files / NAS (plan O3); the
//     adapter cannot detect that, so the doctor prints the reminder.
//
// # JetStream concept -> telemetrylog concept
//
//	JetStream                              telemetrylog
//	-----------------------------------    ---------------------------------
//	stream (Limits, File, Discard:New,     the durable log
//	  MaxAge 0 = no age limit)
//	stream MaxBytes / MaxMsgs (Discard:New) the ErrFull disk safety valve
//	stream MaxMsgSize                       the ErrTooLarge per-record cap
//	stream Duplicates window + Nats-Msg-Id  Record.DedupID drop window
//	subject sbo.push.<org> / sbo.otlp.*     Record.Subject
//	durable pull consumer                   Consumer (Subscribe by Name)
//	consumer FilterSubjects                 ConsumerSpec.FilterSubjects
//	msg.Metadata().Sequence.Stream          Delivered.Sequence
//	msg.Metadata().NumDelivered             Delivered.Attempt (1-based)
//	msg.Ack / Nak(WithDelay) / Term(Reason) Delivered.Ack / Nak / Term
//	PubAck.Duplicate                        PubResult.Duplicate
//	stream.Info().State                     StreamStats
//	consumer NumPending/NumAckPending/...   ConsumerStats
//	min consumer AckFloor + stream Purge    Trimmer.TrimApplied
//
// # Retention (T-823)
//
// A record leaves the stream ONLY when every durable consumer has acked it:
// TrimApplied purges below the lowest ack floor and holds entirely while a
// required durable is missing. There is no age limit, and the byte cap
// refuses new records (ErrFull -> 503 + Retry-After) instead of evicting
// unacked ones, so a slow or stopped consumer backpressures the nodes, which
// keep their rows and retry, rather than losing data. See streamConfig for
// why interest retention was rejected.
//
// # Error mapping
//
// Publish maps its engine's failures onto the contract's sentinels:
//
//   - ErrTooLarge  <- nats.ErrMaxPayload (connection payload cap) or a
//     JetStream API error 10054 ("message size exceeds maximum allowed", the
//     stream MaxMsgSize) or jetstream.ErrMaxBytesExceeded.
//   - ErrFull      <- a JetStream API error 10077 ("maximum messages exceeded"
//     / "maximum bytes exceeded", the Discard:New capacity response) or 10002
//     ("resource limits exceeded for account").
//   - ErrUnavailable <- no-responders, connection-closed, connection
//     reconnecting, reconnect buffer exceeded, timeout, no-servers,
//     no-stream-response, or a context deadline/cancel.
//
// # Broker outages (T-883)
//
// The connection reconnects indefinitely and, should the client library close
// it anyway, the Log rebuilds it, so an outage of any length heals by itself
// once the broker answers again: no process restart. The stream identity that
// Subscribe fences against is never adopted by a reconnect or a rebuild; only
// Reconnect (the ErrReconnectRequired path) does that. See conn.go.
//   - ErrClosed after Close.
//
// The package imports only internal/telemetrylog and the NATS client/server
// libraries; it never imports internal/orgserver/config (config -> natslog is
// the legal direction), database/sql, net/http or fsnotify.
package natslog
