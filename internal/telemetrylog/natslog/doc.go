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
//	stream (Limits, File, Discard:New)     the durable log
//	stream MaxMsgs (Discard:New)           the ErrFull capacity cap
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
//   - ErrUnavailable <- no-responders, connection-closed, timeout, no-servers,
//     no-stream-response, or a context deadline/cancel.
//   - ErrClosed after Close.
//
// The package imports only internal/telemetrylog and the NATS client/server
// libraries; it never imports internal/orgserver/config (config -> natslog is
// the legal direction), database/sql, net/http or fsnotify.
package natslog
