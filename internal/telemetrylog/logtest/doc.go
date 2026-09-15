// Package logtest is the shared conformance suite every telemetrylog.Log adapter
// must pass (the internal/waltest precedent transposed onto the durable-log
// contract). An adapter's own test calls RunConformance with a factory that
// builds a fresh Log from a Config, and the suite drives the contract:
// publish-returns-a-sequence, duplicate-inside-the-window is an accepted no-op,
// ErrFull at capacity, ErrTooLarge, ordered delivery, durable reattach by name,
// Ack/Nak/Term, AckWait redelivery, the MaxDeliver park, wildcard subject
// filtering, attrs round-trip, backlog stats and a healthy probe.
//
// Because a real broker (natslog's embedded NATS server) cannot take an injected
// clock, the suite uses REAL time with deliberately small durations (AckWait
// 500ms, DuplicateWindow 2s, a MaxDeliver of 3) and never sleeps-then-asserts: a
// positive redelivery is awaited through the blocking Fetch(wait) the contract
// already provides, a state condition through the bounded waitFor poll helper,
// and a negative (no redelivery) through a bounded Fetch that must come back
// empty. Every sub-test gets a fresh Log from the factory and closes it via
// t.Cleanup.
//
// Scenarios a broker only APPROXIMATES, called out so an adapter author is not
// surprised:
//   - De-duplication is TIME-WINDOWED, not exact-once forever. The suite pins
//     "duplicate inside the window is a no-op" and (memlog-only, with an injected
//     clock) "the same id after the window is a new record"; a broker's window is
//     wall-clock and best-effort, and natural-key idempotency downstream is the
//     real guarantee.
//   - Sequence numbers are per stream and monotonic, but their absolute values
//     are the engine's; the suite asserts they are non-zero and strictly
//     increasing, never a specific value.
//   - AckWait / Nak redelivery timing is asserted with a generous upper bound
//     (never an exact instant) because a broker redelivers on its own schedule.
package logtest
