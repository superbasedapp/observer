package processobs

import (
	"context"
	"errors"
	"strings"
)

// SinkErrorClass says what the Observer should DO with a batch the run sink
// refused. It is deliberately a three-value answer, not a bool: "this will
// never work" and "I cannot tell" call for different handling, and collapsing
// them is what turned a momentary `database is locked` into permanent capture
// loss (the 2026-08-26 process-capture drop anomaly, task 9c).
type SinkErrorClass string

const (
	// SinkErrorTransient — the same batch is expected to succeed on a later
	// attempt with no change to the data: lock contention (SQLITE_BUSY /
	// SQLITE_LOCKED), a per-call deadline, a momentary I/O timeout. RETAIN.
	SinkErrorTransient SinkErrorClass = "transient"
	// SinkErrorPermanent — no later attempt can succeed because the batch or
	// the schema is wrong (a constraint violation, a missing table/column, a
	// read-only database). Retaining it would only delay the loss AND hold
	// the retention slot against rows that could still land. DROP, counted.
	SinkErrorPermanent SinkErrorClass = "permanent"
	// SinkErrorUnknown — unclassified. Handled exactly like transient
	// (retain, bounded by Options.MaxRetainedRuns), because the two mistakes
	// are not symmetric: wrongly retaining a doomed batch costs a bounded
	// amount of memory and a counted drop when the cap releases it, while
	// wrongly dropping a recoverable batch loses process history that cannot
	// be reconstructed. Erring toward retention is the honest default.
	SinkErrorUnknown SinkErrorClass = "unknown"
)

// Retain reports whether a batch that failed with this class should be held
// for the next flush tick. It is the SINGLE owner of the retain decision — no
// caller re-derives it by listing classes (CLAUDE.md rule 4), which is what
// keeps "unknown behaves as transient" a one-line fact instead of a rule
// duplicated at every call site.
func (c SinkErrorClass) Retain() bool { return c != SinkErrorPermanent }

// SinkErrorClassifier is an OPTIONAL Sink capability. A sink whose driver
// exposes STRUCTURED error codes implements it and answers exactly; every
// other sink simply does not, and the Observer falls back to the shared
// string table below.
//
// It is a capability, not a sink-type check (CLAUDE.md rule 3): this package
// performs no I/O and must not learn what SQLite is, so the only honest way
// to reach a driver's real error code is to let the sink that owns the driver
// answer for itself.
type SinkErrorClassifier interface {
	// ClassifySinkError classifies a non-nil error returned by this sink.
	// Returning SinkErrorUnknown defers to the shared table.
	ClassifySinkError(err error) SinkErrorClass
}

// sinkErrorRule is one row of the classification table. Ordered, walked
// top-down, first match wins (CLAUDE.md rule 5) — so the narrow permanent
// signatures are listed before any broader transient one could shadow them.
type sinkErrorRule struct {
	// Needle is matched case-insensitively as a SUBSTRING of the error text,
	// so a wrapped error ("store.PersistRuns: exec[3]: …") still classifies.
	Needle string
	Class  SinkErrorClass
	// Why records the evidence for the row. A rule nobody can justify is a
	// guess, and a guess that says "permanent" silently destroys data.
	Why string
}

// sinkErrorRules is the fallback classification table, used when the sink
// declares no SinkErrorClassifier or its classifier answers unknown.
//
// THE PERMANENT SET IS DELIBERATELY SMALL. Every row in it converts a failure
// into immediate, irreversible data loss, so a signature earns a place here
// only when no retry could possibly change the outcome. Everything absent
// classifies as unknown and is retained — including the genuinely ambiguous
// ones ("disk I/O error", "database or disk is full"), which look permanent
// but routinely clear on their own (a DrvFs hiccup, a log rotation freeing
// space) and must not be assumed fatal.
var sinkErrorRules = []sinkErrorRule{
	// ---- permanent: the batch or the schema is wrong ------------------
	{Needle: "constraint failed", Class: SinkErrorPermanent, Why: "SQLITE_CONSTRAINT — the row violates the schema; identical retries fail identically"},
	{Needle: "no such table", Class: SinkErrorPermanent, Why: "SQLITE_ERROR — a migration is missing; no retry creates the table"},
	{Needle: "no such column", Class: SinkErrorPermanent, Why: "SQLITE_ERROR — statement/schema drift; no retry reconciles it"},
	{Needle: "readonly database", Class: SinkErrorPermanent, Why: "SQLITE_READONLY — the handle cannot write at all; retrying writes nothing"},
	{Needle: "datatype mismatch", Class: SinkErrorPermanent, Why: "SQLITE_MISMATCH — a bound value cannot be stored in that column"},
	{Needle: "sql: statement is closed", Class: SinkErrorPermanent, Why: "the prepared statement is gone; this batch can never execute"},

	// ---- transient: the same batch is expected to succeed later --------
	{Needle: "database is locked", Class: SinkErrorTransient, Why: "SQLITE_BUSY — the write lock is held by another connection (observed on this box's browser-health drops, 2026-08-26)"},
	{Needle: "database table is locked", Class: SinkErrorTransient, Why: "SQLITE_LOCKED — table-level contention within the same connection pool"},
	{Needle: "sqlite_busy", Class: SinkErrorTransient, Why: "the symbolic code, for drivers that render it instead of the message"},
	{Needle: "busy_timeout", Class: SinkErrorTransient, Why: "the busy handler gave up at its deadline; a later attempt has a fresh budget"},
	{Needle: "context deadline exceeded", Class: SinkErrorTransient, Why: "a per-call deadline, not a data fault"},
	{Needle: "i/o timeout", Class: SinkErrorTransient, Why: "a stalled filesystem/network mount that later attempts routinely clear"},
}

// ClassifySinkError classifies a sink failure using the shared table. It is
// exported so a sink's own SinkErrorClassifier can consult it AFTER its
// structured-code check, keeping one table for the string half rather than
// two that drift (CLAUDE.md rule 4).
//
// A nil error classifies as unknown: callers only reach this on a failure, and
// inventing a class for "no error" would be a fact the input does not carry.
func ClassifySinkError(err error) SinkErrorClass {
	if err == nil {
		return SinkErrorUnknown
	}
	// Structural checks first — these carry an exact answer that no substring
	// match can improve on, and they fire even when the error text was
	// reworded upstream.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return SinkErrorTransient
	}
	msg := strings.ToLower(err.Error())
	for _, rule := range sinkErrorRules {
		if strings.Contains(msg, rule.Needle) {
			return rule.Class
		}
	}
	return SinkErrorUnknown
}

// classifySinkError resolves the class for THIS observer's sink: the sink's
// own structured classifier first (exact), the shared table second.
func (o *Observer) classifySinkError(err error) SinkErrorClass {
	if err == nil {
		return SinkErrorUnknown
	}
	if c, ok := o.sink.(SinkErrorClassifier); ok {
		if class := c.ClassifySinkError(err); class != SinkErrorUnknown {
			return class
		}
	}
	return ClassifySinkError(err)
}
