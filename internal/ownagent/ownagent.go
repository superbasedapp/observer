package ownagent

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// Request contract. AgentHeader names the developer's own agent; the
// X-Superbased- prefix is already stripped before any upstream forward
// (internal/proxy isHostedIdentityHeader). SessionHeader is the existing
// proxy session header, also never forwarded.
const (
	AgentHeader   = "X-Superbased-Agent"
	SessionHeader = "X-Session-Id"
)

// Bounds on the two header values. A value past the raw bound, or one with a
// control character or invalid UTF-8, is malformed and ignored.
const (
	// MaxNameLen is the longest normalized agent name kept (bytes). It keeps
	// "agent:<name>" inside the dashboard's surface_host filter bound.
	MaxNameLen = 48
	// maxRawNameLen bounds the raw header before normalization.
	maxRawNameLen = 256
	// MaxSessionIDLen bounds an explicit X-Session-Id value.
	MaxSessionIDLen = 128
)

// DefaultIdleGap is how long an agent's implicit session (no X-Session-Id)
// stays open between requests. A request after a longer pause starts a new
// session.
const DefaultIdleGap = 30 * time.Minute

// sessionIDPrefix marks every capture session this package mints, so an own
// agent's session can never collide with (and append turns to) a session a
// coding tool owns, even when the developer reuses a coding tool's id.
const sessionIDPrefix = "ca-"

// Status is the outcome of reading one header value.
type Status int

const (
	// StatusAbsent: the header is missing or blank.
	StatusAbsent Status = iota
	// StatusOK: the value normalized cleanly.
	StatusOK
	// StatusMalformed: the value is present but unusable (too long, a
	// control character, invalid UTF-8, or nothing left after
	// normalization). The request then behaves as if it were absent.
	StatusMalformed
)

// String names the status for logs and test failures.
func (s Status) String() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusMalformed:
		return "malformed"
	default:
		return "absent"
	}
}

// NormalizeName turns a raw X-Superbased-Agent value into the stored agent
// token: lowercase, every run of characters outside [a-z0-9._-] collapsed to
// one "-", leading and trailing separators trimmed, capped at MaxNameLen.
// "My Bot!" becomes "my-bot".
func NormalizeName(raw string) (string, Status) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", StatusAbsent
	}
	if len(raw) > maxRawNameLen || !utf8.ValidString(raw) || hasControl(raw) {
		return "", StatusMalformed
	}
	var b strings.Builder
	sep := false
	for _, r := range strings.ToLower(raw) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			if sep && b.Len() > 0 {
				b.WriteByte('-')
			}
			sep = false
			b.WriteRune(r)
			continue
		}
		sep = true
	}
	name := b.String()
	if len(name) > MaxNameLen {
		name = name[:MaxNameLen]
	}
	name = strings.Trim(name, "-._")
	if name == "" {
		return "", StatusMalformed
	}
	return name, StatusOK
}

// NormalizeSessionID validates a raw X-Session-Id value. The value is kept
// as sent (case and punctuation included) apart from surrounding space.
func NormalizeSessionID(raw string) (string, Status) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", StatusAbsent
	}
	if len(raw) > MaxSessionIDLen || !utf8.ValidString(raw) || hasControl(raw) {
		return "", StatusMalformed
	}
	return raw, StatusOK
}

func hasControl(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// SessionID is the capture session id for an explicit X-Session-Id: stable
// for one (agent, session) pair, distinct across agents, and never equal to
// a coding tool's own id.
func SessionID(agent, explicit string) string {
	return sessionIDPrefix + shortHash(agent+"\x00"+explicit, 24)
}

// implicitSessionID mints a fresh id for an agent's implicit session.
func implicitSessionID(agent string, now time.Time) string {
	return sessionIDPrefix + shortHash(agent+"\x00@"+now.UTC().Format(time.RFC3339Nano), 24)
}

func shortHash(s string, n int) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:n]
}

// Claim is the normalized identity of one own-agent request.
type Claim struct {
	// Agent is the normalized agent name token.
	Agent string
	// SessionID is the capture session the request's turn lands on.
	SessionID string
	// Explicit reports whether the session came from X-Session-Id (true) or
	// from the agent's implicit idle-gap session (false).
	Explicit bool
	// SessionStatus is how the X-Session-Id value read (absent, ok or
	// malformed); a malformed value falls back to the implicit session.
	SessionStatus Status
}

// maxTracked bounds the Tracker's memory. Each table evicts its least
// recently used entry past it, so an agent that keeps sending is never
// dropped for a stale one; an evicted implicit session restarts on that
// agent's next request, and an evicted ensured mark costs one repeat of the
// idempotent session-row check.
const maxTracked = 4096

// Tracker resolves claims and remembers each agent's implicit session. It is
// safe for concurrent use. The zero value is not usable; call NewTracker.
type Tracker struct {
	idle time.Duration

	mu       sync.Mutex
	implicit *lru[implicitEntry]
	// ensured holds the sessions whose row the caller has CONFIRMED written
	// (MarkRow / MarkEnsured); the value says whether that row already
	// carries a model. Resolving a claim never adds to it, so a request that
	// fails before its row is made leaves the next request to make it.
	ensured *lru[bool]
}

type implicitEntry struct {
	id   string
	last time.Time
}

// NewTracker returns a Tracker whose implicit sessions close after idle
// without a request (DefaultIdleGap when idle <= 0).
func NewTracker(idle time.Duration) *Tracker {
	if idle <= 0 {
		idle = DefaultIdleGap
	}
	return &Tracker{
		idle:     idle,
		implicit: newLRU[implicitEntry](maxTracked),
		ensured:  newLRU[bool](maxTracked),
	}
}

// Resolve reads the two raw header values at time now. It returns the claim
// and the status of the agent header: only StatusOK yields a usable claim;
// absent and malformed both mean "not an own-agent request", so headerless
// traffic is untouched.
func (t *Tracker) Resolve(agentRaw, sessionRaw string, now time.Time) (Claim, Status) {
	agent, st := NormalizeName(agentRaw)
	if st != StatusOK {
		return Claim{}, st
	}
	sid, sst := NormalizeSessionID(sessionRaw)
	c := Claim{Agent: agent, SessionStatus: sst}

	t.mu.Lock()
	defer t.mu.Unlock()
	if sst == StatusOK {
		c.SessionID = SessionID(agent, sid)
		c.Explicit = true
	} else {
		e, ok := t.implicit.Get(agent)
		if !ok || now.Sub(e.last) > t.idle || now.Before(e.last.Add(-t.idle)) {
			e = implicitEntry{id: implicitSessionID(agent, now)}
		}
		e.last = now
		t.implicit.Put(agent, e)
		c.SessionID = e.id
	}
	return c, StatusOK
}

// Ensured reports whether the caller has confirmed sessionID's row is
// written (MarkEnsured). A daemon restart forgets, which only costs one
// idempotent row check.
func (t *Tracker) Ensured(sessionID string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.ensured.Get(sessionID)
	return ok
}

// MarkEnsured records that sessionID's row is written, with no model yet.
// Call it only after the write succeeded.
func (t *Tracker) MarkEnsured(sessionID string) { t.MarkRow(sessionID, false) }

// NeedsRow reports whether a turn of sessionID must go through the session
// row write: the row is not confirmed yet, or it has no model and this turn
// carries one (a session whose first turn had no model takes the model of
// the first later turn that has one).
func (t *Tracker) NeedsRow(sessionID string, turnHasModel bool) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	modelKnown, ok := t.ensured.Get(sessionID)
	return !ok || (turnHasModel && !modelKnown)
}

// MarkRow records a confirmed row write for sessionID; withModel says the
// write carried a model. A model once known stays known. Call it only after
// the write succeeded.
func (t *Tracker) MarkRow(sessionID string, withModel bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	known, _ := t.ensured.Get(sessionID)
	t.ensured.Put(sessionID, known || withModel)
}
