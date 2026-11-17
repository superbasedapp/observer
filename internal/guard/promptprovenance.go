package guard

import (
	"crypto/sha256"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// promptprovenance.go: the proxy prompt lane judges only what the
// developer typed.
//
// The prompt gate (R-172 secrets, R-190 PII on KindUserPrompt) asks the developer to
// re-enter a prompt that carries a secret or PII value, because the
// developer is the one who typed it. promptturn already keeps tool_result
// blocks out of the prompt text, but that is not enough: an agent's side
// request (Claude Code's auto-mode safety classifier, a summarizer, a
// title call) re-sends the conversation, tool output included, as the
// TEXT of a fresh one-message user turn. On the wire that is a user
// prompt. Live 2026-11-15 (security-assessment pen test under enforce,
// session 9dc8bc8b): the fixture app's fake bearer token, already in the
// conversation from the run's probes, was re-sent as user text by the
// agent's classifier requests (one-message sonnet-5 calls between the
// main model's turns); the gate blocked both ("bearer_token in the prompt
// text, outcome=blocked", api_turns http_status 400) and Claude Code
// reported its safety classifier as unavailable. The unsandboxed
// threat-model run before it had 36 such blocks (secret_assignment x3
// growing to x61 as the re-sent transcript grew).
//
// The fix reads provenance, not tool identity: every request's newest
// exchange (promptturn.Turn.Generated: the newest model turn and the
// trailing tool results, each of which is newest in exactly one request)
// and every response's tool calls (InspectProxyResponse) are scanned with
// the prompt detectors, and the fingerprint of each value found is kept
// for the session. A prompt finding whose value the session's model or
// tools already produced is not something the developer typed, so the
// gate drops it. A value the developer types that no tool or model output
// carried still blocks, exactly as before. The egress scan is untouched:
// under enforce it still masks the value on the way out (R-172 mask).
//
// Only fingerprints are kept (sha256 of the normalized value core), never
// a value; the store is in memory, bounded, and lost on restart (a side
// request after a restart re-blocks until the conversation's next tool
// results are noted, the pre-fix behaviour).

const (
	// maxGeneratedSessions bounds the sessions tracked; the
	// least-recently-touched one is dropped first.
	maxGeneratedSessions = 256
	// maxGeneratedKeysPerSession bounds one session's fingerprints; a
	// full set is reset, which errs toward judging (the pre-fix gate).
	maxGeneratedKeysPerSession = 4096
	// minGeneratedCore is the shortest value core matched on its own;
	// a shorter core falls back to the whole value.
	minGeneratedCore = 8
	// generatedValueStops are the bytes that end a value's core: quoting
	// and escaping a re-rendered transcript adds around a value (a JSON
	// `\n` after `password=...`, a closing quote), and structural
	// punctuation. A detector's greedy value group can swallow them on
	// one side of the round trip and not on the other.
	generatedValueStops = "\\\"'`,;()[]{}<>"
)

// generatedValues is the per-session fingerprint set. Its zero value is
// ready to use; it owns its own lock (separate from proxyMu: noting runs
// on every proxied request and must not contend with record dedup).
type generatedValues struct {
	mu       sync.Mutex
	sessions map[string]*generatedSession
}

type generatedSession struct {
	keys      map[[32]byte]struct{}
	lastTouch time.Time
}

// generatedValueKey is the fingerprint of one detector match: the value's
// core (leading quoting trimmed, cut at the first stop byte; the whole
// value when the core is too short to stand alone), normalized like the
// reconsider-once span hash (separators stripped; PII case-folded,
// secrets case-sensitive), under a domain tag.
func generatedValueKey(class, value string) [32]byte {
	core := strings.TrimLeft(value, generatedValueStops)
	if i := strings.IndexAny(core, generatedValueStops); i >= 0 {
		core = core[:i]
	}
	if len(core) < minGeneratedCore {
		core = value
	}
	normalized := strings.NewReplacer("-", "", " ", "", ".", "").Replace(core)
	if class == scrub.ClassPII || class == "" {
		normalized = strings.ToLower(normalized)
	}
	return sha256.Sum256([]byte("sbo-prompt-provenance-v1\x1e" + normalized))
}

// noteGenerated scans text (content the model or a tool produced) with
// the prompt detectors and records each value's fingerprint for the
// session. No session id, or nothing found, records nothing.
func (g *Guard) noteGenerated(sessionID, text string, now time.Time) {
	if sessionID == "" || strings.TrimSpace(text) == "" {
		return
	}
	findings, _ := scrub.DetectPromptFindings(text, g.promptDetectOptions())
	if len(findings) == 0 {
		return
	}
	keys := make([][32]byte, 0, len(findings))
	for _, f := range findings {
		keys = append(keys, generatedValueKey(f.Class, f.Value))
	}
	g.generated.add(sessionID, keys, now)
}

// generatedSkip is the buildPromptFindings filter for one session: it
// drops a finding whose value the session's model or tools produced. nil
// (no filter) without a session id.
func (g *Guard) generatedSkip(sessionID string) func(class, value string) bool {
	if sessionID == "" {
		return nil
	}
	return func(class, value string) bool {
		return g.generated.has(sessionID, generatedValueKey(class, value))
	}
}

func (v *generatedValues) add(sessionID string, keys [][32]byte, now time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.sessions == nil {
		v.sessions = make(map[string]*generatedSession)
	}
	st := v.sessions[sessionID]
	if st == nil {
		if len(v.sessions) >= maxGeneratedSessions {
			v.evictOldestLocked()
		}
		st = &generatedSession{keys: make(map[[32]byte]struct{})}
		v.sessions[sessionID] = st
	}
	st.lastTouch = now
	for _, k := range keys {
		if _, ok := st.keys[k]; ok {
			continue
		}
		if len(st.keys) >= maxGeneratedKeysPerSession {
			st.keys = make(map[[32]byte]struct{})
		}
		st.keys[k] = struct{}{}
	}
}

func (v *generatedValues) has(sessionID string, key [32]byte) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	st := v.sessions[sessionID]
	if st == nil {
		return false
	}
	_, ok := st.keys[key]
	return ok
}

// evictOldestLocked drops the least-recently-touched session. Caller
// holds mu.
func (v *generatedValues) evictOldestLocked() {
	var oldestID string
	var oldest time.Time
	first := true
	for id, st := range v.sessions {
		if first || st.lastTouch.Before(oldest) {
			oldestID, oldest, first = id, st.lastTouch, false
		}
	}
	if oldestID != "" {
		delete(v.sessions, oldestID)
	}
}
