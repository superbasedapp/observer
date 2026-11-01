package termrun

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/termcore"
)

// Kind classifies how a run was started. It is the core
// internal/termcore.Kind (lane MP-L1K, T-715), re-exported here so the
// terminal stack keeps its spelling while core packages name a kind without
// importing the terminals component.
type Kind = termcore.Kind

// The run kinds; see internal/termcore for each kind's meaning.
const (
	KindHandoff = termcore.KindHandoff
	KindFresh   = termcore.KindFresh
	KindAttach  = termcore.KindAttach
	KindResume  = termcore.KindResume
	KindSSH     = termcore.KindSSH
	KindGUI     = termcore.KindGUI
)

// IsRemoteSensitiveKind reports whether a run kind is remote-VIEW sensitive
// (termcore.IsRemoteSensitiveKind, the one shared table).
func IsRemoteSensitiveKind(k Kind) bool { return termcore.IsRemoteSensitiveKind(k) }

// Source identifies where a correlation observation came from. Ordered by
// trustworthiness: an out-of-band signal from the trusted launcher channel is
// authoritative; a marker seen in a transcript/output stream is a strong hint;
// a heuristic (timing/cwd coincidence) is weak.
type Source string

const (
	// SourceOOB — the run's correlation nonce was echoed on the trusted
	// out-of-band launcher channel (internal/termoob), carrying an id the
	// launcher KNEW (it forced the id via the tool's `--session-id`, or
	// deterministically reattached `--resume <id>`). Highest confidence: the
	// child cannot forge this channel (§2.1b) and the id is not a guess.
	SourceOOB Source = "oob"
	// SourceDiscovered — the run's session id was not KNOWN at launch but was
	// inferred by a corroborated discovery pass. It comes from EITHER of two
	// mechanisms, both of which already abstain on any ambiguity:
	//   - the launcher's post-launch artifact scan — codex has no `--session-id`,
	//     so the launcher discovers the new rollout file this run produced and
	//     echoes the id on the SAME trusted, unforgeable out-of-band channel; or
	//   - the daemon's periodic project+time+uniqueness sweep — for a launcher
	//     with no OOB id echo at all (opencode, gemini, …), the daemon links a
	//     live, still-uncorrelated run to a UNIQUE candidate session that agrees
	//     on tool + git root + launch time (unique-or-abstain, held across a
	//     dwell; internal/termsvc via cmd's terminalDiscoverer).
	// Either way the id itself rests on a filesystem/timing/uniqueness inference
	// rather than a forced or launcher-known id, so it sits below a KNOWN-id OOB
	// echo. Still comfortably above MinLinkConfidence, so a discovered link
	// attaches downstream links — until a stronger KNOWN-id OOB observation
	// upgrades it.
	SourceDiscovered Source = "discovered"
	// SourceMarker — a superbased-handoff marker (or equivalent) was observed in
	// the tool's transcript/output identifying the session. Strong but the
	// stream is untrusted, so it is a hint, not proof.
	SourceMarker Source = "marker"
	// SourceHeuristic — the correlation was inferred from timing / working-
	// directory / project coincidence. Weak; never sufficient on its own.
	SourceHeuristic Source = "heuristic"
)

// Valid reports whether s is a known source.
func (s Source) Valid() bool {
	return s == SourceOOB || s == SourceDiscovered || s == SourceMarker || s == SourceHeuristic
}

// sourceConfidence is the table-driven confidence assigned to a single
// observation from each source (CLAUDE.md rule 5 — a data table, not an
// if/else ladder). Values are in [0,1]; a correlation's confidence is the
// strongest observation it carries (see Score).
var sourceConfidence = []struct {
	source     Source
	confidence float64
}{
	{SourceOOB, 0.95},
	// SourceDiscovered sits below a KNOWN-id OOB echo (the id is a heuristic
	// inference, not a forced/deterministic id) yet above MinLinkConfidence
	// (0.50), so a discovered correlation still Linkable()s — a discovered
	// session id attaches downstream links until a stronger KNOWN-id OOB
	// observation upgrades it (the strictly-stronger-evidence MAX-upgrade rule).
	{SourceDiscovered, 0.75},
	{SourceMarker, 0.70},
	{SourceHeuristic, 0.40},
}

// MinLinkConfidence is the threshold at or above which a correlation is
// considered established enough to attach cost/status/decoration/action links
// (plan §2.1a — "links attach only once a correlation is established"). Below
// it a run shows metadata only, honestly uncorrelated.
const MinLinkConfidence = termcore.MinLinkConfidence

// Run is the pure in-memory identity of one terminal launch. It is the model
// the store persists (internal/store/termrun.go) and the application service
// mints at launch. Content-free by construction: the project root and
// correlation nonce are carried as domain-separated hashes only.
type Run struct {
	// RunID is the durable, opaque run identity minted at launch (NewRunID).
	// Distinct from both the PTY handle and any session id.
	RunID string
	// Tool is the target tool (e.g. "claude-code").
	Tool string
	// Kind is handoff or fresh.
	Kind Kind
	// SourceSessionID is the handoff source session (kind=handoff only). It is
	// NEVER a correlation target — the two are deliberately distinct (§2.1a).
	SourceSessionID string
	// ProjectRootHash is HashProjectRoot(root); the raw path is never stored.
	ProjectRootHash string
	// CorrelationTokenHash is HashCorrelationToken(nonce); the raw nonce —
	// passed to the child out of band so it can echo it back — is never stored.
	CorrelationTokenHash string
	// LaunchedAt is when the run started (UTC).
	LaunchedAt time.Time
	// EndedAt is when the run's process exited; nil while running.
	EndedAt *time.Time
	// ExitCode is the run's exit code; nil while running.
	ExitCode *int
	// PID is the DETACHED child's process id, known only for KindGUI and only
	// AFTER the spawn returns (migration 095). A PTY run deliberately leaves it
	// nil: the PTY handle is that run's identity and the child pid is the
	// termsession manager's business, not the run row's. nil is the honest
	// "no pid recorded", never a zero-value 0.
	PID *int
	// WrapApplied reports whether the GUI launch's routing wrap actually
	// reached the child (internal/guilaunch). KindGUI only; false is the honest
	// zero for every other kind, which carries no wrap concept at all.
	WrapApplied bool
	// WrapNote is the grounded reason a wrap did not apply, or the caveat that
	// qualifies one that did (a cold-start-only app). KindGUI only.
	WrapNote string
	// Isolation is the run's G19 isolation evidence (sandbox plan v2 section
	// 8.4, migration 179): what the launch actually built and the capture
	// level computed for it. The zero value is "not recorded".
	Isolation Isolation
}

// Isolation is the per-run isolation evidence, as closed-vocabulary strings
// (internal/sandboxvocab owns the spellings; this package stays a leaf).
// Every empty field means "not recorded".
type Isolation struct {
	// Class is the effective isolation class built ("none" for a launch
	// that was not sandboxed).
	Class string
	// Stack is the backend ids of the layers, outermost first.
	Stack        []string
	EgressTier   string
	CaptureLevel string
	// CaptureRule is the capture table row that decided CaptureLevel.
	CaptureRule        string
	CaptureOrigin      string
	CaptureDegraded    bool
	NativeSandboxState string
	Verification       string
	KeyCustody         string
}

// Correlation is one scored link from a run to an observed agent session.
type Correlation struct {
	RunID      string
	SessionID  string
	Confidence float64
	Source     Source
	ObservedAt time.Time
}

// Linkable reports whether this correlation is confident enough to attach
// downstream links (>= MinLinkConfidence).
func (c Correlation) Linkable() bool { return c.Confidence >= MinLinkConfidence }

// Observation is a single evidence point that a run corresponds to a session,
// as seen by one source. Multiple observations (possibly from different
// sources) are folded into a single scored Correlation by Score.
type Observation struct {
	Source Source
	At     time.Time
}

// Score folds a run/session pair's observations into one Correlation. The
// confidence is the strongest single source seen (an OOB echo dominates a
// heuristic coincidence); the winning source and its timestamp are recorded so
// the store keeps the best-grounded provenance. Returns ok=false when there are
// no valid observations. This is the ONE place the source→confidence table is
// consulted, so the policy lives in exactly one spot.
func Score(runID, sessionID string, obs []Observation) (Correlation, bool) {
	best := Correlation{RunID: runID, SessionID: sessionID, Confidence: -1}
	for _, o := range obs {
		if !o.Source.Valid() {
			continue
		}
		conf := confidenceFor(o.Source)
		if conf > best.Confidence {
			best.Confidence = conf
			best.Source = o.Source
			best.ObservedAt = o.At
		}
	}
	if best.Confidence < 0 {
		return Correlation{}, false
	}
	return best, true
}

// confidenceFor returns the base confidence for a source via the data table.
// An unknown source scores 0 (never trusted).
func confidenceFor(s Source) float64 {
	for _, row := range sourceConfidence {
		if row.source == s {
			return row.confidence
		}
	}
	return 0
}

// idBytes is the entropy of a run id / correlation nonce (32 bytes → 256
// bits, base64url-encoded to a 43-char opaque string). Both must be
// unguessable: the run id keys durable state and the correlation nonce is the
// unforgeable value the child echoes on the OOB channel.
const idBytes = 32

// NewRunID mints an opaque base64url run identity from crypto/rand. It is
// distinct from a termsession PTY handle and from any agent session id.
func NewRunID() (string, error) { return randID("termrun: read random bytes") }

// NewCorrelationToken mints the opaque correlation nonce the launcher receives
// (out of band) and echoes back on the trusted OOB channel so the daemon can
// correlate the run to the session it produced at SourceOOB confidence.
func NewCorrelationToken() (string, error) {
	return randID("termrun: read correlation nonce bytes")
}

func randID(errCtx string) (string, error) {
	b := make([]byte, idBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("%s: %w", errCtx, err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Domain-separation prefixes keep the two hash spaces disjoint so a
// project-root hash can never collide with — or be linked to — a
// correlation-nonce hash (the M7-class linkability note, plan §7).
const (
	domainProjectRoot = "termrun:project_root:v1:"
	domainCorrNonce   = "termrun:corr_nonce:v1:"
)

// HashProjectRoot returns the domain-separated SHA-256 hash of a project root
// path as lowercase hex, or "" for an empty path. The raw path is never stored.
func HashProjectRoot(root string) string {
	if root == "" {
		return ""
	}
	return domainHash(domainProjectRoot, root)
}

// HashCorrelationToken returns the domain-separated SHA-256 hash of a
// correlation nonce as lowercase hex, or "" for an empty input. The raw nonce
// is never stored; the daemon hashes an OOB-echoed nonce the same way to match
// it against a run.
func HashCorrelationToken(nonce string) string {
	if nonce == "" {
		return ""
	}
	return domainHash(domainCorrNonce, nonce)
}

func domainHash(domain, s string) string {
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}
