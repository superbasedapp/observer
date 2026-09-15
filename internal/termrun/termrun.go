package termrun

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"
)

// Kind classifies how a run was started. The two kinds are structurally
// distinct so a handoff-continue is never confused with a fresh agent launch.
type Kind string

const (
	// KindHandoff — a "continue this session" launch (--continue-from). It
	// carries a source session id (the session continued FROM), which is NOT a
	// correlation target.
	KindHandoff Kind = "handoff"
	// KindFresh — a fresh agent launch with no source session. It has no
	// session id at all until the tool creates one after startup.
	KindFresh Kind = "fresh"
	// KindAttach — a daemon-owned PTY spawned on behalf of the operator's own
	// terminal via the attach socket (session-attach design §3, Phase 1). Unlike
	// KindFresh, the spawn is requested by the CLI attach client over the
	// owner-only AF_UNIX socket rather than by a dashboard POST; it is recorded
	// and feed-published like every other run so an attach session is a
	// first-class run identity.
	KindAttach Kind = "attach"
	// KindResume — a NATIVE resume launch (session-attach design §3, Phase 3):
	// the dashboard spawns a daemon-owned PTY running the tool's own resume
	// mechanism (claude `--resume <id>`, codex `resume <id>`) so a CLOSED
	// session reopens its ACTUAL prior conversation — NOT a distilled fork
	// (that is KindHandoff). Like KindHandoff it carries the resumed session as
	// SourceSessionID (the session reopened FROM), which is NOT a correlation
	// target. Unlike the CLI attach bypass it is a dashboard-initiated launch,
	// so termsvc gates it through the SAME fresh-launch Policy allow-lists.
	KindResume Kind = "resume"
	// KindSSH — an outbound SSH remote-system shell
	// (docs/plans/ssh-remote-profiles-plan-2026-08-27.md). The daemon spawns
	// the OpenSSH client inside its own PTY harness, so the bytes on the
	// terminal come from a shell on ANOTHER machine. It has no source session,
	// no correlated target session (the trusted out-of-band control channel is
	// an inherited fd, and file descriptors do not cross an SSH connection),
	// and no local project root — all three record as honest zero values
	// rather than as guesses.
	//
	// Distinct from the INBOUND [remote]/Tailscale feature, which exposes this
	// node's own dashboard to a paired device. Same word, opposite direction.
	KindSSH Kind = "ssh"
	// KindGUI — a DETACHED IDE / desktop-app launch
	// (docs/plans/ide-desktop-launch-plan-2026-09-03.md). The daemon spawns the
	// app outside any PTY (Windows DETACHED_PROCESS, Unix setsid, darwin
	// `open -a`) so it outlives the daemon and owns its own window; the run row
	// exists to record WHAT was launched, with which pid, and whether the
	// routing wrap actually reached it.
	//
	// Structurally unlike every other kind: there is NO PTY handle, so a GUI run
	// never enters the handle maps, never appears in a terminal Snapshot, and is
	// never joinable ("Jump in" is a PTY affordance). It has no source session
	// and no correlation nonce — the child is a GUI, not an `observer <verb>`
	// launcher, so there is no trusted out-of-band channel to echo one on.
	//
	// NOT remote-view sensitive: the remote-sensitivity table gates who may READ
	// a daemon-owned PTY's bytes, and a GUI run has no bytes to read.
	KindGUI Kind = "gui"
)

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool {
	return k == KindHandoff || k == KindFresh || k == KindAttach ||
		k == KindResume || k == KindSSH || k == KindGUI
}

// remoteSensitiveKinds is the set of run kinds classified as remote-VIEW
// sensitive (session-attach design §3.2). Both kinds bind a daemon-owned
// terminal to a REAL external transcript — an attach session the operator
// started outside the dashboard (KindAttach) or a native reopen of a closed
// session's ACTUAL prior conversation (KindResume) — whose TUI can echo API
// keys / customer data. A fresh/handoff launch has no such pre-existing
// transcript, so it is not remote-sensitive. Whether a remote caller may SEE a
// sensitive-kind PTY is governed by the [remote].allow_terminal_view toggle,
// which now DEFAULTS TRUE (view-on-by-default; the remote WRITE/drive path is
// unchanged) — set allow_terminal_view = false to restore the deny-read
// posture. This table only marks the kinds the toggle applies to; it is a data
// set (not an if-chain) so a new sensitive kind is one row (CLAUDE.md #5).
var remoteSensitiveKinds = map[Kind]bool{
	KindAttach: true,
	KindResume: true,
	// KindSSH — a live shell on another machine. The attach/resume rationale
	// ("its TUI can echo API keys / customer data") applies at least as
	// strongly to a root shell on a production box, so an SSH PTY joins the
	// gated set rather than the fresh/handoff non-sensitive floor.
	KindSSH: true,
}

// IsRemoteSensitiveKind reports whether a run kind is remote-VIEW sensitive: its
// live PTY is hidden from a remote-exposed snapshot and its websocket refused
// for a remote caller WHEN [remote].allow_terminal_view is off (§3.2). That
// toggle now defaults TRUE, so such PTYs are visible by default; the mechanism
// (and the off-switch) is unchanged. Used at BOTH the dashboard visibleSnapshot
// / WS gates and the cmd adapter's IsRemoteSensitiveSession so the two dispatch
// on ONE shared table, never a per-site if-chain. An unknown kind is not
// sensitive (fresh/handoff are the honest non-sensitive floor).
func IsRemoteSensitiveKind(k Kind) bool { return remoteSensitiveKinds[k] }

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
const MinLinkConfidence = 0.50

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
