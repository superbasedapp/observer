package update

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// State is the node's self-reported update state. It is an ENUM and
// nothing else: the posture row that rides the push envelope carries
// this value, never a message, so the wire cannot leak a path or a
// hostname (§2.1, ruling R10).
type State string

const (
	// StateIdle: nothing published that this node is behind on.
	StateIdle State = "idle"
	// StateAvailable: a verified manifest names a newer version; the
	// node has not started (or is not permitted to start) an apply.
	StateAvailable State = "available"
	// StateDownloading: fetching artifact bytes from the org mirror.
	StateDownloading State = "downloading"
	// StateVerified: bytes hashed, vendor signature checked, member
	// extracted and probed — ready to swap.
	StateVerified State = "verified"
	// StateApplying: quiesced, rollback staged, swap in progress or the
	// handshake is running. The OLD daemon owns this state.
	StateApplying State = "applying"
	// StateApplied: the new binary passed its self-check.
	StateApplied State = "applied"
	// StateFailed: the apply aborted; ErrorClass says at which step.
	StateFailed State = "failed"
	// StateRolledBack: the apply failed AND the previous binary (plus,
	// when the schema advanced, the pre-apply DB snapshot) was restored.
	StateRolledBack State = "rolled_back"
	// StateBlocked: this node cannot apply for a structural reason —
	// Reason says which. Not an error and not a failure: it is the
	// honest answer for an npm-owned binary or an unsigned artifact.
	StateBlocked State = "blocked"
	// StateStaleManifest: the newest manifest this node holds is past
	// its expires_at, so the fleet is unfreshened (the anti-freeze
	// signal of §2.3).
	StateStaleManifest State = "stale_manifest"
)

// KnownState reports whether s is a state this agent publishes.
func KnownState(s State) bool {
	_, ok := legalTransitions[s]
	return ok
}

// Reason qualifies StateBlocked. Like State it is a closed vocabulary.
type Reason string

const (
	// ReasonNone is the zero value: no block.
	ReasonNone Reason = ""
	// ReasonUnsignedArtifact: the artifact carries no vendor signature.
	// Until the W6 release pipeline produces per-artifact signatures
	// this is the FAIL-CLOSED interim (review H0) — the two-signature
	// claim is never quietly one signature.
	ReasonUnsignedArtifact Reason = "unsigned_artifact"
	// ReasonRequiredStop: installed version is below min_from_version,
	// so an intermediate version must be installed first.
	ReasonRequiredStop Reason = "required_stop"
	// ReasonNoArtifact: the manifest builds nothing for this os/arch.
	ReasonNoArtifact Reason = "no_artifact"
	// ReasonInstallMethod: a package manager or the VS Code extension
	// owns this binary, so the node must not replace it.
	ReasonInstallMethod Reason = "install_method"
	// ReasonNotWritable: a standalone binary this uid cannot replace.
	ReasonNotWritable Reason = "not_writable"
	// ReasonDowngrade: the manifest targets a lower version and either
	// allow_downgrade_to does not name it or node consent is absent.
	ReasonDowngrade Reason = "downgrade_not_allowed"
	// ReasonWindow: outside the node's maintenance window.
	ReasonWindow Reason = "window"
	// ReasonNoDiskSpace: state_dir's filesystem cannot hold the archive
	// (§2.4's 3x rule) plus, when the target advances the schema, the
	// pre-apply database snapshot. It is a BLOCK, not a failure: an
	// admin reading it needs to free space or move state_dir, and a
	// node that keeps re-attempting a download it cannot finish is the
	// disk-exhaustion class the 2026-08-26 audit forbids.
	ReasonNoDiskSpace Reason = "no_disk_space"
)

// ErrorClass is the fixed error vocabulary the posture row carries. An
// error STRING can leak a path; the class cannot (§2.1).
type ErrorClass string

const (
	// ErrorNone is the zero value.
	ErrorNone ErrorClass = ""
	// ErrorDownload: the artifact fetch failed or exceeded its ceiling.
	ErrorDownload ErrorClass = "download"
	// ErrorHash: archive or member hash mismatch.
	ErrorHash ErrorClass = "hash"
	// ErrorSignature: manifest or vendor signature failed.
	ErrorSignature ErrorClass = "signature"
	// ErrorProbe: the extracted binary's --version disagreed with the
	// target.
	ErrorProbe ErrorClass = "probe"
	// ErrorSwap: the atomic rename failed.
	ErrorSwap ErrorClass = "swap"
	// ErrorPermission: a path was not writable when it had to be.
	ErrorPermission ErrorClass = "permission"
	// ErrorHealthcheck: the new binary's self-check failed, or the
	// handshake timed out.
	ErrorHealthcheck ErrorClass = "healthcheck"
	// ErrorWindow: the maintenance window closed mid-apply.
	ErrorWindow ErrorClass = "window"
	// ErrorDrain: in-flight proxied requests did not reach zero within
	// drain_timeout. Normal admission is resumed before this is
	// reported — ruling R13 guarantees the resume path, so this class
	// never describes a node left refusing traffic.
	ErrorDrain ErrorClass = "drain"
)

// legalTransitions is the state machine as DATA: from -> the states it
// may move to. A table rather than a switch ladder, so a new state is a
// row and the test is a walk over the same rows (CLAUDE.md #5).
//
// Two properties are deliberate:
//
//   - every terminal state can return to idle or available, because a
//     later manifest must be able to re-arm a node that failed once;
//   - applying may go to applied, failed OR rolled_back, which is the
//     whole point of the fork-exec-and-watch handshake: the parent is
//     still alive to write the third one.
var legalTransitions = map[State][]State{
	StateIdle:          {StateAvailable, StateBlocked, StateStaleManifest},
	StateAvailable:     {StateIdle, StateDownloading, StateBlocked, StateStaleManifest, StateFailed},
	StateDownloading:   {StateVerified, StateFailed, StateBlocked, StateIdle},
	StateVerified:      {StateApplying, StateFailed, StateBlocked, StateIdle},
	StateApplying:      {StateApplied, StateFailed, StateRolledBack},
	StateApplied:       {StateIdle, StateAvailable},
	StateFailed:        {StateIdle, StateAvailable, StateDownloading},
	StateRolledBack:    {StateIdle, StateAvailable},
	StateBlocked:       {StateIdle, StateAvailable, StateBlocked},
	StateStaleManifest: {StateIdle, StateAvailable, StateBlocked},
}

// CanTransition reports whether from -> to is a legal move. A
// self-transition is always legal (re-reporting the same state is a
// no-op, not an error).
func CanTransition(from, to State) bool {
	if from == to {
		return KnownState(from)
	}
	for _, allowed := range legalTransitions[from] {
		if allowed == to {
			return true
		}
	}
	return false
}

// Transition validates a move and returns the new state, or an error
// naming both ends. Callers use it instead of assigning a state field
// directly, so an impossible sequence fails where it happens rather
// than surfacing as a nonsensical row on the org board.
func Transition(from, to State) (State, error) {
	if !KnownState(to) {
		return from, fmt.Errorf("update.Transition: unknown state %q", to)
	}
	if !CanTransition(from, to) {
		return from, fmt.Errorf("update.Transition: illegal %s -> %s", from, to)
	}
	return to, nil
}

// States returns every known state, sorted. Used by tests and by the
// wire-shape allow-list.
func States() []State {
	out := make([]State, 0, len(legalTransitions))
	for s := range legalTransitions {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// NodeState is the node-local update state document.
//
// W1 persists it as a JSON file under [update].state_dir because agent
// migration 105 (update_state / update_events) is a W3 item; the field
// set is deliberately the same one that migration will carry, so W3
// moves the storage without moving the shape. Nothing here crosses the
// wire: the posture row that does is a strict, enum-only SUBSET
// composed in internal/store/updateposture.go (§2.1, ruling R10).
type NodeState struct {
	// Channel is the channel this node is assigned to ("" = whatever
	// the org assigns).
	Channel Channel `json:"channel,omitempty"`
	// LastManifestVersion is the highest manifest_version this node has
	// accepted on Channel. Replay protection compares against it
	// (verify rule 6).
	LastManifestVersion int64 `json:"last_manifest_version,omitempty"`
	// LastManifestSeenAt is RFC3339, when that manifest was accepted.
	LastManifestSeenAt string `json:"last_manifest_seen_at,omitempty"`
	// TargetVersion is the version this node is trying to reach.
	TargetVersion string `json:"target_version,omitempty"`
	// State is the current state.
	State State `json:"state,omitempty"`
	// Reason qualifies State when it is blocked.
	Reason Reason `json:"reason,omitempty"`
	// ErrorClass is the last failure's class.
	ErrorClass ErrorClass `json:"error_class,omitempty"`
	// PreviousVersion / PreviousBinaryPath name the rollback binary.
	PreviousVersion    string `json:"previous_version,omitempty"`
	PreviousBinaryPath string `json:"previous_binary_path,omitempty"`
	// PreviousSchemaVersion is the agent schema version recorded BEFORE
	// the swap. It is load-bearing and easy to miss: migrations run
	// inside db.Open (internal/db/db.go:498), so by the time the new
	// binary could look, the pre-apply number is already gone.
	PreviousSchemaVersion int `json:"previous_schema_version,omitempty"`
	// PreviousDBBackupPath names the VACUUM INTO snapshot taken when
	// the target advances the schema; a rollback across a migration
	// restores it (§3.7 step 8).
	PreviousDBBackupPath string `json:"previous_db_backup_path,omitempty"`
	// ApplyingStartedAt / AppliedAt are RFC3339 timestamps.
	ApplyingStartedAt string `json:"applying_started_at,omitempty"`
	AppliedAt         string `json:"applied_at,omitempty"`
	// UpdatedAt is RFC3339, when this document was last written.
	UpdatedAt string `json:"updated_at,omitempty"`
}

// MaxNodeStateBytes caps the node state document. It is small by
// construction; a larger file is corruption, not a bigger state.
const MaxNodeStateBytes = 64 * 1024

// ParseNodeState decodes the node-local state document, tolerating an
// empty file (a node that has never seen a manifest is idle, not
// broken) and refusing anything oversized or trailing.
func ParseNodeState(b []byte) (NodeState, error) {
	if len(b) > MaxNodeStateBytes {
		return NodeState{}, fmt.Errorf("update.ParseNodeState: state document is %d bytes (max %d)", len(b), MaxNodeStateBytes)
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return DefaultNodeState(), nil
	}
	var st NodeState
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&st); err != nil {
		return NodeState{}, fmt.Errorf("update.ParseNodeState: %w", err)
	}
	if dec.More() {
		return NodeState{}, fmt.Errorf("update.ParseNodeState: trailing JSON value")
	}
	if strings.TrimSpace(string(st.State)) == "" {
		st.State = StateIdle
	}
	if !KnownState(st.State) {
		return NodeState{}, fmt.Errorf("update.ParseNodeState: unknown state %q", st.State)
	}
	return st, nil
}

// DefaultNodeState is the state of a node that has never seen a
// manifest.
func DefaultNodeState() NodeState { return NodeState{State: StateIdle} }

// EncodeNodeState renders the state document for writing, sorted and
// indented so an operator can read (and diff) the file directly.
func EncodeNodeState(st NodeState) ([]byte, error) {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("update.EncodeNodeState: %w", err)
	}
	return append(b, '\n'), nil
}
