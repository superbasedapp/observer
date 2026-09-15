package update

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestStateTransitions walks the state machine as a table, one row per
// move that matters.
func TestStateTransitions(t *testing.T) {
	cases := []struct {
		from, to State
		want     bool
	}{
		{StateIdle, StateAvailable, true},
		{StateAvailable, StateDownloading, true},
		{StateDownloading, StateVerified, true},
		{StateVerified, StateApplying, true},
		{StateApplying, StateApplied, true},
		{StateApplying, StateFailed, true},
		{StateApplying, StateRolledBack, true}, // the handshake's third outcome
		{StateApplied, StateIdle, true},
		{StateFailed, StateDownloading, true},   // a retry is legal
		{StateRolledBack, StateAvailable, true}, // a later manifest re-arms the node
		{StateBlocked, StateAvailable, true},
		{StateStaleManifest, StateAvailable, true},
		{StateIdle, StateIdle, true}, // re-reporting is a no-op, not an error

		{StateIdle, StateApplying, false}, // no apply without a verified artifact
		{StateIdle, StateApplied, false},  // no apply without an apply
		{StateAvailable, StateApplied, false},
		{StateDownloading, StateApplying, false}, // verification is not skippable
		{StateApplied, StateRolledBack, false},   // a rollback happens FROM applying
		{StateIdle, State("nonsense"), false},
	}
	for _, tc := range cases {
		t.Run(string(tc.from)+"->"+string(tc.to), func(t *testing.T) {
			if got := CanTransition(tc.from, tc.to); got != tc.want {
				t.Errorf("CanTransition(%q,%q) = %v, want %v", tc.from, tc.to, got, tc.want)
			}
			got, err := Transition(tc.from, tc.to)
			if tc.want {
				if err != nil {
					t.Fatalf("Transition: %v", err)
				}
				if got != tc.to {
					t.Fatalf("Transition returned %q, want %q", got, tc.to)
				}
				return
			}
			if err == nil {
				t.Fatal("expected an illegal-transition error")
			}
			if got != tc.from {
				t.Errorf("a refused transition must leave the state at %q, got %q", tc.from, got)
			}
		})
	}
}

// TestStateVocabularyIsClosed pins the enum itself: the posture row on
// the push envelope carries these values, so adding one is a wire
// change (§2.1, ruling R10).
func TestStateVocabularyIsClosed(t *testing.T) {
	want := []State{
		StateApplied, StateApplying, StateAvailable, StateBlocked, StateDownloading,
		StateFailed, StateIdle, StateRolledBack, StateStaleManifest, StateVerified,
	}
	got := States()
	if len(got) != len(want) {
		t.Fatalf("States() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("States()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	// Every transition target must itself be a known state, or a node
	// could report a value the board cannot render.
	for from, tos := range legalTransitions {
		for _, to := range tos {
			if !KnownState(to) {
				t.Errorf("%q -> unknown state %q", from, to)
			}
		}
	}
}

// TestBlockedReasonsCoverTheFailClosedCases pins the two reasons the
// review findings turn on: H0's unsigned artifact and GitLab-style
// required stops.
func TestBlockedReasonsCoverTheFailClosedCases(t *testing.T) {
	for _, r := range []Reason{ReasonUnsignedArtifact, ReasonRequiredStop, ReasonInstallMethod, ReasonNoArtifact} {
		if r == ReasonNone {
			t.Error("a blocked reason must not be the zero value")
		}
	}
	if ReasonUnsignedArtifact != "unsigned_artifact" {
		t.Errorf("ReasonUnsignedArtifact = %q — the wire vocabulary is fixed", ReasonUnsignedArtifact)
	}
	if ReasonRequiredStop != "required_stop" {
		t.Errorf("ReasonRequiredStop = %q — the wire vocabulary is fixed", ReasonRequiredStop)
	}
}

// TestErrorClassesAreEnumOnly guards the privacy property of §2.1: the
// posture row carries a CLASS, never a message, because a message can
// carry a path.
func TestErrorClassesAreEnumOnly(t *testing.T) {
	classes := []ErrorClass{
		ErrorDownload, ErrorHash, ErrorSignature, ErrorProbe, ErrorSwap,
		ErrorPermission, ErrorHealthcheck, ErrorWindow, ErrorDrain,
	}
	seen := map[ErrorClass]bool{}
	for _, c := range classes {
		if c == ErrorNone {
			t.Error("an error class must not be the zero value")
		}
		if strings.ContainsAny(string(c), " /\\:") {
			t.Errorf("error class %q looks like free text or a path", c)
		}
		if seen[c] {
			t.Errorf("duplicate error class %q", c)
		}
		seen[c] = true
	}
}

// TestNodeState covers the node-local state document W1 persists as
// JSON (agent migration 105 is a W3 item; the field set is already the
// one that migration will carry).
func TestNodeState(t *testing.T) {
	t.Run("an empty file is an idle node, not a broken one", func(t *testing.T) {
		st, err := ParseNodeState(nil)
		if err != nil {
			t.Fatalf("ParseNodeState: %v", err)
		}
		if st.State != StateIdle {
			t.Errorf("state = %q, want idle", st.State)
		}
	})
	t.Run("a document with no state field defaults to idle", func(t *testing.T) {
		st, err := ParseNodeState([]byte(`{"channel":"stable"}`))
		if err != nil {
			t.Fatalf("ParseNodeState: %v", err)
		}
		if st.State != StateIdle || st.Channel != ChannelStable {
			t.Errorf("state = %+v", st)
		}
	})
	t.Run("an unknown state is refused", func(t *testing.T) {
		if _, err := ParseNodeState([]byte(`{"state":"pending"}`)); err == nil {
			t.Fatal("expected an unknown-state refusal")
		}
	})
	t.Run("a trailing JSON value is refused", func(t *testing.T) {
		if _, err := ParseNodeState([]byte(`{"state":"idle"}{"state":"applied"}`)); err == nil {
			t.Fatal("expected a trailing-value refusal")
		}
	})
	t.Run("an oversized document is refused before decoding", func(t *testing.T) {
		big := make([]byte, MaxNodeStateBytes+1)
		for i := range big {
			big[i] = ' '
		}
		if _, err := ParseNodeState(big); err == nil {
			t.Fatal("expected a size refusal")
		}
	})
	t.Run("round trip preserves the rollback fields", func(t *testing.T) {
		want := NodeState{
			Channel: ChannelStable, LastManifestVersion: 17, State: StateApplying,
			TargetVersion: "v1.33.0", PreviousVersion: "v1.32.0",
			PreviousBinaryPath:    "/home/dev/.observer/updates/rollback/observer-v1.32.0",
			PreviousSchemaVersion: 104,
			PreviousDBBackupPath:  "/home/dev/.observer/updates/preupgrade-v1.32.0.db",
		}
		b, err := EncodeNodeState(want)
		if err != nil {
			t.Fatalf("EncodeNodeState: %v", err)
		}
		got, err := ParseNodeState(b)
		if err != nil {
			t.Fatalf("ParseNodeState: %v", err)
		}
		if got != want {
			t.Fatalf("round trip changed the document:\n got %+v\nwant %+v", got, want)
		}
	})
	t.Run("the document carries no free-text error field", func(t *testing.T) {
		b, err := EncodeNodeState(NodeState{State: StateFailed, ErrorClass: ErrorHash})
		if err != nil {
			t.Fatalf("EncodeNodeState: %v", err)
		}
		var generic map[string]any
		if err := json.Unmarshal(b, &generic); err != nil {
			t.Fatalf("decode: %v", err)
		}
		for k := range generic {
			if k == "error" || k == "error_message" || k == "detail" {
				t.Errorf("node state exposes a free-text field %q", k)
			}
		}
	})
}
