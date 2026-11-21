package agentlaunch

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// TestShouldHoldRows walks one case per hold row.
func TestShouldHoldRows(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		o        termrun.Origin
		want     bool
		wantRule string
	}{
		{"P1 agent", termrun.Origin{Initiator: termrun.InitiatorAgent, ParentSessionID: "s"}, true, "P1-agent-held"},
		{"P2 unknown", termrun.Origin{Initiator: termrun.InitiatorUnknown}, false, "P2-unknown-runs"},
		{"P3 human cli", termrun.Origin{Initiator: termrun.InitiatorHumanCLI}, false, "P3-human-runs"},
		{"P3 human dashboard", termrun.Origin{Initiator: termrun.InitiatorHumanDashboard}, false, "P3-human-runs"},
		{"P3 not recorded", termrun.Origin{}, false, "P3-human-runs"},
	} {
		if got, rule := ShouldHold(tc.o); got != tc.want || rule != tc.wantRule {
			t.Errorf("%s: ShouldHold = %v (%s), want %v (%s)", tc.name, got, rule, tc.want, tc.wantRule)
		}
	}
}

// TestMayConfirmRows walks one case per confirm row.
func TestMayConfirmRows(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		f        ConfirmFacts
		want     bool
		wantRule string
	}{
		{"K0 caller gone", ConfirmFacts{CallerGone: true, GoneWhy: "it has exited", Origin: termrun.Origin{Initiator: termrun.InitiatorHumanCLI}}, false, "K0-caller-gone"},
		{"K1 in a box", ConfirmFacts{InBox: true, Origin: termrun.Origin{Initiator: termrun.InitiatorHumanDashboard}}, false, "K1-in-box"},
		{"K2 agent", ConfirmFacts{Origin: termrun.Origin{Initiator: termrun.InitiatorAgent}}, false, "K2-agent"},
		{"K3 human", ConfirmFacts{Origin: termrun.Origin{Initiator: termrun.InitiatorHumanCLI}}, true, "K3-otherwise"},
		{"K3 unidentified", ConfirmFacts{Origin: termrun.Origin{Initiator: termrun.InitiatorUnknown}}, true, "K3-otherwise"},
	} {
		ok, why, rule := MayConfirm(tc.f)
		if ok != tc.want || rule != tc.wantRule || (!ok && why == "") {
			t.Errorf("%s: MayConfirm = %v %q (%s), want %v (%s)", tc.name, ok, why, rule, tc.want, tc.wantRule)
		}
	}
}

// TestCallerPresentRows walks one case per presence row (lane cli-2
// fixes-3, audit M1), and the refusal a launch gets for a gone caller.
func TestCallerPresentRows(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		c        CallerIdentity
		want     bool
		wantRule string
	}{
		{"G1 start unread at connect", CallerIdentity{Now: "boot:7"}, false, "G1-start-unread-at-connect"},
		{"G1 nothing read", CallerIdentity{}, false, "G1-start-unread-at-connect"},
		{"G2 exited", CallerIdentity{AtConnect: "boot:7"}, false, "G2-exited"},
		{"G3 pid reused", CallerIdentity{AtConnect: "boot:7", Now: "boot:9"}, false, "G3-pid-reused"},
		{"G4 present", CallerIdentity{AtConnect: "boot:7", Now: "boot:7"}, true, "G4-present"},
	} {
		ok, why, rule := CallerPresent(tc.c)
		if ok != tc.want || rule != tc.wantRule || (!ok && why == "") {
			t.Errorf("%s: CallerPresent = %v %q (%s), want %v (%s)", tc.name, ok, why, rule, tc.want, tc.wantRule)
		}
	}
	err := CallerGoneError("it has exited")
	if CodeOf(err) != CodeCallerGone || err.Error() == "" {
		t.Fatalf("CallerGoneError = %v (%s)", err, CodeOf(err))
	}
}

// TestHoldsSingleUseAndExpiry pins the store: an id is handed out once,
// expires after the TTL, and the store is bounded.
func TestHoldsSingleUseAndExpiry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	n := 0
	h := NewHolds[string](func() time.Time { return now }, func() (string, error) { n++; return fmt.Sprintf("p%d", n), nil })
	p, err := h.Hold(Pending{Tool: "codex", Origin: termrun.Origin{Initiator: termrun.InitiatorAgent, ParentSessionID: "s"}}, "start-codex")
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}
	if p.ID != "p1" || !p.ExpiresAt.Equal(now.Add(DefaultPendingTTL)) {
		t.Fatalf("held = %+v", p)
	}
	if got := h.List(); len(got) != 1 || got[0].ID != "p1" {
		t.Fatalf("List = %+v", got)
	}
	got, action, err := h.Take("p1")
	if err != nil || action != "start-codex" || got.Tool != "codex" {
		t.Fatalf("Take = %+v %q %v", got, action, err)
	}
	if _, _, err := h.Take("p1"); !errors.Is(err, ErrPendingNotFound) {
		t.Fatalf("second Take = %v, want not found (single use)", err)
	}
	// Expiry.
	if _, err := h.Hold(Pending{Tool: "claude-code"}, "start-claude"); err != nil {
		t.Fatalf("Hold: %v", err)
	}
	now = now.Add(DefaultPendingTTL)
	if _, _, err := h.Take("p2"); !errors.Is(err, ErrPendingNotFound) {
		t.Fatalf("Take after expiry = %v", err)
	}
	if got := h.List(); len(got) != 0 {
		t.Fatalf("expired holds listed: %+v", got)
	}
	// Bound.
	for range MaxPending {
		if _, err := h.Hold(Pending{}, ""); err != nil {
			t.Fatalf("Hold under the bound: %v", err)
		}
	}
	if _, err := h.Hold(Pending{}, ""); CodeOf(err) != CodeTooManyPending {
		t.Fatalf("Hold over the bound = %v", err)
	}
}
