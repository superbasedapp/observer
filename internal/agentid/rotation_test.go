package agentid

import (
	"reflect"
	"testing"
	"time"
)

func ringState(keys ...RingKey) *KeyRingState {
	return &KeyRingState{Keys: keys, RotateEvery: 90 * 24 * time.Hour, PublishLead: 10 * time.Minute, Overlap: 2 * time.Hour, RequireAck: true}
}

// TestKeyRingAdvanceTable: one row per rotation rule.
func TestKeyRingAdvanceTable(t *testing.T) {
	now := t0
	old := now.Add(-100 * 24 * time.Hour)
	cases := []struct {
		name string
		kr   *KeyRingState
		want []KeyOp
	}{
		{"empty ring bootstraps a pending key", ringState(), []KeyOp{{Kind: OpCreatePending}}},
		{"fresh pending waits for publish lead", ringState(RingKey{Kid: "p", State: KeyPending, CreatedAt: now.Add(-time.Minute), Acked: true}), nil},
		{"pending past lead but not ACKed waits", ringState(RingKey{Kid: "p", State: KeyPending, CreatedAt: now.Add(-time.Hour)}), nil},
		{"bootstrap pending eligible activates", ringState(RingKey{Kid: "p", State: KeyPending, CreatedAt: now.Add(-time.Hour), Acked: true}), []KeyOp{{Kind: OpActivate, Kid: "p"}}},
		{"young active: nothing", ringState(RingKey{Kid: "a", State: KeyActive, ActivatedAt: now.Add(-time.Hour)}), nil},
		{"active past lifetime creates a successor", ringState(RingKey{Kid: "a", State: KeyActive, ActivatedAt: old}), []KeyOp{{Kind: OpCreatePending}}},
		{"eligible successor: retire then activate (single-active)", ringState(
			RingKey{Kid: "a", State: KeyActive, ActivatedAt: old},
			RingKey{Kid: "p", State: KeyPending, CreatedAt: now.Add(-time.Hour), Acked: true},
		), []KeyOp{{Kind: OpBeginRetire, Kid: "a"}, {Kind: OpActivate, Kid: "p"}}},
		{"retiring inside overlap stays", ringState(
			RingKey{Kid: "r", State: KeyRetiring, RetiringAt: now.Add(-time.Hour)},
			RingKey{Kid: "a", State: KeyActive, ActivatedAt: now.Add(-time.Hour)},
		), nil},
		{"retiring past overlap retires", ringState(
			RingKey{Kid: "r", State: KeyRetiring, RetiringAt: now.Add(-3 * time.Hour)},
			RingKey{Kid: "a", State: KeyActive, ActivatedAt: now.Add(-3 * time.Hour)},
		), []KeyOp{{Kind: OpRetire, Kid: "r"}}},
		{"two active keys: no ops (never make it worse)", ringState(
			RingKey{Kid: "a", State: KeyActive}, RingKey{Kid: "b", State: KeyActive},
		), nil},
		{"manual rotation only: no auto successor", func() *KeyRingState {
			kr := ringState(RingKey{Kid: "a", State: KeyActive, ActivatedAt: old})
			kr.RotateEvery = 0
			return kr
		}(), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.kr.Advance(now)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ops = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestKeyRingFullCycle drives a ring through a whole rotation via Apply and
// checks the single-active invariant holds after every op.
func TestKeyRingFullCycle(t *testing.T) {
	kr := ringState()
	now := t0
	step := func(kid string) {
		for _, op := range kr.Advance(now) {
			if op.Kind == OpCreatePending {
				op.Kid = kid
			}
			if err := kr.Apply(op, now); err != nil {
				t.Fatalf("apply %+v: %v", op, err)
			}
		}
	}
	step("k1")               // create k1
	now = now.Add(time.Hour) // past lead
	kr.Keys[0].Acked = true  // every replica ACKed
	step("")                 // activate k1
	if kr.Keys[0].State != KeyActive {
		t.Fatalf("k1 = %s", kr.Keys[0].State)
	}
	now = now.Add(91 * 24 * time.Hour)
	step("k2") // successor
	now = now.Add(time.Hour)
	kr.Keys[1].Acked = true
	step("") // k1 retiring, k2 active
	if kr.Keys[0].State != KeyRetiring || kr.Keys[1].State != KeyActive {
		t.Fatalf("states = %s %s", kr.Keys[0].State, kr.Keys[1].State)
	}
	now = now.Add(3 * time.Hour)
	step("")
	if kr.Keys[0].State != KeyRetired {
		t.Fatalf("k1 = %s", kr.Keys[0].State)
	}
	if err := kr.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := kr.Apply(KeyOp{Kind: OpActivate, Kid: "k1"}, now); err == nil {
		t.Fatal("retired key reactivated")
	}
}

func TestKeyRingEmergencyAndConfig(t *testing.T) {
	kr := ringState(RingKey{Kid: "a", State: KeyActive}, RingKey{Kid: "p", State: KeyPending, CreatedAt: t0})
	if _, err := kr.Emergency("p"); err == nil {
		t.Fatal("un-ACKed emergency activation accepted")
	}
	kr.Keys[1].Acked = true
	ops, err := kr.Emergency("p")
	if err != nil || !reflect.DeepEqual(ops, []KeyOp{{Kind: OpBeginRetire, Kid: "a"}, {Kind: OpActivate, Kid: "p"}}) {
		t.Fatalf("emergency ops = %+v %v", ops, err)
	}
	if _, err := kr.Emergency("a"); err == nil {
		t.Fatal("emergency on a non-pending key accepted")
	}
	// Overlap >= max TTL + JWKS cache + skew.
	if err := kr.ValidateConfig(time.Hour, 5*time.Minute, 30*time.Second); err != nil {
		t.Fatalf("2h overlap should satisfy 1h+5m+30s: %v", err)
	}
	kr.Overlap = time.Hour
	if err := kr.ValidateConfig(time.Hour, 5*time.Minute, 30*time.Second); err == nil {
		t.Fatal("short overlap accepted")
	}
}
