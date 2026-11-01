package pspolicy

import (
	"errors"
	"testing"
)

// TestEvaluate is one case per precedence and policy-table row.
func TestEvaluate(t *testing.T) {
	bypass := Launch{BypassArg: true}
	cases := []struct {
		name        string
		list        List
		launch      Launch
		wantOutcome Outcome
		wantPolicy  Policy
		wantScope   Scope
		wantGPO     bool
		wantOver    bool
		wantCertain bool
	}{
		{"machine policy AllSigned outranks the host's Bypass", List{MachinePolicy: AllSigned, CurrentUser: RemoteSigned}, bypass, Blocks, AllSigned, MachinePolicy, true, true, true},
		{"user policy Restricted outranks the host's Bypass", List{UserPolicy: Restricted}, bypass, Blocks, Restricted, UserPolicy, true, true, true},
		{"machine policy RemoteSigned runs a local script", List{MachinePolicy: RemoteSigned}, bypass, Runs, RemoteSigned, MachinePolicy, true, true, true},
		{"machine policy Unrestricted runs", List{MachinePolicy: Unrestricted}, Launch{}, Runs, Unrestricted, MachinePolicy, true, false, true},
		{"host Bypass outranks a local AllSigned", List{CurrentUser: AllSigned, LocalMachine: Restricted}, bypass, Runs, Bypass, Process, false, false, true},
		{"the reader's own Process scope is never the host's", List{Process: Bypass, CurrentUser: AllSigned}, Launch{}, Blocks, AllSigned, CurrentUser, false, false, true},
		{"current user outranks local machine", List{CurrentUser: RemoteSigned, LocalMachine: AllSigned}, Launch{}, Runs, RemoteSigned, CurrentUser, false, false, true},
		{"local machine Restricted blocks without Bypass", List{LocalMachine: Restricted}, Launch{}, Blocks, Restricted, LocalMachine, false, false, true},
		{"explicit Default is edition-dependent", List{LocalMachine: Default}, Launch{}, Blocks, Default, LocalMachine, false, false, false},
		{"nothing set falls back to the edition default", List{MachinePolicy: Undefined}, Launch{}, Blocks, Default, "", false, false, false},
		{"nothing set but the host passes Bypass", List{}, bypass, Runs, Bypass, Process, false, false, true},
		{"unknown value is unclassified", List{MachinePolicy: "SomethingNew"}, bypass, Unclassified, "SomethingNew", MachinePolicy, true, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := Evaluate(tc.list, tc.launch)
			if v.Outcome != tc.wantOutcome || v.Policy != tc.wantPolicy || v.Scope != tc.wantScope ||
				v.GroupPolicy != tc.wantGPO || v.OverridesBypass != tc.wantOver || v.Certain != tc.wantCertain {
				t.Fatalf("Evaluate = %+v, want outcome %s policy %s scope %q gpo %v overrides %v certain %v",
					v, tc.wantOutcome, tc.wantPolicy, tc.wantScope, tc.wantGPO, tc.wantOver, tc.wantCertain)
			}
			if v.Reason == "" {
				t.Error("Reason is empty")
			}
		})
	}
}

// TestPolicyRulesCoverEveryValue: every documented value except Undefined
// has exactly one row.
func TestPolicyRulesCoverEveryValue(t *testing.T) {
	seen := map[Policy]int{}
	for _, r := range policyRules {
		seen[r.policy]++
	}
	for _, p := range []Policy{Restricted, AllSigned, RemoteSigned, Unrestricted, Bypass, Default} {
		if seen[p] != 1 {
			t.Errorf("%s has %d rows, want 1", p, seen[p])
		}
	}
	if seen[Undefined] != 0 {
		t.Error("Undefined must not be a rule row (it means the scope sets nothing)")
	}
}

func TestParseList(t *testing.T) {
	out := "MachinePolicy=AllSigned\r\nuserpolicy=undefined\r\nProcess=Undefined\r\nCurrentUser=remotesigned\r\nLocalMachine=Undefined\r\n\r\nnoise line\r\nOther=Bypass\r\n"
	l, err := ParseList(out)
	if err != nil {
		t.Fatal(err)
	}
	want := List{MachinePolicy: AllSigned, UserPolicy: Undefined, Process: Undefined, CurrentUser: RemoteSigned, LocalMachine: Undefined}
	if len(l) != len(want) {
		t.Fatalf("ParseList = %v, want %v", l, want)
	}
	for k, v := range want {
		if l[k] != v {
			t.Errorf("%s = %q, want %q", k, l[k], v)
		}
	}
	if _, err := ParseList("Get-ExecutionPolicy : not recognised\n"); !errors.Is(err, ErrNoScopes) {
		t.Errorf("garbage err = %v, want ErrNoScopes", err)
	}
	if l, _ := ParseList("MachinePolicy=Fancy"); l[MachinePolicy] != "Fancy" {
		t.Errorf("unknown value not kept verbatim: %v", l)
	}
}
