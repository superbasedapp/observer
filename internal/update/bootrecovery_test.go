package update

import "testing"

// bootrecovery_test.go pins how a daemon that starts while its state says
// `applying` settles it (RecoverAtBoot), including the launchd hand-over
// (SVC-3 option b), where the new binary is started by launchd itself after
// the parent's restart exit: it settles applied once it has stayed up, and
// after MaxSupervisorRestartBoots failed boots it restores the previous one.
func TestDecideBootRecovery(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   BootRecoveryInput
		want BootRecovery
	}{
		{"not applying", BootRecoveryInput{Applying: false, RunningIsTarget: true}, BootNothing},
		{"the swap did not happen", BootRecoveryInput{Applying: true, RunningIsTarget: false}, BootSettleFailed},
		{"the swap did not happen, launchd waiting", BootRecoveryInput{Applying: true, RunningIsTarget: false, AwaitingRestart: true, Attempts: 1}, BootSettleFailed},
		{"lost its parent (reboot)", BootRecoveryInput{Applying: true, RunningIsTarget: true}, BootSettleApplied},
		{"launchd started it: first boot", BootRecoveryInput{Applying: true, RunningIsTarget: true, AwaitingRestart: true, Attempts: 1}, BootSettleAppliedWhenHealthy},
		{"launchd started it: last allowed boot", BootRecoveryInput{Applying: true, RunningIsTarget: true, AwaitingRestart: true, Attempts: MaxSupervisorRestartBoots}, BootSettleAppliedWhenHealthy},
		{"launchd started it: too many failed boots", BootRecoveryInput{Applying: true, RunningIsTarget: true, AwaitingRestart: true, Attempts: MaxSupervisorRestartBoots + 1}, BootRestorePrevious},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := DecideBootRecovery(tc.in); got != tc.want {
				t.Fatalf("DecideBootRecovery(%+v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSupervisorRestartRecord(t *testing.T) {
	r := SupervisorRestart{Target: "v1.43.0", Attempts: 2}
	js, err := EncodeSupervisorRestart(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeSupervisorRestart(js)
	if err != nil || got != r {
		t.Fatalf("round trip %+v, %v", got, err)
	}
	if !got.Matches("1.43.0") || got.Matches("v1.43.1") || (SupervisorRestart{}).Matches("") {
		t.Fatal("Matches")
	}
	if js, _ := EncodeSupervisorRestart(SupervisorRestart{}); js != "" {
		t.Fatalf("an empty record encodes as %q", js)
	}
}
