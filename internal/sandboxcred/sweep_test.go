package sandboxcred

import "testing"

// TestSweepRecordRows is one case per row of sweepRules, plus the dead row
// and the order that asks the dead-run hold last.
func TestSweepRecordRows(t *testing.T) {
	held := func() bool { return true }
	notHeld := func() bool { return false }
	for _, tc := range []struct {
		name   string
		f      SweepFacts
		remove bool
		row    SweepRow
	}{
		{"young file kept", SweepFacts{Young: true}, false, SweepRowYoung},
		{"helper live kept", SweepFacts{HelperLive: true}, false, SweepRowHelperLive},
		{"relay record kept (live, offered or held)", SweepFacts{RelayRecord: true}, false, SweepRowRelayRecord},
		{"hosted record kept", SweepFacts{HostedRecord: true}, false, SweepRowHostedRecord},
		{"dead-run hold keeps it", SweepFacts{HeldByDeadRunHold: held}, false, SweepRowDeadRunHold},
		{"dead: hold lets go", SweepFacts{HeldByDeadRunHold: notHeld}, true, SweepRowDead},
		{"dead: no hold installed", SweepFacts{}, true, SweepRowDead},
	} {
		t.Run(tc.name, func(t *testing.T) {
			remove, row := SweepRecord(tc.f)
			if remove != tc.remove || row != tc.row {
				t.Fatalf("SweepRecord = %v %q, want %v %q", remove, row, tc.remove, tc.row)
			}
		})
	}
}

// TestSweepRecordAsksHoldLast pins that the hold is not asked about a file
// an earlier row keeps (the hold may log its own decision).
func TestSweepRecordAsksHoldLast(t *testing.T) {
	asked := false
	hold := func() bool { asked = true; return true }
	for _, f := range []SweepFacts{
		{Young: true, HeldByDeadRunHold: hold},
		{HelperLive: true, HeldByDeadRunHold: hold},
		{RelayRecord: true, HeldByDeadRunHold: hold},
		{HostedRecord: true, HeldByDeadRunHold: hold},
	} {
		if remove, _ := SweepRecord(f); remove {
			t.Fatalf("removed %+v", f)
		}
	}
	if asked {
		t.Fatal("the dead-run hold was asked about a file an earlier row kept")
	}
}
