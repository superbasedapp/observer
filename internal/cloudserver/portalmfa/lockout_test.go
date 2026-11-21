package portalmfa

import (
	"testing"
	"time"
)

// TestNextRecoveryFailure walks the lockout rows: one case per rule.
func TestNextRecoveryFailure(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name    string
		in      RecoveryFailureState
		wantN   int
		tripped bool
	}{
		{"first failure starts a window", RecoveryFailureState{}, 1, false},
		{"counts inside the window", RecoveryFailureState{Failures: 2, WindowStart: now.Add(-time.Minute)}, 3, false},
		{"the threshold trips the lock", RecoveryFailureState{Failures: RecoveryMaxFailures - 1, WindowStart: now.Add(-time.Minute)}, RecoveryMaxFailures, true},
		{"an old window starts again", RecoveryFailureState{Failures: 4, WindowStart: now.Add(-2 * RecoveryFailureWindow)}, 1, false},
		{"an expired lock starts again", RecoveryFailureState{Failures: 5, WindowStart: now.Add(-time.Minute), LockedUntil: now.Add(-time.Second)}, 1, false},
	}
	for _, c := range cases {
		next, tripped := NextRecoveryFailure(c.in, now)
		if next.Failures != c.wantN || tripped != c.tripped {
			t.Errorf("%s: got %+v tripped=%v", c.name, next, tripped)
		}
		if tripped && !RecoveryLocked(next, now) {
			t.Errorf("%s: tripped but not locked", c.name)
		}
	}
}

// TestApproveDeviceRule pins the FR-6 action row.
func TestApproveDeviceRule(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		s    SessionState
		want string
	}{
		{"passkey session may approve", SessionState{Enrolled: true, Method: MethodPasskey}, ""},
		{"recovery code session may not", SessionState{Enrolled: true, Method: MethodRecoveryCode}, CodePasskeySignInRequired},
		{"primary sign-in alone may not", SessionState{Enrolled: true}, CodePasskeySignInRequired},
		{"not enrolled has nothing to approve with", SessionState{}, CodePasskeySignInRequired},
	}
	for _, c := range cases {
		if got, _ := Decide(ActionApproveDevice, Facts{Session: c.s}); got != c.want {
			t.Errorf("%s: got %q", c.name, got)
		}
	}
}
