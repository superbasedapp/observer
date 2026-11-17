package portalmfa

import "time"

// Recovery-code lockout (FR-24, docs/security.md PORTALMFA-1). A recovery code
// has 50 bits; the shared per-IP and per-account portal limits are not a
// dedicated guess bound, so each account keeps its own failure counter.
const (
	// RecoveryMaxFailures is how many wrong codes within RecoveryFailureWindow
	// lock recovery-code entry for the account.
	RecoveryMaxFailures = 5
	// RecoveryFailureWindow is how long a failure counts toward the lockout.
	RecoveryFailureWindow = 15 * time.Minute
	// RecoveryLockoutDuration is how long entry stays locked.
	RecoveryLockoutDuration = 30 * time.Minute
)

// RecoveryFailureState is the stored counter.
type RecoveryFailureState struct {
	Failures    int
	WindowStart time.Time
	LockedUntil time.Time
}

// RecoveryLocked reports whether entry is locked at now.
func RecoveryLocked(s RecoveryFailureState, now time.Time) bool {
	return !s.LockedUntil.IsZero() && now.Before(s.LockedUntil)
}

// NextRecoveryFailure returns the counter after one more wrong code at now
// and whether this failure tripped the lockout. A window older than
// RecoveryFailureWindow (or an expired lock) starts again at one.
func NextRecoveryFailure(s RecoveryFailureState, now time.Time) (next RecoveryFailureState, tripped bool) {
	if s.WindowStart.IsZero() || now.Sub(s.WindowStart) > RecoveryFailureWindow || (!s.LockedUntil.IsZero() && !now.Before(s.LockedUntil)) {
		s = RecoveryFailureState{WindowStart: now}
	}
	s.Failures++
	if s.Failures >= RecoveryMaxFailures {
		s.LockedUntil = now.Add(RecoveryLockoutDuration)
		return s, true
	}
	return s, false
}

// DeviceApprovalTTL is how long a passkey-verified approval of a new device
// stays usable by that device's next exchange.
const DeviceApprovalTTL = 15 * time.Minute

// CodeDeviceApprovalRequired is the exchange refusal for a new device of an
// account that holds a passkey.
const CodeDeviceApprovalRequired = "device_approval_required"

// CodeRecoveryLocked is the refusal while recovery-code entry is locked.
const CodeRecoveryLocked = "recovery_locked"
