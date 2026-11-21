package hostclient

import (
	"errors"
	"fmt"
)

// ResolveError is a CreateResolver's typed refusal: Reason names what is
// missing, and lands in the outbox row's error class as
// "not_sent:resolve:<Reason>". The row stays in the outbox and is retried
// with backoff; it is never parked, because a missing extra is a state of
// the control plane, not a fault of the intent.
type ResolveError struct {
	// Reason is a short fixed word: 1 to 40 of [a-z0-9_].
	Reason string
}

// Error implements error.
func (e *ResolveError) Error() string {
	return fmt.Sprintf("hostclient: create extras not resolved: %s", e.Reason)
}

// validReason reports whether r is a fixed word fit for an error class.
func validReason(r string) bool {
	if r == "" || len(r) > 40 {
		return false
	}
	for _, c := range []byte(r) {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// resolveReason is the NotSent reason of a resolver error: "resolve", plus
// the typed reason when err is a *ResolveError with a well-formed Reason.
func resolveReason(err error) string {
	var re *ResolveError
	if errors.As(err, &re) && validReason(re.Reason) {
		return "resolve:" + re.Reason
	}
	return "resolve"
}
