package oidcissuer

import (
	"fmt"
	"time"
)

// PublicationLead is how long a promoted key is published in the JWKS
// before it may first sign (design 3.3: "New kid published in JWKS 24 hours
// before first use"). Tenants cache the JWKS for one hour and refetch once on
// an unknown kid, so the lead covers stale caches with a wide margin.
const PublicationLead = 24 * time.Hour

// keyTransition is one allowed move of a signing key's status. Anything not
// in the table is refused.
type keyTransition struct {
	from, to string
	// needsNotBefore: the move sets not_before (promotion).
	needsNotBefore bool
}

// keyTransitions is the whole key lifecycle: staged -> active (promotion,
// with a not_before), active -> retiring (stop signing, stay published),
// retiring -> retired and staged -> retired (stop publishing).
var keyTransitions = []keyTransition{
	{from: KeyStaged, to: KeyActive, needsNotBefore: true},
	{from: KeyActive, to: KeyRetiring},
	{from: KeyRetiring, to: KeyRetired},
	{from: KeyStaged, to: KeyRetired},
}

// CheckKeyTransition reports whether a key may move from -> to, and whether
// the move must set not_before. An unlisted move is an error.
func CheckKeyTransition(from, to string) (needsNotBefore bool, err error) {
	for _, t := range keyTransitions {
		if t.from == from && t.to == to {
			return t.needsNotBefore, nil
		}
	}
	return false, fmt.Errorf("oidcissuer.CheckKeyTransition: a signing key cannot move from %q to %q", from, to)
}

// CheckPromotion checks a promotion's not_before against now: it must be at
// least lead ahead (so the kid is published before its first use). A lead
// below PublicationLead is the operator's explicit choice (the very first key
// of a fresh deployment has no cache to outrun) and must still be positive.
func CheckPromotion(notBefore, now time.Time, lead time.Duration) error {
	if lead <= 0 {
		return fmt.Errorf("oidcissuer.CheckPromotion: the publication lead must be positive, got %s", lead)
	}
	if notBefore.Before(now.Add(lead)) {
		return fmt.Errorf("oidcissuer.CheckPromotion: not_before %s is less than %s after now", notBefore.UTC().Format(time.RFC3339), lead)
	}
	return nil
}
