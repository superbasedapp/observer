package telemetrylog

import "fmt"

// ValidateRecord checks the invariants every adapter's Publish depends on and
// returns ErrInvalidRecord (wrapped with the specific reason) when they do not
// hold: an empty Org, Subject, DedupID or Payload; a Subject whose org token
// does not decode back to r.Org (which would route the record to the wrong org
// partition); or an Attrs map containing an empty key (which no engine can
// carry as a header name). Adapters call it first in Publish so a malformed
// record is rejected before it reaches the backend.
func ValidateRecord(r Record) error {
	if r.Org == "" {
		return fmt.Errorf("%w: empty Org", ErrInvalidRecord)
	}
	if r.Subject == "" {
		return fmt.Errorf("%w: empty Subject", ErrInvalidRecord)
	}
	if r.DedupID == "" {
		return fmt.Errorf("%w: empty DedupID", ErrInvalidRecord)
	}
	if len(r.Payload) == 0 {
		return fmt.Errorf("%w: empty Payload", ErrInvalidRecord)
	}
	org, ok := OrgOf(r.Subject)
	if !ok {
		return fmt.Errorf("%w: Subject %q is not a telemetry log subject", ErrInvalidRecord, r.Subject)
	}
	if org != r.Org {
		return fmt.Errorf("%w: Subject %q belongs to org %q, not record Org %q", ErrInvalidRecord, r.Subject, org, r.Org)
	}
	for k := range r.Attrs {
		if k == "" {
			return fmt.Errorf("%w: Attrs contains an empty key", ErrInvalidRecord)
		}
	}
	return nil
}
