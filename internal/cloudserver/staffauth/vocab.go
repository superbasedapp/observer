package staffauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Verb is one entry kind of the staff action log (staff_actions.verb). The
// vocabulary is closed: the store refuses a verb not listed here.
type Verb string

// The staff action log's verbs.
const (
	// VerbStaffCreated: the operator created a staff member.
	VerbStaffCreated Verb = "staff.created"
	// VerbEnrolmentMinted: the operator minted a one-time enrolment code.
	VerbEnrolmentMinted Verb = "enrolment.minted"
	// VerbCredentialRegistered: a staff member registered a passkey with an
	// enrolment code.
	VerbCredentialRegistered Verb = "credential.registered" //nolint:gosec // G101: an audit verb name, not a credential
	// VerbCredentialRevoked: the operator revoked a staff passkey (the
	// recovery path for a lost or compromised authenticator).
	VerbCredentialRevoked Verb = "credential.revoked" //nolint:gosec // G101: an audit verb name, not a credential
	// VerbSessionStarted: a verified assertion minted a staff session.
	VerbSessionStarted Verb = "session.started"
	// VerbSessionEnded: a staff member signed out.
	VerbSessionEnded Verb = "session.ended"
	// VerbAvailabilitySet: a staff member wrote an availability input.
	VerbAvailabilitySet Verb = "availability.set"
	// VerbAvailabilityDeleted: a staff member removed an availability input.
	VerbAvailabilityDeleted Verb = "availability.deleted"
	// VerbActionRefused: a signed-in staff member was refused an action by
	// the authorization table (the attempted action is the target).
	VerbActionRefused Verb = "action.refused"
	// VerbSupportSignIn: a staff member was issued a support code for an
	// org (M7a.2); written in the same transaction as the code.
	VerbSupportSignIn Verb = "support.signin"
	// VerbTeamAllowlistAdded: a staff member (or the operator) added a team
	// create allow-list entry (cloud 0130); written in the same transaction
	// as the entry.
	VerbTeamAllowlistAdded Verb = "team_allowlist.added"
	// VerbTeamAllowlistRemoved: a team create allow-list entry was removed.
	VerbTeamAllowlistRemoved Verb = "team_allowlist.removed"
)

// KnownVerbs lists every verb.
var KnownVerbs = []Verb{
	VerbStaffCreated, VerbEnrolmentMinted, VerbCredentialRegistered,
	VerbCredentialRevoked, VerbSessionStarted, VerbSessionEnded, VerbAvailabilitySet,
	VerbAvailabilityDeleted, VerbActionRefused, VerbSupportSignIn,
	VerbTeamAllowlistAdded, VerbTeamAllowlistRemoved,
}

// Known reports whether v is in the vocabulary.
func (v Verb) Known() bool {
	for _, k := range KnownVerbs {
		if v == k {
			return true
		}
	}
	return false
}

// MaxActivePasskeys is how many unrevoked passkeys one staff member may hold
// (operator ruling Staff 2, decision log L-83): enough for a primary, a
// backup and a few devices, few enough that a stolen enrolment flow cannot
// quietly pile up authenticators. Revoked passkeys do not count. A member who
// already holds more (registered before the cap) keeps them; nothing is
// deleted, only a further registration is refused.
const MaxActivePasskeys = 5

// ErrPasskeyLimit is returned when a staff member already holds
// MaxActivePasskeys unrevoked passkeys.
var ErrPasskeyLimit = fmt.Errorf("staffauth: a staff member may hold at most %d active passkeys; revoke one (observer-cloud staff revoke-credential) before registering another", MaxActivePasskeys)

// CheckPasskeyCap reports whether a staff member holding active unrevoked
// passkeys may register one more: nil, or ErrPasskeyLimit.
func CheckPasskeyCap(active int) error {
	if active >= MaxActivePasskeys {
		return ErrPasskeyLimit
	}
	return nil
}

// MaxReasonRunes bounds a reason (staff_actions.reason and
// availability_inputs.reason CHECK 1..1000 characters).
const MaxReasonRunes = 1000

// ErrReasonRequired is returned for an empty or blank reason.
var ErrReasonRequired = errors.New("staffauth: a reason is required")

// ValidateReason checks a staff-supplied reason: present, at most
// MaxReasonRunes, valid UTF-8, and no control character other than a line
// break or a tab. It returns the reason trimmed.
func ValidateReason(reason string) (string, error) {
	r := strings.TrimSpace(reason)
	if r == "" {
		return "", ErrReasonRequired
	}
	if !utf8.ValidString(r) {
		return "", errors.New("staffauth.ValidateReason: not valid UTF-8")
	}
	if utf8.RuneCountInString(r) > MaxReasonRunes {
		return "", fmt.Errorf("staffauth.ValidateReason: longer than %d characters", MaxReasonRunes)
	}
	for _, c := range r {
		if (c < 0x20 && c != '\n' && c != '\t') || c == 0x7f {
			return "", errors.New("staffauth.ValidateReason: contains a control character")
		}
	}
	return r, nil
}

// Section is one typed section of the availability envelope (plan 06
// 18.3.5). The vocabulary mirrors the availability_inputs.section CHECK.
type Section string

// The three envelope sections.
const (
	// SectionComponents: per component, its reach.
	SectionComponents Section = "components"
	// SectionOrgControls: per org (or platform-wide), ingest and inference
	// controls.
	SectionOrgControls Section = "org_controls"
	// SectionReleaseFlags: release flags (plan 06 18.4).
	SectionReleaseFlags Section = "release_flags"
)

// KnownSections lists every section.
var KnownSections = []Section{SectionComponents, SectionOrgControls, SectionReleaseFlags}

// MaxAvailabilityValueBytes bounds an input value in its compact JSON form.
// The database bounds the stored jsonb text at 8192 bytes; jsonb's text form
// adds at most a space per separator, so half of that is always safe.
const MaxAvailabilityValueBytes = 4096

// availabilityKey is the availability_inputs.key CHECK.
var availabilityKey = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// AvailabilityInput is a validated input: what the store writes.
type AvailabilityInput struct {
	Section Section
	Key     string
	// Value is the compact JSON object.
	Value []byte
}

// ValidateAvailabilityInput checks a section, key and JSON value. The value
// must be a JSON object; the result carries it compacted. What each
// section's object means is M7a.6's schema; this lane stores it opaquely and
// checks only the shape the envelope composer can rely on.
func ValidateAvailabilityInput(section, key string, value []byte) (AvailabilityInput, error) {
	sec, err := ParseSection(section)
	if err != nil {
		return AvailabilityInput{}, err
	}
	if !availabilityKey.MatchString(key) {
		return AvailabilityInput{}, fmt.Errorf("staffauth.ValidateAvailabilityInput: key %q must match %s", key, availabilityKey)
	}
	trimmed := bytes.TrimSpace(value)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return AvailabilityInput{}, errors.New("staffauth.ValidateAvailabilityInput: value must be a JSON object")
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &obj); err != nil {
		return AvailabilityInput{}, fmt.Errorf("staffauth.ValidateAvailabilityInput: value: %w", err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, trimmed); err != nil {
		return AvailabilityInput{}, fmt.Errorf("staffauth.ValidateAvailabilityInput: value: %w", err)
	}
	if compact.Len() > MaxAvailabilityValueBytes {
		return AvailabilityInput{}, fmt.Errorf("staffauth.ValidateAvailabilityInput: value is %d bytes, at most %d", compact.Len(), MaxAvailabilityValueBytes)
	}
	return AvailabilityInput{Section: sec, Key: key, Value: compact.Bytes()}, nil
}

// ParseSection returns the section named s.
func ParseSection(s string) (Section, error) {
	for _, k := range KnownSections {
		if string(k) == s {
			return k, nil
		}
	}
	return "", fmt.Errorf("staffauth.ParseSection: %q is not an availability section", s)
}

// Actor is the staff_actions.actor (and availability_inputs.author) form of a
// staff member: "staff:<staff_id>".
func Actor(staffID string) string { return "staff:" + staffID }

// ActorOperator is the actor of an operator command.
const ActorOperator = "operator"
