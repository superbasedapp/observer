package frontdoor

import (
	"net/url"
	"strings"
)

// Identity is the local SuperBased sign-in state, as a credential read on
// this machine reports it (no network call).
type Identity int

// The identity states. The zero value is unknown: this build or this
// surface cannot read the sign-in, so the sentence says nothing about it.
const (
	// IdentityUnknown: the sign-in state could not be read.
	IdentityUnknown Identity = iota
	// IdentitySignedOut: no sign-in is stored on this machine.
	IdentitySignedOut
	// IdentitySignedIn: a sign-in is stored on this machine.
	IdentitySignedIn
)

// Destination is where this machine's data goes: the enrolment in force, or
// none.
type Destination struct {
	// Attached is true when the machine is enrolled with an organization.
	Attached bool
	// OrgName is the organization's display name.
	OrgName string
	// ServerURL is the organization server's address (the name fallback).
	ServerURL string
	// Managed is true for a managed (organization-controlled) enrolment.
	Managed bool
	// MemberEmail is the member the machine is enrolled as.
	MemberEmail string
	// Locked is true when company-managed configuration locks the machine
	// to its destination.
	Locked bool
	// DisplayName is the connection's name as `observer connect` recorded
	// it from the cloud's approval ("your personal dashboard" for an
	// unnamed personal dashboard); "" when the enrolment was made otherwise.
	// It wins over OrgName in the sentence.
	DisplayName string
	// OnlineURL is the connection's online dashboard address as `observer
	// connect` recorded it; "" when not recorded. For a button only: the
	// sentence never contains it.
	OnlineURL string
}

// Facts is everything Sentence needs.
type Facts struct {
	Destination Destination
	Identity    Identity
}

// Kind is the closed vocabulary of destinations the status reports.
type Kind string

// The kinds.
const (
	// KindLocal: data stays on this machine.
	KindLocal Kind = "local"
	// KindManaged: an organization-controlled enrolment.
	KindManaged Kind = "managed"
	// KindIndividual: a node-controlled enrolment.
	KindIndividual Kind = "individual"
)

// Status is the front door's status: the sentence plus the parts it was
// built from, for a surface that wants to style them.
type Status struct {
	// Sentence is the one sentence every surface shows.
	Sentence string `json:"sentence"`
	// Kind is the destination's kind.
	Kind Kind `json:"kind"`
	// Destination is the destination's name ("" when local).
	Destination string `json:"destination,omitempty"`
	// SignedIn is true when a SuperBased sign-in is stored here.
	SignedIn bool `json:"signed_in"`
	// IdentityKnown is false when the sign-in state could not be read.
	IdentityKnown bool `json:"identity_known"`
	// Locked is true when company config locks the destination.
	Locked bool `json:"locked"`
	// DisplayName is the connected dashboard's name for a surface's own
	// line ("" when local).
	DisplayName string `json:"display_name,omitempty"`
	// OnlineURL is the connected dashboard's online address, for a button
	// ("" when local or unknown). Never printed in CLI text.
	OnlineURL string `json:"online_url,omitempty"`
}

// destinationRule is one row of the destination table.
type destinationRule struct {
	name string
	when func(d Destination) bool
	kind Kind
}

// destinationRules picks the destination's kind, top-down. One test case
// per row.
var destinationRules = []destinationRule{
	{name: "not attached", when: func(d Destination) bool { return !d.Attached }, kind: KindLocal},
	{name: "managed", when: func(d Destination) bool { return d.Managed }, kind: KindManaged},
	{name: "individual", when: func(Destination) bool { return true }, kind: KindIndividual},
}

// Sentence builds the status from facts.
func Sentence(f Facts) Status {
	kind := KindIndividual
	for _, r := range destinationRules {
		if r.when(f.Destination) {
			kind = r.kind
			break
		}
	}
	st := Status{
		Kind:          kind,
		SignedIn:      f.Identity == IdentitySignedIn,
		IdentityKnown: f.Identity != IdentityUnknown,
		Locked:        f.Destination.Attached && f.Destination.Locked,
	}
	var b strings.Builder
	if kind == KindLocal {
		b.WriteString("Local only")
	} else {
		st.Destination = destinationName(f.Destination)
		st.DisplayName = st.Destination
		st.OnlineURL = onlineURL(f.Destination)
		name := st.Destination
		if strings.TrimSpace(f.Destination.DisplayName) != "" {
			// Only a recorded display name is a phrase to capitalize; a
			// server host or the "an organization" fallback is printed as is.
			name = capitalizeFirst(name)
		}
		b.WriteString(name)
		b.WriteString(" (")
		b.WriteString(string(kind))
		if st.Locked {
			b.WriteString(", locked")
		}
		b.WriteString(")")
		if e := strings.TrimSpace(f.Destination.MemberEmail); e != "" {
			b.WriteString(" as ")
			b.WriteString(e)
		}
	}
	if st.SignedIn {
		b.WriteString(" · signed in to superbased")
	}
	st.Sentence = b.String()
	return st
}

// destinationName is the connection's recorded name, else the
// organization's name, else its server's host, else "an organization".
func destinationName(d Destination) string {
	if n := strings.TrimSpace(d.DisplayName); n != "" {
		return n
	}
	if n := strings.TrimSpace(d.OrgName); n != "" {
		return n
	}
	if u, err := url.Parse(strings.TrimSpace(d.ServerURL)); err == nil && u.Host != "" {
		return u.Host
	}
	return "an organization"
}

// onlineURL is the connection's recorded online address, else the
// organization server's own address (a team dashboard is served there), for
// a button. Only an absolute http(s) URL is passed on.
func onlineURL(d Destination) string {
	for _, raw := range []string{d.OnlineURL, d.ServerURL} {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil {
			return u.String()
		}
	}
	return ""
}

// capitalizeFirst upper-cases the first letter of a recorded display name
// that opens the sentence ("your personal dashboard" reads "Your personal
// dashboard"). A host name is never passed here.
func capitalizeFirst(s string) string {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return s
	}
	return string(s[0]-('a'-'A')) + s[1:]
}
