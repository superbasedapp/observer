// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package discover

import (
	"strings"
)

// Candidate lifecycle (the mcp_discovery_candidate.status CHECK).
const (
	StatusNew       = "new"
	StatusReviewed  = "reviewed"
	StatusAdopted   = "adopted"
	StatusDismissed = "dismissed"
)

// Refusal codes PlanAdopt returns. They are stable wire codes: the admin API
// surfaces them verbatim and the UI keys its copy on them.
const (
	// RefuseAlreadyAdopted: the candidate already became a registry row.
	RefuseAlreadyAdopted = "already_adopted"
	// RefuseNeedsNodeDisclosure: the candidate carries no raw locator - a
	// share-off / hash-only row (only server_name_hash), or a legacy pin-feed
	// row (a name but no url / command). One-click adoption REQUIRES the raw
	// locator (R14.6); the UI shows "needs node disclosure" until an
	// authorized raw name + locator arrives from the node.
	RefuseNeedsNodeDisclosure = "needs_node_disclosure"
	// RefuseAlreadyRegistered: a live registry server already matches it.
	RefuseAlreadyRegistered = "already_registered"
)

// Refusal is PlanAdopt's typed "no". It is an error so a caller can wrap it.
type Refusal struct {
	Code   string
	Reason string
	// Match is set for RefuseAlreadyRegistered.
	Match Match
}

// Error implements error.
func (r *Refusal) Error() string { return "discover: adopt refused (" + r.Code + "): " + r.Reason }

// AdoptInput is the candidate PlanAdopt decides on (plain fields - the
// caller's row type never crosses into this package).
type AdoptInput struct {
	Status      string
	Source      string
	Scope       string
	Fingerprint string
	NameHash    string
	Transport   string
	Name        string
	URL         string
	Command     string
	// RequestedName is the admin's registry name override ("" = suggest one).
	RequestedName string
}

// AdoptPlan is the registry row an adoption creates (source 'discovered').
type AdoptPlan struct {
	// Name is the reverse-DNS registry name (the admin's, or SuggestServerName).
	Name string
	// Transport is the mcp_server.transport: streamable_http / sse_legacy for a
	// remote candidate, node_local_stdio for a stdio one (the node relay wraps
	// it; its per-node identity stays the candidate's (source_scope,
	// locator_fingerprint), R13.7).
	Transport string
	// URL is the remote endpoint (empty for stdio: the registry CHECK forbids
	// a url on node_local_stdio).
	URL string
	// NodeManaged is true for a stdio adoption (a node-relay managed entry).
	NodeManaged bool
}

// adoptRule is one refusal row, walked top-down; the first hit refuses.
type adoptRule struct {
	code   string
	reason string
	bad    func(in AdoptInput) bool
}

var adoptRules = []adoptRule{
	{RefuseAlreadyAdopted, "the candidate is already adopted", func(in AdoptInput) bool { return in.Status == StatusAdopted }},
	{
		RefuseNeedsNodeDisclosure, "the node disclosed only the keyed server-name hash; adoption needs the raw server name and locator",
		func(in AdoptInput) bool { return strings.TrimSpace(in.Name) == "" },
	},
	{
		RefuseNeedsNodeDisclosure, "the candidate carries no transport (a legacy pin-feed row has no locator); adoption needs the node's inventory row",
		func(in AdoptInput) bool { return TransportClass(in.Transport) == "" },
	},
	{
		RefuseNeedsNodeDisclosure, "a remote candidate needs its disclosed url",
		func(in AdoptInput) bool {
			if TransportClass(in.Transport) != ClassRemote {
				return false
			}
			_, ok := NormalizeURL(in.URL)
			return !ok
		},
	},
	{
		RefuseNeedsNodeDisclosure, "a stdio candidate needs its disclosed command",
		func(in AdoptInput) bool {
			return TransportClass(in.Transport) == ClassStdio && strings.TrimSpace(in.Command) == ""
		},
	},
}

// PlanAdopt decides whether a candidate can be adopted into the registry and,
// if so, the row it becomes. reg is the live registry (a match refuses with
// RefuseAlreadyRegistered - adopt never creates a duplicate of a registered
// server). A hash-only candidate is ALWAYS refused RefuseNeedsNodeDisclosure,
// never adopted (R14.6).
func PlanAdopt(orgID string, in AdoptInput, reg []RegistryServer) (AdoptPlan, *Refusal) {
	for _, r := range adoptRules {
		if r.bad(in) {
			return AdoptPlan{}, &Refusal{Code: r.code, Reason: r.reason}
		}
	}
	class := TransportClass(in.Transport)
	rawURL := ""
	if class == ClassRemote {
		rawURL = strings.TrimSpace(in.URL)
	}
	if m := MatchRegistry(orgID, in.Name, in.NameHash, rawURL, reg); m.Registered && in.RequestedName == "" {
		return AdoptPlan{}, &Refusal{Code: RefuseAlreadyRegistered, Reason: "registry server " + m.ServerName + " already matches (" + m.Rule + ")", Match: m}
	} else if m.Registered && m.Rule == MatchURL {
		// An explicit name cannot launder a second row for the same endpoint.
		return AdoptPlan{}, &Refusal{Code: RefuseAlreadyRegistered, Reason: "registry server " + m.ServerName + " already serves this url", Match: m}
	}
	name := strings.TrimSpace(in.RequestedName)
	if name == "" {
		name = SuggestServerName(class, in.Fingerprint, in.Name)
	}
	return AdoptPlan{
		Name:        name,
		Transport:   RegistryTransport(in.Transport),
		URL:         rawURL,
		NodeManaged: class == ClassStdio,
	}, nil
}

// segmentMax is the registry name's server-segment length cap (the
// [A-Za-z0-9][A-Za-z0-9_.-]{0,127} rule).
const segmentMax = 128

// SuggestServerName derives a reverse-DNS registry name for an adopted
// candidate: "discovered.<class>-<fp8>/<server segment>". The fingerprint
// prefix keeps two nodes' same-named stdio servers (each its own managed
// entry, R13.7) from colliding on the registry's UNIQUE(org, name); the
// segment is the node's server name with every character outside
// [A-Za-z0-9_.-] replaced by '-'.
func SuggestServerName(class, fingerprint, name string) string {
	if class == "" {
		class = ClassRemote
	}
	fp := strings.ToLower(fingerprint)
	if len(fp) > 8 {
		fp = fp[:8]
	}
	if fp == "" {
		fp = "0"
	}
	return "discovered." + class + "-" + fp + "/" + sanitizeSegment(name)
}

// sanitizeSegment maps a free-form server name onto the registry segment
// alphabet.
func sanitizeSegment(name string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '.', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	s := b.String()
	if s == "" || !isAlnum(s[0]) {
		s = "s" + s
	}
	if len(s) > segmentMax {
		s = s[:segmentMax]
	}
	return s
}

func isAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
