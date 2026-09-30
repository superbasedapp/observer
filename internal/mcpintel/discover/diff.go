// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package discover

import (
	"sort"
	"strings"
)

// Candidate sources (the mcp_discovery_candidate.source CHECK). Diff emits the
// first two; proxy_tools / hook are reserved vocabulary for later feeds.
const (
	SourceGuardPin     = "guard_pin"
	SourceMCPInventory = "mcp_inventory"
)

// InventoryItem is one node-reported configured MCP server - the plain form
// of an orgcontract.MCPInventoryRow after the server has bound its
// source_scope. The raw locator fields (Name, URL, Command, Client, Args,
// EnvKeys, ConfigPathHash) are EMPTY on a reduced (share-off) row; Scope,
// Fingerprint, NameHash, Transport and the times are always present.
type InventoryItem struct {
	Scope          string
	Fingerprint    string
	NameHash       string
	Transport      string
	Name           string
	URL            string
	Command        string
	Client         string
	Args           []string
	EnvKeys        []string
	ConfigPathHash string
	ObservedAt     int64
	FirstSeen      int64
	LastSeen       int64
}

// PinItem is one legacy pin-feed row (orgcontract.GuardPinRow with kind
// mcp_server) under its bound source_scope. Name and Client are raw (the pin
// feed carries them raw; it ships only under shipsRawContent()).
type PinItem struct {
	Scope     string
	Name      string
	Client    string
	Status    string
	FirstSeen int64
	LastSeen  int64
}

// RegistryServer is the registry view the diff and the match need: one
// mcp_server row. Retired rows never match.
type RegistryServer struct {
	ID        string
	Name      string
	Transport string
	URL       string
	Status    string
}

// Evidence is the scrubbed inventory evidence a candidate carries in
// evidence_json: args scrubbed, env KEY names only, the config-path HASH, and
// (pin feed) the node's pin status. Never an env value, never a raw path.
type Evidence struct {
	Args           []string `json:"args,omitempty"`
	EnvKeys        []string `json:"env_keys,omitempty"`
	ConfigPathHash string   `json:"config_path_hash,omitempty"`
	PinStatus      string   `json:"pin_status,omitempty"`
}

// Empty reports whether the evidence carries nothing (stored as NULL).
func (e Evidence) Empty() bool {
	return len(e.Args) == 0 && len(e.EnvKeys) == 0 && e.ConfigPathHash == "" && e.PinStatus == ""
}

// Candidate is one discovery-queue row the ingest owner upserts on
// (org, Source, Scope, Fingerprint). Raw fields are empty when the node did
// not disclose them.
type Candidate struct {
	Source      string
	Scope       string
	Fingerprint string
	NameHash    string
	Transport   string
	Name        string
	URL         string
	Command     string
	Client      string
	FirstSeen   int64
	LastSeen    int64
	Evidence    Evidence
}

// HashOnly reports whether the candidate carries no raw server name - the
// share-off / hash-only shape that can never be adopted (R14.6).
func (c Candidate) HashOnly() bool { return strings.TrimSpace(c.Name) == "" }

// Match vocabulary (MatchRegistry's Rule).
const (
	MatchURL      = "url"
	MatchExact    = "exact"
	MatchSuffix   = "suffix"
	MatchNameHash = "name_hash"
	MatchNone     = "none"
)

// Match is the registry match of one candidate.
type Match struct {
	Registered bool
	Rule       string
	ServerID   string
	ServerName string
}

// matchView is what a match rule reads: the candidate's comparable identity.
type matchView struct {
	orgID    string
	name     string
	nameHash string
	url      string
}

// matchRule is one row of the registry-match table.
type matchRule struct {
	rule string
	hit  func(v matchView, s RegistryServer) bool
}

// lastSegment is a reverse-DNS registry name's server segment
// (io.github.owner/github -> github) - the node pins the client key, not the
// registry name (the existing shadow-MCP view's suffix rule).
func lastSegment(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}

// matchRules is walked top-down; the first hit wins. URL first (the strongest
// identity), then the raw name (exact, then the registry name's last
// segment), then the keyed name hash - the ONLY rule a reduced (hash-only)
// row can satisfy.
var matchRules = []matchRule{
	{MatchURL, func(v matchView, s RegistryServer) bool {
		if v.url == "" || s.URL == "" {
			return false
		}
		a, okA := NormalizeURL(v.url)
		b, okB := NormalizeURL(s.URL)
		return okA && okB && a == b
	}},
	{MatchExact, func(v matchView, s RegistryServer) bool { return v.name != "" && v.name == s.Name }},
	{MatchSuffix, func(v matchView, s RegistryServer) bool { return v.name != "" && v.name == lastSegment(s.Name) }},
	{MatchNameHash, func(v matchView, s RegistryServer) bool {
		if v.nameHash == "" {
			return false
		}
		return v.nameHash == ServerNameHash(v.orgID, s.Name) || v.nameHash == ServerNameHash(v.orgID, lastSegment(s.Name))
	}},
}

// retiredStatus is the registry lifecycle state that never matches.
const retiredStatus = "retired"

// MatchRegistry reports whether a candidate identity (raw name, keyed name
// hash, url - any may be empty) names a live registry server. Servers are
// tried rule by rule (every server for rule 1, then every server for rule 2,
// ...) so a URL match always beats a name match elsewhere in the registry.
func MatchRegistry(orgID, name, nameHash, rawURL string, reg []RegistryServer) Match {
	v := matchView{orgID: orgID, name: strings.TrimSpace(name), nameHash: nameHash, url: rawURL}
	for _, r := range matchRules {
		for _, s := range reg {
			if s.Status == retiredStatus {
				continue
			}
			if r.hit(v, s) {
				return Match{Registered: true, Rule: r.rule, ServerID: s.ID, ServerName: s.Name}
			}
		}
	}
	return Match{Rule: MatchNone}
}

// candidateKey is the dedupe identity (source, scope, fingerprint) - the
// table's UNIQUE minus org_id.
type candidateKey struct{ source, scope, fingerprint string }

// Diff computes the discovery candidates of one push: every inventory item
// and every legacy pin that names NO live registry server. It is idempotent
// and order-independent:
//
//   - inventory items sharing (scope, fingerprint) merge into ONE candidate
//     (earliest first_seen, latest last_seen) - the same remote URL declared
//     in two clients, or a repeated stdio report (R13.7);
//   - a pin is SUPERSEDED (no candidate) when an inventory item of the same
//     scope carries the same keyed name hash: the inventory row is the richer
//     feed for that server, the pin stays the pin/drift feed (R12.10);
//   - output is sorted by (source, scope, fingerprint) for deterministic
//     upserts and tests.
func Diff(orgID string, inv []InventoryItem, pins []PinItem, reg []RegistryServer) []Candidate {
	out := map[candidateKey]*Candidate{}
	covered := map[string]bool{} // scope|nameHash covered by inventory
	for _, it := range inv {
		if it.Scope == "" || it.Fingerprint == "" || it.NameHash == "" {
			continue // not ingestible: the identity is NOT NULL
		}
		covered[it.Scope+"|"+it.NameHash] = true
		if MatchRegistry(orgID, it.Name, it.NameHash, it.URL, reg).Registered {
			continue
		}
		first, last := seenBounds(it.FirstSeen, it.LastSeen, it.ObservedAt)
		k := candidateKey{SourceMCPInventory, it.Scope, it.Fingerprint}
		if c, ok := out[k]; ok {
			mergeSeen(c, first, last)
			fillRaw(c, it)
			continue
		}
		c := &Candidate{
			Source: SourceMCPInventory, Scope: it.Scope, Fingerprint: it.Fingerprint, NameHash: it.NameHash,
			Transport: it.Transport, FirstSeen: first, LastSeen: last,
		}
		fillRaw(c, it)
		out[k] = c
	}
	for _, p := range pins {
		name := strings.TrimSpace(p.Name)
		if p.Scope == "" || name == "" {
			continue
		}
		nameHash := ServerNameHash(orgID, name)
		if covered[p.Scope+"|"+nameHash] {
			continue
		}
		if MatchRegistry(orgID, name, nameHash, "", reg).Registered {
			continue
		}
		first, last := seenBounds(p.FirstSeen, p.LastSeen, 0)
		k := candidateKey{SourceGuardPin, p.Scope, PinLocatorFingerprint(p.Client, name)}
		if c, ok := out[k]; ok {
			mergeSeen(c, first, last)
			continue
		}
		out[k] = &Candidate{
			Source: SourceGuardPin, Scope: p.Scope, Fingerprint: k.fingerprint, NameHash: nameHash,
			Name: name, Client: p.Client, FirstSeen: first, LastSeen: last,
			Evidence: Evidence{PinStatus: p.Status},
		}
	}
	keys := make([]candidateKey, 0, len(out))
	for k := range out {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.source != b.source {
			return a.source < b.source
		}
		if a.scope != b.scope {
			return a.scope < b.scope
		}
		return a.fingerprint < b.fingerprint
	})
	res := make([]Candidate, 0, len(keys))
	for _, k := range keys {
		res = append(res, *out[k])
	}
	return res
}

// seenBounds resolves (first, last) from the row's own values, falling back to
// the observation time, and never lets first exceed last.
func seenBounds(first, last, observed int64) (int64, int64) {
	if last <= 0 {
		last = observed
	}
	if first <= 0 {
		first = last
	}
	if first > last {
		first, last = last, first
	}
	return first, last
}

// mergeSeen widens c's seen window to cover (first, last).
func mergeSeen(c *Candidate, first, last int64) {
	if first > 0 && (c.FirstSeen == 0 || first < c.FirstSeen) {
		c.FirstSeen = first
	}
	if last > c.LastSeen {
		c.LastSeen = last
	}
}

// fillRaw copies the disclosed raw fields of it onto c, keeping the first
// non-empty value. Two items sharing a fingerprint share their locator by
// construction, so only the client can differ between them - and the
// lexically-first client wins, which keeps the merge order-independent.
func fillRaw(c *Candidate, it InventoryItem) {
	if c.Name == "" {
		c.Name = strings.TrimSpace(it.Name)
	}
	if c.URL == "" {
		c.URL = it.URL
	}
	if c.Command == "" {
		c.Command = it.Command
	}
	if it.Client != "" && (c.Client == "" || it.Client < c.Client) {
		c.Client = it.Client
	}
	if c.Evidence.Args == nil && len(it.Args) > 0 {
		c.Evidence.Args = append([]string(nil), it.Args...)
	}
	if c.Evidence.EnvKeys == nil && len(it.EnvKeys) > 0 {
		c.Evidence.EnvKeys = sortedCopy(it.EnvKeys)
	}
	if c.Evidence.ConfigPathHash == "" {
		c.Evidence.ConfigPathHash = it.ConfigPathHash
	}
}
