// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard/mcpsec"
	"github.com/marmutapp/superbased-observer/internal/mcpintel/discover"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// mcpinventory.go composes the shadow-MCP discovery inventory wire
// (orgcontract.MCPInventoryRow; Agent Access P11 item (c),
// docs/plans/agent-access-implementation-plan-2026-09-23.md §11.12b (c);
// rulings R12.10, R13.7, R13.8, R14.6). This file - NOT orgpush.go - is the
// one place the push path reaches the node's MCP inventory, and it reaches it
// ONLY through the MCPInventoryProviders FUNCTION seam the host binds
// (cmd/observer/mcpinventory_wire.go reads the client configs through
// internal/mcp/locate + internal/guard/mcpsec): the store never opens a
// client config file itself, and orgpush.go names no inventory source (the
// RoutingSummaryRow / MCPRelayActivity precedent; the privacy sentinel pins
// it).
//
// TWO shapes, decided at the ONE composition site in orgpush.go by passing
// the shipsRawContent() predicate in:
//
//   - FULL (raw=true): the raw locator rides along - client, server name,
//     url (userinfo stripped, scrubbed), command, SCRUBBED args, env KEY
//     names only, the config-path HASH;
//   - REDUCED (raw=false): only the identity + metadata ingest and replay
//     need - source scope, locator fingerprint, keyed server-name hash,
//     transport, observed / first / last seen - and NO raw locator field
//     (R14.6). The identity is computed from the SAME scrubbed locator in
//     both shapes, so a node flipping share mode keeps its candidate rows.
//
// The fingerprint and the name hash come from internal/mcpintel/discover so
// the node and the org server can never disagree on them.

// MCPInventoryEntry is one configured MCP server as the host's extraction
// read it: the mcpsec inventory unit plus the config file it came from (the
// file path never leaves the node - only its sha256 does, and only in the
// full shape).
type MCPInventoryEntry struct {
	mcpsec.Server
	// ConfigPath is the absolute path of the client config file that declares
	// the server.
	ConfigPath string
}

// MCPInventoryProviders is the host-bound inventory seam. A zero value (a
// Store the host never wired) composes nothing - the envelope stays
// byte-identical to a pre-P11 node.
type MCPInventoryProviders struct {
	// Inventory reads the node's configured MCP servers. Required for the
	// wire to compose anything.
	Inventory func(ctx context.Context) ([]MCPInventoryEntry, error)
	// Probe is an OPTIONAL cheap change token over the inventory's sources
	// (e.g. each client config file's size + mtime), consulted by the
	// snapshot gate so an unchanged inventory is not re-read and re-shipped
	// every tick. nil hashes the full Inventory read instead.
	Probe func(ctx context.Context) (string, error)
	// Now is the observation clock (nil = time.Now).
	Now func() time.Time
}

// SetMCPInventoryProviders wires the inventory seam. Idempotent.
func (s *Store) SetMCPInventoryProviders(p MCPInventoryProviders) { s.mcpInventory = p }

// SelectMCPInventory reads the node's configured MCP servers through the
// provider seam and shapes them into wire rows for orgID. raw selects the
// FULL shape (the caller passes shipsRawContent()); false yields the REDUCED
// shape with no raw locator field. SourceScope is left for the push client
// to stamp (it owns the node key) and the server re-binds it anyway. Rows
// sharing a locator fingerprint (the same remote URL in two clients) fold into
// one, the lexically-first client winning; output is sorted by fingerprint.
func (s *Store) SelectMCPInventory(ctx context.Context, orgID string, raw bool) ([]orgcontract.MCPInventoryRow, error) {
	p := s.mcpInventory
	if p.Inventory == nil {
		return nil, nil
	}
	entries, err := p.Inventory(ctx)
	if err != nil {
		return nil, fmt.Errorf("store.SelectMCPInventory: %w", err)
	}
	if len(entries) == 0 {
		return nil, nil
	}
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	observed := now().UTC().Unix()
	firstSeen, err := s.mcpPinFirstSeen(ctx)
	if err != nil {
		return nil, fmt.Errorf("store.SelectMCPInventory: %w", err)
	}
	byFP := map[string]*orgcontract.MCPInventoryRow{}
	clientOf := map[string]string{} // fp -> the client the kept row came from (both shapes)
	for _, e := range entries {
		name := strings.TrimSpace(e.Name)
		if name == "" {
			continue
		}
		loc := mcpInventoryLocator(e)
		fp := discover.LocatorFingerprint(loc)
		first := observed
		if t, ok := firstSeen[e.Client+"\x00"+name]; ok && t > 0 && t < first {
			first = t
		}
		row := orgcontract.MCPInventoryRow{
			LocatorFingerprint: fp,
			ServerNameHash:     discover.ServerNameHash(orgID, name),
			Transport:          e.Transport,
			ObservedAt:         observed,
			FirstSeen:          first,
			LastSeen:           observed,
		}
		if raw {
			row.Client, row.ServerName = e.Client, name
			row.URL, row.Command = loc.URL, loc.Command
			row.Args = loc.Args
			row.EnvKeys = append([]string(nil), e.EnvKeys...)
			sort.Strings(row.EnvKeys)
			if len(row.EnvKeys) == 0 {
				row.EnvKeys = nil
			}
			row.ConfigPathHash = loc.ConfigPathHash
		}
		if prev, ok := byFP[fp]; ok {
			earliest := min(prev.FirstSeen, first)
			if e.Client < clientOf[fp] {
				*prev = row
				clientOf[fp] = e.Client
			}
			prev.FirstSeen = earliest
			continue
		}
		r := row
		byFP[fp] = &r
		clientOf[fp] = e.Client
	}
	out := make([]orgcontract.MCPInventoryRow, 0, len(byFP))
	for _, r := range byFP {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LocatorFingerprint < out[j].LocatorFingerprint })
	return out, nil
}

// mcpInventoryLocator derives the canonical locator of one entry from its
// SCRUBBED fields: a remote server's URL has its userinfo dropped and every
// part run through the node scrubber; a stdio server's args are scrubbed
// one by one and its config file contributes only its hash.
func mcpInventoryLocator(e MCPInventoryEntry) discover.Locator {
	if discover.TransportClass(e.Transport) == discover.ClassStdio {
		var args []string
		if len(e.Args) > 0 {
			args = make([]string, len(e.Args))
			for i, a := range e.Args {
				args[i] = contentScrubber().String(a)
			}
		}
		return discover.Locator{
			Transport:      e.Transport,
			Command:        contentScrubber().String(e.Command),
			Args:           args,
			ConfigPathHash: discover.ConfigPathHash(e.ConfigPath),
		}
	}
	return discover.Locator{Transport: e.Transport, URL: scrubMCPURL(e.Command)}
}

// scrubMCPURL strips the userinfo (it can only be a credential) and runs the
// node scrubber over the rest, so a token in a query parameter is redacted
// before the URL is fingerprinted or shipped.
func scrubMCPURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if u, err := url.Parse(raw); err == nil && u.User != nil {
		u.User = nil
		raw = u.String()
	}
	return contentScrubber().String(raw)
}

// mcpPinFirstSeen maps (client, name) -> the node's pin first_seen (unix
// seconds) for its pinned MCP servers, through the guard store's own read
// seam (guard.go owns guard_pins). A node with pinning off has no rows; the
// observation time then stands in.
func (s *Store) mcpPinFirstSeen(ctx context.Context) (map[string]int64, error) {
	pins, err := s.LoadGuardPins(ctx, "mcp_server")
	if err != nil {
		return nil, fmt.Errorf("mcp pin first_seen: %w", err)
	}
	out := make(map[string]int64, len(pins))
	for _, p := range pins {
		if !p.FirstSeen.IsZero() {
			out[p.Client+"\x00"+p.Name] = p.FirstSeen.UTC().Unix()
		}
	}
	return out, nil
}

// probeMCPInventory is the snapshot-gate change probe for the inventory
// family (orgsnapgate.go). The provider's own cheap Probe when bound;
// otherwise a sha256 over the inventory's identity-bearing fields (never the
// observation time, which moves every tick). An unwired provider probes as a
// constant, so the family is never recomputed for nothing.
func (s *Store) probeMCPInventory(ctx context.Context) (string, error) {
	p := s.mcpInventory
	if p.Inventory == nil {
		return "mi-unwired", nil
	}
	if p.Probe != nil {
		tok, err := p.Probe(ctx)
		if err != nil {
			return "", fmt.Errorf("store.probeMCPInventory: %w", err)
		}
		return "mi-p" + tok, nil
	}
	entries, err := p.Inventory(ctx)
	if err != nil {
		return "", fmt.Errorf("store.probeMCPInventory: %w", err)
	}
	h := sha256.New()
	for _, e := range entries {
		for _, part := range append([]string{e.Client, e.Name, e.Transport, e.Command, e.ConfigPath}, append(append([]string(nil), e.Args...), e.EnvKeys...)...) {
			h.Write([]byte(part))
			h.Write([]byte{0})
		}
		h.Write([]byte{1})
	}
	return "mi-h" + hex.EncodeToString(h.Sum(nil)), nil
}
