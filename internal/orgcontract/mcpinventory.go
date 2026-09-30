// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package orgcontract

// MCPInventoryRow is one MCP server a node's AI clients have CONFIGURED - the
// shadow-MCP discovery inventory wire row (Agent Access P11 item (c),
// docs/plans/agent-access-implementation-plan-2026-09-23.md §11.12b (c);
// rulings R12.10, R13.7, R13.8, R14.6). GuardPinRow stays the pin / drift
// feed; this is the RICHER per-configured-server row that feeds the org's
// mcp_discovery_candidate queue.
//
// It is a CONTENT-BEARING node-push path, composed by
// internal/store/mcpinventory.go through the store.MCPInventoryProviders
// function seam (orgpush.go names no inventory source), in one of TWO shapes:
//
//   - FULL (the node's ShareOptions.shipsRawContent() - teams / enterprise by
//     default, R9.5): every field below, the raw locator included (client,
//     server name, url, command, SCRUBBED args, env KEY names only, the
//     config-path HASH);
//   - REDUCED (share-off): ONLY the identity + metadata an ingest and a
//     replay need - SourceScope, LocatorFingerprint, ServerNameHash,
//     Transport, ObservedAt and the first/last-seen counts - and NO raw
//     locator field (R14.6). It is still ingestible:
//     mcp_discovery_candidate.locator_fingerprint and server_name_hash are
//     NOT NULL, the raw columns are nullable. An INDIVIDUAL (non-org-
//     enrolled) node ships the row at all only under
//     [org_client.share].mcp_activity (R8.30.b), and then in this reduced
//     shape.
//
// Every raw field is omitempty, so the reduced shape is structurally free of
// them on the wire (the share-off negative test pins the key set). The
// server binds SourceScope to the authenticated pushing node (it never trusts
// the row's value) and upserts idempotently on (org, source, source_scope,
// locator_fingerprint); a re-push of the same (node, locator) only moves
// last_seen (replay identity (source_node, locator_fingerprint, observed_at)).
// Optional both directions (compat invariant): a pre-P11 agent sends no
// mcp_inventory key; a pre-P11 server ignores it.
type MCPInventoryRow struct {
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`

	// SourceScope is the reporting node's id as the node knows it (its
	// PushEnvelope.SourceNodeKey, "" before P4 key registration). The server
	// overwrites it with the node key it bound for the push.
	SourceScope string `json:"source_scope"`
	// LocatorFingerprint is the lower-hex sha256 over the canonical locator
	// (internal/mcpintel/discover.LocatorFingerprint): remote = {transport,
	// normalized url}; stdio = {transport, command, scrubbed args,
	// config_path_hash}. Always present.
	LocatorFingerprint string `json:"locator_fingerprint"`
	// ServerNameHash is the typed keyed HMAC of the server name
	// ("hmac-sha256:v1:<hex>", discover.ServerNameHash, keyed per org). Always
	// present.
	ServerNameHash string `json:"server_name_hash"`
	// Transport is the declared transport ("stdio", "http", "sse", ...) -
	// metadata, shipped in every shape.
	Transport string `json:"transport"`
	// ObservedAt is when the node read its client configs for this push
	// (unix seconds).
	ObservedAt int64 `json:"observed_at"`
	// FirstSeen / LastSeen bound the node's sightings (unix seconds): the
	// node's pin first_seen when it has one, else the observation time; the
	// last sighting is this observation.
	FirstSeen int64 `json:"first_seen"`
	LastSeen  int64 `json:"last_seen"`

	// --- RAW locator fields: present ONLY under shipsRawContent() ---

	// Client is the AI client whose config declares the server.
	Client string `json:"client,omitempty"`
	// ServerName is the configured server name (the config map key).
	ServerName string `json:"server_name,omitempty"`
	// URL is a remote server's endpoint, userinfo stripped and scrubbed.
	URL string `json:"url,omitempty"`
	// Command is a stdio server's launch command.
	Command string `json:"command,omitempty"`
	// Args are a stdio server's launch arguments, each SCRUBBED.
	Args []string `json:"args,omitempty"`
	// EnvKeys are the env-var NAMES the entry sets - never a value.
	EnvKeys []string `json:"env_keys,omitempty"`
	// ConfigPathHash is the lower-hex sha256 of the client config file path.
	ConfigPathHash string `json:"config_path_hash,omitempty"`
}
