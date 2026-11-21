package ownagent

import "strings"

// Capture-surface vocabulary for an own-agent session. The session's
// surface kind is "sdk" (programmatic) and its host is the agent name behind
// a prefix that no vendor host token uses.
const (
	// SurfaceKind is the models.SurfaceSDK kind an own-agent session carries.
	SurfaceKind = "sdk"
	// surfaceHostPrefix marks a stored surface_host as a developer-chosen
	// agent name rather than a vendor host token.
	surfaceHostPrefix = "agent:"
	// wireHashPrefix marks the hashed form on the org wire. "#" is outside
	// the normalized name alphabet, so a hash can never be read as a name.
	wireHashPrefix = "agent#"
)

// SurfaceHost is the sessions.surface_host value for an agent name.
func SurfaceHost(agent string) string { return surfaceHostPrefix + agent }

// AgentFromSurfaceHost returns the agent name a stored surface_host carries,
// and whether it is an own-agent host at all.
func AgentFromSurfaceHost(host string) (string, bool) {
	name, ok := strings.CutPrefix(host, surfaceHostPrefix)
	if !ok || name == "" {
		return "", false
	}
	return name, true
}

// WireSurfaceHost decides how a stored surface_host crosses the org push
// wire when it names an own agent. A developer-chosen name can encode a
// client or a project, so it ships raw only when rawContent (the node's
// ShareOptions.shipsRawContent()) is true, and otherwise as a stable hash
// that still groups one agent's sessions. The hash is deliberately unsalted,
// like the other wire hashes (root_path_hash, git_remote_hash): an org-id
// salt would not stop the org server, which knows the id, from confirming a
// guessed name, so it is a grouping key and not a secret (docs/security.md
// OWNAGENT-2). ok is false for a host that is not an own-agent host; the
// caller then applies its normal host vocabulary.
func WireSurfaceHost(stored string, rawContent bool) (wire string, ok bool) {
	name, isAgent := AgentFromSurfaceHost(stored)
	if !isAgent {
		return "", false
	}
	if rawContent {
		return SurfaceHost(name), true
	}
	return wireHashPrefix + shortHash(name, 16), true
}
