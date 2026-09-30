// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package orgclient

import (
	"github.com/marmutapp/superbased-observer/internal/dpop/jose"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// SetAgentAccessKeyStore injects the per-device agent-access key slot
// (Agent Access P1; keychain first, hardened 0600 file fallback) so every push can carry
// PushEnvelope.SourceNodeKey (P4 W4e, R8.30.a). Safe to leave unset: the
// envelope then omits the key and the server keys this node's relay rows
// 'member:' || member_id, the pre-P4 compat shape.
func (c *Client) SetAgentAccessKeyStore(keys AgentAccessKeyStore) { c.agentAccessKeys = keys }

// SourceNodeKeyForKey derives the envelope's source_node_key from a device
// key: the SHA-256 of its RFC 7638 public-key thumbprint - the SAME
// thumbprint the registration rail recorded as agent_credential.key_thumbprint,
// which is what lets the server bind the two. Pure.
func SourceNodeKeyForKey(k AgentAccessKey) (string, error) {
	if k.Signer == nil {
		return "", ErrNoSecret
	}
	jwk, err := jose.PublicJWK(k.Signer.Public(), k.Alg, "")
	if err != nil {
		return "", err
	}
	jkt, err := jwk.Thumbprint()
	if err != nil {
		return "", err
	}
	return orgcontract.SourceNodeKeyFromThumbprint(jkt), nil
}

// sourceNodeKey is the push-time accessor: "" whenever the slot is unwired,
// empty, or unreadable - a node that cannot name its device key still pushes
// (member-keyed on the server), it never fails a push over identity
// enrichment. Read on every push like the bearer, never cached, so a key
// re-generated after an EXPIRED registration is picked up on the next tick.
func (c *Client) sourceNodeKey() string {
	if c == nil || c.agentAccessKeys == nil {
		return ""
	}
	k, err := c.agentAccessKeys.LoadAgentAccessKey()
	if err != nil {
		return ""
	}
	key, err := SourceNodeKeyForKey(k)
	if err != nil {
		return ""
	}
	return key
}
