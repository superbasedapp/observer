package mcpaccess

// SchemaHint returns a one-line allowed-keys descriptor for the
// tools.mcp_access body, a PROMPT AID for a self-hosted policy-evolution
// reviewer so a small model does not emit stray keys DecodeBody's
// DisallowUnknownFields would reject. It is NOT a validator. The drift
// guard is TestSchemaHintDecodes.
func SchemaHint() string {
	return `A JSON object. Top-level keys (use ONLY these): "mode" (string: "observe" or "enforce"), ` +
		`"registry" (object), "grants" (array). ` +
		`"registry" has keys: "issuer", "org", "gateway_base_uri", "policy_gen" (number), "vservers" (array). ` +
		`Each "vservers" element has keys: "id", "slug", "audience", "sender_constraint" (bearer|dpop|mtls|dpop_or_mtls), "servers" (array). ` +
		`Each "servers" element has keys: "id", "target", "credential_mode", and optionally "snapshot" ` +
		`(object with keys "id", "tools" (array of strings) - the member's active approved snapshot as the registry renders it; omit it when the member has none). ` +
		`Each "grants" element has keys: "id", "ord" (number), "subject", "resource", "action" ` +
		`(discover|list|call|read|subscribe - no wildcard; tasks/get, tasks/update and tasks/cancel are in the vocabulary but a grant on them is refused as feature_unavailable in v1), "effect" (allow|deny|ask), ` +
		`"hierarchy_level" (number), "audit_class" (normal|strict), "conditions", "enabled" (boolean). ` +
		`A grant's "subject" has keys: "kind" (any|user|product|agent_def|agent_kind|env|ws|group), "value". ` +
		`A grant's "resource" has keys: "vserver", "server", "name". ` +
		`A grant's "conditions" has keys: "requires_cred_assurance", "requires_client_attestation", "expires_at" (number). ` +
		`Do not introduce any other key.`
}
