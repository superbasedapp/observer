// Package mcpaccess is the `tools.mcp_access` policy FAMILY body (Agent
// Access plan §11.4 W2b, decision D10): the org-wire JSON shape a policy
// publish carries and the node / gateway later find inside a fetched
// SignedPolicyResource.Body, plus its compiler onto internal/mcpaccess.Spec.
//
// A body is the whole compiled input: the registry view (issuer, org,
// gateway base URI, the policy_gen floor, the virtual servers with their
// member servers) and the grant rows. CompileBody refuses a body that does
// not compile - including the typed feature_unavailable refusals (judge /
// taint / requires_mfa, R8.1) and the passthrough-on-non-bearer error
// (R14.11) - and returns the canonical bytes to sign/hash. Mode is the
// family's observe/enforce posture: observe publishes a body that changes
// no runtime behaviour (plan §11.4 flag step 3).
//
// Pure package: wire shape + compile/validate only; no SQL/HTTP/fsnotify.
package mcpaccess
