package mcprelay

import "github.com/marmutapp/superbased-observer/internal/mcprelay/localpdp"

// attest.go is the parent-process attestation seam (R8.24.o / B12): the
// stdio wrapper was SPAWNED by the AI client, so its parent process IS the
// client - but "read the parent" is not enough. The derivation is an
// OS-specific VERIFIED parent identity (the running executable's bytes,
// hashed from the kernel's own view of the process image, checked against
// the signed registered-client list, with a start-time re-read so a PID
// reused mid-check cannot pass). Any unknown / racy / unsupported case
// DOWNGRADES to `configured` (the node-wide principal); nothing here ever
// raises above what the platform proved.

// ParentIdentity is the attestation result for the wrapper's parent.
type ParentIdentity struct {
	// PID is the parent pid observed; Exe the executable path the kernel
	// reports; SHA256 the hex digest of the running image (Linux).
	PID    int
	Exe    string
	SHA256 string
	// Agent / Product are the registered client the image matched
	// ("agent:claude-code" / "claude-code"); empty when unverified.
	Agent, Product string
	// Attestation is process_attested (verified) or configured.
	Attestation string
	// Reason explains a downgrade (logged, never a secret).
	Reason string
}

// ClientRegistry is the signed registered-client list the verified parent
// is matched against: an executable path AND the digest of its running
// image must both be listed for one product client.
type ClientRegistry interface {
	Match(exePath, sha256Hex string) (agent, product string, ok bool)
}

// StaticClientRegistry is a ClientRegistry over fixed rows.
type StaticClientRegistry []RegisteredClient

// RegisteredClient is one signed registered-client row as the node sees it.
type RegisteredClient struct {
	Agent   string
	Product string
	// Exe is the executable path (exact) and SHA256 its image digest.
	Exe    string
	SHA256 string
}

// Match implements ClientRegistry.
func (s StaticClientRegistry) Match(exePath, sha string) (string, string, bool) {
	for _, c := range s {
		if c.Exe == exePath && c.SHA256 == sha && c.SHA256 != "" {
			return c.Agent, c.Product, true
		}
	}
	return "", "", false
}

// Attestor verifies the wrapper's parent process.
type Attestor interface {
	Attest(reg ClientRegistry) ParentIdentity
}

// configured is the honest downgrade result.
func configured(pid int, reason string) ParentIdentity {
	return ParentIdentity{PID: pid, Attestation: localpdp.AttestConfigured, Reason: reason}
}

// DefaultAttestor returns the platform attestor: a /proc-backed verifier on
// Linux; an honest always-configured attestor elsewhere this wave (macOS
// audit-token / code-signing and Windows Authenticode are follow-ups).
func DefaultAttestor() Attestor { return defaultAttestor() }
