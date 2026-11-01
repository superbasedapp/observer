package orgclient

import (
	"sync"
)

// What this process last saw of its own org credential (WINNODE2, issue
// 1b). On Windows the credential's store depends on the logon context: an
// enrolment over SSH writes the 0600 file store, a daemon started at the
// developer's sign-in reads Credential Manager. A daemon that resolves no
// credential cannot push, yet `observer org push-status` showed a running
// loop with an old "Last attempt" from another daemon. Each push cycle now
// records what the pushing process saw; the daemon persists every change
// (cmd/observer/org_daemoncred.go), so the CLI and the dashboard report it
// per daemon instead of a healthy-looking loop.

// CredentialState is one process's view of its own org credential at its
// last push cycle.
type CredentialState struct {
	// Known is false before the process ran a push cycle.
	Known bool
	// Enrolled is true when the process found an enrolment record and could
	// read both the bearer and the agent signing key.
	Enrolled bool
	// Backend names the credential store the process opened ("keychain" or
	// "file"; "" without one).
	Backend string
	// Reason says why the process is not enrolled ("" when Enrolled).
	Reason string
}

// credentialView is the owner of a process's CredentialState.
type credentialView struct {
	mu    sync.Mutex
	state CredentialState
}

// SetCredentialSink receives every CHANGE of this process's credential view
// (the daemon persists it for push-status, org status and the dashboard).
func (c *Client) SetCredentialSink(sink func(CredentialState)) { c.credentialSink = sink }

// Credential is this process's last credential view.
func (c *Client) Credential() CredentialState {
	c.credentialState.mu.Lock()
	defer c.credentialState.mu.Unlock()
	return c.credentialState.state
}

// credentialReasons are the plain sentences noteCredentialMissing uses.
const (
	credentialNoRecord = "no enrolment record in the node database" //nolint:gosec // G101: an operator sentence, not a credential
	credentialNoBearer = "this process cannot read the org credential (bearer) from its credential store"
	credentialNoKey    = "this process cannot read the agent signing key from its credential store"
)

// noteCredential records one push cycle's view and hands a change to the
// sink.
func (c *Client) noteCredential(enrolled bool, reason string) {
	next := CredentialState{Known: true, Enrolled: enrolled, Reason: reason}
	if c.bearers != nil {
		next.Backend = c.bearers.Backend()
	}
	v := &c.credentialState
	v.mu.Lock()
	changed := v.state != next
	v.state = next
	v.mu.Unlock()
	if changed && c.credentialSink != nil {
		c.credentialSink(next)
	}
}
