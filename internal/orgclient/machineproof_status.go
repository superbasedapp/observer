package orgclient

import (
	"errors"
	"syscall"
)

// Machine-proof status (WINNODE item 4). On Windows the machine key lives in
// the Windows credential store only: there is deliberately no file fallback
// (agentaccess_keyfile_other.go: no O_NOFOLLOW refusal and no owner/ACL check
// to make one safe), unlike the bearer, which falls back to a file. A process
// with no interactive logon session (an SSH key logon, a WMI-started process,
// session 0) cannot read or write that store, so its requests carry no machine
// proof. That absence is made loud and named here instead of a file fallback.

// errNoSuchLogonSession is Windows ERROR_NO_SUCH_LOGON_SESSION (1312), what
// CredReadW / CredWriteW return to a process with no logon session. The
// keyring library returns the raw errno. Linux errno values stay far below
// it, so the comparison is safe on every OS.
const errNoSuchLogonSession syscall.Errno = 1312

// machineProofReasons maps a machine-key error to the reason an operator
// reads, top-down; the last row is the catch-all.
var machineProofReasons = []struct {
	match  func(error) bool
	reason func(error) string
}{
	{
		match: func(err error) bool { return errors.Is(err, errNoSuchLogonSession) },
		reason: func(error) string {
			return "no Windows logon session (the Windows credential store that holds the machine key needs the developer's interactive sign-in; an SSH key logon, a WMI-started process or a session 0 service has none)"
		},
	},
	{
		match:  func(error) bool { return true },
		reason: func(err error) string { return "the OS credential store refused the machine key: " + err.Error() },
	},
}

// MachineProofUnavailableReason names why a machine-key error leaves this
// process without machine proof.
func MachineProofUnavailableReason(err error) string {
	for _, r := range machineProofReasons {
		if r.match(err) {
			return r.reason(err)
		}
	}
	return ""
}

// MachineProofState is one process's machine-proof outcome.
type MachineProofState struct {
	// Known is false before the process attempted a proof.
	Known     bool
	Available bool
	Reason    string
}

// SetMachineProofSink receives every CHANGE of this process's machine-proof
// outcome (the daemon persists it for doctor, org status and the dashboard).
func (c *Client) SetMachineProofSink(sink func(MachineProofState)) { c.machineProofSink = sink }

// MachineProof is this process's last machine-proof outcome.
func (c *Client) MachineProof() MachineProofState {
	st := &c.machineKeyState
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.proof
}

// ProbeMachineProof reads the machine key slot without creating a key, for a
// command that reports this process's own view. A slot that holds no key yet
// is available: the next request that names the machine creates one.
func (c *Client) ProbeMachineProof() MachineProofState {
	if c.machineKeys == nil {
		return MachineProofState{}
	}
	if _, err := c.machineKeyRing(); err != nil {
		return MachineProofState{Known: true, Reason: MachineProofUnavailableReason(err)}
	}
	return MachineProofState{Known: true, Available: true}
}

// machineKeyNoticeKey names the machine-key warning's notice marker.
const machineKeyNoticeKey = "org-machine-key"

// SetNoticeDir names the observer dir whose notices/ markers make a routine
// warning print once per install and state (WINNODE2, section 16c).
func (c *Client) SetNoticeDir(dir string) { c.noticeDir = dir }

// noteMachineProof records one attempt's outcome. A change is logged once
// (an unavailable proof as a warning naming the reason, a recovered one as
// info) and handed to the sink; an unchanged outcome logs nothing, so a node
// without a logon session warns once per process, not on every request. With
// a notice dir the unavailable warning prints once per install and reason:
// over SSH every CLI call is a new process, and it printed on each.
func (c *Client) noteMachineProof(next MachineProofState) {
	st := &c.machineKeyState
	st.mu.Lock()
	changed := st.proof != next
	prev := st.proof
	st.proof = next
	st.mu.Unlock()
	if !changed {
		return
	}
	switch {
	case !next.Available && !noticeFirst(c.noticeDir, machineKeyNoticeKey, "unavailable: "+next.Reason):
		// Already said on this install for this reason (WINNODE2, 16c);
		// the daemon's persisted report keeps saying it in doctor, org
		// status and the dashboard.
		c.logger.Debug("org machine key unavailable (reported once per install)", "reason", next.Reason)
	case !next.Available:
		c.logger.Warn("org machine key unavailable; requests carry no machine proof, so machine-scoped grants and the machine's budget binding are withheld until it is",
			"reason", next.Reason)
	case prev.Known:
		c.logger.Info("org machine key available again; requests carry machine proof")
	}
	if c.machineProofSink != nil {
		c.machineProofSink(next)
	}
}
