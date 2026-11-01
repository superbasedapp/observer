//go:build linux

package sandboxrelayd

// idle reports that nothing waits to be sent and no send is in flight. Only
// the Linux relay tests read it (p2d_test.go), so it lives in a Linux test
// file (WINFIX4 lint: unused on Windows).
func (p *pendingHealth) idle() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.sending && !(p.rep.HooksDrifted || p.rep.MissedHeartbeats > 0 || p.rep.Dropped > 0)
}
