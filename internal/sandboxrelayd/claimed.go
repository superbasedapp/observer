package sandboxrelayd

// SessionClaim reports whether runID's own relayed hooks already speak for
// session id (the claim table claimSessions keeps, its one owner), and
// whether that claim was fresh: the node recorded no session of that id
// when the run first claimed it, so the run started it rather than resumed
// a session that existed before (the P-032 resume rule lets a run resume
// its own project's session, a host session included). It reads the table
// only: it never claims and never releases. The proxy's session fold of an
// injected local run (F-003, OSH-R-150; audit FU3-A1) folds a turn onto a
// session only when both hold.
func (d *Daemon) SessionClaim(runID, id string) (claimed, fresh bool) {
	if d == nil || runID == "" || id == "" {
		return false, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	owner, ok := d.sessions[id]
	if !ok || owner != runID {
		return false, false
	}
	return true, d.fresh[id]
}
