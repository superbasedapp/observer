package pidbridge

import "context"

// LiveSession returns the bridge row for pid only when it still names a
// live process of the row's tool: the same check the proxy's ancestor walk
// makes before it trusts a hit (liveness plus tool identity on Linux; off
// Linux the process table cannot be read and a row is trusted unchanged,
// as there). A stale row for a recycled pid is a miss, never a wrong
// session. It reads one row and walks nothing: the caller supplies the pid
// (lane cli-2's launch initiator walks a launching process's ancestry with
// peerproc.Ancestors and asks here per ancestor).
func (s *Store) LiveSession(ctx context.Context, pid int) (Entry, bool, error) {
	e, hit, err := s.Lookup(ctx, pid)
	if err != nil || !hit {
		return Entry{}, false, err
	}
	if platformCanValidate && !ValidateLocalProcess(pid, e.Tool) {
		return Entry{}, false, nil
	}
	return e, true, nil
}
