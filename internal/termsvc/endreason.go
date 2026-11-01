package termsvc

import "github.com/marmutapp/superbased-observer/internal/termrun"

// endreason.go records WHY a run ended (Windows 11 Pro run 4, N3): a run
// closed by the dashboard's Stop & close recorded exit code 1 with no reason
// and no daemon log line. Whoever ends a run marks the reason on its live
// handle first (MarkEnding); EndRunByHandle records that reason with the
// exit code, or, when nobody marked one, the reason the exit code alone
// gives (termrun.EndReasonForExit), and logs one line. The reason is kept
// with the run's retained metadata so the dashboard's exit frame can name
// it (EndReasonForHandle).

// MarkEnding records reason as the end reason of the live run on handle,
// before the caller ends it (Stop & close, an org floor, a teardown). A
// reason already marked is kept; an unknown or ended handle is left as it
// is. Reports whether the reason was marked.
func (s *Service) MarkEnding(handle, reason string) bool {
	if reason == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, live := s.byHandle[handle]; !live {
		return false
	}
	m, ok := s.byMeta[handle]
	if !ok || m.endReason != "" {
		return false
	}
	m.endReason = reason
	s.byMeta[handle] = m
	return true
}

// MarkAllEnding marks reason on every live run that has none yet (the
// daemon's graceful stop, before its PTYs are closed) and returns how many
// it marked.
func (s *Service) MarkAllEnding(reason string) int {
	if reason == "" {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for handle := range s.byHandle {
		if m, ok := s.byMeta[handle]; ok && m.endReason == "" {
			m.endReason = reason
			s.byMeta[handle] = m
			n++
		}
	}
	return n
}

// EndReasonForHandle is the end reason recorded (or marked) for handle's
// run, "" when none is known yet. It reads the retained metadata, so it
// answers through the exited handle's linger.
func (s *Service) EndReasonForHandle(handle string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byMeta[handle].endReason
}

// endReasonFor is the reason a run's end records: the marked one, else
// what the exit code alone says.
func endReasonFor(marked string, exitCode int) string {
	if marked != "" {
		return marked
	}
	return termrun.EndReasonForExit(exitCode)
}
