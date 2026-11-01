package policy

// security_match.go holds the matcher helpers for Event.Security (security
// pillar plan section 4.3: core residue, so the pillar's Match closures and
// the hook context seam share one answer).

// IsWriteCapable reports whether an event may change files: a shell
// command, an MCP call, a config change, or a file write or edit. The hook
// raises the project's dirty marker before such a call proceeds (section
// 4.8), so a commit right after it is never judged on stale scans.
func IsWriteCapable(ev *Event) bool {
	if ev == nil {
		return false
	}
	switch ev.Kind {
	case KindShellExec, KindMCPCall, KindConfigChange:
		return true
	case KindFileAccess:
		return actionIsWrite(ev.ActionType)
	}
	return false
}

// SecurityPostureOf returns the event's posture state, reading a missing
// or unset state as unknown (never clean, PR14). An event without
// Security facts (the module inactive) reads as absent.
func SecurityPostureOf(ev *Event) SecurityPosture {
	if ev == nil || ev.Security == nil {
		return SecurityPostureAbsent
	}
	if ev.Security.Posture == "" {
		return SecurityPostureUnknown
	}
	return ev.Security.Posture
}
