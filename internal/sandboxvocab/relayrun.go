package sandboxvocab

// relayrun.go holds the hosted sandbox relay's run-stamp spellings (live
// run 2 finding N5: relayed api_turns rows had no session). The proxy reads
// them on every request, so they live in this pure leaf rather than in
// internal/sandboxremote, which an always-on daemon path must never link
// (tests/invariant TestSandboxRemoteNotLinkedByDaemonPaths).
// internal/sandboxremote re-exports them under its own names.

// RelayRunHeader names the hosted run a relayed model request came from.
// Only the home side of the run's relay sets it (a value the box sent is
// replaced), and the proxy files the turn under RelaySessionID and never
// forwards the header upstream.
const RelayRunHeader = "X-Observer-Sandbox-Run"

// relayRunIDMax is the longest run id ValidRelayRunID accepts.
const relayRunIDMax = 80

// RekeyID namespaces a box-reported id under the run, so a box can never
// collide with or upgrade another session's rows (sandbox plan v2 section
// 5.7). "" when id is "".
func RekeyID(runID, id string) string {
	if id == "" {
		return ""
	}
	return "rsbx-" + runID + "-" + id
}

// RelaySessionID is the session a relayed model turn of run runID lands
// on: the session the request names, re-keyed like a pulled transcript's
// (RekeyID), or the run's own key when it names none. "" when the run id is
// not one a run carries.
func RelaySessionID(runID, sid string) string {
	if !ValidRelayRunID(runID) {
		return ""
	}
	if sid == "" {
		return "rsbx-" + runID
	}
	return RekeyID(runID, sid)
}

// ValidRelayRunID reports whether s is shaped like a run id (1 to 80 ASCII
// letters, digits, '.', '_' or '-').
func ValidRelayRunID(s string) bool {
	if s == "" || len(s) > relayRunIDMax {
		return false
	}
	for _, c := range s {
		ok := c == '-' || c == '_' || c == '.' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !ok {
			return false
		}
	}
	return true
}
