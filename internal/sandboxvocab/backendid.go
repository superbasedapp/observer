package sandboxvocab

// maxBackendIDLen bounds a backend id.
const maxBackendIDLen = 32

// ValidBackendID reports whether id has the shape of a backend registry id:
// 1 to 32 lower-case letters, digits, dashes and underscores. It is the one
// id rule the registry (internal/sandboxbackend, pinned by its coverage
// test), [terminal.sandbox].backends and the org's managed sandbox body all
// obey. The underscore is there because the registry's own process_lite
// carries one: a dash-only rule refused it, so the row could not be
// configured at all (Linux live check 2026-10-23, LIN-1 F1).
func ValidBackendID(id string) bool {
	if id == "" || len(id) > maxBackendIDLen {
		return false
	}
	for _, r := range id {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}
