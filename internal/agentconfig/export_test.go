package agentconfig

// SetRelocationsForTest replaces the relocation rules of one FileRow id in
// fileRelocations and returns the function that restores them. Test-only
// (compiled into this package's test binaries alone): it lets the external
// relocation test prove that a rule added to the one owner reaches every
// shared path resolver with no edit there. Never call it from a parallel
// test.
func SetRelocationsForTest(id string, rules []Relocation) (restore func()) {
	old, had := fileRelocations[id]
	fileRelocations[id] = rules
	return func() {
		if had {
			fileRelocations[id] = old
			return
		}
		delete(fileRelocations, id)
	}
}
