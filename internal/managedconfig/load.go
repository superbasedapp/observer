package managedconfig

// Load reads this OS's fixed ceiling source and decides (see the package
// doc). lastKnown is the caller's stored last-known explicit set (with its
// catalog version and source hash), or nil when none was ever stored; the
// caller persists Result.Ceiling when Result.Persist is true.
func Load(lastKnown *Ceiling) Result {
	return Decide(probeOS(), lastKnown)
}

// LoadAttach reads this OS's fixed source (the same one Load reads, with the
// same checks) and decides its attach policy (attach.go). The node's attach
// and detach entry points call it.
func LoadAttach() AttachResult {
	return DecideAttach(probeOS())
}
