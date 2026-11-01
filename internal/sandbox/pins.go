package sandbox

import "path/filepath"

// PinMount is one mount a pin may lie under, as a non-bwrap driver composes
// it: its target path in the box and whether it is a read-write bind of the
// same host path. A read-only bind, a hidden directory and a tmpfs are all
// Writable false.
type PinMount struct {
	Target   string
	Writable bool
}

// PinWritable reports whether pin may be bound read-write onto itself among
// mounts (lane SHR-FOLLOWUPS audit finding 1, ledger SBX-BE-10): the NEAREST
// mount enclosing it (the deepest target pin lies strictly inside) must be a
// read-write bind. Being inside some read-write bind is not enough: a
// read-only bind nested in a write bind (an extra_ro_binds repository, a tool
// bin directory, a runtime directory) would otherwise have its .git reopened
// writable by a pin mounted over it. A pin that is itself a mount target, or
// that no mount encloses, is not writable; when two mounts share the nearest
// target, any read-only one wins. The oci and Apple container rows both call
// it (one rule, two drivers); bwrap's planner orders its own binds instead.
func PinWritable(pin string, mounts []PinMount) bool {
	pin = filepath.Clean(pin)
	best, writable := -1, false
	for _, m := range mounts {
		if m.Target == "" {
			continue
		}
		t := filepath.Clean(m.Target)
		if t == pin {
			return false
		}
		if !isWithin(pin, t) {
			continue
		}
		switch d := len(t); {
		case d > best:
			best, writable = d, m.Writable
		case d == best:
			writable = writable && m.Writable
		}
	}
	return best >= 0 && writable
}
