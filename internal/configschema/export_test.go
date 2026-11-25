package configschema

// Test-only accessors: production callers use SecretShapedLeaf.

// SecretShaped reports whether a value about to be written holds a string
// that looks like a credential (the injected detector) or a string under a
// credential-named map key. The posture (warn / refuse) is the caller's.
func SecretShaped(v any, detect func(string) bool) bool {
	return secretShaped(v, detect, true)
}
