package cachetrack

// Test-only accessors: no production code reads these, so they are compiled
// only into this package's tests (including the external cachetrack_test
// package in this directory).

// BucketLabel returns a stable string label for the bucket a Kind
// folds into ("hit" / "write" / "skipped" / "unknown"), so tests
// read bucketOf rather than re-deriving it (the previous external
// liveBucket/bucketLabel mirrors silently drifted from bucketOf
// if a new Kind landed without re-syncing — closing that drift was
// the §15.3 (c) G2-anchor groundwork).
//
// §15.3 implicit-cache kinds return "skipped" — they're skipped
// from the Anthropic §10 gate by design. Use [IsImplicitCacheKind]
// to test for the implicit-cache subset directly.
func BucketLabel(k Kind) string {
	switch bucketOf(k) {
	case bucketHit:
		return "hit"
	case bucketWrite:
		return "write"
	case bucketSkipped:
		return "skipped"
	default:
		return "unknown"
	}
}

// SessionEstimateEMA returns the per-session R6 calibration
// scaling factor for (sessionID, model, scope). Returns a zero
// value when no observations have been recorded for the tuple.
// Read-only.
func (e *Engine) SessionEstimateEMA(sessionID, model, scope string) SessionEMA {
	e.mu.Lock()
	defer e.mu.Unlock()
	s, ok := e.sessions[engineSessionKey{SessionID: sessionID, Model: model, Scope: scope}]
	if !ok {
		return SessionEMA{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.model.EstimateEMA
}
