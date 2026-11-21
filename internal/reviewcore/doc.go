// Package reviewcore is the pure rule set of the team review queue (Plane A
// build-out W5-6, lane C10): the assignment-mode and pool vocabularies,
// round-robin picking, the conflict rule that opens an adjudication step,
// inter-reviewer agreement statistics (percent, pairwise and Krippendorff's
// alpha), and the table-driven rules that route negative feedback into a
// review queue.
//
// It does no I/O. The org owner (internal/orgserver/orgeval) and the
// machine twin (internal/obs/store) call it with plain values; it imports
// only internal/scorecore (itself pure).
package reviewcore
