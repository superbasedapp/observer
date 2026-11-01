// Package gatetable is the commit gate's section 4.8 decision table (one
// row per posture state, one cell per column) and its helpers, pure: it
// imports internal/policy only. internal/secposture re-exports it, and the
// rule tables in internal/secrules read its managed-floor column for the
// commit gate floor's rows (lane SEC-P4 decision 9).
package gatetable
