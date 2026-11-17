// Package trainhalt is the deploy train's halt rule table (plan 06 section
// 18.2.6, plan 07 M11.4): given the signals of one judging window (the
// canary phase, the post-promotion phase, or the staging soak), it says
// whether the train may promote, must halt, or cannot tell (inconclusive).
//
// It is pure: no SQL, no HTTP, no clock. `observer-org train judge` reads
// the window from a file `deploy/saas-ovh/roll.sh` writes (or from the raw
// Prometheus query results roll.sh fetched) and prints [Judge]'s verdict.
// It is not rolloutcore: that package judges node policy rollouts on reject
// and ineffective rates and takes none of these inputs.
//
// The rules are an ordered table ([Rules]); every row is evaluated, and the
// verdict is the worst outcome: one halt halts, else one inconclusive row
// makes the window inconclusive, else the train promotes. An inconclusive
// window never promotes. A missing signal is inconclusive, never a pass.
package trainhalt
