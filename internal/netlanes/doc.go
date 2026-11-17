// Package netlanes is the user-facing list of every network lane the
// Observer node binary declares: what each one sends, where to, what starts
// it, whether it is on by default, and how to turn it off.
//
// It is the ONE source for that list. `observer privacy` prints it (and
// renders it as Markdown with --markdown for the README), and
// tests/invariant/netlanes_coverage_test.go checks it against the developer
// lane table in tests/invariant/egress_lanes_test.go: every lane that can
// leave the machine must be named by a row here, and every row must name
// only declared lanes. A new egress lane therefore cannot ship without a
// plain-language row.
//
// Pure data and formatting: no network, no file system, no config.
package netlanes
