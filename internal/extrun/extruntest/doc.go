// Package extruntest is the fake exec seam for internal/extrun: a recording
// Executor and an in-memory file table, so a test can drive a Runner (or a
// consumer that takes one) without starting a process. The process
// declaration test in tests/invariant uses it to check every recorded run
// against the owning component's Surface.Processes.
package extruntest
