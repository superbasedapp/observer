// Package poll is the low-fidelity polling backend for Process
// Observability (docs/process-observability.md §5.4). It diffs successive
// process-table snapshots into fork/exec/exit events, implementing
// processobs.Backend without any kernel tracing.
//
// It is explicitly APPROXIMATE and must not be presented as complete
// process history: a process born and gone within one poll interval is
// missed entirely, and a re-exec of a surviving pid is not detected. It
// exists so the feature works (and is testable) before the high-fidelity
// Linux eBPF / Windows ETW backends land, and as the dev/test backend.
//
// The snapshot-diff core is pure and cross-platform; the per-OS process
// enumeration is build-tagged (enum_linux.go reads /proc; other OSes return
// ErrUnsupported until their native enumerate lands). enumerate is also an
// injectable Option so the core logic is unit-tested without a real OS.
package poll
