package adapter

import "context"

// TerminalSessionFile describes a regular file held by a validated primary
// tool process. ReadPath addresses that open descriptor, while Path is its
// source filename. Callers revalidate descriptor and process ownership after
// the adapter resolves the identity. Neither field contains file contents.
type TerminalSessionFile struct {
	Path     string
	ReadPath string
	Append   bool
	Writable bool
}

// TerminalProcess is a live terminal's primary native tool process. The caller
// proves executable or installed script identity, stops before tool-launched
// descendants, and checks process birth and parent identity around adapter I/O.
// PID alone is not authority and must not be supplied from a historical bridge.
type TerminalProcess struct {
	PID int
	// StartIdentity is the host's stable process-birth identity when available.
	// Linux uses linux:<boot_id>:<proc start ticks>, matching native writer
	// leases. An empty value cannot authorize a lease based on PID alone.
	StartIdentity string
	Files         []TerminalSessionFile
}

// TerminalSessionIdentity is a session identified by vendor-native ownership
// evidence. Evidence is a stable metadata key or source path used to compare
// repeated resolutions; it must never contain credentials or transcript text.
// An empty SessionID means the adapter cannot yet prove the session identity.
type TerminalSessionIdentity struct {
	SessionID string
	Evidence  string
}

// TerminalSessionResolver optionally exposes native process-to-session
// ownership. Implementations read bounded metadata, reject shared/ambiguous
// identities and subagent-only records, and honor cancellation. The caller
// checks the identified session against the captured tool, revalidates the
// live process, and links through the terminal service. Unsupported adapters
// retain their existing discovery; an unresolved supported adapter waits.
type TerminalSessionResolver interface {
	ResolveTerminalSession(context.Context, TerminalProcess) (TerminalSessionIdentity, error)
}

// TerminalNativeExecutable identifies adapters whose installed script is only
// a launcher for a native child. For these adapters the process walk must pass
// through the script and stop at the native executable named by the launch
// registry. Other adapters may bind an exact installed interpreter entrypoint.
type TerminalNativeExecutable interface {
	TerminalNativeExecutableOnly() bool
	TerminalNativeExecutablePaths(launcher string) []string
}

// TerminalScriptExecutable identifies an installed interpreted launcher whose
// primary runtime uses a different script. Returned paths name exact installed
// runtime entrypoints; wrappers and unrelated scripts must not be included.
type TerminalScriptExecutable interface {
	TerminalScriptExecutablePaths(launcher string) []string
}
