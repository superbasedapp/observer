package intervention

// processControlBackends is the table of operating systems with an
// identity-safe process-control backend (process_linux.go). Every other OS
// builds process_other.go, whose Inspect and Acquire report ErrUnsupported:
// on those the node process cutoff is not available by design, which callers
// must report as "not supported on this OS", never as a verification failure
// (WINNODE item 3).
var processControlBackends = map[string]bool{
	"linux": true,
}

// ProcessControlSupportedOn reports whether goos (a runtime.GOOS value) has a
// process-control backend.
func ProcessControlSupportedOn(goos string) bool {
	return processControlBackends[goos]
}
