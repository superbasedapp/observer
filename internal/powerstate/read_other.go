//go:build !linux && !windows

package powerstate

// Read answers Unknown off Linux and Windows: reading the power source on
// macOS needs IOKit or a pmset subprocess, which this package does not use.
func Read() State { return Unknown }
