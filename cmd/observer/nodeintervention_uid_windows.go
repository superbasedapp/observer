//go:build windows

package main

// nodeInterventionAuthorityUID is the OS user id every caller passes to the
// node intervention authority (the launch admission, the posture report and
// the `observer org status` control line). Windows has no POSIX uid
// (os.Getuid is -1, which the authority reads as "inputs unavailable" and so
// refused every managed launch on a native Windows node, Windows 11 Pro live
// run PT-02, and reported the posture and the control line as unverifiable).
// The launch path uses only the decision's budget binding and signals no
// process, and the process intervention that does bind a uid is Linux-only
// (internal/intervention binding_other.go), so 0 is a defined, inert value
// here.
func nodeInterventionAuthorityUID() int { return 0 }
