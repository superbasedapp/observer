//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep

package main

import (
	"strconv"

	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// engineCoverageNote is the doctor's line for an engine manifest the node
// refused because it names no entry for this platform and revokes
// nothing (content.ContentReasonNotCoveredHere, WINFIX4 audit finding 6):
// the last good manifest and engine stay. "" when the last update did not
// fail that way.
func engineCoverageNote(st content.State, goos, goarch string) string {
	if st.LastFailure != content.ContentReasonNotCoveredHere {
		return ""
	}
	kept := "no engine manifest was accepted before, so the compiled pins hold"
	if st.Accepted != nil {
		kept = "the last good one (manifest version " + strconv.FormatInt(st.Accepted.ManifestVersion, 10) + ") stays in use"
	}
	return "engine manifest: not_covered_here: the newest one (" + st.LastFailureAt + ") names no engine for " + goos + "/" + goarch + " and revokes nothing; " + kept
}
