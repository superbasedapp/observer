//go:build !sbo_omit_security && !sbo_omit_security_deps && (sbo_omit_security_reach_go || sbo_omit_security_scan_osv)

package main

import (
	"context"
	"errors"
)

// security_reach_go_source_omit.go: a build without security.reach.go, or
// without the osv-scanner driver it runs, has no Go source check. The opt-in
// verbs still read and write the record; a run is refused.

const reachSourceCompiled = false

var errReachSourceNotCompiled = errors.New("the Go source check is not in this build (security.reach.go or security.scan.osv is compiled out)")

func (e *depsScanEnv) runReachSource(context.Context, reachSourceOptions) (reachSourceReport, error) {
	return reachSourceReport{}, errReachSourceNotCompiled
}

func reachSourceIsolationAvailable(*depsScanEnv) bool { return false }
