// Package sandboxadopt is the pure decision layer of re-adopting a LOCAL
// container run after its host helper or the daemon went away (sandbox
// plan v2 section 5.5 and gap G50, lane GATES-SBX), and of the Podman
// checkpoint and restore that re-enters through the same rules.
//
// It decides from facts only and does nothing: whether the engine kept the
// container (engine.go, one row per engine mode), whether a run is offered
// for re-adoption, held while an update waits on it, or reaped as today
// (adopt.go, an ordered table walked top-down), and whether a checkpoint or
// a restore may run and where its export goes (checkpoint.go). Every fact
// is read by the caller: the Engine API client is internal/sandboxengine,
// and the run records, files and terminals are cmd/observer's
// (sandbox_readopt*.go).
//
// The package is pure: no database/sql, net, net/http, os, os/exec or
// fsnotify, and no observer-internal import (imports_test.go pins it).
package sandboxadopt
