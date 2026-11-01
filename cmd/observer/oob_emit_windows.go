//go:build windows && !sbo_omit_terminals

package main

import (
	"io"
	"os"
	"time"

	"github.com/marmutapp/superbased-observer/internal/termoob"
)

// oob_emit_windows.go is the launcher's OOB emitter on native Windows. A
// daemon-spawned launcher there has no inherited fd 3 (the ConPTY child
// inherits no handles, sandbox plan section 5.6), so only a sandbox driver
// that brings its own stream emits: the MXC driver's box-side launcher
// (lane SBX-P6) writes to its run's loopback port, where the host helper
// treats every frame as an untrusted box claim (it can only lower what the
// daemon believes: a session id it forwards is marked discovered). Every
// other Windows invocation stays a no-op, as before.

// envOOBBox marks the one box process that may open the box OOB stream
// (the inner launcher). The launcher unsets it at once, so the tool and the
// hooks it starts never inherit it. Its OBSERVER_OOB_ prefix keeps it in
// isInternalChildEnv's scrub of every daemon launch.
const envOOBBox = "OBSERVER_OOB_BOX"

// boxOOBStream opens a driver's box OOB stream and the token its Hello
// carries; nil (the default) means no driver offers one.
var boxOOBStream func() (io.WriteCloser, string, bool)

// emitOOBLaunchHello opens the box OOB stream when this process is the
// inner launcher of a driver that offers one, authenticates it and emits
// launcher_started; the returned finalizer emits tool_exec_end.
func emitOOBLaunchHello() func(exitCode int) {
	noop := func(int) {}
	ensureBoxDetected()
	if os.Getenv(envOOBBox) != "1" || boxOOBStream == nil {
		return noop
	}
	_ = os.Unsetenv(envOOBBox)
	w, token, ok := boxOOBStream()
	if !ok {
		return noop
	}
	enc := termoob.NewEncoder(w)
	if err := enc.WriteHello(termoob.Hello{AuthToken: token, PID: os.Getpid()}); err != nil {
		_ = w.Close()
		return noop
	}
	oobChanMu.Lock()
	oobEncoder, oobBoxClaims = enc, true
	oobChanMu.Unlock()
	_ = enc.WriteLifecycle(termoob.Lifecycle{Phase: termoob.PhaseLauncherStarted, At: time.Now().UnixNano()})
	return func(exitCode int) {
		oobChanMu.Lock()
		_ = enc.WriteLifecycle(termoob.Lifecycle{Phase: termoob.PhaseToolExecEnd, ExitCode: &exitCode, At: time.Now().UnixNano()})
		oobEncoder, oobBoxClaims = nil, false
		oobChanMu.Unlock()
		_ = w.Close()
	}
}
