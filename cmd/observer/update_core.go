package main

import (
	"context"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/quiesce"
)

// update_core.go holds the two pieces of the update wiring every build needs
// (lane MP-GOV4, T-711): the proxy takes the drain gate whether or not the
// org.update component is compiled in (with it compiled out nothing ever
// closes the gate, so it admits every request), and waitForListener is a
// plain dial loop. Everything else of the update rail is in the update*.go
// files, which a build with -tags sbo_omit_org_update leaves out
// (update_omitted.go stands in for them).

// updateGateOnce guards the process-wide drain gate.
var (
	updateGateOnce sync.Once
	updateGate     *quiesce.Gate
)

// updateDrainGate returns the process's single admission gate.
//
// A package-level singleton rather than a field threaded through
// buildProxy's frozen return arity: there is exactly one proxy and one
// updater per process, and the alternative (a ninth return value on a
// function whose signature is deliberately pinned) would be a worse
// coupling than one accessor with a stated invariant.
func updateDrainGate() *quiesce.Gate {
	updateGateOnce.Do(func() { updateGate = quiesce.NewGate() })
	return updateGate
}

// fileExists reports whether path names something that can be stat'ed. The
// update apply path and the enrolment path (orgenrol_core.go) both use it,
// so it lives in this always-compiled file.
func fileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	_, err := os.Stat(path) //nolint:gosec // G703: a metadata read of a path from Observer's own config
	return err == nil
}

// waitForListener blocks until addr accepts a TCP connection or ctx ends.
//
// It is announceDashboardReady's dial loop without the banner: the update
// handshake needs the same fact ("the listener is actually accepting"), and
// deriving it from a successful dial rather than from "New() returned" is
// what makes a bind failure visible to the watching parent instead of
// reported as a healthy start.
func waitForListener(ctx context.Context, addr string) {
	if strings.TrimSpace(addr) == "" {
		return
	}
	d := net.Dialer{Timeout: 500 * time.Millisecond}
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}
