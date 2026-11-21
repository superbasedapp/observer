//go:build linux && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
)

// terminal_sandbox_openshell_egress_linux.go is the Linux half of the
// openshell driver's egress lane (lane O3): the gateway config's OCSF
// export probe, the daemon's OCSF receiver lifecycle and the host helper's
// box id recorder. The row runs on Linux only, so the other platforms'
// twin does nothing.

// openShellOCSFExport reads the OCSF export keys of the gateway config at
// path (owner-checked, no-follow, 1 MiB, never written). It is the one D3
// probe function (openShellOCSFExportAt).
func openShellOCSFExport(path string) sandboxopenshell.OCSFExport {
	if path == "" {
		return sandboxopenshell.OCSFExport{}
	}
	b, err := openShellReadOwned(path, 1<<20)
	return openShellOCSFExportFrom(path, b, err)
}

// openShellOCSFReceiverFacts gathers the receiver facts for a launch from
// the kernel's socket table and the daemon's marker (audit finding O3-A1).
func openShellOCSFReceiverFacts(stateDir string) sandboxopenshell.OCSFReceiverFacts {
	return openShellReceiverFactsAt("/proc", stateDir, sandboxopenshell.OCSFReceiverListen, os.Getuid())
}

// openShellLoopbackListenAddrs are the /proc/net local-address spellings
// (hex, as the kernel prints them) of the listeners that surely take a
// connection to 127.0.0.1: the loopback address, the IPv4 wildcard, and
// their v4-mapped IPv6 forms. The IPv6 wildcard is apart
// (openShellV6AnyAddr): it takes IPv4 only when dual-stack, which /proc
// does not show; ::1 never does and is not read at all (audit finding
// O3-V5).
var openShellLoopbackListenAddrs = []string{
	"0100007F", "00000000",
	"0000000000000000FFFF00000100007F", "0000000000000000FFFF000000000000",
}

// openShellV6AnyAddr is the IPv6 wildcard [::] as /proc/net/tcp6 prints it.
const openShellV6AnyAddr = "00000000000000000000000000000000"

// openShellProcListener is one listening socket on the receiver's port.
type openShellProcListener struct {
	uid   int
	inode string
	// v6Any: it listens on the IPv6 wildcard (dual-stack not known).
	v6Any bool
}

// openShellReceiverFactsAt gathers the facts under procRoot: every
// listening TCP socket on addr's port that takes loopback connections, its
// owner uid and inode, and whether the process the daemon's marker names
// (the marker's own address must be addr) holds every one of them.
func openShellReceiverFactsAt(procRoot, stateDir, addr string, uid int) sandboxopenshell.OCSFReceiverFacts {
	var f sandboxopenshell.OCSFReceiverFacts
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return f
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return f
	}
	var ls []openShellProcListener
	for _, table := range []string{"net/tcp", "net/tcp6"} {
		ls = append(ls, openShellProcListeners(filepath.Join(procRoot, table), port)...)
	}
	var sure []openShellProcListener
	for _, l := range ls {
		if l.v6Any {
			f.V6AnyListener = true
			continue
		}
		sure = append(sure, l)
	}
	ls = sure
	if len(ls) == 0 {
		return f
	}
	f.Listener, f.ListenerOurUID = true, true
	for _, l := range ls {
		if l.uid != uid {
			f.ListenerOurUID = false
		}
	}
	m, ok := openShellReadOCSFMarker(stateDir)
	if !ok || m.Addr != addr {
		return f
	}
	f.Marker, f.SinkReady = true, m.SinkReady
	held := openShellProcSocketInodes(filepath.Join(procRoot, strconv.Itoa(m.PID), "fd"))
	f.MarkerOwnsListener = true
	for _, l := range ls {
		if !held[l.inode] {
			f.MarkerOwnsListener = false
		}
	}
	return f
}

// openShellProcListeners reads one /proc/net/tcp* table for the LISTEN
// sockets (state 0A) on port whose local address can take loopback
// traffic (surely, or the IPv6 wildcard, marked v6Any).
func openShellProcListeners(path string, port int) []openShellProcListener {
	b, err := os.ReadFile(path) //nolint:gosec // G304: a fixed /proc table
	if err != nil {
		return nil
	}
	want := fmt.Sprintf(":%04X", port)
	var out []openShellProcListener
	for i, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 10 || f[3] != "0A" || !strings.HasSuffix(f[1], want) {
			continue
		}
		local := strings.TrimSuffix(f[1], want)
		v6Any := local == openShellV6AnyAddr
		if !v6Any && !slices.Contains(openShellLoopbackListenAddrs, local) {
			continue
		}
		uid, err := strconv.Atoi(f[7])
		if err != nil {
			continue
		}
		out = append(out, openShellProcListener{uid: uid, inode: f[9], v6Any: v6Any})
	}
	return out
}

// openShellProcSocketInodes are the socket inodes a process's fd dir holds
// (empty when it cannot be read: another user's process, or none).
func openShellProcSocketInodes(fdDir string) map[string]bool {
	out := map[string]bool{}
	ents, err := os.ReadDir(fdDir)
	if err != nil {
		return out
	}
	for _, e := range ents {
		l, err := os.Readlink(filepath.Join(fdDir, e.Name()))
		if err != nil {
			continue
		}
		if in, ok := strings.CutPrefix(l, "socket:["); ok {
			out[strings.TrimSuffix(in, "]")] = true
		}
	}
	return out
}

// openShellEnsureOCSF starts the daemon's OCSF receiver for the row's
// state dir (beside the labelled reaper, while openshell is listed).
func openShellEnsureOCSF(stateDir, observerDir string, logger *slog.Logger) bool {
	return openShellStartOCSFReceiver(stateDir, observerDir, logger)
}

// openShellReleaseOCSF stops it (openshell is no longer listed).
func openShellReleaseOCSF() { openShellStopOCSFReceiver() }

// openShellBoxIDWait bounds how long the host helper asks for its box's id.
const openShellBoxIDWait = 2 * time.Minute

// openShellTrackBoxID starts recording the run's box id in its run dir
// (openShellRecordSandboxID) through the pinned gateway, and returns the
// stop the host helper calls when the box's command has exited.
func openShellTrackBoxID(pf openShellPlanFile, runDir string) func() {
	get := openShellBoxIDGetter(openShellRunner(), pf)
	if get == nil {
		return func() {}
	}
	ctx, cancel := context.WithTimeout(context.Background(), openShellBoxIDWait)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := openShellRecordSandboxID(ctx, get, runDir); errors.Is(err, errOpenShellBoxIDGaveUp) {
			// Said on the run's terminal (audit finding O3-A7): the box
			// keeps running, but its refused connections go unrecorded.
			fmt.Fprintf(os.Stderr, "\r\n[observer: the box's OpenShell id was not read within %s, so its refused connections are not recorded in the refusal audit]\r\n", openShellBoxIDWait)
		}
	}()
	return func() {
		cancel()
		<-done
	}
}
