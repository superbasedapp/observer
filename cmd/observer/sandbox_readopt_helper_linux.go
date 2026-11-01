//go:build linux && !sbo_omit_terminals_sandbox_oci_readopt && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxadopt"
	"github.com/marmutapp/superbased-observer/internal/sandboxengine"
	"github.com/marmutapp/superbased-observer/internal/sandboxnet"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// sandbox_readopt_helper_linux.go is the new host helper of a re-adopted
// local container run (lane GATES-SBX, gap G50): `observer sandbox readopt
// <run>` in the user's own terminal. It re-checks the run against the same
// table the sweep used, serves the run's host services again in the SAME
// per-run socket dir (the one bound into the container: a new directory
// would not be visible inside), with the relay record the sweep re-keyed,
// shows the marker that the scrollback starts empty, records the gap, and
// attaches to the container through the Engine API the way the run's own
// helper did (sandbox_readopt_linux.go has the store and the sweep).

// readoptStaleNames are the files a dead helper leaves in its socket dir;
// only these are removed before the services are served there again.
var readoptStaleNames = []string{sandboxrelayd.BoxRecordName, sandboxrelayd.RelaySocketName, sandbox.ProxySocketName, sandbox.GatewaySocketName}

// readoptHostServices serves the run's host services in its existing
// socket dir: the relay (holding the run's liveness lock and writing the
// re-keyed box record), the model proxy forward and the egress gateway, as
// startHostServices does for a fresh run.
func readoptHostServices(h sandbox.HostArgs) (func(), error) {
	var undo []func()
	stop := func() {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
	}
	if err := readoptSockDirCheck(h.SockDir); err != nil {
		return stop, err
	}
	for _, name := range readoptStaleNames {
		p := filepath.Join(h.SockDir, name)
		if fi, err := os.Lstat(p); err == nil && (fi.Mode().IsRegular() || fi.Mode()&os.ModeSocket != 0) {
			_ = os.Remove(p)
		}
	}
	allow, err := sandboxnet.ParseAllowCIDRs(h.AllowCIDRs)
	if err != nil {
		return stop, err
	}
	// The gateway, host list included, is built before anything is served:
	// a run whose list cannot be read is not re-adopted at all (fail
	// closed, OSH-R-153), rather than coming back with a gateway that has
	// lost [terminal.sandbox].egress_allow_hosts or an org pin of it.
	var gw *sandboxnet.Gateway
	if h.Gateway {
		if gw, err = hostEgressGateway(h, allow); err != nil {
			return stop, fmt.Errorf("the egress host list: %w", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	undo = append(undo, cancel)
	if h.RelayRun != "" {
		relayStop, err := serveRelay(ctx, h)
		if err != nil {
			return stop, fmt.Errorf("capture relay: %w", err)
		}
		undo = append(undo, relayStop)
	}
	if h.ProxyAddr != "" {
		if c, derr := net.DialTimeout("tcp", h.ProxyAddr, 2*time.Second); derr == nil {
			_ = c.Close()
			ln, lerr := net.Listen("unix", filepath.Join(h.SockDir, sandbox.ProxySocketName))
			if lerr != nil {
				return stop, fmt.Errorf("listen for the model proxy: %w", lerr)
			}
			undo = append(undo, func() { _ = ln.Close() })
			target := h.ProxyAddr
			go func() {
				_ = sandboxnet.ServeForward(ctx, ln, func(ctx context.Context) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "tcp", target)
				})
			}()
		}
	}
	if h.Gateway {
		ln, lerr := net.Listen("unix", filepath.Join(h.SockDir, sandbox.GatewaySocketName))
		if lerr != nil {
			return stop, fmt.Errorf("listen for the egress gateway: %w", lerr)
		}
		srv := &http.Server{
			Handler:           gw,
			ReadHeaderTimeout: 30 * time.Second,
			BaseContext:       func(net.Listener) context.Context { return ctx },
		}
		undo = append(undo, func() { _ = srv.Close() })
		go func() { _ = srv.Serve(ln) }()
	}
	return stop, nil
}

// readoptPrepared is a run checked and ready to attach.
type readoptPrepared struct {
	entry readoptEntry
	h     sandbox.HostArgs
	c     *sandboxengine.Client
	eng   readoptEngine
	ct    sandboxoci.ContainerFact
}

// readoptPrepare re-checks runID against the sweep's table.
func readoptPrepare(ctx context.Context, observerDir, runID string) (readoptPrepared, error) {
	var p readoptPrepared
	if !sandboxoci.ValidToken(runID) {
		return p, errors.New("not a run id")
	}
	set := readoptLoadSettings(ctx)
	if !set.active {
		return p, fmt.Errorf("%s: re-adoption is off on this node; select %s in Settings > Components", sandboxadopt.CodeComponentInactive, readoptComponent)
	}
	e := readoptRead(observerDir, runID)
	if !e.hasOffer {
		return p, fmt.Errorf("run %s is not offered for re-adoption (see observer sandbox runs)", runID)
	}
	if e.offer.Checkpointed {
		return p, fmt.Errorf("run %s is checkpointed; restore it first (observer sandbox restore %s)", runID, runID)
	}
	if readoptHelper(observerDir, runID) == readoptHelperHeld {
		return p, fmt.Errorf("run %s already has a live helper", runID)
	}
	if !e.planOK || !e.keptOK {
		return p, fmt.Errorf("%s: the run's kept plan or record is unreadable", sandboxadopt.CodeRecordMissing)
	}
	// Today's settings, floors and backend list, before the engine is
	// touched (audit F4).
	if err := readoptPolicyCheck(e.kept.Policy); err != nil {
		return p, err
	}
	c, err := ociEngineClient(e.plan.Socket, e.plan.APIVersion)
	if err != nil {
		return p, err
	}
	if err := readoptCheckSocket(e.plan); err != nil {
		return p, err
	}
	installID, err := ociInstallID(observerDir)
	if err != nil {
		return p, err
	}
	list, err := c.ContainerList(ctx, sandboxoci.InstallFilter(installID))
	if err != nil {
		return p, fmt.Errorf("%s: %w", sandboxoci.VerdictEngineUnreachable, err)
	}
	var ct sandboxoci.ContainerFact
	found := false
	for _, x := range list {
		if x.Labels[sandboxoci.LabelRun] == runID {
			ct, found = x, true
		}
	}
	if !found {
		return p, fmt.Errorf("%s: run %s has no container", sandboxadopt.CodeNotRunning, runID)
	}
	eng := readoptReadEngine(ctx, c)
	d := sandboxadopt.Decide(readoptFactsFor(ctx, c, observerDir, e, ct, installID, eng, set, readoptNow()))
	if d.Action == sandboxadopt.ActionReap {
		return p, fmt.Errorf("%s: %s", d.Code, d.Reason)
	}
	h, err := readoptHostArgs(e.kept)
	if err != nil {
		return p, err
	}
	return readoptPrepared{entry: e, h: h, c: c, eng: eng, ct: ct}, nil
}

// readoptRunHelper re-adopts runID on t and returns the agent's exit code.
func readoptRunHelper(ctx context.Context, observerDir, runID string, t ociTerm) (int, error) {
	p, err := readoptPrepare(ctx, observerDir, runID)
	if err != nil {
		return sandboxHelperFailCode, err
	}
	stopSvc, err := readoptHostServices(p.h)
	release := sync.OnceFunc(stopSvc)
	defer release()
	if err != nil {
		return sandboxHelperFailCode, fmt.Errorf("the run's host services: %w", err)
	}
	// The gap is recorded before anything of the agent is shown again.
	offer := p.entry.offer
	offer.ReadoptedAt = readoptNow()
	if offer.GapFrom.IsZero() {
		offer.GapFrom = offer.OfferedAt
	}
	_ = readoptWriteFile(readoptRunDir(observerDir, runID), readoptOfferFile, offer)
	fmt.Fprintf(t.out, "%s\r\n", sandboxadopt.RingMarker)
	fmt.Fprintf(t.out, "[observer] capture gap: %s to %s\r\n", offer.GapFrom.Format(time.RFC3339), offer.ReadoptedAt.Format(time.RFC3339))
	code := readoptAttach(ctx, p.c, p.ct.ID, p.eng.id.Engine, t)
	release()
	_ = os.RemoveAll(p.h.SockDir)
	_ = os.RemoveAll(readoptRunDir(observerDir, runID))
	return code, nil
}

// readoptAttach drives an already running container on t through the same
// ociRun the run's own helper used (attach, wait, pumps, resize with a
// repaint), and removes the container when it ends.
func readoptAttach(ctx context.Context, c *sandboxengine.Client, cid string, engine sandboxoci.Engine, t ociTerm) int {
	run := &ociRun{c: c, id: cid, engine: engine, term: t}
	defer run.remove()
	wait, err := c.ContainerWait(ctx, cid, "not-running")
	if err != nil {
		fmt.Fprintf(t.out, "observer sandbox: open the wait: %v\r\n", err)
		return sandboxHelperFailCode
	}
	stream, err := c.ContainerAttach(ctx, cid)
	if err != nil {
		fmt.Fprintf(t.out, "observer sandbox: attach to the container: %v\r\n", err)
		return sandboxHelperFailCode
	}
	run.setStream(stream)
	restore := func() {}
	if t.raw != nil {
		restore = t.raw()
	}
	defer restore()
	run.running.Store(true)
	run.resize(ctx, true)
	go run.pumpInput()
	go run.watch(ctx)
	return run.pumpOutput(ctx, wait)
}
