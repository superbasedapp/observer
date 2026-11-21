package main

import (
	"context"
	"fmt"
	"io"
	"time"

	otlpingest "github.com/marmutapp/superbased-observer/internal/ingest/otlp"
	"github.com/marmutapp/superbased-observer/internal/planechoice"
)

// obs_wire_receiver.go is the daemon's native OTLP receiver goroutine
// (native-console Rail A, made vendor-agnostic by T-475), moved out of
// start.go for the AI Apps hot-enable (first-run plan 3.8). It ingests any
// mapped AI tool's own telemetry export (internal/otlpvendor) and, when AI
// Apps is on, the developer's own app traces (Plane A). Gated by
// [ingest.otel] enabled and [observability] enabled (both default off: no
// listener). Loopback-only unless allow_non_loopback, which then requires
// the receiver token. Fail-soft and P1: a bind failure logs, is recorded
// for `observer doctor`, and never cancels a sibling.
//
// What hot-enable changed: with apps (the daemon's appsRuntime) set,
//   - Plane A always reaches the receiver through apps.traces, a switch the
//     enable seam installs the obs handler into without a rebind;
//   - with nothing on, the goroutine waits for an enable request instead of
//     returning, then binds late and answers the request with the outcome;
//   - a bind failure is answered too, and the next enable request retries.
// With apps nil (no dashboard in this process) it behaves as before.

// runOTLPReceiver runs until ctx ends.
func runOTLPReceiver(ctx context.Context, configPath string, stderr io.Writer, apps *appsRuntime) error {
	var reply chan planechoice.Receiver
	answer := func(r planechoice.Receiver) {
		if apps != nil {
			apps.recv.report(r)
		}
		if reply != nil {
			reply <- r
			reply = nil
		}
	}
	// wait parks the goroutine until an enable asks again; false when the
	// daemon stops (or no runtime can ask).
	wait := func() bool {
		if apps == nil {
			return false
		}
		r, ok := apps.recv.await(ctx)
		reply = r
		return ok
	}
	hot := apps != nil && apps.inBuild
	for {
		rcfg, rdb, rcleanup, rerr := loadConfigAndDB(ctx, configPath)
		if rerr != nil {
			answer(planechoice.Receiver{State: planechoice.ReceiverNoAnswer, Error: rerr.Error()})
			return nil
		}
		// The shared OTLP receiver serves logs when [ingest.otel] is on and
		// traces when [observability] is on (the obs subsystem registers its
		// trace handler here, the single host->obs seam, build-tagged). Off
		// only when both are off.
		if !rcfg.Ingest.OTel.Enabled && !rcfg.Observability.Enabled {
			rcleanup()
			answer(planechoice.Receiver{State: planechoice.ReceiverNotRunning})
			if !wait() {
				return nil
			}
			continue
		}
		rlogger := newLogger(rcfg.Observer.LogLevel)
		opts := otlpingest.Options{
			GRPCAddr:         rcfg.Ingest.OTel.GRPCAddr,
			HTTPAddr:         rcfg.Ingest.OTel.HTTPAddr,
			AllowNonLoopback: rcfg.Ingest.OTel.AllowNonLoopback,
			Logger:           rlogger,
		}
		// A receiver opened to the network authenticates every request
		// (SR27-B5, T-475): the shared token is generated once and kept 0600
		// beside the DB. Fail closed: no token, no non-loopback listener.
		if rcfg.Ingest.OTel.AllowNonLoopback {
			tok, terr := resolveLocalTokenFile(otlpIngestTokenPath(rcfg))
			if terr != nil {
				fmt.Fprintf(stderr, "otlp receiver disabled: allow_non_loopback needs a receiver token and it could not be resolved: %v\n", terr)
				rcleanup()
				answer(planechoice.Receiver{
					State: planechoice.ReceiverBindFailed, GRPCAddr: opts.GRPCAddr, HTTPAddr: opts.HTTPAddr,
					Error: "allow_non_loopback needs a receiver token and it could not be resolved: " + terr.Error(),
				})
				if !wait() {
					return nil
				}
				continue
			}
			opts.RequireToken, opts.ReceiverToken = true, tok
			// CLOUDTEL-1 (CA-D18): an active per-environment cloud-session
			// ship token is accepted too.
			opts.AcceptToken = otlpShipTokenAcceptor(ctx, rdb, nil)
			rlogger.Info("otlp receiver: non-loopback bind requires the receiver token header",
				"header", otlpingest.HeaderEdgeToken, "token_file", otlpIngestTokenPath(rcfg))
		}
		// Plane A (internal/obs) gets every trace resource no coding-tool
		// mapping row claims; Plane B (the vendor table) gets the claimed
		// ones, plus every logs export. guardPlaneA keeps a developer's own
		// agent's spans (sbo.agent) out of Plane A in every configuration
		// (PT-55, otlp_planeguard.go).
		var planeA otlpingest.TraceHandler
		if hot {
			// Hot-enable: Plane A goes through the switch. AI Apps on at
			// start installs its handler here; turned on later, the enable
			// seam installs it (obs_wire_apps.go).
			if rcfg.Observability.Enabled && !apps.traces.On() {
				apps.traces.Set(guardPlaneA(newObsTraceHandler(ctx, rcfg, rdb, rlogger), rlogger))
			}
			planeA = apps.traces.Handle
		} else {
			planeA = guardPlaneA(newObsTraceHandler(ctx, rcfg, rdb, rlogger), rlogger)
		}
		opts.TraceHandler = planeA
		if rcfg.Ingest.OTel.Enabled {
			// The vendor table and logs handler belong to ingest.otlp
			// (otlp_ingest.go / otlp_ingest_omit.go).
			opts.Handler, opts.TraceHandler = wireVendorOTLPIngest(ctx, rcfg, rdb, rlogger, planeA)
		}
		if opts.Handler == nil && opts.TraceHandler == nil {
			rcleanup()
			answer(planechoice.Receiver{State: planechoice.ReceiverNotRunning})
			if !wait() {
				return nil
			}
			continue // nothing this build can serve
		}
		recv, err := otlpingest.New(opts)
		if err != nil {
			// No silent loss (W0-4, F25): a port clash is an ERROR in the
			// daemon log as well as stderr, and is recorded so `observer
			// doctor` shows it as the otlp.receiver FAIL row.
			rlogger.Error("otlp receiver NOT running: could not bind; spans and logs sent to this machine are lost until the port is free and the daemon restarts",
				"grpc_addr", opts.GRPCAddr, "http_addr", opts.HTTPAddr, "err", err)
			fmt.Fprintf(stderr, "otlp receiver disabled: init failed: %v (see `observer doctor`)\n", err)
			if serr := recordOTLPReceiverStatus(rcfg, otlpReceiverStatus{
				State: otlpReceiverBindFailed, GRPCAddr: opts.GRPCAddr, HTTPAddr: opts.HTTPAddr, Error: err.Error(),
			}); serr != nil {
				rlogger.Warn("otlp receiver: status record not written", "err", serr)
			}
			rcleanup()
			answer(planechoice.Receiver{State: planechoice.ReceiverBindFailed, GRPCAddr: opts.GRPCAddr, HTTPAddr: opts.HTTPAddr, Error: err.Error()})
			if !wait() {
				return nil
			}
			continue
		}
		if serr := recordOTLPReceiverStatus(rcfg, otlpReceiverStatus{
			State: otlpReceiverListening, GRPCAddr: recv.GRPCAddr(), HTTPAddr: recv.HTTPAddr(),
		}); serr != nil {
			rlogger.Warn("otlp receiver: status record not written", "err", serr)
		}
		recv.Start()
		answer(planechoice.Receiver{State: planechoice.ReceiverListening, GRPCAddr: recv.GRPCAddr(), HTTPAddr: recv.HTTPAddr()})
		<-ctx.Done()
		sctx, scancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		_ = recv.Shutdown(sctx)
		scancel()
		rcleanup()
		return nil
	}
}
