package diag

import (
	"os/exec"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// detailCheck accumulates the sub-check lines of a multi-step check and the
// worst Status any of them reported. Its zero value is ready to use (no
// details, worst StatusOK).
type detailCheck struct {
	details []string
	worst   Status
}

// note appends one sub-check line and raises worst to status if higher.
func (d *detailCheck) note(status Status, msg string) {
	d.details = append(d.details, msg)
	if status > d.worst {
		d.worst = status
	}
}

// result builds the Check: okMsg when every sub-check was OK, warnMsg
// otherwise, with the accumulated lines as Details.
func (d *detailCheck) result(name, okMsg, warnMsg string) Check {
	msg := okMsg
	if d.worst != StatusOK {
		msg = warnMsg
	}
	return Check{Name: name, Status: d.worst, Message: msg, Details: d.details}
}

// noteOTLPReceiver notes whether Observer's OTLP receiver at addr accepts a
// TCP connection. A non-empty target is appended to the OK line in
// parentheses, naming what points at the receiver.
func (d *detailCheck) noteOTLPReceiver(addr, target string) {
	if dialable(addr) {
		msg := "OTLP receiver reachable at " + addr
		if target != "" {
			msg += " (" + target + ")"
		}
		d.note(StatusOK, msg)
		return
	}
	d.note(StatusWarn, "OTLP receiver NOT reachable at "+addr+" - is `observer start` running with [ingest.otel].enabled?")
}

// noteOTLPReceivers runs noteOTLPReceiver over the configured gRPC and HTTP
// listen addresses, in that order, skipping an empty one.
func (d *detailCheck) noteOTLPReceivers(cfg config.Config, target string) {
	for _, addr := range []string{cfg.Ingest.OTel.GRPCAddr, cfg.Ingest.OTel.HTTPAddr} {
		if addr == "" {
			continue
		}
		d.noteOTLPReceiver(addr, target)
	}
}

// npxPinWillNotStart is the WARN line for an `npx -y @superbased/observer`
// MCP pin whose deployment names no file.
const npxPinWillNotStart = "npx not on PATH - the `npx -y @superbased/observer` MCP pin will not start"

// noteNPX notes whether npx is on PATH, which the `npx -y
// @superbased/observer` MCP pin needs to start: okMsg when it is (nothing
// when okMsg is empty), warnMsg as a WARN when it is not.
func (d *detailCheck) noteNPX(okMsg, warnMsg string) {
	if _, err := exec.LookPath("npx"); err == nil {
		if okMsg != "" {
			d.note(StatusOK, okMsg)
		}
		return
	}
	d.note(StatusWarn, warnMsg)
}
