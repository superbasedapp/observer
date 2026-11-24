//go:build !sbo_omit_org_update

package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/service"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/update"
)

// update_handover_doctor.go is `observer doctor`'s update.handover row: can
// the next in-place update hand the running daemon over under this node's
// supervisor, and did the last one refuse (the UPD-9 interlock,
// service.DecideHandover)? It reads the RUNNING daemon's own facts, never
// this CLI process's: the doctor is not the process an update hands over.

// handoverDoctorInput is what the check decides on.
type handoverDoctorInput struct {
	// Enabled is [update].enabled.
	Enabled bool
	// DaemonRunning reports a live daemon on this database; Facts are its
	// hand-over facts (the daemon would be the apply's parent).
	DaemonRunning bool
	Facts         service.HandoverInput
	// LastRefusal is the refusal the newest ledger row names, if any.
	LastRefusal service.HandoverRefusal
}

// updateHandoverCheckName is the row's id (`observer doctor update`).
const updateHandoverCheckName = "update.handover"

// updateHandoverDoctorCheckFrom decides the row.
func updateHandoverDoctorCheckFrom(in handoverDoctorInput) diag.Check {
	c := diag.Check{Name: updateHandoverCheckName, Status: diag.StatusOK}
	if !in.Enabled {
		c.Message = "update management is off on this node ([update].enabled = false)"
		return c
	}
	if in.LastRefusal != service.HandoverAllowed {
		c.Status = diag.StatusWarn
		c.Message = fmt.Sprintf("the last update's hand-over was refused (%s); the node stayed on its previous binary", in.LastRefusal)
		c.Details = []string{in.LastRefusal.Explain()}
		return c
	}
	if !in.DaemonRunning {
		c.Message = "no daemon is running on this database; the hand-over is checked when an update applies"
		return c
	}
	if r := service.DecideHandover(in.Facts); r != service.HandoverAllowed {
		c.Status = diag.StatusWarn
		c.Message = fmt.Sprintf("the next update would be refused at the hand-over (%s)", r)
		c.Details = []string{r.Explain()}
		return c
	}
	if in.Facts.Supervisor == service.SupervisorNone {
		c.Message = "the daemon is not run by observer.service or the LaunchAgent; an update hands over with no supervisor to follow"
		return c
	}
	c.Message = fmt.Sprintf("%s: an update hands the daemon over and it stays supervised", in.Facts.Supervisor)
	return c
}

// daemonHandoverFacts resolves the running daemon's hand-over facts. On
// Linux it reads the daemon's own /proc/<pid>/cgroup and environ (the same
// user can); on macOS, where another process's environment is not readable,
// an installed LaunchAgent is taken as the supervisor and its plist decides
// the restart. daemonVersion is the daemon's version from its start lock: it
// is the parent of the next apply.
func daemonHandoverFacts(goos string, pid int, daemonVersion string, readProc func(pid int, name string) (string, error), plist func() string) service.HandoverInput {
	in := service.HandoverInput{ParentKeepsSupervision: update.ParentKeepsSupervision(daemonVersion)}
	switch goos {
	case "linux":
		cg, _ := readProc(pid, "cgroup")
		env, _ := readProc(pid, "environ")
		in.Supervisor = service.DetectSupervisor(cg, "")
		for _, kv := range strings.Split(env, "\x00") {
			if v, ok := strings.CutPrefix(kv, "NOTIFY_SOCKET="); ok && strings.TrimSpace(v) != "" {
				in.NotifySocket = true
			}
		}
	case "darwin":
		if p := plist(); strings.TrimSpace(p) != "" {
			in.Supervisor = service.SupervisorLaunchd
			in.AgentRestartsOnFailure = service.LaunchAgentRestartsOnFailure(p)
		} else {
			in.Supervisor = service.SupervisorNone
		}
	default:
		in.Supervisor = service.SupervisorNone
	}
	return in
}

// readDaemonProcFile reads /proc/<pid>/<name>.
func readDaemonProcFile(pid int, name string) (string, error) {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), name))
	return string(b), err
}

// updateHandoverDoctorChecks is the doctor's entry: one row.
func updateHandoverDoctorChecks(ctx context.Context, cfg config.Config, database *sql.DB) []diag.Check {
	in := handoverDoctorInput{Enabled: cfg.Update.Enabled}
	if !in.Enabled {
		return []diag.Check{updateHandoverDoctorCheckFrom(in)}
	}
	if database != nil {
		if events, err := store.New(database).LoadUpdateEvents(ctx, 1); err == nil && len(events) > 0 {
			in.LastRefusal = service.HandoverRefusalIn(events[0].Detail)
		}
	}
	if lock, ok := liveDaemonFor(cfg.Observer.DBPath); ok {
		in.DaemonRunning = true
		in.Facts = daemonHandoverFacts(runtime.GOOS, lock.PID, lock.Version, readDaemonProcFile, launchAgentPlist)
	}
	return []diag.Check{updateHandoverDoctorCheckFrom(in)}
}
