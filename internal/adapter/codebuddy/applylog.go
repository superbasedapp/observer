package codebuddy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// execHint is the lowercase substring a CodeBuddy CLI process's comm or
// command line must contain for a pid seed to validate: the npm package
// path (`@tencent-ai/codebuddy-code`) and every bin name carry it.
const execHint = "codebuddy"

// genTimingV is this adapter's gen-timing parser version
// (TokenEvent.GenTimingV): bump it when the duration rule changes.
const genTimingV = 1

// applyLog stamps the facts only CodeBuddy's diagnostic log holds
// (logs.go) onto a finished parse: the tool version, the terminal surface,
// the owning process id for process attribution, and the per-call
// generation duration. Every output is optional: no log, no stamp.
func (st *parseState) applyLog(res *adapter.ParseResult, fromOffset int64) {
	if fromOffset > 0 && len(res.ToolEvents) == 0 && len(res.TokenEvents) == 0 {
		return // an idle poll tick: nothing new to attribute
	}
	if st.sessionID == "" {
		return
	}
	home := dataHome(st.path)
	if home == "" {
		return
	}
	times := []time.Time{st.firstTS, st.lastTS}
	if fi, err := os.Stat(st.path); err == nil {
		times = append(times, fi.ModTime())
	}
	facts := lookupSessionLog(home, st.sessionID, times...)

	if v := toolVersionFor(home, facts); v != "" {
		res.SessionToolVersions = append(res.SessionToolVersions,
			models.SessionToolVersion{SessionID: st.sessionID, Version: v})
	}
	if facts.CLI {
		// A process started through the CLI dispatcher is a terminal run.
		res.SessionSurfaces = append(res.SessionSurfaces,
			models.SessionSurface{SessionID: st.sessionID, Surface: models.SurfaceCLI})
	}
	if facts.PID > 1 && ownsHome(home) {
		res.SessionProcessSeeds = append(res.SessionProcessSeeds, models.SessionProcessSeed{
			PID:       facts.PID,
			SessionID: st.sessionID,
			Tool:      models.ToolCodeBuddy,
			CWD:       crossmount.TranslateForeignPath(st.cwd),
			ExecHint:  execHint,
		})
	}
	for i := range res.TokenEvents {
		tok := &res.TokenEvents[i]
		if tok.GenMs != 0 || tok.MessageID == "" {
			continue
		}
		if mc, ok := facts.ModelCalls[tok.MessageID]; ok && mc.durationMs > 0 {
			tok.GenMs, tok.GenBasis, tok.GenTimingV = mc.durationMs, models.GenBasisNative, genTimingV
		}
	}
}

// ownsHome reports whether the data home belongs to the running process's
// own OS side. A pid logged by a CodeBuddy running on the OTHER side of a
// WSL / Windows bridge is meaningless to this host's process table and must
// never be seeded (the store would at best reject it, at worst match a
// recycled pid).
func ownsHome(home string) bool {
	if env := strings.TrimSpace(os.Getenv(configDirEnv)); env != "" {
		if abs, err := filepath.Abs(env); err == nil && samePath(abs, home) {
			return true
		}
	}
	user, err := os.UserHomeDir()
	if err != nil || user == "" {
		return false
	}
	return samePath(filepath.Join(user, ".codebuddy"), home)
}

func samePath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}
