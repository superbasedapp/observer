package autohand

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

const (
	// activeAgentsDirName is the vendor's live-process registry under the
	// data home (ActiveAgentRegistry): one JSON file per running CLI
	// process, written with a 5 s heartbeat and removed on exit.
	activeAgentsDirName = "active-agents"

	// maxActiveAgentBytes mirrors the vendor's own isOwnedFile ceiling.
	maxActiveAgentBytes = 128 << 10
	// maxActiveAgentEntries bounds a registry scan.
	maxActiveAgentEntries = 512

	// terminalFreshness is how recent a heartbeat must be for the terminal
	// resolver to trust it (vendor staleness is 15 s; this leaves slack for a
	// busy host).
	terminalFreshness = 2 * time.Minute

	// execHint is the substring a live process's comm/cmdline must carry for a
	// seed to validate: the npm build is `node …/autohand-cli/dist/…`, the
	// native build `autohand(.exe)`; the `agent`/`ah` aliases launch the same.
	execHint = "autohand"
)

// activeAgent is the part of an active-agents record this adapter uses. The
// record also carries the current instruction, command and paths written
// (activity); none of it is decoded.
type activeAgent struct {
	Version       int    `json:"version"`
	PID           int    `json:"pid"`
	SessionID     string `json:"sessionId"`
	WorkspaceRoot string `json:"workspaceRoot"`
	UpdatedAt     string `json:"updatedAt"`
}

// readActiveAgent reads one registry file, applying the vendor's own
// private-regular-file bounds. ok is false for anything that is not a valid
// version-1 record.
func readActiveAgent(path string) (rec activeAgent, ok bool) {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxActiveAgentBytes {
		return rec, false
	}
	f, err := os.Open(path) //nolint:gosec // vendor registry file under the data home
	if err != nil {
		return rec, false
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, maxActiveAgentBytes))
	if err != nil {
		return rec, false
	}
	if json.Unmarshal(body, &rec) != nil {
		return activeAgent{}, false
	}
	if rec.Version != 1 || rec.PID <= 1 || rec.SessionID == "" || strings.ContainsAny(rec.SessionID, `/\`) {
		return activeAgent{}, false
	}
	return rec, true
}

// listActiveAgents returns the valid records of <dataHome>/active-agents with
// the file each came from.
func listActiveAgents(dataHome string) (recs []activeAgent, files []string) {
	dir := filepath.Join(dataHome, activeAgentsDirName)
	d, err := os.Open(dir) //nolint:gosec // vendor registry directory under the data home
	if err != nil {
		return nil, nil
	}
	defer d.Close()
	entries, err := d.ReadDir(maxActiveAgentEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, nil
	}
	if len(entries) > maxActiveAgentEntries {
		return nil, nil
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if rec, ok := readActiveAgent(p); ok {
			recs = append(recs, rec)
			files = append(files, p)
		}
	}
	return recs, files
}

// processSeeds returns the (pid -> session) seed for the session's live CLI
// process, if it has a registry record. A running CLI heartbeats its record,
// so a session captured while it runs gets a direct process attribution.
func processSeeds(dataHome, sessID string) []models.SessionProcessSeed {
	recs, _ := listActiveAgents(dataHome)
	var out []models.SessionProcessSeed
	for _, r := range recs {
		if r.SessionID != sessID {
			continue
		}
		out = append(out, models.SessionProcessSeed{
			PID:       r.PID,
			SessionID: r.SessionID,
			Tool:      models.ToolAutohand,
			CWD:       r.WorkspaceRoot,
			ExecHint:  execHint,
		})
	}
	return out
}

// ResolveTerminalSession implements adapter.TerminalSessionResolver. The
// vendor's active-agents record is written by the CLI process itself and names
// its own pid and session, so a validated primary process whose pid matches
// exactly one fresh record resolves to that record's session. Only registries
// of the running OS are consulted (a pid is meaningless across an OS
// boundary), the session directory must exist, and two different sessions
// claiming the pid is an abstention.
func (a *Adapter) ResolveTerminalSession(ctx context.Context, process adapter.TerminalProcess) (adapter.TerminalSessionIdentity, error) {
	if err := ctx.Err(); err != nil {
		return adapter.TerminalSessionIdentity{}, err
	}
	if process.PID <= 1 {
		return adapter.TerminalSessionIdentity{}, nil
	}
	var found adapter.TerminalSessionIdentity
	for _, spec := range a.specs {
		if err := ctx.Err(); err != nil {
			return adapter.TerminalSessionIdentity{}, err
		}
		if spec.os != "" && spec.os != runtimeHomeOS() {
			continue
		}
		dataHome := filepath.Dir(spec.path)
		recs, files := listActiveAgents(dataHome)
		for i, r := range recs {
			if r.PID != process.PID {
				continue
			}
			if t := parseTime(r.UpdatedAt); t.IsZero() || time.Since(t) > terminalFreshness {
				continue
			}
			if fi, err := os.Stat(filepath.Join(spec.path, r.SessionID)); err != nil || !fi.IsDir() {
				continue
			}
			id := adapter.TerminalSessionIdentity{
				SessionID: r.SessionID,
				Evidence:  filepath.Clean(files[i]) + "#" + r.SessionID,
			}
			if found.SessionID != "" && found.SessionID != id.SessionID {
				return adapter.TerminalSessionIdentity{}, nil
			}
			found = id
		}
	}
	return found, ctx.Err()
}

var _ adapter.TerminalSessionResolver = (*Adapter)(nil)
