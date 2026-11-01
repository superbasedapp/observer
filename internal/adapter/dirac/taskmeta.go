package dirac

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// Task sidecar + global index names.
const (
	taskMetadataName = "task_metadata.json"
	stateDirName     = "state"
	taskHistoryName  = "taskHistory.json"
	// metaScanBytes caps the task_metadata.json read (live files are a few
	// hundred bytes; files_in_context grows with the task).
	metaScanBytes = 256 * 1024
	// historyScanBytes caps the taskHistory.json read. One entry is
	// ~0.5 KiB, so the cap is thousands of tasks.
	historyScanBytes = 16 << 20
)

// taskMetadata is the subset of `<task>/task_metadata.json` read here
// (same shape as the Cline extension's; `files_in_context` is not read):
//
//	{"model_usage":[{"ts":…,"model_id":"gpt-5.6-luna",
//	                 "model_provider_id":"openai-codex","mode":"act"}],
//	 "environment_history":[{"ts":…,"os_name":"linux",…,
//	   "host_name":"Dirac CLI - Node.js","host_version":"0.5.22",
//	   "dirac_version":"0.5.22"}]}
type taskMetadata struct {
	ModelUsage []struct {
		Ts         int64  `json:"ts"`
		ModelID    string `json:"model_id"`
		ProviderID string `json:"model_provider_id"`
	} `json:"model_usage"`
	EnvironmentHistory []struct {
		Ts           int64  `json:"ts"`
		HostName     string `json:"host_name"`
		HostVersion  string `json:"host_version"`
		DiracVersion string `json:"dirac_version"`
	} `json:"environment_history"`
}

// readTaskMetadata reads the task's sidecar. ok=false when absent,
// symlinked or malformed — every consumer degrades to "no stamp".
func readTaskMetadata(taskDir string) (taskMetadata, bool) {
	body, ok := readCapped(filepath.Join(taskDir, taskMetadataName), metaScanBytes)
	if !ok {
		return taskMetadata{}, false
	}
	var m taskMetadata
	if err := json.Unmarshal(body, &m); err != nil {
		return taskMetadata{}, false
	}
	return m, true
}

// latestModel returns the most recent model_usage entry (model, provider).
func (m taskMetadata) latestModel() (string, string) {
	var bestTs int64 = -1
	model, provider := "", ""
	for _, u := range m.ModelUsage {
		if u.ModelID == "" || u.Ts < bestTs {
			continue
		}
		bestTs, model, provider = u.Ts, u.ModelID, u.ProviderID
	}
	return model, provider
}

// surfaceRow is one entry of the host_name → surface table.
type surfaceRow struct {
	kind string
	host string
}

// surfaceByHostName resolves environment_history[].host_name (the
// bundle's getHostVersion `platform` string) into the normalized surface
// vocabulary. "Dirac CLI - Node.js" is grounded on disk (both OSes);
// "Dirac ACP Agent" is the bundle's ACP-mode platform string (Dirac run
// as an external agent inside JetBrains AI Assistant / Zed) — the editor
// itself is not named, so no host token is invented. An unlisted name
// stamps nothing.
var surfaceByHostName = map[string]surfaceRow{
	"dirac cli - node.js": {kind: models.SurfaceCLI, host: "dirac-cli"},
	"dirac acp agent":     {kind: models.SurfaceIDE, host: ""},
}

// sessionStamps returns the surface and tool-version stamps for a task,
// both from its EARLIEST environment record (the session's origin).
func sessionStamps(sessionID string, m taskMetadata) ([]models.SessionSurface, []models.SessionToolVersion) {
	if len(m.EnvironmentHistory) == 0 {
		return nil, nil
	}
	first := m.EnvironmentHistory[0]
	for _, e := range m.EnvironmentHistory[1:] {
		if e.Ts > 0 && (first.Ts == 0 || e.Ts < first.Ts) {
			first = e
		}
	}
	var surfaces []models.SessionSurface
	if row, ok := surfaceByHostName[strings.ToLower(strings.TrimSpace(first.HostName))]; ok {
		surfaces = append(surfaces, models.SessionSurface{SessionID: sessionID, Surface: row.kind, SurfaceHost: row.host})
	}
	var versions []models.SessionToolVersion
	v := strings.TrimSpace(first.DiracVersion)
	if v == "" {
		v = strings.TrimSpace(first.HostVersion)
	}
	if v != "" {
		versions = append(versions, models.SessionToolVersion{SessionID: sessionID, Version: v})
	}
	return surfaces, versions
}

// historyEntry is the per-task subset of `<data>/state/taskHistory.json`
// (a JSON array, one entry per task). It is the ONLY grounded record of
// a task's working directory: Dirac's environment_details block carries
// no "Current Working Directory" banner (unlike the Cline extension's).
type historyEntry struct {
	ID                      string `json:"id"`
	CwdOnTaskInitialization string `json:"cwdOnTaskInitialization"`
	WorkspaceRootPath       string `json:"workspaceRootPath"`
}

// historyIndex caches one parsed taskHistory.json per data dir, keyed by
// (size, mtime) so an unchanged index is decoded once, not per parse.
type historyIndex struct {
	mu      sync.Mutex
	entries map[string]historyCacheEntry
}

type historyCacheEntry struct {
	size  int64
	mtime int64
	cwds  map[string]string
}

// cwdFor returns the task's raw working directory ("" when the index is
// missing, unreadable, or does not list the task yet).
func (h *historyIndex) cwdFor(taskDir, taskID string) string {
	path := filepath.Join(filepath.Dir(filepath.Dir(taskDir)), stateDirName, taskHistoryName)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.entries == nil {
		h.entries = map[string]historyCacheEntry{}
	}
	if c, ok := h.entries[path]; ok && c.size == info.Size() && c.mtime == info.ModTime().UnixNano() {
		return c.cwds[taskID]
	}
	body, ok := readCapped(path, historyScanBytes)
	if !ok {
		return ""
	}
	var list []historyEntry
	if err := json.Unmarshal(body, &list); err != nil {
		return ""
	}
	cwds := make(map[string]string, len(list))
	for _, e := range list {
		cwd := strings.TrimSpace(e.CwdOnTaskInitialization)
		if cwd == "" {
			cwd = strings.TrimSpace(e.WorkspaceRootPath)
		}
		if e.ID != "" && cwd != "" {
			cwds[e.ID] = cwd
		}
	}
	h.entries[path] = historyCacheEntry{size: info.Size(), mtime: info.ModTime().UnixNano(), cwds: cwds}
	return cwds[taskID]
}

// readCapped reads a regular (non-symlink) file up to limit bytes. A
// symlink is refused so a derived sibling path can never pull in a file
// this adapter promises not to read (secrets.json sits two levels up).
func readCapped(path string, limit int64) ([]byte, bool) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, false
	}
	f, err := os.Open(path) //nolint:gosec // derived sibling of a watched task file; symlinks refused above
	if err != nil {
		return nil, false
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return nil, false
	}
	return body, true
}
