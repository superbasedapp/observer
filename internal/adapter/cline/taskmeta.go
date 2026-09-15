package cline

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/vscodehost"
)

// taskMetadataName is the sibling file Cline (and every fork of it)
// writes next to api_conversation_history.json inside a task dir.
const taskMetadataName = "task_metadata.json"

// taskMetadataScanBytes caps how much of task_metadata.json we read.
// The live files are a few hundred bytes; the cap only bounds the cost
// of a pathological one (files_in_context grows with the session).
const taskMetadataScanBytes = 256 * 1024

// taskMetadata is the subset of `task_metadata.json` this adapter
// reads. Grounded 2026-09-02 against the operator's live Cline 3.88.0
// tasks (read-only; anonymized into
// testdata/cline/task_metadata.json):
//
//	{
//	  "files_in_context": [],
//	  "model_usage": [
//	    {"ts":1780707193719,"model_id":"deepseek/deepseek-v4-flash",
//	     "model_provider_id":"cline","mode":"act"}
//	  ],
//	  "environment_history": [
//	    {"ts":1780707193714,"os_name":"win32","os_version":"10.0.26200",
//	     "os_arch":"x64","host_name":"Visual Studio Code",
//	     "host_version":"1.123.0","cline_version":"3.88.0"}
//	  ]
//	}
//
// `files_in_context` is deliberately NOT read: it is a file-content
// bookkeeping list, not activity, and the adapter already emits
// per-tool-call file rows.
type taskMetadata struct {
	ModelUsage         []taskModelUsage        `json:"model_usage"`
	EnvironmentHistory []taskEnvironmentRecord `json:"environment_history"`
}

// taskModelUsage is one entry of `model_usage[]` — the model the task
// was running at `ts`. A task that switched models mid-session carries
// several, oldest first.
type taskModelUsage struct {
	Ts              int64  `json:"ts"`
	ModelID         string `json:"model_id"`
	ModelProviderID string `json:"model_provider_id"`
	Mode            string `json:"mode"`
}

// taskEnvironmentRecord is one entry of `environment_history[]` — the
// editor host the task ran inside at `ts`. host_name is the host's
// DISPLAY name ("Visual Studio Code"), not a slug; hostTokenFor
// normalizes it.
type taskEnvironmentRecord struct {
	Ts           int64  `json:"ts"`
	OSName       string `json:"os_name"`
	HostName     string `json:"host_name"`
	HostVersion  string `json:"host_version"`
	ClineVersion string `json:"cline_version"`
}

// hostTokenByName resolves Cline's `environment_history[].host_name`
// into the lowercase surface-host token vocabulary shared with
// internal/platform/vscodehost. Keys are matched case-insensitively
// after trimming, so both the grounded DISPLAY names ("Visual Studio
// Code") and the slug spellings a fork may write ("vscode") resolve.
//
// Honesty rule (plan §3.1): a host_name that is not a key here refines
// NOTHING — the path-derived product token stands. We never invent a
// host token from an unrecognised vendor string.
var hostTokenByName = map[string]string{
	"visual studio code":            "vscode",
	"vscode":                        "vscode",
	"code":                          "vscode",
	"visual studio code - insiders": "vscode-insiders",
	"vscode-insiders":               "vscode-insiders",
	"vscodium":                      "vscodium",
	"cursor":                        "cursor",
	"windsurf":                      "windsurf",
	"kiro":                          "kiro",
	"qoder":                         "qoder",
	"trae":                          "trae",
	"jetbrains":                     "jetbrains",
}

// defaultSurfaceHost is the host token for a Cline task whose path
// sniffs to no known VS Code-family product AND whose
// task_metadata.json names no recognised host: the EMPTY string.
//
// Honesty rule (plan §3.1, and how clinecli/surface.go resolves the
// same question): with both grounded signals absent we do not know
// which editor ran the task, and "vscode" — however probable — would
// be a fabricated attribution that reads on the dashboard exactly like
// a measured one. The SURFACE stays models.SurfaceIDE, which IS
// grounded (this parser only ever reads an editor extension's
// globalStorage); only the host token goes empty. The store's surface
// upsert accepts a kind with no host.
const defaultSurfaceHost = ""

// hostTokenFor normalizes one host_name string. ok is false for an
// empty or unrecognised name.
func hostTokenFor(hostName string) (string, bool) {
	key := strings.ToLower(strings.TrimSpace(hostName))
	if key == "" {
		return "", false
	}
	tok, ok := hostTokenByName[key]
	return tok, ok
}

// readTaskMetadata loads the task_metadata.json sitting beside the
// api_conversation_history.json at apiHistoryPath. ok is false when
// the file is absent (pre-metadata Cline builds and every Roo/Kilo
// task that predates it) or unreadable/malformed — the caller then
// falls back to the path-derived host and leaves models alone.
func readTaskMetadata(apiHistoryPath string) (taskMetadata, bool) {
	p := filepath.Join(filepath.Dir(apiHistoryPath), taskMetadataName)
	f, err := os.Open(p) //nolint:gosec // path is a sibling of a file already under a watch root
	if err != nil {
		return taskMetadata{}, false
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, taskMetadataScanBytes))
	if err != nil || len(body) == 0 {
		return taskMetadata{}, false
	}
	var meta taskMetadata
	if err := json.Unmarshal(body, &meta); err != nil {
		return taskMetadata{}, false
	}
	return meta, true
}

// latestModelID returns the model_id of the newest `model_usage[]`
// entry (largest ts, falling back to the last element when no entry
// carries a ts). Empty when the list is absent or carries no model id.
//
// It is used ONLY to fill a ToolEvent whose Model is empty — the
// per-message `model` / `modelInfo.modelId` keys stay authoritative
// wherever they exist, because they are per-turn and this is
// per-task.
func latestModelID(meta taskMetadata) string {
	best := ""
	var bestTs int64 = -1
	for _, u := range meta.ModelUsage {
		if u.ModelID == "" {
			continue
		}
		if u.Ts >= bestTs {
			bestTs, best = u.Ts, u.ModelID
		}
	}
	return best
}

// latestHostToken returns the normalized host token of the newest
// `environment_history[]` entry that names a host we recognise. ok is
// false when the list is absent, empty, or names only unrecognised
// hosts.
func latestHostToken(meta taskMetadata) (string, bool) {
	tok := ""
	var bestTs int64 = -1
	for _, e := range meta.EnvironmentHistory {
		got, ok := hostTokenFor(e.HostName)
		if !ok {
			continue
		}
		if e.Ts >= bestTs {
			bestTs, tok = e.Ts, got
		}
	}
	return tok, tok != ""
}

// resolveSurfaceHost decides the SurfaceHost token for one task.
//
// Two grounded signals, path first then metadata refinement:
//
//  1. The task path itself. Cline's store lives under a VS Code-family
//     product's globalStorage, so vscodehost.ProductForPath recovers
//     which product (Code → "vscode", Cursor → "cursor", Code -
//     Insiders → "vscode-insiders", .vscode-server → "vscode-remote",
//     …) without the adapter re-deriving the per-OS convention.
//  2. task_metadata.json's environment_history[].host_name, when the
//     file exists AND names a host in hostTokenByName. This REFINES
//     the path answer: a Roo install relocated by
//     `roo-cline.customStoragePath` sits outside any product dir, and
//     the sniff then yields nothing while the metadata still knows.
//
// Neither signal ⇒ defaultSurfaceHost, the EMPTY token: the surface
// kind is still models.SurfaceIDE (grounded — this store only ever
// exists inside an editor extension's storage) but the host is not
// guessed.
func resolveSurfaceHost(apiHistoryPath string, meta taskMetadata, haveMeta bool) string {
	host := defaultSurfaceHost
	if p, ok := vscodehost.ProductForPath(apiHistoryPath); ok && p.Host != "" {
		host = p.Host
	}
	if haveMeta {
		if tok, ok := latestHostToken(meta); ok {
			host = tok
		}
	}
	return host
}

// sessionSurfaceFor builds the single models.SessionSurface a Cline /
// Roo / legacy-Kilo task stamps. The KIND is unconditional: this
// parser only ever reads an editor extension's globalStorage, so every
// session it sees is models.SurfaceIDE. Only the host varies.
func sessionSurfaceFor(sessionID, apiHistoryPath string, meta taskMetadata, haveMeta bool) models.SessionSurface {
	return models.SessionSurface{
		SessionID:   sessionID,
		Surface:     models.SurfaceIDE,
		SurfaceHost: resolveSurfaceHost(apiHistoryPath, meta, haveMeta),
	}
}
