package antigravity

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// cliProjectFile is the subset of ~/.gemini/config/projects/<uuid>.json
// the metadata resolver consumes. The on-disk shape is richer (mcp
// permissions, knowledge resources, etc.) — only `name` and the first
// `gitFolder.folderUri` are used today.
type cliProjectFile struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	ProjectResources struct {
		Resources []struct {
			// FolderURI at the resource level is the shape the VS Code
			// extension's agy backend wrote 2026-09-03
			// (`{"folderUri": "file:///c%3A/…"}`); the CLI's own
			// projects nest it under gitFolder. Either may be set.
			FolderURI string `json:"folderUri"`
			GitFolder struct {
				FolderURI string `json:"folderUri"`
			} `json:"gitFolder"`
		} `json:"resources"`
	} `json:"projectResources"`
}

// workspaceURI returns the first resource's folder URI, whichever of
// the two shapes carries it.
func (p cliProjectFile) workspaceURI() string {
	for _, r := range p.ProjectResources.Resources {
		if r.GitFolder.FolderURI != "" {
			return r.GitFolder.FolderURI
		}
		if r.FolderURI != "" {
			return r.FolderURI
		}
	}
	return ""
}

// cliLogBinding captures the per-conversation lifecycle facts the CLI
// emits to its glog-formatted log file: project_uuid the conversation
// belongs to, the launch workspace directory, and the wall-clock moment
// the conversation was created.
//
// workspaceDir is the directory agy was launched in (logged as
// "Initializing CLI store manager for workspace <path>" / workspaceDirs=[…]).
// It is recovered for EVERY conversation — including the no-active-workspace
// "default-cli-project" sessions whose project json carries no folderUri —
// so a CLI conversation still attributes to the repo it ran in, the same way
// codex/claude-code use the launch cwd as the project root.
type cliLogBinding struct {
	projectUUID  string
	workspaceDir string
	created      time.Time
}

// cliConversationLogRegex matches the "Created conversation <uuid>"
// line written by agy's server.go:747. The project-uuid binding
// appears on the immediately preceding "Conversation using project
// ID: <uuid>" line (server.go:726). Both UUIDs are RFC 4122 dashed.
var (
	cliProjectIDRegex = regexp.MustCompile(`Conversation using project ID:\s+([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})`)
	cliCreatedRegex   = regexp.MustCompile(`Created conversation\s+([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})`)
	// cliWorkspaceRegex captures agy's launch workspace directory, logged at
	// backend init (manager.go: "Initializing CLI store manager for workspace
	// <path>"). Present for every session regardless of whether an antigravity
	// "active workspace" / project was set, so it recovers the project folder
	// for default-cli-project conversations the project-json path can't.
	cliWorkspaceRegex = regexp.MustCompile(`Initializing CLI store manager for workspace\s+(.+)$`)
)

// lookupCLIIndexEntry resolves metadata for an Antigravity-CLI
// conversation .pb file. CLI installs don't ship a desktop-style
// state.vscdb index; we synthesise the equivalent indexEntry by:
//
//  1. Walking up from sessionPath to find the .gemini/antigravity-cli
//     root and the sibling .gemini/config/projects/ dir.
//  2. Parsing cli-*.log files under <cliRoot>/log/ for the line pair:
//     "Conversation using project ID: <project-uuid>"
//     "Created conversation <conversation-uuid>"
//     to map conversation_uuid → project_uuid + creation timestamp.
//  3. Loading ~/.gemini/config/projects/<project-uuid>.json to get the
//     workspace path (.name) and gitFolder.folderUri.
//
// Returns nil for any miss — caller falls back to synthetic
// `[antigravity]` attribution. Results are memoised in indexCache
// keyed by `"cli:"+logDir`, invalidated when the log directory's
// mtime advances (new log file written, existing log appended).
func (a *Adapter) lookupCLIIndexEntry(sessionPath, conversationID string) *indexEntry {
	cliRoot, geminiRoot := cliRootsFor(sessionPath)
	if cliRoot == "" || geminiRoot == "" {
		return nil
	}
	logDir := filepath.Join(cliRoot, "log")
	cacheKey := "cli:" + logDir

	a.indexMu.Lock()
	defer a.indexMu.Unlock()

	// Cache freshness MUST track log-file appends, not just dir
	// changes. On Linux ext4 (and via the WSL2 9p protocol over
	// drvfs / virtiofs), appending to an existing file does NOT bump
	// the parent dir's mtime — only file creates/renames/deletes do.
	// agy writes the `Conversation using project ID: <uuid>` binding
	// line to the currently-open cli-*.log AT the moment the
	// conversation is created, which is also the moment the watcher
	// fires on the new .pb file. If the daemon has already cached an
	// empty result from a probe milliseconds earlier (e.g. an initial
	// scan that found the log dir but not yet the binding), a pure
	// dir-mtime cache key never invalidates and every subsequent
	// lookup returns nil — the conversation lands with the
	// `[antigravity]` placeholder forever. Using the latest log file
	// mtime captures both file-create and append events.
	dirMtime := cliLogFreshnessUnix(logDir)
	if dirMtime == 0 {
		return nil
	}
	cached, ok := a.indexCache[cacheKey]
	if ok && cached.mtime == dirMtime {
		if e, hit := cached.entries[conversationID]; hit {
			return &e
		}
		return nil
	}

	bindings := parseCLILogBindings(logDir)
	if len(bindings) == 0 {
		a.indexCache[cacheKey] = &indexCacheEntry{mtime: dirMtime, entries: map[string]indexEntry{}}
		return nil
	}

	projectsDir := filepath.Join(geminiRoot, "config", "projects")
	entries := make(map[string]indexEntry, len(bindings))
	for convUUID, b := range bindings {
		wsURI := ""
		title := ""
		if b.projectUUID != "" {
			if proj, ok := readCLIProjectFile(filepath.Join(projectsDir, b.projectUUID+".json")); ok {
				title = proj.Name
				if len(proj.ProjectResources.Resources) > 0 {
					wsURI = proj.ProjectResources.Resources[0].GitFolder.FolderURI
				}
				if wsURI == "" && proj.Name != "" {
					wsURI = "file://" + proj.Name
				}
			}
		}
		// Fall back to the launch workspace dir from the log when the project
		// json yielded no folder — the default-cli-project (no active
		// workspace) case, which is exactly the "no project folder" symptom.
		if wsURI == "" && b.workspaceDir != "" {
			wsURI = "file://" + b.workspaceDir
		}
		if wsURI == "" {
			continue
		}
		entries[convUUID] = indexEntry{
			uuid:         convUUID,
			title:        title,
			workspaceURI: wsURI,
			created:      b.created,
		}
	}
	a.indexCache[cacheKey] = &indexCacheEntry{mtime: dirMtime, entries: entries}
	if e, hit := entries[conversationID]; hit {
		return &e
	}
	return nil
}

// cliRootsFor walks up from a .pb file to locate the CLI install root
// (~/.gemini/antigravity-cli) and the gemini config parent
// (~/.gemini). Returns ("","") when the path doesn't sit under a
// recognised CLI layout.
func cliRootsFor(sessionPath string) (cliRoot, geminiRoot string) {
	cur := filepath.Dir(sessionPath)
	for cur != "" && cur != filepath.Dir(cur) {
		if filepath.Base(cur) == "antigravity-cli" {
			cliRoot = cur
			parent := filepath.Dir(cur)
			if filepath.Base(parent) == ".gemini" {
				geminiRoot = parent
			}
			return cliRoot, geminiRoot
		}
		cur = filepath.Dir(cur)
	}
	return "", ""
}

// desktopRootFor walks up from a desktop .pb file to locate the
// desktop Antigravity install root (~/.gemini/antigravity) and the
// gemini config parent (~/.gemini). The desktop root is the parent
// of both `conversations/` (the encrypted .pb store) AND `brain/`
// (the plaintext overview.txt store). Returns ("","") when the path
// doesn't sit under a recognised desktop layout.
//
// Mirrors cliRootsFor for the desktop layout — kept as a separate
// function (rather than a combined "rootsFor(path, layout)") so the
// CLI logic stays untouched and the desktop addition is a pure
// extension.
func desktopRootFor(sessionPath string) (desktopRoot, geminiRoot string) {
	cur := filepath.Dir(sessionPath)
	for cur != "" && cur != filepath.Dir(cur) {
		if filepath.Base(cur) == "antigravity" {
			// Guard against picking up an unrelated `antigravity`
			// directory deeper in the tree (e.g. someone naming a
			// project dir that). The desktop root's parent is always
			// `.gemini`.
			parent := filepath.Dir(cur)
			if filepath.Base(parent) == ".gemini" {
				return cur, parent
			}
		}
		cur = filepath.Dir(cur)
	}
	return "", ""
}

// transcriptPathFor returns the layout-appropriate plaintext per-
// turn transcript path for a session .pb file. CLI sessions use
// brain/<uuid>/.system_generated/logs/transcript.jsonl; desktop
// sessions use the same directory shape but the file is named
// overview.txt. Returns "" when sessionPath doesn't classify into a
// known layout or its expected install root can't be walked up to.
//
// Centralises the layout switch so callers (augmentResultFromHistory,
// historyOnlyResult) don't repeat the conditional. The two files
// have identical JSONL schemas — readCLITranscriptEntries handles
// either.
func transcriptPathFor(sessionPath, conversationID string) string {
	switch classifyLayout(sessionPath) {
	case LayoutCLI, LayoutCLIDB:
		// Both the older per-conversation .pb (LayoutCLI) and the newer
		// plaintext-SQLite .db (LayoutCLIDB) are agy CLI installs that share
		// the brain/<uuid>/.system_generated/logs/transcript.jsonl trace.
		cliRoot, _ := cliRootsFor(sessionPath)
		if cliRoot == "" {
			return ""
		}
		return cliTranscriptPath(cliRoot, conversationID)
	case LayoutDesktop, LayoutDesktopDB:
		// The encrypted .pb and the agy-backed plaintext .db (VS Code
		// extension, 2026-09-03) share the desktop brain/ transcript.
		desktopRoot, _ := desktopRootFor(sessionPath)
		if desktopRoot == "" {
			return ""
		}
		return desktopTranscriptPath(desktopRoot, conversationID)
	}
	return ""
}

// geminiRootFor returns the ~/.gemini parent for a session path in
// EITHER tree (antigravity-cli/ or antigravity/), or "" when the path
// sits in neither. The per-project config files the .db's
// trajectory_metadata_blob points at live under <geminiRoot>/config/
// projects/ regardless of which tree wrote the conversation.
func geminiRootFor(sessionPath string) string {
	if _, g := cliRootsFor(sessionPath); g != "" {
		return g
	}
	_, g := desktopRootFor(sessionPath)
	return g
}

// dirMtimeUnix returns the directory's mtime as unix seconds, or 0
// when the dir doesn't exist or can't be stat'd. Used as the cache
// validity key — appending to or rotating any log file inside bumps
// the parent dir's mtime on Linux, invalidating the cache.
func dirMtimeUnix(dir string) int64 {
	fi, err := os.Stat(dir)
	if err != nil {
		return 0
	}
	return fi.ModTime().Unix()
}

// cliLogFreshnessUnix returns the max of (dir mtime, latest cli-*.log
// file mtime) so the CLI index cache invalidates on both new-file and
// existing-file-appended events. Pure dir mtime is insufficient on
// Linux ext4 / WSL2 9p mounts, where appending to an existing file
// doesn't touch the parent dir's mtime — see lookupCLIIndexEntry for
// the failure mode (binding line written milliseconds after observer's
// first probe → cache holds empty → next lookup returns nil forever).
//
// Cost: 1 readdir + N stats per call (N = number of cli-*.log files,
// typically ≤ 10). The CLI doesn't generate enough log volume for this
// to matter; the cost is well under the existing parseCLILogBindings
// pass that runs on every cache miss anyway.
func cliLogFreshnessUnix(logDir string) int64 {
	maxMtime := dirMtimeUnix(logDir)
	entries, err := os.ReadDir(logDir)
	if err != nil {
		return maxMtime
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "cli-") || !strings.HasSuffix(name, ".log") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if m := info.ModTime().Unix(); m > maxMtime {
			maxMtime = m
		}
	}
	return maxMtime
}

// parseCLILogBindings reads every cli-*.log file under logDir and
// returns the conversation_uuid → (project_uuid, created_ts) map for
// every binding it observes. Logs are scanned mtime-desc so the
// freshest binding wins on the rare collision (re-imported conv UUID).
func parseCLILogBindings(logDir string) map[string]cliLogBinding {
	entries, err := os.ReadDir(logDir)
	if err != nil {
		return nil
	}
	type logFile struct {
		name  string
		mtime time.Time
	}
	var logs []logFile
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "cli-") || !strings.HasSuffix(name, ".log") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		logs = append(logs, logFile{name: name, mtime: fi.ModTime()})
	}
	sort.Slice(logs, func(i, j int) bool { return logs[i].mtime.After(logs[j].mtime) })

	out := map[string]cliLogBinding{}
	for _, lg := range logs {
		scanCLILogFile(filepath.Join(logDir, lg.name), lg.mtime, out)
	}
	return out
}

// scanCLILogFile reads one cli-*.log and writes any
// conversation→project bindings it discovers into out. Existing
// entries in out are NOT overwritten — the caller pre-sorts logs
// mtime-desc, so the freshest binding lands first.
func scanCLILogFile(path string, fileMtime time.Time, out map[string]cliLogBinding) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var lastProject string
	var lastWorkspace string
	var lastTimestamp time.Time
	for scanner.Scan() {
		line := scanner.Text()
		if m := cliWorkspaceRegex.FindStringSubmatch(line); m != nil {
			if ws := strings.TrimSpace(m[1]); ws != "" {
				lastWorkspace = ws
			}
			continue
		}
		if m := cliProjectIDRegex.FindStringSubmatch(line); m != nil {
			lastProject = m[1]
			lastTimestamp = parseCLILogTimestamp(line, fileMtime)
			continue
		}
		if m := cliCreatedRegex.FindStringSubmatch(line); m != nil {
			// Bind on a UUID project (resolves to a config/projects folder) OR
			// just the launch workspace (default-cli-project sessions, which
			// have no UUID project but still ran in a real directory).
			if lastProject == "" && lastWorkspace == "" {
				continue
			}
			conv := m[1]
			if _, exists := out[conv]; exists {
				continue
			}
			ts := parseCLILogTimestamp(line, fileMtime)
			if ts.IsZero() {
				ts = lastTimestamp
			}
			out[conv] = cliLogBinding{projectUUID: lastProject, workspaceDir: lastWorkspace, created: ts}
		}
	}
}

// parseCLILogTimestamp extracts the wall-clock from a glog-formatted
// log line ("I0523 14:13:00.172473 ...") combined with the year from
// fallback's location (the log file's mtime). Returns zero time on
// any parse failure.
func parseCLILogTimestamp(line string, fallback time.Time) time.Time {
	if len(line) < 21 {
		return time.Time{}
	}
	// glog format: <severity><month><day> <hour>:<min>:<sec>.<usec> <tid> ...
	if !isGlogSeverity(line[0]) {
		return time.Time{}
	}
	parts := strings.Fields(line[1:])
	if len(parts) < 2 {
		return time.Time{}
	}
	monthDay := parts[0]
	timestr := parts[1]
	if len(monthDay) != 4 {
		return time.Time{}
	}
	month, err := strconv.Atoi(monthDay[:2])
	if err != nil {
		return time.Time{}
	}
	day, err := strconv.Atoi(monthDay[2:])
	if err != nil {
		return time.Time{}
	}
	var hms, frac string
	if idx := strings.Index(timestr, "."); idx > 0 {
		hms = timestr[:idx]
		frac = timestr[idx+1:]
	} else {
		hms = timestr
	}
	tparts := strings.Split(hms, ":")
	if len(tparts) != 3 {
		return time.Time{}
	}
	h, err := strconv.Atoi(tparts[0])
	if err != nil {
		return time.Time{}
	}
	min, err := strconv.Atoi(tparts[1])
	if err != nil {
		return time.Time{}
	}
	s, err := strconv.Atoi(tparts[2])
	if err != nil {
		return time.Time{}
	}
	nsec := 0
	if frac != "" {
		if v, err := strconv.Atoi(frac); err == nil {
			switch len(frac) {
			case 9:
				nsec = v
			case 6:
				nsec = v * 1000
			case 3:
				nsec = v * 1_000_000
			}
		}
	}
	year := fallback.Year()
	loc := fallback.Location()
	if loc == nil {
		loc = time.UTC
	}
	return time.Date(year, time.Month(month), day, h, min, s, nsec, loc)
}

func isGlogSeverity(b byte) bool {
	switch b {
	case 'I', 'W', 'E', 'F':
		return true
	}
	return false
}

// readCLIProjectFile loads and decodes a project JSON file. Returns
// (zero, false) on any I/O or parse error — callers fall through to
// synthetic attribution.
func readCLIProjectFile(path string) (cliProjectFile, bool) {
	body, err := os.ReadFile(path)
	if err != nil {
		return cliProjectFile{}, false
	}
	var p cliProjectFile
	if err := json.Unmarshal(body, &p); err != nil {
		return cliProjectFile{}, false
	}
	return p, true
}
