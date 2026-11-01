package agentconfigsvc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/agentconfig/vendorschema"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// LayerStore is the node-local layer store seam (internal/store/agentconfig.go).
type LayerStore interface {
	RecordAgentConfigSave(ctx context.Context, layers []store.AgentConfigLayerRow, write store.AgentConfigWriteRow) (int64, error)
	LoadAgentConfigLayers(ctx context.Context, filePaths []string) ([]store.AgentConfigLayerRow, error)
	ListAgentConfigWrites(ctx context.Context, tool string, limit int) ([]store.AgentConfigWriteRow, error)
}

// Options configures a Service. Zero values pick the documented defaults.
type Options struct {
	// Home is the user's home directory (default os.UserHomeDir).
	Home string
	// GOOS defaults to runtime.GOOS.
	GOOS string
	// Getenv reads the relocation variables of the files the service reads
	// and writes. nil is the one pinned-home rule (crossmount.HomeEnv,
	// R-188 F1): os.Getenv only when Home is not pinned and the process home
	// is not isolated, and no variable otherwise.
	Getenv func(string) string
	// SystemRoot re-roots managed / system paths (tests).
	SystemRoot string
	// Store records saves; nil keeps no layer rows and no history.
	Store LayerStore
	// Lock takes the cross-process advisory lock on a vendor file
	// (internal/hook.LockSettingsFile). nil locks nothing (tests).
	Lock func(path string) (func(), error)
	// ProxyAddrs are the host:port spellings of Observer's proxy.
	ProxyAddrs []string
	// Detect / MaskText default to internal/scrub's secret detectors.
	Detect   agentconfig.SecretDetector
	MaskText func(string) (string, bool)
	// Schema defaults to vendorschema.Check.
	Schema agentconfig.SchemaCheck
	// Captured reports a tool Observer captures on this node (its adapter
	// is enabled): a refuse_while_integrated setting may not be loosened.
	Captured func(tool string) bool
	// Access resolves the node's write posture (individual: editable;
	// managed: read-only until phase P6 grants editing). nil = individual.
	Access func(ctx context.Context) agentconfig.Access
	// EditGrants reads the honoured AI tool setting edit grants (T-436) for
	// the org apply pass; nil = none.
	EditGrants func(ctx context.Context, now time.Time) []string
	// Origin labels history rows ("dashboard", "cli").
	Origin string
	// Committed reports whether HEAD of the git clone at projectRoot carries
	// an org instruction block in the file at rel (slash-separated). nil
	// checks nothing. cmd/observer injects a read-only git grep (T-426).
	Committed func(projectRoot, rel string) bool
	// BackupKeep is the backup ring size per file (default 5).
	BackupKeep int
	// MaxFileBytes caps a read (default DefaultMaxFileBytes).
	MaxFileBytes int64
	Now          func() time.Time
}

// Service is the editor boundary.
type Service struct {
	o Options
	// commitHook replaces commitFile in the L1 fan-out (tests only: it is how
	// a mid-fan-out failure is reproduced); nil uses commitFile.
	commitHook func(pinnedTarget, Preview) (written, error)
}

// New builds a Service.
func New(o Options) *Service {
	pinnedHome := o.Home
	if o.Home == "" {
		o.Home, _ = os.UserHomeDir()
	}
	if o.GOOS == "" {
		o.GOOS = runtime.GOOS
	}
	o.Getenv = crossmount.HomeEnv(pinnedHome, o.Getenv)
	if o.Detect == nil {
		o.Detect = DefaultDetect
	}
	if o.MaskText == nil {
		o.MaskText = DefaultMaskText
	}
	if o.Schema == nil {
		o.Schema = vendorschema.Check
	}
	if o.Origin == "" {
		o.Origin = "dashboard"
	}
	if o.BackupKeep <= 0 {
		o.BackupKeep = 5
	}
	if o.MaxFileBytes <= 0 {
		o.MaxFileBytes = DefaultMaxFileBytes
	}
	if o.Committed == nil {
		o.Committed = GitCommitted
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Service{o: o}
}

// DefaultDetect is internal/scrub's pattern-certain secret detector.
func DefaultDetect(v string) bool {
	for _, f := range scrub.DetectSecrets(v) {
		if f.Certain {
			return true
		}
	}
	return false
}

// DefaultMaskText masks pattern-certain secrets in free text.
func DefaultMaskText(v string) (string, bool) {
	out, findings := scrub.MaskSecrets(v, func(f scrub.TypedFinding) bool { return f.Certain })
	found := false
	for _, f := range findings {
		if f.Certain {
			found = true
		}
	}
	return out, found
}

// Errors the Service returns; the dashboard maps them onto HTTP statuses.
var (
	ErrUnknownTool    = errors.New("agentconfigsvc: unknown tool")
	ErrUnknownFile    = errors.New("agentconfigsvc: unknown file for this tool")
	ErrBadTarget      = errors.New("agentconfigsvc: the file path does not belong to this file row")
	ErrNotEditable    = errors.New("agentconfigsvc: this file is not editable")
	ErrStale          = errors.New("agentconfigsvc: the file changed since the preview")
	ErrConfirm        = errors.New("agentconfigsvc: the save needs confirmation")
	ErrBlocked        = errors.New("agentconfigsvc: the hygiene check refused the save")
	ErrReadBackFailed = errors.New("agentconfigsvc: read-back verification failed; the previous file was restored")
)

// env is the ONE path environment every read and write of the service
// resolves a file row through (FU-140): the editor view, raw / preview /
// save, the effective layers, the integrated-capture refusal, the managed
// inventory and the org apply all name the same file. Relocate is on, so a
// variable that moves a tool's file (CLAUDE_CONFIG_DIR, CODEX_HOME and the
// rest of agentconfig's relocation table) moves it here exactly as it moves
// it for the tool. Getenv is the pinned-home lookup New installed
// (crossmount.HomeEnv): an isolated or pinned home reads no variable. A
// relative value resolves to PathRelocationUnresolved, which every caller
// treats as "no file", never as the default location (R-188 F6).
func (s *Service) env(project string) agentconfig.PathEnv {
	return agentconfig.PathEnv{
		GOOS: s.o.GOOS, Home: s.o.Home, Project: project, Getenv: s.o.Getenv, SystemRoot: s.o.SystemRoot,
		Relocate: true,
	}
}

// relocationNote says, in the file's own words, how a relocation variable
// decided the path: the variable that moved it, the one whose relative value
// leaves no file to name, or the set ones that were refused. Variable names
// only, never a value. "" when no variable is involved.
func relocationNote(row agentconfig.FileRow, rp agentconfig.ResolvedPath) string {
	switch {
	case rp.Status == agentconfig.PathRelocationUnresolved:
		return fmt.Sprintf("%s holds a relative path, which %s reads against its own working directory, so Observer cannot name this file and writes nothing (not the default location either).", rp.RelocatedBy, row.Tool)
	case rp.RelocatedBy != "":
		return fmt.Sprintf("Moved by %s: %s reads this file here, not at its default location.", rp.RelocatedBy, row.Tool)
	}
	if refused := refusedRelocations(rp.RelocationIgnored); len(refused) > 0 {
		return "Default location: a set relocation variable was refused (" + strings.Join(refused, ", ") + ")."
	}
	return ""
}

// refusedRelocations drops the "<ENV>:does_not_move" entries: a variable the
// catalogue declares not to move this file (DIRAC_DIR for the Hooks folder,
// the Kimchi harness variables) was never a candidate, so it is not refused.
func refusedRelocations(ignored []string) []string {
	var out []string
	for _, e := range ignored {
		if strings.HasSuffix(e, ":"+string(agentconfig.RelocIgnoreDoesNotMove)) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// RelocationNotes maps each settings file id of a tool to its relocation
// note (relocationNote), for the files a relocation variable decided; a file
// no variable touched is absent. Variable names only, never a value.
func (s *Service) RelocationNotes(tool, project string) map[string]string {
	out := map[string]string{}
	env := s.env(project)
	for _, f := range settingsFiles(tool) {
		if n := relocationNote(f, agentconfig.ResolvePath(f, env)); n != "" {
			out[f.ID] = n
		}
	}
	return out
}

func (s *Service) access(ctx context.Context) agentconfig.Access {
	a := agentconfig.Access{SecretsPosture: agentconfig.SecretsWarn}
	if s.o.Access != nil {
		a = s.o.Access(ctx)
		if a.SecretsPosture == "" {
			a.SecretsPosture = agentconfig.SecretsWarn
		}
	}
	return a
}

func (s *Service) spanEnv() agentconfig.SpanEnv {
	return agentconfig.SpanEnv{ProxyAddrs: s.o.ProxyAddrs}
}

// knownTool reports a registry tool with a catalogue.
func knownTool(tool string) bool {
	for _, t := range integration.Tools() {
		if t == tool {
			return true
		}
	}
	return false
}

// settingsFiles are a tool's non-instruction file rows.
func settingsFiles(tool string) []agentconfig.FileRow {
	var out []agentconfig.FileRow
	for _, f := range agentconfig.Files() {
		if f.Tool != tool {
			continue
		}
		switch f.Kind {
		case agentconfig.KindInstructions, agentconfig.KindSkill, agentconfig.KindAgent, agentconfig.KindCommand, agentconfig.KindRule:
			continue
		}
		out = append(out, f)
	}
	return out
}

func fileRow(id string) (agentconfig.FileRow, bool) {
	for _, f := range agentconfig.Files() {
		if f.ID == id {
			return f, true
		}
	}
	return agentconfig.FileRow{}, false
}

// snapshot reads one file row (never a PrivNever file).
func (s *Service) snapshot(f agentconfig.FileRow, env agentconfig.PathEnv) agentconfig.FileSnapshot {
	snap := agentconfig.FileSnapshot{Row: f, Resolved: agentconfig.ResolvePath(f, env)}
	snap.Reason = relocationNote(f, snap.Resolved)
	if f.WriteNeeds == agentconfig.PrivNever {
		snap.State, snap.Reason = agentconfig.FileNeverRead, "Never read by Observer (the catalogue marks this file off-limits)."
		snap.Resolved.Path = ""
		return snap
	}
	if snap.Resolved.Status != agentconfig.PathResolved {
		snap.State = agentconfig.FileUnresolved
		return snap
	}
	if isProjectScope(f.Scope) && projectLinkEscapes(snap.Resolved.Path, env.Project) {
		snap.State, snap.Reason = agentconfig.FileUnreadable, errProjectLinkEscapes.Error()
		return snap
	}
	b, present, err := s.readFile(snap.Resolved.Path)
	switch {
	case err != nil:
		snap.State, snap.Reason = agentconfig.FileUnreadable, err.Error()
	case !present:
		snap.State = agentconfig.FileMissing
	default:
		snap.State, snap.Bytes = agentconfig.FilePresent, b
	}
	return snap
}

// readFile reads a regular file under the size cap (ReadRegularFile; a
// missing file is not present, never an error).
func (s *Service) readFile(path string) ([]byte, bool, error) {
	b, err := ReadRegularFile(path, s.o.MaxFileBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

// snapshots reads every settings file of a tool.
func (s *Service) snapshots(tool, project string) []agentconfig.FileSnapshot {
	env := s.env(project)
	var out []agentconfig.FileSnapshot
	for _, f := range settingsFiles(tool) {
		out = append(out, s.snapshot(f, env))
	}
	return out
}

func (s *Service) layers(ctx context.Context, snaps []agentconfig.FileSnapshot) []agentconfig.LayerRecord {
	if s.o.Store == nil {
		return nil
	}
	var paths []string
	for _, sn := range snaps {
		if sn.State == agentconfig.FilePresent {
			paths = append(paths, sn.Resolved.Path)
		}
	}
	if len(paths) == 0 {
		return nil
	}
	rows, err := s.o.Store.LoadAgentConfigLayers(ctx, paths)
	if err != nil {
		return nil
	}
	out := make([]agentconfig.LayerRecord, 0, len(rows))
	for _, r := range rows {
		out = append(out, agentconfig.LayerRecord{
			FilePath: r.FilePath, Key: r.KeyPath, Layer: agentconfig.ValueLayer(r.Layer),
			CommonKey: agentconfig.CommonKey(r.CommonKey), ValueHash: r.ValueHash,
		})
	}
	return out
}

// Inspect builds the read-only view of one tool (phase P4).
func (s *Service) Inspect(ctx context.Context, tool, project string) (agentconfig.ToolView, error) {
	if !knownTool(tool) {
		return agentconfig.ToolView{}, fmt.Errorf("%w: %q", ErrUnknownTool, tool)
	}
	snaps := s.snapshots(tool, project)
	return agentconfig.InspectTool(agentconfig.InspectInput{
		Tool: tool, Files: snaps, Layers: s.layers(ctx, snaps), Detect: s.o.Detect,
		Spans: s.spanEnv(), Access: s.access(ctx), Project: project,
	}), nil
}

// ToolSummary is one row of the tool picker.
type ToolSummary struct {
	Tool            string                     `json:"tool"`
	Status          agentconfig.CoverageStatus `json:"status"`
	Rows            int                        `json:"rows"`
	Verified        int                        `json:"verified"`
	Writable        int                        `json:"writable"`
	Dangerous       int                        `json:"dangerous"`
	VerifiedAgainst string                     `json:"verified_against,omitempty"`
	Note            string                     `json:"note,omitempty"`
	Installed       bool                       `json:"installed"`
	FilesPresent    int                        `json:"files_present"`
	Files           int                        `json:"files"`
	Common          int                        `json:"common"`
}

// Tools lists every registry tool with its coverage and whether it looks
// installed (a user-scope config file or its directory exists).
func (s *Service) Tools(_ context.Context) []ToolSummary {
	common := map[string]int{}
	for _, m := range agentconfig.MapRows() {
		common[m.Tool]++
	}
	var out []ToolSummary
	for _, c := range agentconfig.Coverage() {
		ts := ToolSummary{
			Tool: c.Tool, Status: c.Status, Rows: c.Rows, Verified: c.Verified, Writable: c.Writable, Dangerous: c.Dangerous,
			VerifiedAgainst: c.VerifiedAgainst, Note: c.Note, Common: common[c.Tool],
		}
		for _, sn := range s.snapshots(c.Tool, "") {
			ts.Files++
			if sn.State == agentconfig.FilePresent {
				ts.FilesPresent++
			}
		}
		ts.Installed = s.Installed(c.Tool)
		out = append(out, ts)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Installed != out[j].Installed {
			return out[i].Installed
		}
		return out[i].Tool < out[j].Tool
	})
	return out
}

// Installed reports a tool that looks installed here: one of its user-scope
// config files, or the directory that holds it, exists. A PrivNever file
// is not opened; its directory's existence still counts.
func (s *Service) Installed(tool string) bool {
	env := s.env("")
	for _, f := range agentconfig.Files() {
		// A borrowed directory (IBM Bob reading ~/.claude/skills, any tool
		// reading ~/.agents/skills) exists because ANOTHER tool, or the
		// operator, made it: never evidence that this tool is installed.
		if f.Tool != tool || f.Scope != agentconfig.ScopeUser || f.Borrowed {
			continue
		}
		rp := agentconfig.ResolvePath(f, env)
		if rp.Path == "" {
			continue
		}
		p := rp.Path
		if rp.Status == agentconfig.PathGlob {
			p = globBase(p)
		}
		dir := filepath.Dir(p)
		if dir == s.o.Home || dir == "" || dir == "." {
			// A dotfile directly in home (~/.claude.json): only the file
			// itself counts, and a PrivNever one is not stat'ed.
			if f.WriteNeeds == agentconfig.PrivNever || rp.Status != agentconfig.PathResolved {
				continue
			}
			if _, err := os.Stat(p); err == nil {
				return true
			}
			continue
		}
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			return true
		}
	}
	return false
}

// globBase returns the directory prefix of a glob path before its first
// wildcard segment.
func globBase(p string) string {
	if i := strings.IndexAny(p, "*?["); i >= 0 {
		return filepath.Dir(p[:i] + "x")
	}
	return p
}

// RawView is one file's text with every secret hidden.
type RawView struct {
	FileID   string             `json:"file_id"`
	Path     string             `json:"path"`
	Format   agentconfig.Format `json:"format"`
	State    string             `json:"state"`
	Text     string             `json:"text"`
	Etag     string             `json:"etag"`
	Masked   []string           `json:"masked,omitempty"`
	Editable bool               `json:"editable"`
	// NotEditable says why (a read-only node, a never-read file, ...).
	NotEditable string `json:"not_editable,omitempty"`
	// RawSaveBlocked: a Markdown file holding a hidden secret cannot be
	// saved from the raw view (the placeholder could not be restored).
	RawSaveBlocked bool                    `json:"raw_save_blocked,omitempty"`
	Spans          []agentconfig.SpanState `json:"spans,omitempty"`
}

// Target names the file a request reads or writes.
type Target struct {
	Tool    string `json:"tool"`
	FileID  string `json:"file_id"`
	Project string `json:"project,omitempty"`
	// Path is required for a glob row (an instruction / skill / agent
	// file); it must match the row's glob under home or the project.
	Path string `json:"path,omitempty"`
}

// resolveTarget turns a Target into the file row and the concrete path.
func (s *Service) resolveTarget(t Target) (agentconfig.FileRow, string, error) {
	if !knownTool(t.Tool) {
		return agentconfig.FileRow{}, "", fmt.Errorf("%w: %q", ErrUnknownTool, t.Tool)
	}
	row, ok := fileRow(t.FileID)
	if !ok || row.Tool != t.Tool {
		return agentconfig.FileRow{}, "", fmt.Errorf("%w: %q", ErrUnknownFile, t.FileID)
	}
	if row.WriteNeeds == agentconfig.PrivNever {
		return row, "", fmt.Errorf("%w: %s is never read or written by Observer", ErrNotEditable, row.ID)
	}
	env := s.env(t.Project)
	rp := agentconfig.ResolvePath(row, env)
	switch rp.Status {
	case agentconfig.PathResolved:
		if t.Path != "" && filepath.Clean(t.Path) != filepath.Clean(rp.Path) {
			return row, "", ErrBadTarget
		}
		if isProjectScope(row.Scope) {
			if err := projectLinkCheck(rp.Path, t.Project); err != nil {
				return row, "", fmt.Errorf("%w: %s is %w", ErrNotEditable, row.ID, err)
			}
		}
		return row, rp.Path, nil
	case agentconfig.PathGlob:
		if t.Path == "" {
			return row, "", fmt.Errorf("%w: a path is required for %s", ErrBadTarget, row.ID)
		}
		p, err := s.matchGlobTarget(row, t.Path, t.Project)
		if err == nil && isProjectScope(row.Scope) {
			if cerr := projectLinkCheck(p, t.Project); cerr != nil {
				return row, "", fmt.Errorf("%w: %s is %w", ErrNotEditable, row.ID, cerr)
			}
		}
		return row, p, err
	case agentconfig.PathRelocationUnresolved:
		return row, "", fmt.Errorf("%w: %s: %s", ErrNotEditable, row.ID, relocationNote(row, rp))
	}
	return row, "", fmt.Errorf("%w: %s has no concrete file here (%s)", ErrNotEditable, row.ID, rp.Status)
}

// matchGlobTarget checks a concrete path against a glob row, anchored at
// home (user scope) or the project (project scope), with no ".." escape. A
// user row a relocation variable moves is anchored at the directory the
// variable names (FU-142).
func (s *Service) matchGlobTarget(row agentconfig.FileRow, path, project string) (string, error) {
	raw := row.Paths.Linux
	anchor, pat := "", ""
	switch {
	case strings.HasPrefix(raw, "~/"):
		anchor, pat = s.o.Home, strings.TrimPrefix(raw, "~/")
		if a, p, ok := s.relocatedGlobAnchor(row, project); ok {
			anchor, pat = a, p
		}
	case strings.HasPrefix(raw, "<project>/"):
		if project == "" {
			return "", fmt.Errorf("%w: select a project", ErrBadTarget)
		}
		anchor, pat = project, strings.TrimPrefix(raw, "<project>/")
	default:
		return "", ErrBadTarget
	}
	clean := filepath.Clean(path)
	rel, err := filepath.Rel(anchor, clean)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return "", ErrBadTarget
	}
	if !agentconfig.MatchGlob(pat, filepath.ToSlash(rel)) {
		return "", ErrBadTarget
	}
	return clean, nil
}

// Raw returns one file's masked text for the raw editor.
func (s *Service) Raw(ctx context.Context, t Target) (RawView, error) {
	row, path, err := s.resolveTarget(t)
	if err != nil {
		return RawView{}, err
	}
	rv := RawView{FileID: row.ID, Path: path, Format: row.Format, State: string(agentconfig.FileMissing)}
	b, present, err := s.readFile(path)
	if err != nil {
		return rv, err
	}
	snap := agentconfig.FileSnapshot{Row: row, Resolved: agentconfig.ResolvedPath{Status: agentconfig.PathResolved, Path: path}, State: agentconfig.FileMissing}
	if present {
		rv.State = string(agentconfig.FilePresent)
		snap.State, snap.Bytes = agentconfig.FilePresent, b
		md, _ := agentconfig.MaskedFile(row, b, s.o.Detect, s.o.MaskText)
		rv.Text, rv.Masked = string(md.Bytes), md.Paths
		rv.Etag = agentconfig.Etag(b, true)
		if (row.Format == agentconfig.FormatMarkdown || row.Format == agentconfig.FormatMDC) && len(md.Paths) > 0 {
			rv.RawSaveBlocked = true
		}
	}
	view := agentconfig.InspectTool(agentconfig.InspectInput{
		Tool: row.Tool, Files: []agentconfig.FileSnapshot{snap}, Detect: s.o.Detect, Spans: s.spanEnv(), Access: s.access(ctx),
	})
	for _, f := range view.Files {
		rv.Editable, rv.NotEditable, rv.Spans = f.Editable, f.NotEditable, f.Spans
	}
	return rv, nil
}

// SaveRequest is one proposed save (form edits or the raw text).
type SaveRequest struct {
	Target
	Edits []agentconfig.Edit `json:"edits,omitempty"`
	Raw   *string            `json:"raw,omitempty"`
	// PreviewEtag is the etag Preview returned (required by Save).
	PreviewEtag string `json:"preview_etag,omitempty"`
	// Confirm acknowledges the confirm-severity findings of the preview.
	Confirm bool `json:"confirm,omitempty"`
}

// Preview is a planned save, never written.
type Preview struct {
	agentconfig.SaveResult
	FileID string `json:"file_id"`
	Path   string `json:"path"`
	Layer  string `json:"layer"`
}

// layerFor names the developer layer a save of a file authors.
func layerFor(row agentconfig.FileRow) agentconfig.ValueLayer {
	switch row.Scope {
	case agentconfig.ScopeProjectShared, agentconfig.ScopeProjectLocal:
		return agentconfig.ValueL3
	}
	return agentconfig.ValueL2
}

// integrated reports whether Observer captures or hooks this tool here: a
// live Observer span in any of its files, or its adapter is enabled.
func (s *Service) integrated(tool string, snaps []agentconfig.FileSnapshot) bool {
	if s.o.Captured != nil && s.o.Captured(tool) {
		return true
	}
	view := agentconfig.InspectTool(agentconfig.InspectInput{Tool: tool, Files: snaps, Spans: s.spanEnv()})
	for _, f := range view.Files {
		for _, sp := range f.Spans {
			if sp.Live && sp.Enforced {
				return true
			}
		}
	}
	return false
}

// plan runs the hygiene pipeline for a request against current bytes.
func (s *Service) plan(ctx context.Context, req SaveRequest) (Preview, error) {
	return s.planAccess(ctx, req, s.access(ctx))
}

// planAccess is plan under an explicit write posture (the org apply judges
// its own writes under orgWriteAccess, never the developer's locks).
func (s *Service) planAccess(_ context.Context, req SaveRequest, access agentconfig.Access) (Preview, error) {
	row, path, err := s.resolveTarget(req.Target)
	if err != nil {
		return Preview{}, err
	}
	b, present, err := s.readFile(path)
	if err != nil {
		return Preview{}, err
	}
	snaps := s.snapshots(row.Tool, req.Project)
	var others []agentconfig.FileSnapshot
	for _, sn := range snaps {
		if sn.Row.Shape == row.Shape && sn.Row.ID != row.ID && sn.State == agentconfig.FilePresent {
			others = append(others, sn)
		}
	}
	res := agentconfig.PlanSave(agentconfig.SaveInput{
		File:  agentconfig.SaveFile{Row: row, Path: path, Present: present, Bytes: b},
		Edits: req.Edits, Raw: req.Raw, Others: others,
		Detect: s.o.Detect, MaskText: s.o.MaskText, Spans: s.spanEnv(), Access: access,
		Integrated: s.integrated(row.Tool, snaps), Schema: s.o.Schema,
	})
	return Preview{SaveResult: res, FileID: row.ID, Path: path, Layer: string(layerFor(row))}, nil
}

// Preview plans a save without writing (pipeline steps 1-7).
func (s *Service) Preview(ctx context.Context, req SaveRequest) (Preview, error) {
	return s.plan(ctx, req)
}

// SaveOutcome is a completed save.
type SaveOutcome struct {
	Saved      bool                  `json:"saved"`
	NoChange   bool                  `json:"no_change,omitempty"`
	FileID     string                `json:"file_id"`
	Path       string                `json:"path"`
	BackupPath string                `json:"backup_path,omitempty"`
	Created    bool                  `json:"created,omitempty"`
	Etag       string                `json:"etag"`
	Changes    []agentconfig.Change  `json:"changes"`
	Findings   []agentconfig.Finding `json:"findings"`
	Excluded   string                `json:"excluded,omitempty"`
}

// SaveError carries the preview a refused save was judged on.
type SaveError struct {
	Err     error
	Preview Preview
}

func (e *SaveError) Error() string { return e.Err.Error() }
func (e *SaveError) Unwrap() error { return e.Err }

// Save runs the whole pipeline (steps 1-10) for one file.
func (s *Service) Save(ctx context.Context, req SaveRequest) (SaveOutcome, error) {
	row, path, err := s.resolveTarget(req.Target)
	if err != nil {
		return SaveOutcome{}, err
	}
	unlock, err := s.lock(path)
	if err != nil {
		return SaveOutcome{}, err
	}
	defer unlock()
	pin := pinTarget(path)
	p, err := s.plan(ctx, req)
	if err != nil {
		return SaveOutcome{}, err
	}
	if err := gate(p, req.PreviewEtag, req.Confirm); err != nil {
		return SaveOutcome{}, err
	}
	out := SaveOutcome{FileID: row.ID, Path: path, Changes: p.Changes, Findings: p.Findings, Etag: p.BeforeEtag}
	if p.NoChange {
		out.NoChange = true
		return out, nil
	}
	w, err := s.commitFile(pin, p)
	if err != nil {
		return SaveOutcome{}, err
	}
	out.Saved, out.BackupPath, out.Created, out.Etag = true, w.backup, w.created, p.AfterEtag
	if p.AddExclude && req.Project != "" {
		out.Excluded = s.addGitExclude(req.Project, path)
	}
	s.record(ctx, row, path, req.Project, p, w, string(layerFor(row)), "", modeOf(req))
	return out, nil
}

func modeOf(req SaveRequest) string {
	if req.Raw != nil {
		return "raw"
	}
	return "form"
}

// gate is the save-side decision on a fresh plan: blocked, stale, or
// unconfirmed saves never reach the disk.
func gate(p Preview, previewEtag string, confirmed bool) error {
	switch {
	case !p.OK:
		return &SaveError{Err: ErrBlocked, Preview: p}
	case previewEtag == "" || previewEtag != p.PreviewEtag:
		return &SaveError{Err: ErrStale, Preview: p}
	case p.NeedsConfirm && !confirmed:
		return &SaveError{Err: ErrConfirm, Preview: p}
	}
	return nil
}

func (s *Service) lock(path string) (func(), error) {
	if s.o.Lock == nil {
		return func() {}, nil
	}
	return s.o.Lock(path)
}

// written is one file write, for record and rollback.
type written struct {
	path, backup string
	created      bool
	before       []byte
	mode         os.FileMode
}

// commitFile backs up, writes atomically and reads back one planned file.
func (s *Service) commitFile(pin pinnedTarget, p Preview) (written, error) {
	w := written{path: pin.target, created: !fileExists(pin.target), mode: 0o600}
	if fi, err := os.Stat(pin.target); err == nil {
		w.mode = fi.Mode().Perm()
	}
	if !w.created {
		b, _, err := s.readFile(pin.target)
		if err != nil {
			return w, err
		}
		w.before = b
		bak, err := s.backup(pin.target, b, w.mode)
		if err != nil {
			return w, fmt.Errorf("agentconfigsvc: backup %s: %w", pin.target, err)
		}
		w.backup = bak
	}
	if err := pin.verifyUnmoved(); err != nil {
		return w, err
	}
	if err := writeAtomic(pin.target, p.After, w.mode); err != nil {
		return w, err
	}
	back, _, err := s.readFile(pin.target)
	if err == nil && string(back) != string(p.After) {
		err = errors.New("the bytes on disk differ from the bytes written")
	}
	if err == nil {
		err = reparse(p.FileID, back)
	}
	if err != nil {
		if rerr := s.rollback(w); rerr != nil {
			return w, fmt.Errorf("%w: %w (and restoring the previous content failed: %w; the backup beside the file holds it)", ErrReadBackFailed, err, rerr)
		}
		return w, fmt.Errorf("%w: %w", ErrReadBackFailed, err)
	}
	return w, nil
}

func reparse(fileID string, b []byte) error {
	row, ok := fileRow(fileID)
	if !ok {
		return nil
	}
	res := agentconfig.PlanSave(agentconfig.SaveInput{
		File: agentconfig.SaveFile{Row: row, Present: false}, Raw: strPtr(string(b)),
		Access: agentconfig.Access{SecretsPosture: agentconfig.SecretsAllow},
	})
	for _, f := range res.Findings {
		if f.Code == "parse_error" {
			return errors.New(f.Message)
		}
	}
	return nil
}

func strPtr(s string) *string { return &s }

// rollback restores a written file to its pre-save bytes and reports whether
// it could (review M3-08: a caller must not claim a restore that failed).
func (s *Service) rollback(w written) error {
	if w.created {
		if err := os.Remove(w.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return writeAtomic(w.path, w.before, w.mode)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// backup writes <file>.bak-observer-<stamp> and prunes the ring.
func (s *Service) backup(path string, b []byte, mode os.FileMode) (string, error) {
	stamp := s.o.Now().UTC().Format("20060102T150405.000000000Z")
	bak := path + BackupPrefix + stamp
	if err := writeAtomic(bak, b, mode); err != nil {
		return "", err
	}
	matches, _ := filepath.Glob(globEscape(path) + BackupPrefix + "*")
	sort.Strings(matches)
	for len(matches) > s.o.BackupKeep {
		_ = os.Remove(matches[0])
		matches = matches[1:]
	}
	return bak, nil
}

// BackupPrefix is the routingapply backup convention (<file>.bak-observer-<stamp>).
const BackupPrefix = ".bak-observer-"

func globEscape(p string) string {
	r := strings.NewReplacer("*", `\*`, "?", `\?`, "[", `\[`)
	if runtime.GOOS == "windows" {
		return p
	}
	return r.Replace(p)
}

// record writes the layer rows and the history row (best effort: the file
// is already written and verified; a store failure loses the badge, not
// the save).
func (s *Service) record(ctx context.Context, row agentconfig.FileRow, path, project string, p Preview, w written, layer, common, mode string) {
	if s.o.Store == nil {
		return
	}
	afterTree := decodeTree(row, p.After)
	var layers []store.AgentConfigLayerRow
	var keys []string
	warnings := 0
	for _, f := range p.Findings {
		if f.Severity == agentconfig.SevWarning {
			warnings++
		}
	}
	for _, c := range p.Changes {
		keys = append(keys, c.Path)
		if c.Path == "(content)" {
			continue
		}
		lr := store.AgentConfigLayerRow{
			FilePath: path, KeyPath: c.Path, Tool: row.Tool, SettingID: c.SettingID, Layer: layer, CommonKey: common,
			ProjectRoot: project, UpdatedAt: s.o.Now(),
		}
		if c.Op == "delete" {
			lr.Delete = true
		} else {
			v, _ := lookupDotted(afterTree, c.Path)
			lr.ValueHash = agentconfig.ValueHash(v)
			if !c.Secret {
				if b, err := json.Marshal(v); err == nil && len(b) <= 4096 {
					lr.ValueJSON = string(b)
				}
			}
		}
		layers = append(layers, lr)
	}
	// The file is already written: a caller that went away (a closed tab
	// cancels the request context) must not cost the save its record.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	_, _ = s.o.Store.RecordAgentConfigSave(rctx, layers, store.AgentConfigWriteRow{
		At: s.o.Now(), Tool: row.Tool, FileID: row.ID, FilePath: path, Layer: layer, CommonKey: common,
		Origin: s.o.Origin, Mode: mode, ChangedKeys: keys, BeforeSHA256: p.BeforeEtag, AfterSHA256: p.AfterEtag,
		BackupPath: w.backup, Created: w.created, Warnings: warnings,
	})
}

// History lists recent saves (key names only).
func (s *Service) History(ctx context.Context, tool string, limit int) ([]store.AgentConfigWriteRow, error) {
	if s.o.Store == nil {
		return nil, nil
	}
	return s.o.Store.ListAgentConfigWrites(ctx, tool, limit)
}

func decodeTree(row agentconfig.FileRow, b []byte) map[string]any {
	return agentconfig.DecodeTree(row, b)
}

// lookupDotted reads a dotted path the way Change.Path spells it.
func lookupDotted(tree map[string]any, dotted string) (any, bool) {
	return agentconfig.LookupDotted(tree, dotted)
}

// addGitExclude adds a newly created project_local file to the clone's
// .git/info/exclude (local to the clone, never committed; plan section
// 6.3). It returns the line added ("" when nothing was done).
func (s *Service) addGitExclude(project, path string) string {
	gitDir := filepath.Join(project, ".git")
	fi, err := os.Stat(gitDir)
	if err != nil || !fi.IsDir() {
		return "" // not a repo root, or a worktree (.git is a file): leave it
	}
	rel, err := filepath.Rel(project, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return ""
	}
	line := "/" + filepath.ToSlash(rel)
	ex := filepath.Join(gitDir, "info", "exclude")
	cur, _ := os.ReadFile(ex)
	for _, l := range strings.Split(string(cur), "\n") {
		if strings.TrimSpace(l) == line {
			return ""
		}
	}
	out := string(cur)
	if out != "" && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	out += "# added by Observer's settings editor (local to this clone)\n" + line + "\n"
	if err := writeAtomic(ex, []byte(out), 0o644); err != nil {
		return ""
	}
	return line
}

// fingerprint is a short sha256 used in combined etags.
func fingerprint(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}
