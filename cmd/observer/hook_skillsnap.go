package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/guidance"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/skillhistory"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

// -----------------------------------------------------------------------------
// Skills-history hook snapshots (S10-SKILLS, docs/projects-page.md "Skills:
// versions across commits and sessions").
//
// At Claude Code SessionStart (startup / resume / clear / compact) the hook
// hashes every SKILL.md the session can load - the project's and the
// operator's home skills - and at PostToolUse for the Skill tool it hashes
// the invoked skill's SKILL.md. The result is the OBSERVED fact the Skills
// tab reports: exactly what was on disk at that moment, never an inference.
//
// Runs AFTER the hook has replied (markHookReplied), is time-budgeted, and
// fails open: any error is logged to stderr and dropped, never surfaced to
// the host. Discovery reuses internal/guidance (the one owner of "where do
// skills live": its KindSkill rows, its symlink containment, its size cap);
// the write goes through the one owner store.InsertSkillSnapshot.
// -----------------------------------------------------------------------------

// skillSnapBudget bounds one snapshot's filesystem work. The hook has
// already replied, but the host still waits for the process to exit.
const skillSnapBudget = 250 * time.Millisecond

// skillSnapMaxFiles caps the members one snapshot records; past it the
// snapshot is marked incomplete (a missing skill then reads "unknown").
const skillSnapMaxFiles = 200

// skillSnapRequest is what one hook event asks to be snapshotted.
type skillSnapRequest struct {
	SessionID      string
	Event          string // skillhistory.EventSessionStart | EventSkillInvoke
	Source         string
	ToolUseID      string
	InvokedName    string
	Cwd            string
	TranscriptPath string
}

// skillSnapEnv is the injected I/O: production wires the real disk, tests a
// fake tree.
type skillSnapEnv struct {
	// Scan runs one guidance scan anchored at anchor.
	Scan func(ctx context.Context, anchor string, opts guidance.Options) (guidance.Result, error)
	// ReadSkill reads one SKILL.md (size-capped, containment-checked).
	ReadSkill func(anchor, abs string, maxBytes int64) ([]byte, error)
	// ProjectRoot resolves the project root for a (local) cwd.
	ProjectRoot func(cwd string) string
	// UserHome is the hook process's own home directory.
	UserHome func() (string, error)
	HostOS   string
	Now      func() time.Time
}

func productionSkillSnapEnv() skillSnapEnv {
	return skillSnapEnv{
		Scan: func(ctx context.Context, anchor string, opts guidance.Options) (guidance.Result, error) {
			return guidance.Scan(ctx, anchor, guidance.OSFS(anchor), opts)
		},
		ReadSkill: func(anchor, abs string, maxBytes int64) ([]byte, error) {
			fsys := guidance.OSFS(anchor)
			info, err := fsys.Stat(abs)
			if err != nil {
				return nil, err
			}
			if info.IsDir() || info.Size() > maxBytes {
				return nil, fmt.Errorf("not a readable skill file")
			}
			return fsys.ReadFile(abs)
		},
		ProjectRoot: func(cwd string) string {
			if root, ok := git.FindRoot(cwd); ok {
				return root
			}
			return cwd
		},
		UserHome: os.UserHomeDir,
		HostOS:   runtime.GOOS,
		Now:      time.Now,
	}
}

// homeRung is one row of the home-directory resolution ladder, walked top
// down. The Windows Claude Code + WSL daemon straddle runs this hook inside
// WSL, so the process's own home is the WRONG home for the tool's skills;
// the transcript path names the tool's real .claude directory.
type homeRung struct {
	name    string
	resolve func(env skillSnapEnv, req skillSnapRequest) (string, bool)
}

var homeLadder = []homeRung{
	{"transcript path's .claude ancestor", func(_ skillSnapEnv, req skillSnapRequest) (string, bool) {
		tp := strings.ReplaceAll(crossmount.TranslateForeignPath(req.TranscriptPath), `\`, "/")
		i := strings.Index(tp, "/.claude/")
		if tp == "" || i <= 0 {
			return "", false
		}
		return filepath.FromSlash(tp[:i]), true
	}},
	{"the hook's own home, when the tool runs on this OS", func(env skillSnapEnv, req skillSnapRequest) (string, bool) {
		if env.HostOS != "windows" && looksWindowsPath(req.Cwd) {
			return "", false
		}
		h, err := env.UserHome()
		return h, err == nil && h != ""
	}},
}

func resolveSkillHome(env skillSnapEnv, req skillSnapRequest) (string, bool) {
	for _, r := range homeLadder {
		if h, ok := r.resolve(env, req); ok {
			return h, true
		}
	}
	return "", false
}

// buildSkillSnapshot computes one snapshot. ok=false means there is
// nothing to record (no session, no cwd, or an invocation of a skill that
// lives in neither the project nor the home skill directories - a plugin
// skill, which the tab reports as "unmatched" instead).
func buildSkillSnapshot(ctx context.Context, env skillSnapEnv, req skillSnapRequest) (store.SkillSnapshot, bool) {
	if strings.TrimSpace(req.SessionID) == "" || strings.TrimSpace(req.Cwd) == "" {
		return store.SkillSnapshot{}, false
	}
	cwd := crossmount.TranslateForeignPath(req.Cwd)
	root := env.ProjectRoot(cwd)
	home, homeOK := resolveSkillHome(env, req)
	snap := store.SkillSnapshot{
		SessionID: req.SessionID, Tool: models.ToolClaudeCode, Event: req.Event, Source: req.Source,
		ToolUseID: req.ToolUseID, InvokedName: req.InvokedName, ProjectRoot: root,
		ObservedAt: env.Now(), Complete: true, HomeResolved: homeOK,
	}
	ctx, cancel := context.WithTimeout(ctx, skillSnapBudget)
	defer cancel()

	if req.Event == skillhistory.EventSkillInvoke {
		return invokedSkillSnapshot(ctx, env, req, snap, root, home, homeOK)
	}

	opts := guidance.DefaultOptions()
	opts.Kinds = []guidance.Kind{guidance.KindSkill}
	opts.Tools = []string{models.ToolClaudeCode}
	opts.GitBlobIDs = true
	passes := []struct {
		anchor string
		o      guidance.Options
	}{{root, withProjectOnly(opts)}}
	if homeOK {
		passes = append(passes, struct {
			anchor string
			o      guidance.Options
		}{home, withUserOnly(opts, home)})
	}
	for _, p := range passes {
		res, err := env.Scan(ctx, p.anchor, p.o)
		if err != nil || res.Incomplete || res.Skipped > 0 || len(res.Errors) > 0 {
			// A partial pass: what it found is real, what it did not
			// find is UNKNOWN, never absent.
			snap.Complete = false
		}
		for _, f := range res.Files {
			if len(snap.Members) >= skillSnapMaxFiles {
				snap.Complete = false
				break
			}
			snap.Members = append(snap.Members, memberFromGuidance(f))
		}
	}
	return snap, true
}

func withProjectOnly(o guidance.Options) guidance.Options {
	o.IncludeUserScope = false
	return o
}

func withUserOnly(o guidance.Options, home string) guidance.Options {
	o.IncludeUserScope, o.UserScopeOnly, o.UserHome = true, true, home
	return o
}

func memberFromGuidance(f guidance.File) store.SkillSnapshotMember {
	m := store.SkillSnapshotMember{
		Scope: string(f.Scope), RelPath: f.RelPath, DirKey: strings.ToLower(path.Dir(f.RelPath)),
		Name: f.Name, State: skillhistory.MemberPresent, ContentHash: f.ContentHash,
		BlobOID: f.GitBlobOID, BlobOIDLF: f.GitBlobOIDLF, SizeBytes: f.SizeBytes,
	}
	if f.ContentHash == "" || f.GitBlobOID == "" {
		// A read failure (guidance reports it as ParseErr with no hash)
		// is never recorded as a version.
		m.State, m.ContentHash, m.BlobOID, m.BlobOIDLF = skillhistory.MemberUnreadable, "", "", ""
	}
	return m
}

// invokedSkillSnapshot hashes the invoked skill's SKILL.md in both scopes
// (a project skill and a home skill may share a name; the tab reports that
// as ambiguous rather than picking one). A name that no skill directory
// carries under its own directory name falls back to a frontmatter-name
// match over a skills-only scan.
func invokedSkillSnapshot(ctx context.Context, env skillSnapEnv, req skillSnapRequest, snap store.SkillSnapshot, root, home string, homeOK bool) (store.SkillSnapshot, bool) {
	name := strings.TrimSpace(req.InvokedName)
	// A name is one directory component: no separators, no drive colon,
	// and never "." / ".." (which would address the skills root itself).
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) || strings.Contains(name, ":") {
		return snap, false
	}
	maxBytes := guidance.DefaultOptions().MaxFileBytes
	type loc struct {
		scope, anchor, rel string
	}
	var locs []loc
	for _, dp := range skillhistory.DirPatterns(guidance.Rules(), models.ToolClaudeCode) {
		switch {
		case dp.Scope == string(guidance.ScopeUser) && homeOK:
			locs = append(locs, loc{dp.Scope, home, dp.Prefix + name + "/" + dp.File})
		case dp.Scope == string(guidance.ScopeProject):
			locs = append(locs, loc{dp.Scope, root, dp.Prefix + name + "/" + dp.File})
		}
	}
	for _, l := range locs {
		abs := filepath.Join(l.anchor, filepath.FromSlash(strings.TrimPrefix(l.rel, "~/")))
		body, err := env.ReadSkill(l.anchor, abs, maxBytes)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				snap.Members = append(snap.Members, store.SkillSnapshotMember{
					Scope: l.scope, RelPath: l.rel, DirKey: strings.ToLower(path.Dir(l.rel)),
					Name: name, State: skillhistory.MemberUnreadable,
				})
			}
			continue
		}
		sum := sha256.Sum256(body)
		oid, oidLF := guidance.GitBlobOID(body)
		snap.Members = append(snap.Members, store.SkillSnapshotMember{
			Scope: l.scope, RelPath: l.rel, DirKey: strings.ToLower(path.Dir(l.rel)), Name: name,
			State: skillhistory.MemberPresent, ContentHash: hex.EncodeToString(sum[:]),
			BlobOID: oid, BlobOIDLF: oidLF, SizeBytes: int64(len(body)),
		})
	}
	if len(snap.Members) > 0 {
		return snap, true
	}
	// Frontmatter name != directory name: find it by name.
	full, ok := buildSkillSnapshot(ctx, env, skillSnapRequest{
		SessionID: req.SessionID, Event: skillhistory.EventSessionStart, Cwd: req.Cwd, TranscriptPath: req.TranscriptPath,
	})
	if !ok {
		return snap, false
	}
	for _, m := range full.Members {
		if strings.EqualFold(m.Name, name) {
			snap.Members = append(snap.Members, m)
		}
	}
	snap.Complete = full.Complete
	return snap, len(snap.Members) > 0
}

// claudeSkillSnapPayload is the slice of a SessionStart / PostToolUse
// payload the snapshot needs.
type claudeSkillSnapPayload struct {
	SessionID      string `json:"session_id"`
	Cwd            string `json:"cwd"`
	Source         string `json:"source"`
	TranscriptPath string `json:"transcript_path"`
	ToolName       string `json:"tool_name"`
	ToolUseID      string `json:"tool_use_id"`
	ToolInput      struct {
		Skill string `json:"skill"`
	} `json:"tool_input"`
}

// skillSnapRequestFor maps a hook payload onto a snapshot request, or
// ok=false when this event does not snapshot. A PostToolUse is a skill
// invocation when the TAXONOMY says its tool is skill_invoke - an action
// type lookup, never a raw tool-name comparison.
func skillSnapRequestFor(event string, p claudeSkillSnapPayload) (skillSnapRequest, bool) {
	req := skillSnapRequest{SessionID: p.SessionID, Cwd: p.Cwd, TranscriptPath: p.TranscriptPath}
	switch event {
	case "SessionStart":
		req.Event, req.Source = skillhistory.EventSessionStart, p.Source
		return req, true
	case "PostToolUse":
		at, ok := tooltax.ResolveActionType(models.ToolClaudeCode, p.ToolName)
		if !ok || at != models.ActionSkillInvoke || p.ToolUseID == "" {
			return req, false
		}
		req.Event, req.ToolUseID, req.InvokedName = skillhistory.EventSkillInvoke, p.ToolUseID, p.ToolInput.Skill
		return req, true
	}
	return req, false
}

// recordClaudeSkillSnapshot is the hook seam: decode, gate on
// [projects].skill_history, snapshot, write. Best-effort: every failure
// logs to stderr and returns.
func recordClaudeSkillSnapshot(body []byte, event, label, configPath string, stderr io.Writer) {
	var p claudeSkillSnapPayload
	if err := json.Unmarshal(bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF}), &p); err != nil {
		return
	}
	req, ok := skillSnapRequestFor(event, p)
	if !ok {
		return
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		fmt.Fprintf(stderr, "observer-hook: %s skill snapshot config: %v\n", label, err)
		return
	}
	if !cfg.Projects.SkillHistory {
		return
	}
	snap, ok := buildSkillSnapshot(context.Background(), productionSkillSnapEnv(), req)
	if !ok {
		return
	}
	// Same DB-open posture as recordClaudecodeEffort: unbounded open (the
	// integrity probe competes with the daemon's WAL holder), bounded write.
	database, err := db.Open(context.Background(), db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		fmt.Fprintf(stderr, "observer-hook: %s skill snapshot db: %v\n", label, err)
		return
	}
	defer database.Close()
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Observer.Hooks.HookTimeout())
	defer cancel()
	if err := store.New(database).InsertSkillSnapshot(ctx, snap); err != nil {
		fmt.Fprintf(stderr, "observer-hook: %s skill snapshot: %v\n", label, err)
	}
}
