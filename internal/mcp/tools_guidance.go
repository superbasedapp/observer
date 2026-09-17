package mcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/fsview"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// -----------------------------------------------------------------------------
// get_project_guidance — the agent's own view of the guidance files it (and
// every other assistant) is configured to read in this project: CLAUDE.md /
// AGENTS.md instructions, skills, sub-agent definitions, slash commands and
// conditionally-applied rules, per tool.
//
// Why an assistant wants this: it is the only way to see the guidance OTHER
// tools carry (a Cursor rule, a Copilot instructions file) and the skills that
// exist but were never invoked — the things a session cannot learn from its own
// context window.
//
// Metadata is served from the inventory the daemon's scan loop already
// persisted; no filesystem walk happens on the call. Bodies are opt-in
// (include_content) and are re-read on demand through the capped, symlink-safe
// fsview reader and scrubbed — the DB never holds a guidance file's body
// (CLAUDE.md "no content in the DB" rule).
// -----------------------------------------------------------------------------

const (
	// guidanceContentPerFileCap bounds ONE file's returned body. Guidance
	// files are prose; a caller that needs more should read the file itself.
	guidanceContentPerFileCap = 32 * 1024
	// guidanceContentTotalCap bounds the whole response's content budget so a
	// project with 200 skills cannot blow the model's context in one call.
	guidanceContentTotalCap = 128 * 1024
)

type getProjectGuidanceTool struct{ db *sql.DB }

func newGetProjectGuidanceTool(db *sql.DB) Tool { return &getProjectGuidanceTool{db: db} }

func (*getProjectGuidanceTool) Name() string { return "get_project_guidance" }

func (*getProjectGuidanceTool) Description() string {
	return "List the agent-guidance files configured for a project: instruction files " +
		"(CLAUDE.md, AGENTS.md, GEMINI.md, .goosehints), skills, sub-agent definitions, " +
		"slash commands, and conditionally-applied rules (.cursor/rules, " +
		".github/instructions) — for EVERY AI tool used in that project, not just this one. " +
		"Returns each file's tool, kind, scope, relative path, name, description, size, " +
		"and whether it still exists on disk. Pass include_content=true to also get the " +
		"files' scrubbed bodies (capped). Use it to find guidance you are not currently " +
		"loading — a skill that exists but was never invoked, or a rule another tool reads."
}

func (*getProjectGuidanceTool) InputSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"project_root": map[string]any{
				"type": "string",
				"description": "Absolute project root. Omit to use the current working directory's " +
					"project (the nearest scanned root at or above it).",
			},
			"tool": map[string]any{
				"type":        "string",
				"description": "Restrict to one tool id (e.g. claude-code, cursor, codex).",
			},
			"kind": map[string]any{
				"type":        "string",
				"description": "Restrict to one kind: instructions, skill, agent, command, rule, config.",
			},
			"include_content": map[string]any{
				"type": "boolean",
				"description": "Also return each file's scrubbed body, capped at 32KB per file and " +
					"128KB overall. Default false.",
			},
		},
	}
}

type getProjectGuidanceArgs struct {
	ProjectRoot    string `json:"project_root"`
	Tool           string `json:"tool"`
	Kind           string `json:"kind"`
	IncludeContent bool   `json:"include_content"`
}

// guidanceToolFile is one wire row. It mirrors store.GuidanceRow's vocabulary
// minus the columns an assistant has no use for (abs_path, content_hash,
// first_seen) and plus the optional body.
type guidanceToolFile struct {
	Tool        string            `json:"tool"`
	Kind        string            `json:"kind"`
	Scope       string            `json:"scope"`
	RelPath     string            `json:"rel_path"`
	Name        string            `json:"name,omitempty"`
	Description string            `json:"description,omitempty"`
	SizeBytes   int64             `json:"size_bytes"`
	ModifiedAt  string            `json:"modified_at,omitempty"`
	Present     bool              `json:"present"`
	Frontmatter map[string]string `json:"frontmatter,omitempty"`
	ParseError  string            `json:"parse_error,omitempty"`
	// Content is set only when include_content was requested AND the body
	// was readable. ContentTruncated says the body was cut at a cap.
	Content          string `json:"content,omitempty"`
	ContentTruncated bool   `json:"content_truncated,omitempty"`
	// ContentNote explains an ABSENT body honestly (capped out, unreadable,
	// binary) rather than returning an empty string that reads like an
	// empty file.
	ContentNote string `json:"content_note,omitempty"`
}

type getProjectGuidanceResult struct {
	ProjectRoot string             `json:"project_root"`
	ScannedAt   string             `json:"scanned_at,omitempty"`
	Count       int                `json:"count"`
	Files       []guidanceToolFile `json:"files"`
	// ContentScrubbed is true whenever any body was returned — the bodies
	// pass through the secret scrubber and there is no raw mode.
	ContentScrubbed bool `json:"content_scrubbed"`
	// Note is the honest explanation when the answer is empty or partial.
	Note string `json:"note,omitempty"`
}

func (t *getProjectGuidanceTool) Invoke(ctx context.Context, raw json.RawMessage) (any, error) {
	var args getProjectGuidanceArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, fmt.Errorf("get_project_guidance: invalid arguments: %w", err)
		}
	}
	st := store.New(t.db)

	known, err := st.GuidanceProjects(ctx)
	if err != nil {
		return nil, fmt.Errorf("get_project_guidance: %w", err)
	}
	roots := make([]string, 0, len(known))
	for _, k := range known {
		roots = append(roots, k.ProjectRoot)
	}

	root, note := resolveGuidanceRoot(args.ProjectRoot, roots)
	if root == "" {
		return getProjectGuidanceResult{
			Files: []guidanceToolFile{},
			Note:  note,
		}, nil
	}

	rows, err := st.ListGuidance(ctx, root, false)
	if err != nil {
		return nil, fmt.Errorf("get_project_guidance: %w", err)
	}

	wantTool := strings.TrimSpace(args.Tool)
	wantKind := strings.TrimSpace(args.Kind)
	out := make([]guidanceToolFile, 0, len(rows))
	var scannedAt string
	budget := guidanceContentTotalCap
	scrubber := scrub.New()
	for _, r := range rows {
		if wantTool != "" && r.Tool != wantTool {
			continue
		}
		if wantKind != "" && r.Kind != wantKind {
			continue
		}
		if ts := r.LastScanned.UTC().Format(guidanceTimeLayout); ts > scannedAt {
			scannedAt = ts
		}
		f := guidanceToolFile{
			Tool: r.Tool, Kind: r.Kind, Scope: r.Scope, RelPath: r.RelPath,
			Name: r.Name, Description: r.Description, SizeBytes: r.SizeBytes,
			Present: r.Present, Frontmatter: r.Frontmatter, ParseError: r.ParseError,
		}
		if !r.ModifiedAt.IsZero() {
			f.ModifiedAt = r.ModifiedAt.UTC().Format(guidanceTimeLayout)
		}
		if args.IncludeContent {
			t.attachContent(ctx, &f, root, r, scrubber, &budget)
		}
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Tool != out[j].Tool {
			return out[i].Tool < out[j].Tool
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].RelPath < out[j].RelPath
	})

	res := getProjectGuidanceResult{
		ProjectRoot:     root,
		ScannedAt:       scannedAt,
		Count:           len(out),
		Files:           out,
		ContentScrubbed: args.IncludeContent,
		Note:            note,
	}
	if len(out) == 0 && res.Note == "" {
		res.Note = "no guidance files recorded for this project — either none exist or the daemon has not scanned it yet (`observer guidance scan --project " + root + "`)"
	}
	return res, nil
}

// guidanceTimeLayout is RFC3339 in UTC — the one timestamp spelling every
// guidance surface emits.
const guidanceTimeLayout = "2006-01-02T15:04:05Z07:00"

// attachContent fills in one row's body, honouring the per-file and overall
// caps. Every absent body carries a reason; none is silently empty.
func (t *getProjectGuidanceTool) attachContent(
	ctx context.Context,
	f *guidanceToolFile,
	projectRoot string,
	row store.GuidanceRow,
	scrubber *scrub.Scrubber,
	budget *int,
) {
	if !row.Present {
		f.ContentNote = "file no longer on disk"
		return
	}
	if *budget <= 0 {
		f.ContentNote = "omitted — the response's 128KB content budget was already spent; narrow with tool= or kind="
		return
	}
	anchor, rel, ok := guidanceReadAnchor(projectRoot, row)
	if !ok {
		f.ContentNote = "not readable through the contained reader (no resolvable anchor for this scope)"
		return
	}
	limit := guidanceContentPerFileCap
	if *budget < limit {
		limit = *budget
	}
	c, err := fsview.Read(ctx, anchor, rel, limit)
	if err != nil {
		f.ContentNote = "unreadable: " + guidanceReadErrCode(err)
		return
	}
	if c.Binary {
		f.ContentNote = "binary file — not guidance prose"
		return
	}
	body := scrubber.String(c.Data)
	f.Content = body
	f.ContentTruncated = c.Truncated
	*budget -= len(body)
}

// guidanceReadAnchor resolves a row to the (root, rel) pair fsview needs.
// A project-scope row is anchored at the project root; a user-scope row is
// anchored at the operator's home directory and its RelPath is written with a
// leading "~/" (internal/guidance's convention), so the prefix is stripped.
//
// Anchoring on a ROOT rather than on the stored AbsPath is deliberate: it is
// what keeps fsview's containment meaningful instead of turning it into a
// rubber stamp over a path the DB happens to hold.
func guidanceReadAnchor(projectRoot string, row store.GuidanceRow) (root, rel string, ok bool) {
	rel = row.RelPath
	if strings.HasPrefix(rel, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", "", false
		}
		return home, strings.TrimPrefix(rel, "~/"), true
	}
	if projectRoot == "" || rel == "" {
		return "", "", false
	}
	return projectRoot, rel, true
}

// guidanceReadErrCode maps an fsview sentinel onto a short, path-free code —
// an absolute filesystem path is never echoed back to the model.
func guidanceReadErrCode(err error) string {
	switch {
	case errors.Is(err, fsview.ErrNotFound):
		return "not_found"
	case errors.Is(err, fsview.ErrOutsideRoot), errors.Is(err, fsview.ErrAbsolutePath):
		return "outside_root"
	case errors.Is(err, fsview.ErrIsDir), errors.Is(err, fsview.ErrNotDir), errors.Is(err, fsview.ErrNotRegular):
		return "not_a_regular_file"
	default:
		return "read_error"
	}
}

// resolveGuidanceRoot picks the project root to report on.
//
// An explicit project_root must be one the scanner knows — an unknown one is
// answered with an honest note naming the roots that DO exist, never with a
// filesystem walk of whatever the model passed. With no argument the working
// directory's nearest scanned ancestor wins (the MCP server is spawned by the
// AI client inside the project, so cwd is the right default).
func resolveGuidanceRoot(requested string, known []string) (root, note string) {
	clean := make([]string, 0, len(known))
	for _, k := range known {
		if k != "" {
			clean = append(clean, filepath.Clean(k))
		}
	}
	if len(clean) == 0 {
		return "", "no project has been scanned for guidance files yet — run `observer guidance scan --all` (or start the daemon, which scans every known project every 15 minutes)"
	}
	if requested != "" {
		want := filepath.Clean(requested)
		for _, k := range clean {
			if k == want {
				return k, ""
			}
		}
		return "", "project_root " + requested + " has no guidance inventory; scanned roots are: " + strings.Join(clean, ", ")
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", "no project_root given and the working directory could not be read; scanned roots are: " + strings.Join(clean, ", ")
	}
	cwd = filepath.Clean(cwd)
	best := ""
	for _, k := range clean {
		if k == cwd || strings.HasPrefix(cwd, k+string(filepath.Separator)) {
			if len(k) > len(best) {
				best = k
			}
		}
	}
	if best == "" {
		return "", "the working directory is not inside any scanned project; pass project_root explicitly — scanned roots are: " + strings.Join(clean, ", ")
	}
	return best, ""
}
