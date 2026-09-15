package kirocli

import (
	"encoding/json"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// toolArgs is the decoded `args` object of a Kiro tool_use. Only the
// fields the normalizer consults are typed; the rest are ignored.
//
// The CLI layouts and the IDE layout spell the SAME operands
// differently (snake_case vs camelCase, `file_text` vs `text`), so both
// spellings are typed here and the per-tool cases pick the one their
// schema uses. Grounded against the live IDE capture 2026-09-03 —
// testdata/kirocli/ide/9f3c1d0b7a4e2856/.
type toolArgs struct {
	Command    string `json:"command"`     // fs_write: create|append|insert|str_replace ; execute_bash/execute_pwsh carry the shell line; todo_list carries create|complete
	Path       string `json:"path"`        // fs_write / single-op fs_read / IDE read_file / str_replace / list_directory
	FileText   string `json:"file_text"`   // fs_write create/append (CLI)
	Text       string `json:"text"`        // fs_write body (IDE)
	NewStr     string `json:"new_str"`     // fs_write str_replace/insert (CLI)
	NewStrIDE  string `json:"newStr"`      // str_replace replacement (IDE + flat stream)
	Content    string `json:"content"`     // flat-stream `write` create body
	TargetFile string `json:"targetFile"`  // delete_file (IDE)
	WorkingDir string `json:"working_dir"` // execute_bash
	// execute_bash carries `command` (the shell line); fs_write also
	// carries `command` (the write mode) — disambiguated by tool name.
	Operations []struct {
		Path string `json:"path"`
	} `json:"operations"` // fs_read batch
}

// normalizeTool maps a Kiro built-in / MCP tool name onto the spec §5
// normalized action taxonomy and derives a human Target + the authored
// ContentBytes. The mapping is table-driven at the switch level; the
// raw name is always preserved by the caller in RawToolName.
//
// Kiro CLI native tools (grounded against a live conversations_v2
// capture + the session's own `tools` spec block):
//
//	fs_read        → read_file
//	fs_write       → write_file (create/append/insert) | edit_file (str_replace)
//	execute_bash   → run_command
//	introspect     → unknown (kiro's own help/docs tool)
//
// Kiro IDE native tools (grounded against the operator's live Kiro IDE
// 1.0.411 run, 2026-09-03 — the IDE ships an ENTIRELY DIFFERENT tool
// vocabulary from the CLI, which is why every one of these landed
// `unknown` before this table existed):
//
//	read_file      → read_file
//	fs_write       → write_file      (IDE spells the body `text`, and
//	                                  sends NO `command` sub-arg — the
//	                                  IDE has a separate edit tool)
//	str_replace    → edit_file       (args path / oldStr / newStr)
//	execute_pwsh   → run_command     (args command / cwd; the shell is
//	                                  named by `_meta.kiro.shellType`,
//	                                  so a bash host would spell this
//	                                  `execute_bash`, already mapped)
//	delete_file    → edit_file       (args targetFile / explanation;
//	                                  the taxonomy has NO canonical
//	                                  delete type — edit_file is the
//	                                  established precedent, matching
//	                                  copilot/grok `deletefile` and
//	                                  cowork `Delete` in internal/tooltax)
//	list_directory → search_files    (args path / explanation / depth)
//	todo_list      → todo_update     (args command=create|complete plus
//	                                  tasks / completed_task_ids /
//	                                  context_update / modified_files)
//
// `create` and `complete` are NOT tool names: they are the `todo_list`
// sub-command, and they only ever appeared as action TARGETS because
// genericToolTarget probes the `command` arg key when a tool is
// unmapped. They stay the target here, now under an honest
// `todo_update` action.
//
//	<server>___<t> → mcp_call (MCP tools are namespaced with "___")
//	(anything else)→ unknown
func normalizeTool(name string, rawArgs json.RawMessage) (action, target string, contentBytes int64) {
	var a toolArgs
	if len(rawArgs) > 0 {
		_ = json.Unmarshal(rawArgs, &a)
	}
	switch name {
	case "fs_read":
		return models.ActionReadFile, firstReadPath(a), 0
	case "read", "read_file":
		// `read` is the INTERACTIVE flat stream's spelling of the same
		// tool the SQLite store calls `fs_read` (grounded 2026-09-03; it
		// carries the batch `operations` array, not a bare `path`).
		return models.ActionReadFile, firstReadPath(a), 0
	case "fs_write", "write":
		// `write` is the flat stream's spelling of `fs_write`. Both carry
		// the sub-command that splits create from str-replace; the flat
		// stream spells the replace mode `strReplace` (camelCase) where
		// the SQLite store spells it `str_replace`.
		if a.Command == "str_replace" || a.Command == "strReplace" {
			return models.ActionEditFile, a.Path, int64(len(firstNonEmpty(a.NewStr, a.NewStrIDE)))
		}
		// create / append / insert all author file content. The IDE
		// sends the body as `text` with no sub-command at all; the flat
		// stream sends it as `content`.
		body := firstNonEmpty(a.FileText, a.Text, a.Content, a.NewStr)
		return models.ActionWriteFile, a.Path, int64(len(body))
	case "shell":
		// The flat stream's spelling of `execute_bash` / `execute_cmd`.
		return models.ActionRunCommand, a.Command, 0
	case "str_replace":
		return models.ActionEditFile, a.Path, int64(len(a.NewStrIDE))
	case "execute_bash", "execute_pwsh":
		return models.ActionRunCommand, a.Command, 0
	case "delete_file":
		return models.ActionEditFile, a.TargetFile, 0
	case "list_directory":
		return models.ActionSearchFiles, a.Path, 0
	case "todo_list":
		return models.ActionTodoUpdate, a.Command, 0
	case "introspect":
		return models.ActionUnknown, "", 0
	default:
		if strings.Contains(name, "___") {
			return models.ActionMCPCall, "", 0
		}
		return models.ActionUnknown, "", 0
	}
}

// firstNonEmpty returns the first non-empty candidate, or "".
func firstNonEmpty(candidates ...string) string {
	for _, c := range candidates {
		if c != "" {
			return c
		}
	}
	return ""
}

// firstReadPath returns the single-op path or the first batch-op path
// of an fs_read call.
func firstReadPath(a toolArgs) string {
	if a.Path != "" {
		return a.Path
	}
	if len(a.Operations) > 0 {
		return a.Operations[0].Path
	}
	return ""
}

// resolveProjectRoot translates a foreign-OS cwd (WSL2 reading /mnt/c,
// or a Windows observer reading \\wsl.localhost) BEFORE git.Resolve.
// The translation is UNCONDITIONAL — crossmount.TranslateForeignPath
// always converts a `C:\...` drive path to its `/mnt/c/...` absolute
// equivalent, so the drive-letter string never reaches git.Resolve
// where filepath.Abs would treat it as relative and CWD-prefix the
// observer's own .git onto it ([[feedback-foreign-path-git-resolve]]).
// Mirrors opencode/clinecli. Returns (projectRoot, gitBranch,
// gitRemote); a blank cwd yields ("", "", "").
func resolveProjectRoot(rawCWD string) (root, branch, remote string, id git.Identity) {
	cwd := strings.TrimSpace(rawCWD)
	if cwd == "" {
		return "", "", "", git.Identity{}
	}
	cwd = crossmount.TranslateForeignPath(cwd)
	identity, err := git.ResolveIdentity(cwd, git.IdentityOptions{})
	if err != nil {
		return cwd, "", "", git.Identity{}
	}
	// identity.Remote is already NormalizeRemote'd by ResolveIdentity.
	return identity.Root, identity.Branch, identity.Remote, identity
}
