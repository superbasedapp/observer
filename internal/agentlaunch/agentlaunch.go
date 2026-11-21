package agentlaunch

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// Workspace sources: the closed vocabulary internal/workspace.Source holds
// (pinned equal by TestWorkspaceSourcesMatchWorkspacePackage).
const (
	WorkspaceLive        = "live"
	WorkspaceCloneLocal  = "clone-local"
	WorkspaceCloneRemote = "clone-remote"
	WorkspaceWorktree    = "worktree"
)

// Sandbox spellings that are not backend ids.
const (
	// SandboxNone (or an empty value) launches unsandboxed.
	SandboxNone = "none"
	// SandboxAuto lets the daemon's selection table pick an offered,
	// non-beta backend.
	SandboxAuto = "auto"
)

// Refusal codes. Closed: the attach socket carries them and the CLI maps
// them to exit codes.
const (
	// CodeInvalid: the request itself is malformed (a usage error).
	CodeInvalid = "invalid_request"
	// CodeNotLaunchable: the tool has no terminal launch row.
	CodeNotLaunchable = "not_launchable"
	// CodeSandboxUnavailable: the requested sandbox cannot be built here.
	CodeSandboxUnavailable = "sandbox_unavailable"
	// CodeRefused: a launch policy refused the launch ([terminal.launch],
	// the organization's terminals or sandbox policy, a launch gate).
	CodeRefused = "launch_refused"
	// CodeTooMany: the concurrent terminal cap is reached.
	CodeTooMany = "too_many_terminals"
	// CodeFailed: the launch failed after every policy allowed it.
	CodeFailed = "launch_failed"
)

// maxFieldLen bounds every free-text field (branch, remote, model).
const maxFieldLen = 512

// Request is one launch as the caller asked for it.
type Request struct {
	// Tool is a registry tool id ("claude-code") or its launcher verb
	// ("claude").
	Tool string
	// Project is the project directory, absolute.
	Project string
	// Sandbox is "", "none", "auto" or an offered backend id.
	Sandbox string
	// Workspace is the workspace source; "" means live.
	Workspace string
	// Remote is the clone URL for clone-remote.
	Remote string
	// Branch is checked out after a clone or worktree.
	Branch string
	// Model is an optional model id for the tool.
	Model string
}

// Normalized is a request that passed every validation row.
type Normalized struct {
	// Tool is the canonical registry tool id.
	Tool string
	// Subcommand is the tool's `observer <verb>` launcher verb.
	Subcommand string
	// Project is the cleaned absolute project directory.
	Project string
	// Sandboxed is true unless the request asked for no sandbox.
	Sandboxed bool
	// Auto is true when the daemon's selection picks the backend.
	Auto bool
	// Backend is the explicitly named backend ("" when Auto or unsandboxed).
	Backend string
	// Workspace is the resolved source ("live" when not sandboxed).
	Workspace string
	Remote    string
	Branch    string
	Model     string
}

// Error is a refusal with a closed code and the field it concerns.
type Error struct {
	Code    string
	Field   string
	Message string
}

// Error implements error.
func (e *Error) Error() string { return e.Message }

// CodeOf returns the refusal code of err, or "" when err is not an *Error.
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func refuse(code, field, format string, a ...any) *Error {
	return &Error{Code: code, Field: field, Message: fmt.Sprintf(format, a...)}
}

// validationRow is one ordered row of the request validation table.
type validationRow struct {
	id    string
	check func(r *Request, n *Normalized) *Error
}

// validationRows are walked top-down; the first refusal wins. One test
// case per row (TestNormalizeRows).
var validationRows = []validationRow{
	{"V1-tool-present", func(r *Request, _ *Normalized) *Error {
		if strings.TrimSpace(r.Tool) == "" {
			return refuse(CodeInvalid, "tool", "a tool is required (for example: observer launch claude)")
		}
		return nil
	}},
	{"V2-tool-launchable", func(r *Request, n *Normalized) *Error {
		tool, sub, ok := ResolveTool(strings.TrimSpace(r.Tool))
		if !ok {
			return refuse(CodeNotLaunchable, "tool", "%q is not a tool Observer can launch in a terminal", r.Tool)
		}
		n.Tool, n.Subcommand = tool, sub
		return nil
	}},
	{"V3-project-absolute", func(r *Request, n *Normalized) *Error {
		p := strings.TrimSpace(r.Project)
		if p == "" || !filepath.IsAbs(p) {
			return refuse(CodeInvalid, "project", "the project directory must be an absolute path (got %q)", r.Project)
		}
		if hasControl(p) {
			return refuse(CodeInvalid, "project", "the project directory contains a control character")
		}
		n.Project = filepath.Clean(p)
		return nil
	}},
	{"V4-sandbox-spelling", func(r *Request, n *Normalized) *Error {
		s := strings.TrimSpace(r.Sandbox)
		switch s {
		case "", SandboxNone:
			return nil
		case SandboxAuto:
			n.Sandboxed, n.Auto = true, true
			return nil
		}
		if !backendID(s) {
			return refuse(CodeInvalid, "sandbox", "%q is not a sandbox backend id (use auto, none or an id from observer sandbox status)", r.Sandbox)
		}
		n.Sandboxed, n.Backend = true, s
		return nil
	}},
	{"V5-workspace-known", func(r *Request, n *Normalized) *Error {
		w := strings.TrimSpace(r.Workspace)
		if w == "" {
			w = WorkspaceLive
		}
		switch w {
		case WorkspaceLive, WorkspaceCloneLocal, WorkspaceCloneRemote, WorkspaceWorktree:
			n.Workspace = w
			return nil
		}
		return refuse(CodeInvalid, "workspace", "unknown workspace source %q (live, clone-local, clone-remote or worktree)", r.Workspace)
	}},
	{"V6-workspace-needs-sandbox", func(_ *Request, n *Normalized) *Error {
		if n.Workspace != WorkspaceLive && !n.Sandboxed {
			return refuse(CodeInvalid, "workspace", "--workspace %s prepares a sandbox workspace; add --sandbox auto or --sandbox <backend>", n.Workspace)
		}
		return nil
	}},
	{"V7-remote-only-with-clone-remote", func(r *Request, n *Normalized) *Error {
		remote := strings.TrimSpace(r.Remote)
		switch {
		case n.Workspace == WorkspaceCloneRemote && remote == "":
			return refuse(CodeInvalid, "remote", "--workspace clone-remote needs --remote <url>")
		case n.Workspace != WorkspaceCloneRemote && remote != "":
			return refuse(CodeInvalid, "remote", "--remote is used only with --workspace clone-remote")
		}
		if err := plainField("remote", remote); err != nil {
			return err
		}
		// The daemon's own guard on a host-side `git clone` (no ext::, no
		// transport helper, no file://, no --upload-pack, only https, ssh
		// and scp form), run here too so a bad URL is a usage error before
		// any daemon work. The daemon still applies its host allow-list.
		if remote != "" {
			if err := workspace.ValidateRemoteURL(remote, nil); err != nil {
				return refuse(CodeInvalid, "remote", "--remote %v", err)
			}
		}
		n.Remote = remote
		return nil
	}},
	{"V8-branch-not-live", func(r *Request, n *Normalized) *Error {
		branch := strings.TrimSpace(r.Branch)
		if branch != "" && n.Workspace == WorkspaceLive {
			return refuse(CodeInvalid, "branch", "--branch is used only with a clone or worktree workspace (the live workspace is the directory as it is)")
		}
		if err := plainField("branch", branch); err != nil {
			return err
		}
		// Every workspace source takes ONE git branch name component (a
		// clone checks out -b <branch>, whose token may hold no '/'; a
		// worktree composes observer-sandbox/<id>/<label>), judged by git's
		// own check-ref-format rules for a component.
		if branch != "" {
			if err := workspace.ValidateRefComponent(branch); err != nil {
				return refuse(CodeInvalid, "branch", "--branch: %v", err)
			}
		}
		n.Branch = branch
		return nil
	}},
	{"V9-model-plain", func(r *Request, n *Normalized) *Error {
		model := strings.TrimSpace(r.Model)
		if err := plainField("model", model); err != nil {
			return err
		}
		n.Model = model
		return nil
	}},
}

// Normalize walks the validation rows and returns the normalized request,
// or the first row's refusal (an *Error).
func Normalize(r Request) (Normalized, error) {
	var n Normalized
	for _, row := range validationRows {
		if err := row.check(&r, &n); err != nil {
			return Normalized{}, err
		}
	}
	return n, nil
}

// ResolveTool maps a tool id or launcher verb to the canonical tool id and
// its launcher verb, for a row the embedded terminal may launch
// (integration.TerminalLaunchable: a grounded launch spec and an advertised
// lifecycle). ok is false otherwise.
func ResolveTool(name string) (tool, subcommand string, ok bool) {
	if name == "" {
		return "", "", false
	}
	candidates := []string{name}
	if t, found := integration.ToolForLaunchSubcommand(name); found && t != name {
		candidates = append(candidates, t)
	}
	for _, t := range candidates {
		c, found := integration.For(t)
		if !found || !integration.TerminalLaunchable(c) {
			continue
		}
		return c.Tool, c.Handoff.Launch.Subcommand, true
	}
	return "", "", false
}

// backendID reports whether s is spelled like a registry backend id
// (lower-case letters, digits and dashes). Membership is judged by Choose
// against the daemon's own rows.
func backendID(s string) bool {
	if s == "" || len(s) > 64 || s[0] == '-' {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

// plainField refuses a value that could be read as an option, carries a
// control character or whitespace, or is unreasonably long. Empty is fine.
func plainField(field, v string) *Error {
	switch {
	case v == "":
		return nil
	case len(v) > maxFieldLen:
		return refuse(CodeInvalid, field, "--%s is longer than %d characters", field, maxFieldLen)
	case strings.HasPrefix(v, "-"):
		return refuse(CodeInvalid, field, "--%s must not start with '-'", field)
	case hasControl(v) || strings.ContainsFunc(v, unicode.IsSpace):
		return refuse(CodeInvalid, field, "--%s must not contain spaces or control characters", field)
	}
	return nil
}

func hasControl(s string) bool { return strings.ContainsFunc(s, unicode.IsControl) }
