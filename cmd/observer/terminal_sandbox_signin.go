//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"golang.org/x/term"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxsignin"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// terminal_sandbox_signin.go is sign-in seeding (lane BOXSIGNIN, operator
// ruling P-180 (6), tracker R-186): the ONE seam every backend asks whether
// a sandboxed run gets a copy of the tool's sign-in. The decision is
// internal/sandboxsignin's table over facts resolved here (the tool's
// registry sign-in row, the backend's projection or hosting, the org's
// forbid, the remembered and per-launch consent); the copy is here.
//
// Only a run whose tool state is PROJECTED gets a copy: a container row
// that crosses a kernel (oci-runsc) or runs the image's own copy of the
// tool (oci-runc, Podman), which starts from an empty per-run state
// directory under <managed>/<run>.state. Every other local row (bwrap,
// Landlock, Seatbelt, mxc-process, Apple container, oci-runc with the
// host's tool) binds or grants the tool's own state directory, so its
// sign-in is the host's file read in place, never a copy; the VM row has no
// tool state yet. A hosted row is refused (the copy would sit on a third
// party's machine). The copy lives inside the projection, so it goes with
// it on every end path (the helper after the run, Destroy, the daemon-start
// sweep keyed on the run's relay record), and nothing the tool writes to it
// is copied back.
//
// A bound row shares the tool's sign-in with the box on every launch, and
// that is kept (operator ruling P-183, "Keep it, say it plainly"): the box
// limits files and network, not the tool's own login. Every such launch
// says so plainly (sandboxSignInShared: the launcher inside the box prints
// sandboxsignin.SharedLine; oci-runc says it in its own notices), and the
// consent and the org forbid apply to clean-copy runs only.

func init() { sandboxSignInSharedNotice = sandboxSignInSharedLine }

// sandboxSignInMaxBytes caps one copied sign-in file.
const sandboxSignInMaxBytes = 64 << 10

// sandboxSignInAnswer maps the per-launch answer.
func sandboxSignInAnswer(p *bool) sandboxsignin.Answer {
	switch {
	case p == nil:
		return sandboxsignin.AnswerNone
	case *p:
		return sandboxsignin.AnswerYes
	default:
		return sandboxsignin.AnswerNo
	}
}

// signInDecision decides one launch from the runtime's effective config (an
// org forbid is already applied there by the sandbox managed policy).
func (r *sandboxRuntime) signInDecision(req termsvc.PrepareRequest, projected, hosted bool) sandboxsignin.Decision {
	in := sandboxsignin.Input{
		Tool: req.Tool, Hosted: hosted, Projected: projected,
		OrgForbidden: r.cfg.SignInSeedForbidden,
		Remembered:   slices.Contains(r.cfg.SignInSeedTools, req.Tool),
		Launch:       sandboxSignInAnswer(req.SignInSeed),
		Interactive:  req.SignInAsk,
	}
	if row, ok := integration.SandboxSignInFor(req.Tool); ok {
		in.Files, in.Keychain, in.MayUseKeychain = row.Files, row.KeychainOnOS(runtime.GOOS), row.MayUseKeychain
	}
	return sandboxsignin.Decide(in)
}

// signInGate is a decision's effect before any workspace is made: an ask
// returns the consent question (the dashboard's inline step, the CLI
// prompt), and an explicit yes the decision cannot honour (hosted, no row,
// keychain, the organization) refuses the launch by name, so no one starts
// a box they believe is signed in.
func signInGate(req termsvc.PrepareRequest, d sandboxsignin.Decision) error {
	switch {
	case d.Verdict == sandboxsignin.VerdictAsk:
		return &termsvc.SignInConsentError{Tool: req.Tool, Files: d.Files, Text: sandboxsignin.ConsentText(req.Tool, d.Files)}
	case d.RefusesExplicit() && req.SignInSeed != nil && *req.SignInSeed:
		return sandboxRefusalError{msg: fmt.Sprintf("terminal_sandbox: %s's sign-in is not copied into the box: %s", req.Tool, d.Reason)}
	}
	return nil
}

// sandboxSignInCopy is one planned copy: the real file, the directory the
// confined open starts from (no symbolic link below it), and its place in
// the run's projected state.
type sandboxSignInCopy struct{ Rel, From, Root, To string }

// sandboxSeedSignIn copies each planned file, returning the HOME-relative
// names copied. A file the machine does not have is skipped (the tool is
// not signed in through it here); any other problem refuses the launch.
func sandboxSeedSignIn(copies []sandboxSignInCopy) ([]string, error) {
	var out []string
	for _, c := range copies {
		ok, err := sandboxCopySignInFile(c.Root, c.From, c.To)
		if err != nil {
			return out, err
		}
		if ok {
			out = append(out, c.Rel)
		}
	}
	return out, nil
}

// sandboxCopySignInFile copies one sign-in file: opened by the confined
// reader's rules under root (sandboxrelayd.OpenConfinedTail: no symbolic
// link at any component below root, O_NOFOLLOW and O_NONBLOCK, so a FIFO or
// a device swapped in can never hold the open, the opened descriptor the
// regular file that was checked), under the cap, written fresh (O_EXCL)
// with owner-only permissions under owner-only directories. ok is false for
// a file that is not there.
func sandboxCopySignInFile(root, from, to string) (bool, error) {
	if _, err := os.Lstat(from); errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	src, err := sandboxrelayd.OpenConfinedTail([]string{root}, from)
	if err != nil {
		return false, fmt.Errorf("sign-in file %s is not a regular file reached without a symbolic link (a link at any component, a FIFO or a device is refused, never followed), so the sign-in is not copied", from)
	}
	defer func() { _ = src.Close() }()
	if fi, err := src.Stat(); err != nil || fi.Size() > sandboxSignInMaxBytes {
		return false, fmt.Errorf("sign-in file %s is not a regular file under %d bytes, so the sign-in is not copied", from, sandboxSignInMaxBytes)
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		return false, fmt.Errorf("sign-in copy: %w", err)
	}
	dst, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the run's own fresh projected state directory
	if err != nil {
		return false, fmt.Errorf("sign-in copy: %w", err)
	}
	n, werr := io.Copy(dst, io.LimitReader(src, sandboxSignInMaxBytes+1))
	if werr == nil && n > sandboxSignInMaxBytes {
		werr = fmt.Errorf("sign-in file %s grew past %d bytes while it was copied", from, sandboxSignInMaxBytes)
	}
	if cerr := dst.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(to)
		return false, werr
	}
	return true, nil
}

// sandboxSignInGetenv is the environment the sign-in files' relocation
// variables (CLAUDE_CONFIG_DIR, CODEX_HOME) are read from: this process's
// own, unless its home is isolated from the account's real home, where no
// variable is read (the pinned or isolated home rule of
// proxyroute.defaultInspectEnv). A variable for tests.
var sandboxSignInGetenv = func() func(string) string {
	if crossmount.IsolationReason() != "" {
		return nil
	}
	return os.Getenv
}

// sandboxSignInSource is where one sign-in file is on this machine.
type sandboxSignInSource struct{ from, root string }

// sandboxSignInSources resolves each of tool's sign-in files (files, in the
// row's order) through the vendor's own relocation rule
// (agentconfig.ResolveArtifact on the row's Artifacts, audit finding 5): a
// moved file is read where the tool reads it. A variable whose relative
// value the tool reads against its own working directory, or a row that
// names no single file, refuses by name; a file outside home is opened
// under its own directory.
func sandboxSignInSources(home, tool string, files []string, getenv func(string) string) ([]sandboxSignInSource, error) {
	row, _ := integration.SandboxSignInFor(tool)
	out := make([]sandboxSignInSource, 0, len(files))
	for i, f := range files {
		src := sandboxSignInSource{from: filepath.Join(home, filepath.FromSlash(f)), root: home}
		if i < len(row.Artifacts) && row.Artifacts[i] != "" {
			got, err := agentconfig.ResolveArtifact(row.Artifacts[i], agentconfig.PathEnv{GOOS: runtime.GOOS, Home: home, Getenv: getenv})
			if err != nil {
				return nil, fmt.Errorf("terminal_sandbox: %s's sign-in file: %w", tool, err)
			}
			switch got.Status {
			case agentconfig.PathResolved:
				src.from = filepath.Clean(got.Path)
				if rel, rerr := filepath.Rel(home, src.from); rerr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					src.root = filepath.Dir(src.from)
				}
			case agentconfig.PathRelocationUnresolved:
				return nil, sandboxRefusalError{msg: fmt.Sprintf("terminal_sandbox: %s's sign-in is not copied: %s holds a relative path the tool reads against its own working directory, so Observer cannot name the file", tool, got.RelocatedBy)}
			default:
				return nil, sandboxRefusalError{msg: fmt.Sprintf("terminal_sandbox: %s's sign-in is not copied: its file has no single path on this machine (%s)", tool, got.Status)}
			}
		}
		out = append(out, src)
	}
	return out, nil
}

// sandboxSignInPlan pairs each sign-in file's source with its place in the
// run's projected state: the place the tool inside the box reads (the
// row's default path under the box's home, which no relocation variable
// reaches), and the source wherever the vendor's relocation put it.
func sandboxSignInPlan(home string, places []sandboxSignInPlace, tool string, files []string, getenv func(string) string) ([]sandboxSignInCopy, error) {
	srcs, err := sandboxSignInSources(home, tool, files, getenv)
	if err != nil {
		return nil, err
	}
	if len(places) != len(files) {
		return nil, sandboxRefusalError{msg: fmt.Sprintf("terminal_sandbox: %s's sign-in is not copied: its file has no place in this run's projected state", tool)}
	}
	out := make([]sandboxSignInCopy, 0, len(files))
	for i, f := range files {
		out = append(out, sandboxSignInCopy{Rel: f, From: srcs[i].from, Root: srcs[i].root, To: places[i].to})
	}
	return out, nil
}

// sandboxSignInPlace is where one sign-in file goes in a run's projection.
type sandboxSignInPlace struct{ to string }

// sandboxSignInDropEnv is what a run's box must not get (sandboxenv
// .Spec.Drop): on a projected run, every relocation variable of the tool's
// sign-in files (the registry row's Artifacts through
// agentconfig.RelocationsFor: CLAUDE_CONFIG_DIR, CODEX_HOME), so the tool
// reads its projected state, the seeded copy included, at the default path
// instead of a host path the box does not bind. A run that binds the
// tool's own state keeps them.
func sandboxSignInDropEnv(tool string, projected bool) []string {
	row, ok := integration.SandboxSignInFor(tool)
	if !projected || !ok {
		return nil
	}
	var out []string
	for _, id := range row.Artifacts {
		for _, r := range agentconfig.RelocationsFor(id) {
			if r.Env != "" && !slices.Contains(out, r.Env) {
				out = append(out, r.Env)
			}
		}
	}
	return out
}

// sandboxStateBinder is a driver whose box binds or grants the tool's own
// state directory (Landlock, Seatbelt, mxc-process, Apple container), so
// the tool's sign-in is shared with the box on every launch (operator
// ruling P-183). bubblewrap (the runtime's own path) binds it too; the
// container driver says it in its own notices, where it knows the run's
// projection; the VM and hosted rows do not bind it.
type sandboxStateBinder interface{ bindsToolState() bool }

// sandboxSignInSharedTool is tool when it has a sign-in row (the launch
// names it to the box, sandboxenv.EnvSignInShared), "" otherwise.
func sandboxSignInSharedTool(tool string) string {
	if _, ok := integration.SandboxSignInFor(tool); ok {
		return tool
	}
	return ""
}

// sandboxSignInSharedLine is the run's terminal line for a box that shares
// tool's own state (sandboxsignin.SharedLine), "" for a tool with no row.
func sandboxSignInSharedLine(tool string) string {
	row, ok := integration.SandboxSignInFor(tool)
	if !ok {
		return ""
	}
	return "observer sandbox: " + sandboxsignin.SharedLine(tool, row.Files)
}

// sandboxSignInForbiddenSeam backs the Settings card's org forbid (audit
// finding 3): the config at configPath with the in-force sandbox managed
// policy composed onto it (effectiveSandboxConfig), read at each call, so
// the card shows the forbid the next launch obeys.
func sandboxSignInForbiddenSeam(configPath string) func() bool {
	return func() bool {
		cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
		if err != nil {
			return false
		}
		return effectiveSandboxConfig(cfg).SignInSeedForbidden
	}
}

// sandboxCLICanAsk reports whether the CLI launch can ask (stdin and stderr
// are terminals).
func sandboxCLICanAsk() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd()))
}

// sandboxCLIAskSignIn asks the consent question on the terminal: y copies
// the sign-in for this run, a copies it and remembers the answer for the
// tool ([terminal.sandbox].sign_in_seed_tools), anything else starts
// without it.
func sandboxCLIAskSignIn(in io.Reader, out io.Writer, q *termsvc.SignInConsentError) (yes, remember bool, err error) {
	fmt.Fprintf(out, "observer sandbox: %s\n  [y] yes, for this run  [a] always for %s  [N] no, start without it: ", q.Text, q.Tool)
	line, rerr := bufio.NewReader(in).ReadString('\n')
	if rerr != nil && !errors.Is(rerr, io.EOF) {
		return false, false, fmt.Errorf("read your answer: %w", rerr)
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, false, nil
	case "a", "always":
		return true, true, nil
	default:
		return false, false, nil
	}
}

// sandboxRememberSignIn adds tool to [terminal.sandbox].sign_in_seed_tools
// in the local config file (a structural patch: comments and every other
// key stay as they are).
func sandboxRememberSignIn(configPath, tool string) error {
	path, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return err
	}
	mu := config.WriteLock()
	mu.Lock()
	defer mu.Unlock()
	cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
	if err != nil {
		return err
	}
	if slices.Contains(cfg.Terminal.Sandbox.SignInSeedTools, tool) {
		return nil
	}
	next := cfg
	next.Terminal.Sandbox.SignInSeedTools = append(append([]string(nil), cfg.Terminal.Sandbox.SignInSeedTools...), tool)
	patches, err := config.StructuralPatches(cfg, next)
	if err != nil {
		return err
	}
	_, err = config.PatchFile(path, next, patches)
	return err
}

// sandboxSignInDoctorChecks is the posture line of sign-in seeding (lane
// BOXSIGNIN) for doctor and `observer sandbox status`: the remembered tools
// and the org's forbid, tool names only.
func sandboxSignInDoctorChecks(eff config.TerminalSandboxConfig) []diag.Check {
	msg := "sign-in seeding: asked at launch (" + strings.Join(integration.SandboxSignInTools(), ", ") + ") on a clean-copy container run; none remembered"
	switch {
	case eff.SignInSeedForbidden:
		msg = "sign-in seeding: " + sandboxsignin.OrgReason
	case len(eff.SignInSeedTools) > 0:
		msg = "sign-in seeding: copied without asking for " + strings.Join(eff.SignInSeedTools, ", ") + " ([terminal.sandbox].sign_in_seed_tools) on a clean-copy container run; asked for the others"
	}
	// What seeding does not cover, said plainly (operator ruling P-183).
	msg += "; " + sandboxsignin.BoundNote
	return []diag.Check{{Name: "sandbox.sign_in_seed", Status: diag.StatusOK, Message: msg}}
}
