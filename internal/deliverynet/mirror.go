package deliverynet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Mirror operation timeouts.
const (
	cloneTimeout    = 10 * time.Minute
	fetchTimeout    = 5 * time.Minute
	lsRemoteTimeout = 60 * time.Second
	localTimeout    = 20 * time.Second
)

// gitEnvAllow are the variables a git process inherits. Everything that
// could point git at another repository (GIT_DIR, GIT_WORK_TREE,
// GIT_INDEX_FILE, GIT_OBJECT_DIRECTORY, GIT_ALTERNATE_OBJECT_DIRECTORIES,
// GIT_CONFIG_*) is deliberately absent. GIT_SSH and GIT_SSH_COMMAND are
// absent too: the user's ssh command is folded into the one batch-mode
// GIT_SSH_COMMAND every process gets (see sshBatchCommand).
var gitEnvAllow = []string{
	"PATH", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "SYSTEMROOT",
	"TMPDIR", "TEMP", "TMP", "SSH_AUTH_SOCK",
	"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy", "ALL_PROXY",
	"SSL_CERT_FILE", "SSL_CERT_DIR", "GIT_SSL_CAINFO",
}

// reMirrorName is the only directory name a mirror may have.
var reMirrorName = regexp.MustCompile(`^[0-9a-f]{16}\.git$`)

// reBranch is a conservative branch-name shape for the fetch refspec.
var reBranch = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._/-]{0,199}$`)

// ValidBranch reports whether b is safe to place in a refspec.
func ValidBranch(b string) bool {
	if !reBranch.MatchString(b) || strings.Contains(b, "..") || strings.Contains(b, "//") ||
		strings.HasSuffix(b, "/") || strings.HasSuffix(b, ".") || strings.HasSuffix(b, ".lock") {
		return false
	}
	return true
}

// MirrorRoot returns the Observer-owned mirror root
// (~/.observer/delivery/mirrors unless overridden).
func (c *Client) MirrorRoot() (string, error) {
	if c.mirrorRoot != "" {
		return filepath.Abs(c.mirrorRoot)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", newErr(KindInvalid, 0, "no home directory")
	}
	return filepath.Join(home, ".observer", "delivery", "mirrors"), nil
}

// URLHash is sha256(url)[:16] hex: the mirror's directory name and the
// delivery_mirrors url_hash. url must already be sanitised.
func URLHash(u string) string {
	sum := sha256.Sum256([]byte(u))
	return hex.EncodeToString(sum[:])[:16]
}

// MirrorDir returns the mirror directory for a remote URL (sanitised first).
func (c *Client) MirrorDir(rawURL string) (string, error) {
	u, err := c.SanitizeRemoteURL(rawURL)
	if err != nil {
		return "", err
	}
	root, err := c.MirrorRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, URLHash(u)+".git"), nil
}

// checkMirrorDir refuses any directory that is not a direct child of the
// mirror root named <16 hex>.git. A path outside the root (a user
// repository, a traversal, a symlink) is refused before git ever runs.
func (c *Client) checkMirrorDir(dir string) (string, error) {
	root, err := c.MirrorRoot()
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", newErr(KindInvalid, 0, "bad mirror directory")
	}
	abs = filepath.Clean(abs)
	if filepath.Dir(abs) != filepath.Clean(root) || !reMirrorName.MatchString(filepath.Base(abs)) {
		return "", newErr(KindInvalid, 0, "mirror directory must be under the Observer mirror root")
	}
	if fi, err := os.Lstat(abs); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return "", newErr(KindInvalid, 0, "mirror directory is a symlink")
	}
	return abs, nil
}

var reSCP = regexp.MustCompile(`^([A-Za-z0-9._-]+@)?([A-Za-z0-9.-]+):([A-Za-z0-9._~/-]+)$`)

// SanitizeRemoteURL returns the remote URL a mirror may use: https with no
// user info; ssh:// with at most a user name (a password is dropped);
// scp-style user@host:path as is; file:// only when AllowFileRemotes. Plain
// http, git://, ext:: and anything starting with "-" are refused.
func (c *Client) SanitizeRemoteURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "-") || strings.ContainsAny(raw, " \t\r\n\x00") || strings.Contains(raw, "::") {
		return "", newErr(KindInvalid, 0, "remote URL not allowed")
	}
	if m := reSCP.FindStringSubmatch(raw); m != nil && !strings.Contains(raw, "://") {
		if strings.HasPrefix(m[3], "-") {
			return "", newErr(KindInvalid, 0, "remote URL not allowed")
		}
		return raw, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", newErr(KindInvalid, 0, "remote URL not allowed")
	}
	switch u.Scheme {
	case "https":
		if u.Host == "" {
			return "", newErr(KindInvalid, 0, "remote URL not allowed")
		}
		u.User = nil
	case "ssh":
		if u.Host == "" {
			return "", newErr(KindInvalid, 0, "remote URL not allowed")
		}
		if u.User != nil {
			u.User = url.User(u.User.Username())
		}
	case "file":
		if !c.allowFile {
			return "", newErr(KindInvalid, 0, "remote URL not allowed")
		}
		u.User = nil
	default:
		return "", newErr(KindInvalid, 0, "remote URL not allowed")
	}
	u.RawQuery, u.Fragment = "", ""
	return u.String(), nil
}

// allowedProtocols is GIT_ALLOW_PROTOCOL: the transports git may use at all
// (also for submodules and redirects inside git itself).
func (c *Client) allowedProtocols() string {
	if c.allowFile {
		return "https:ssh:file"
	}
	return "https:ssh"
}

// failingAskpass is a program that exits non-zero, so a credential prompt
// can never block or leak.
func failingAskpass() string {
	if _, err := os.Stat("/bin/false"); err == nil {
		return "/bin/false"
	}
	return "false"
}

// sshBatchCommand returns the GIT_SSH_COMMAND every mirror git process runs
// with: the user's own ssh command, taken in git's own precedence order
// (the GIT_SSH_COMMAND variable, else core.sshCommand from their
// configuration, else the GIT_SSH program, else plain ssh), with batch mode
// forced on by APPENDING the flag. Batch mode is never optional: ssh then
// fails at once instead of asking for a password, a key passphrase or a
// host key confirmation, so a mirror fetch can never hang on a prompt nobody
// sees. A key that needs a passphrase works only when it is loaded in
// ssh-agent (SSH_AUTH_SOCK is inherited). PuTTY's plink takes -batch
// instead of -o BatchMode=yes.
func sshBatchCommand(userCommand, configCommand, gitSSH string) string {
	base := strings.TrimSpace(userCommand)
	if base == "" {
		base = strings.TrimSpace(configCommand)
	}
	if base == "" && strings.TrimSpace(gitSSH) != "" {
		base = shellQuote(strings.TrimSpace(gitSSH))
	}
	if base == "" {
		base = "ssh"
	}
	if isPlink(base) {
		return base + " -batch"
	}
	return base + " -o BatchMode=yes"
}

// isPlink reports whether a shell command's program is PuTTY's plink (or
// TortoisePlink), which spells batch mode -batch.
func isPlink(command string) bool {
	command = strings.TrimSpace(command)
	var prog string
	if q := command[:min(1, len(command))]; q == "'" || q == `"` {
		// A quoted program path may hold spaces: it runs to the closing quote.
		end := strings.Index(command[1:], q)
		if end < 0 {
			return false
		}
		prog = command[1 : end+1]
	} else if f := strings.Fields(command); len(f) > 0 {
		prog = f[0]
	}
	name := strings.ToLower(prog)
	// A Windows path names its program after the last backslash, even when
	// this binary runs on another OS (a configuration copied between hosts).
	name = strings.TrimSuffix(name[strings.LastIndexAny(name, `/\`)+1:], ".exe")
	return strings.Contains(name, "plink")
}

// shellQuote quotes a program path for the shell git runs GIT_SSH_COMMAND
// through.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// configSSHCommand reads core.sshCommand from the user's own git
// configuration (read only: `git config --get`, outside any repository),
// "" when unset.
func (c *Client) configSSHCommand(ctx context.Context, bin, root string) string {
	cctx, cancel := context.WithTimeout(ctx, localTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, "config", "--get", "core.sshCommand") //nolint:gosec // G204: fixed argv
	cmd.Dir = root
	cmd.Env = c.baseGitEnv(root)
	cmd.Stdin = bytes.NewReader(nil)
	var out, errOut capBuffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		return ""
	}
	return strings.TrimSpace(out.String())
}

// baseGitEnv is the fixed environment without the ssh command or GIT_DIR.
func (c *Client) baseGitEnv(root string) []string {
	env := c.env(gitEnvAllow)
	return append(env,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS="+failingAskpass(),
		"SSH_ASKPASS="+failingAskpass(),
		"GCM_INTERACTIVE=never",
		"LC_ALL=C",
		"GIT_ALLOW_PROTOCOL="+c.allowedProtocols(),
		"GIT_CEILING_DIRECTORIES="+filepath.Dir(root),
	)
}

// gitEnv composes the fixed environment of every git process: no terminal
// prompt, a failing askpass, a batch-mode ssh command, the allow-listed
// variables and, for a command inside a mirror, its GIT_DIR.
func (c *Client) gitEnv(root, gitDir, sshCommand string) []string {
	env := append(c.baseGitEnv(root), "GIT_SSH_COMMAND="+sshCommand)
	if gitDir != "" {
		env = append(env, "GIT_DIR="+gitDir)
	}
	return env
}

// runGit runs one git process with cwd = the mirror root (never a user
// directory) and returns stdout. The output is capped; stderr text is never
// returned.
func (c *Client) runGit(ctx context.Context, timeout time.Duration, gitDir string, args ...string) ([]byte, error) {
	root, err := c.MirrorRoot()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, newErr(KindInvalid, 0, "cannot create the mirror root")
	}
	bin, err := c.resolve("git")
	if err != nil {
		return nil, newErr(KindUnavailable, 0, "git is not installed")
	}
	// No hooks from the user's global core.hooksPath ever run in a mirror.
	argv := append([]string{"-c", "core.hooksPath=" + filepath.Join(root, ".no-hooks")}, args...)
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, argv...) //nolint:gosec // G204: fixed argv; URL, dir and branch are validated before this call
	cmd.Dir = root
	ssh := sshBatchCommand(c.getenv("GIT_SSH_COMMAND"), "", c.getenv("GIT_SSH"))
	if c.getenv("GIT_SSH_COMMAND") == "" {
		ssh = sshBatchCommand("", c.configSSHCommand(ctx, bin, root), c.getenv("GIT_SSH"))
	}
	cmd.Env = c.gitEnv(root, gitDir, ssh)
	cmd.Stdin = bytes.NewReader(nil)
	var out, errOut capBuffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err = cmd.Run()
	if cctx.Err() != nil {
		return nil, newErr(KindUnreachable, 0, "git timed out")
	}
	var ee *exec.ExitError
	switch {
	case err == nil:
		return out.Bytes(), nil
	case errors.As(err, &ee):
		return nil, classifyGit(errOut.String())
	}
	return nil, newErr(KindUnavailable, 0, "git did not start")
}

// gitRule maps a git failure message to a Kind (first match wins).
type gitRule struct {
	needle string
	kind   Kind
	msg    string
}

// needsNonInteractiveMsg is the one message for a refused credential prompt.
const needsNonInteractiveMsg = "git needed to ask for a password, a key passphrase or a host key confirmation, " +
	"and mirror fetches never ask. Use a credential helper, a key loaded in ssh-agent, or a known host"

var gitRules = []gitRule{
	{"authentication failed", KindAuthFailed, "the remote refused your git credentials"},
	// A prompt the fixed environment refused (GIT_TERMINAL_PROMPT=0, the
	// failing askpass, ssh BatchMode): the remote may well accept the
	// user, just not interactively.
	{"terminal prompts disabled", KindNeedsNonInteractive, needsNonInteractiveMsg},
	{"could not read username", KindNeedsNonInteractive, needsNonInteractiveMsg},
	{"could not read password", KindNeedsNonInteractive, needsNonInteractiveMsg},
	{"unable to read askpass response", KindNeedsNonInteractive, needsNonInteractiveMsg},
	{"host key verification failed", KindNeedsNonInteractive, needsNonInteractiveMsg},
	{"permission denied", KindAuthFailed, "the remote refused your git credentials (an ssh key with a passphrase must be loaded in ssh-agent)"},
	{"repository not found", KindNotFound, "the remote repository was not found"},
	{"does not appear to be a git repository", KindNotFound, "the remote repository was not found"},
	{"couldn't find remote ref", KindNotFound, "the default branch was not found on the remote"},
	{"could not resolve host", KindUnreachable, "the remote host could not be resolved"},
	{"unable to access", KindUnreachable, "the remote could not be reached"},
	{"connection", KindUnreachable, "the remote could not be reached"},
	{"transport", KindInvalid, "this remote transport is not allowed"},
}

func classifyGit(stderr string) *Error {
	low := strings.ToLower(stderr)
	for _, r := range gitRules {
		if strings.Contains(low, r.needle) {
			return newErr(r.kind, 0, r.msg)
		}
	}
	return newErr(KindUnreachable, 0, "git failed")
}

// Clone creates a bare blobless mirror of rawURL at dir:
// `git clone --template= --bare --filter=blob:none --no-tags -- <url> <dir>`.
// dir MUST be the MirrorDir of the URL under the mirror root; anything else
// is refused. The URL is sanitised first, so the mirror's config never holds
// user info.
func (c *Client) Clone(ctx context.Context, rawURL, dir string) error {
	u, err := c.SanitizeRemoteURL(rawURL)
	if err != nil {
		return err
	}
	abs, err := c.checkMirrorDir(dir)
	if err != nil {
		return err
	}
	if filepath.Base(abs) != URLHash(u)+".git" {
		return newErr(KindInvalid, 0, "mirror directory does not belong to this URL")
	}
	if _, err := os.Lstat(abs); err == nil {
		return newErr(KindInvalid, 0, "mirror directory already exists")
	}
	if _, err := c.runGit(ctx, cloneTimeout, "", "clone", "--template=", "--bare", "--filter=blob:none", "--no-tags", "--quiet", "--", u, abs); err != nil {
		_ = os.RemoveAll(abs)
		return err
	}
	return nil
}

// LsRemote returns the sha the remote advertises for ref (for example
// "refs/heads/main"), the no-change check before every refresh. It runs
// with no repository at all.
func (c *Client) LsRemote(ctx context.Context, rawURL, ref string) (string, error) {
	u, err := c.SanitizeRemoteURL(rawURL)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(ref, "refs/heads/") || !ValidBranch(strings.TrimPrefix(ref, "refs/heads/")) {
		return "", newErr(KindInvalid, 0, "bad ref")
	}
	out, err := c.runGit(ctx, lsRemoteTimeout, "", "ls-remote", "--", u, ref)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		sha, name, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if ok && name == ref && ValidSHA(sha) {
			return sha, nil
		}
	}
	return "", newErr(KindNotFound, 0, "the default branch was not found on the remote")
}

// Refresh fetches the default branch into the mirror only:
// `git -C <dir> fetch --no-tags --filter=blob:none origin +refs/heads/<b>:refs/heads/<b>`.
func (c *Client) Refresh(ctx context.Context, dir, defaultBranch string) error {
	abs, err := c.existingMirror(dir)
	if err != nil {
		return err
	}
	if !ValidBranch(defaultBranch) {
		return newErr(KindInvalid, 0, "bad branch name")
	}
	spec := "+refs/heads/" + defaultBranch + ":refs/heads/" + defaultBranch
	_, err = c.runGit(ctx, fetchTimeout, abs, "-C", abs, "fetch", "--no-tags", "--filter=blob:none", "--quiet", "origin", spec)
	return err
}

// HeadBranch returns the branch the mirror's HEAD names (the remote's
// default branch at clone time).
func (c *Client) HeadBranch(ctx context.Context, dir string) (string, error) {
	abs, err := c.existingMirror(dir)
	if err != nil {
		return "", err
	}
	out, err := c.runGit(ctx, localTimeout, abs, "-C", abs, "symbolic-ref", "--quiet", "HEAD")
	if err != nil {
		return "", err
	}
	b := strings.TrimPrefix(strings.TrimSpace(string(out)), "refs/heads/")
	if !ValidBranch(b) {
		return "", newErr(KindWrongShape, 0, "mirror HEAD is not a branch")
	}
	return b, nil
}

// LocalTip returns the mirror's own refs/heads/<branch> sha.
func (c *Client) LocalTip(ctx context.Context, dir, branch string) (string, error) {
	abs, err := c.existingMirror(dir)
	if err != nil {
		return "", err
	}
	if !ValidBranch(branch) {
		return "", newErr(KindInvalid, 0, "bad branch name")
	}
	out, err := c.runGit(ctx, localTimeout, abs, "-C", abs, "rev-parse", "--verify", "--quiet", "refs/heads/"+branch)
	if err != nil {
		return "", err
	}
	sha := strings.TrimSpace(string(out))
	if !ValidSHA(sha) {
		return "", newErr(KindWrongShape, 0, "unexpected rev-parse output")
	}
	return sha, nil
}

// Size returns the bytes a mirror occupies on disk.
func (c *Client) Size(dir string) (int64, error) {
	abs, err := c.existingMirror(dir)
	if err != nil {
		return 0, err
	}
	var total int64
	err = filepath.WalkDir(abs, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			if fi, err := d.Info(); err == nil {
				total += fi.Size()
			}
		}
		return nil
	})
	if err != nil {
		return 0, newErr(KindInvalid, 0, "cannot measure the mirror")
	}
	return total, nil
}

// RemoveMirror deletes a mirror directory (only ever one under the mirror
// root). A missing directory is not an error.
func (c *Client) RemoveMirror(dir string) error {
	abs, err := c.checkMirrorDir(dir)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(abs); err != nil {
		return newErr(KindInvalid, 0, "cannot remove the mirror")
	}
	return nil
}

// existingMirror validates dir and requires it to be a bare repository.
func (c *Client) existingMirror(dir string) (string, error) {
	abs, err := c.checkMirrorDir(dir)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(filepath.Join(abs, "HEAD"))
	if err != nil || !fi.Mode().IsRegular() {
		return "", newErr(KindNotFound, 0, "mirror does not exist")
	}
	return abs, nil
}
