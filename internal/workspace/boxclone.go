package workspace

import (
	"fmt"
	"path"
	"strings"
)

// boxclone.go composes the box-side clone of a remote_clone delivery on a
// hosted row whose box clones with no git credential (the vendor rows; the
// org-hosted row's clone argv is its organization's own,
// internal/openshellorg.CloneArgv). The box runs these; nothing of this
// machine's tree is uploaded, and the clone is never made here. Pure: argv
// and environment only, the hosted core runs them in the box.

// BoxCloneRequest is one box-side clone: the URL (validated by
// ValidateBoxCloneURL), the box's workspace path it clones into, and the
// optional work branch made after the clone (the clone-remote source's
// Branch, the same `checkout -b` the host-side clone runs).
type BoxCloneRequest struct {
	URL    string
	Dest   string
	Branch string
}

// BoxClone is the composed box-side clone.
type BoxClone struct {
	// GitCheck exits 0 when the box has git (run before the clone, so a box
	// without it is refused plainly instead of failing inside the clone).
	GitCheck []string
	// Clone is `git clone -- <url> <dest>`, the host-side clone's argv.
	Clone []string
	// Branch is `git -C <dest> checkout -b <branch>`, nil when no branch.
	Branch []string
	// Head prints the commit the box cloned (`git -C <dest> rev-parse
	// --verify HEAD`); the return diff is against it.
	Head []string
	// Env is the clone's fixed environment: no prompt, so a repository that
	// asks for a sign-in fails at once instead of waiting.
	Env map[string]string
}

// boxGitCheckScript exits 0 exactly when git is on the box's PATH.
const boxGitCheckScript = `command -v git >/dev/null 2>&1`

// PlanBoxClone composes the box-side clone of req.
func PlanBoxClone(req BoxCloneRequest) (BoxClone, error) {
	if err := validateNoControlOrWhitespace("URL", req.URL); err != nil || req.URL == "" || strings.HasPrefix(req.URL, "-") {
		return BoxClone{}, fmt.Errorf("workspace.PlanBoxClone: the URL %q is not a validated remote", req.URL)
	}
	if err := validateBoxPath(req.Dest); err != nil {
		return BoxClone{}, err
	}
	c := BoxClone{
		GitCheck: []string{"sh", "-c", boxGitCheckScript},
		Clone:    []string{"git", "clone", "--", req.URL, req.Dest},
		Head:     []string{"git", "-C", req.Dest, "rev-parse", "--verify", "HEAD"},
		Env:      map[string]string{"GIT_TERMINAL_PROMPT": "0"},
	}
	if req.Branch != "" {
		if err := validateCleanToken("Branch", req.Branch); err != nil {
			return BoxClone{}, err
		}
		c.Branch = []string{"git", "-C", req.Dest, "checkout", "-b", req.Branch}
	}
	return c, nil
}

// validateBoxPath requires a clean absolute slash path in the box (the box
// is Linux whatever this machine is, so path, not filepath).
func validateBoxPath(p string) error {
	if err := validateNoControlOrWhitespace("Dest", p); err != nil {
		return err
	}
	if !path.IsAbs(p) || path.Clean(p) != p || p == "/" {
		return fmt.Errorf("workspace: the box path %q must be a clean absolute path below /", p)
	}
	return nil
}

// BoxCloneDiffArgv is the return diff of a box-side clone run: every change
// staged in the box (the hosted core stages with `git add -A` first) against
// the commit the box cloned, so commits the agent made in the box are in it
// too. The flags are the guest staged diff's: no external diff driver, no
// textconv filter, no pager, no color, binary hunks as patches.
func BoxCloneDiffArgv(commit string) ([]string, error) {
	if !ValidSHA(commit) {
		return nil, fmt.Errorf("workspace.BoxCloneDiffArgv: %q is not a full commit name", commit)
	}
	return []string{"git", "--no-pager", "diff", "--no-ext-diff", "--no-textconv", "--no-color", "--binary", "--cached", commit}, nil
}

// BoxCloneDiffEnv is the return diff's fixed environment.
func BoxCloneDiffEnv() map[string]string {
	return map[string]string{"GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": "cat", "GIT_EXTERNAL_DIFF": ""}
}

// boxCloneURLRule is one rule of ValidateBoxCloneURL beyond
// ValidateRemoteURL: refuses reports whether the URL breaks it, why says so
// in plain words.
type boxCloneURLRule struct {
	name    string
	refuses func(url string, httpsOnly bool) bool
	why     string
}

// boxCloneURLRules are walked top-down; the first that refuses wins.
var boxCloneURLRules = []boxCloneURLRule{
	{"credential-in-url", urlCarriesCredential, "it carries a user name, password or token; a box gets no git credential from this machine, so name the repository without one"},
	{"https-only", func(u string, httpsOnly bool) bool { return httpsOnly && !strings.HasPrefix(u, "https://") }, "a box with no git credential can clone only a public https:// address (an ssh address needs a key the box does not have)"},
}

// ValidateBoxCloneURL is ValidateRemoteURL for a clone the box runs, plus
// the rules of a box this machine does not control: the URL carries no
// credential (the box would hold it), and, when httpsOnly (a row whose box
// gets no git credential at all), it is an https:// address. Callers pass a
// non-empty allowedHosts: a box-side clone never takes the empty list's
// "any host" branch.
func ValidateBoxCloneURL(url string, allowedHosts []string, httpsOnly bool) error {
	if len(allowedHosts) == 0 {
		return fmt.Errorf("workspace.ValidateBoxCloneURL: no git hosts are listed for a box to clone from")
	}
	if err := ValidateRemoteURL(url, allowedHosts); err != nil {
		return err
	}
	for _, r := range boxCloneURLRules {
		if r.refuses(url, httpsOnly) {
			return fmt.Errorf("workspace.ValidateBoxCloneURL: %s", r.why)
		}
	}
	return nil
}

// urlCarriesCredential reports whether a URL-form remote names userinfo
// (https: any; ssh: a password), or an https query or fragment (a token's
// other hiding places). The scp form's user (git@host:path) names no
// secret.
func urlCarriesCredential(u string, _ bool) bool {
	for _, scheme := range []string{"https://", "ssh://"} {
		rest, ok := strings.CutPrefix(u, scheme)
		if !ok {
			continue
		}
		auth := rest
		if i := strings.IndexAny(auth, "/?#"); i >= 0 {
			auth = auth[:i]
		}
		user, _, hasUser := strings.Cut(auth, "@")
		if scheme == "https://" {
			return hasUser || strings.ContainsAny(rest, "?#")
		}
		return hasUser && strings.Contains(user, ":")
	}
	return false
}
