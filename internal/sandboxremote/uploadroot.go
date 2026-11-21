package sandboxremote

import (
	"path"
	"strings"
)

// uploadroot.go says, before Start, whether a folder can be uploaded to a
// hosted box at all (lane UX, item H8): the same root rules PlanManifest
// applies at launch (a root below /, never the home folder, only a git
// repository) plus the launch's listing rule that the folder must be the
// repository's own top level (cmd/observer hostedListWorkspace), as one
// table walked top-down, each answer a closed code with a plain sentence
// and its technical detail. TestCheckUploadRootAgreesWithPlanManifest pins
// the shared rows against PlanManifest.
//
// Decision SBXD-8 adds one row that answers OK with a note: a folder that is
// not a repository, with [terminal.sandbox.hosted].upload_non_git on (the
// default), is uploaded through the non-repository listing, and the dialog
// says how its files are chosen instead of blocking Start. A folder inside a
// repository, the home folder and / stay refused.

// UploadRootFacts are what CheckUploadRoot reads: the folder and the home
// folder (absolute slash paths, symlinks resolved by the caller), whether
// git sees a repository there, and that repository's top level.
type UploadRootFacts struct {
	Root          string
	Home          string
	IsRepository  bool
	RepositoryTop string
	// UploadNonGit is [terminal.sandbox.hosted].upload_non_git: a folder
	// that is not a repository is uploaded through the non-repository
	// listing (SBXD-8).
	UploadNonGit bool
}

// UploadRootVerdict is CheckUploadRoot's answer: OK, or the closed Code,
// the sentence a person reads and the technical detail. An OK answer may
// carry a Code and a Message too: a note said before Start that blocks
// nothing (UploadNonRepositoryNote).
type UploadRootVerdict struct {
	OK        bool   `json:"ok"`
	Code      string `json:"code,omitempty"`
	Message   string `json:"message,omitempty"`
	Technical string `json:"technical,omitempty"`
}

// ErrScopeInsideRepository is the code of a folder inside, not at the top
// of, a git repository.
const ErrScopeInsideRepository = "upload_scope_inside_repository"

// UploadNonRepositoryNote is the code of the OK-with-a-note answer for a
// folder that is not a repository, uploaded through the non-repository
// listing (SBXD-8).
const UploadNonRepositoryNote = "upload_non_repository"

// uploadRootRules is the ordered table: the first match decides (a row
// with ok refuses nothing and carries a note); no match is OK.
var uploadRootRules = []struct {
	code  string
	ok    bool
	match func(f UploadRootFacts, root, home string) bool
	say   func(f UploadRootFacts, root string) (string, string)
}{
	{ErrScopeRoot.Error(), false, func(f UploadRootFacts, root, _ string) bool {
		return f.Root == "" || !path.IsAbs(root) || root == "/"
	}, func(_ UploadRootFacts, root string) (string, string) {
		return "Pick a project folder: a hosted sandbox cannot upload this one.", "the workspace root " + root + " is not an absolute directory below /"
	}},
	{ErrScopeHome.Error(), false, func(f UploadRootFacts, root, home string) bool {
		return f.Home != "" && (root == home || within(home, root))
	}, func(_ UploadRootFacts, root string) (string, string) {
		return "This folder is your home folder or holds it, and a hosted sandbox never uploads your home folder. Pick a project folder inside it.", root + " is the home directory or holds it"
	}},
	{UploadNonRepositoryNote, true, func(f UploadRootFacts, _, _ string) bool { return !f.IsRepository && f.UploadNonGit }, func(_ UploadRootFacts, root string) (string, string) {
		return "This folder is not a git repository: Observer uploads its files except dependency, build and virtual-environment folders, .env and other secret-looking files, operating-system clutter and anything its .gitignore leaves out, and the agent's changes come back as a diff file. The consent screen lists the files.",
			root + " is not a git repository; with upload_non_git on it is listed by git ls-files --others --exclude-standard through a temporary git directory outside the folder (the folder is never written), with the default ignore set and upload_ignore"
	}},
	{ErrScopeNotRepository.Error(), false, func(f UploadRootFacts, _, _ string) bool { return !f.IsRepository }, func(_ UploadRootFacts, root string) (string, string) {
		return "A hosted sandbox uploads only the files of a git repository, and this folder is not one. Pick a folder that is a git repository, turn on uploading folders that are not repositories under Terminals > Settings > Hosted sandboxes, or use a sandbox on this machine.", root + " is not a git repository and upload_non_git is off (PlanManifest refuses it)"
	}},
	{ErrScopeInsideRepository, false, func(f UploadRootFacts, root, _ string) bool {
		return f.RepositoryTop != "" && path.Clean(f.RepositoryTop) != root
	}, func(f UploadRootFacts, root string) (string, string) {
		top := path.Clean(f.RepositoryTop)
		return "This folder is inside the git repository at " + top + ", and a hosted sandbox uploads a whole repository. Pick " + top + " instead.", root + " is inside the repository " + top + " (the launch lists the repository root only)"
	}},
}

// CheckUploadRoot walks the table.
func CheckUploadRoot(f UploadRootFacts) UploadRootVerdict {
	root := path.Clean(strings.TrimSpace(f.Root))
	home := path.Clean(f.Home)
	for _, r := range uploadRootRules {
		if r.match(f, root, home) {
			msg, tech := r.say(f, root)
			return UploadRootVerdict{OK: r.ok, Code: r.code, Message: msg, Technical: r.code + ": " + tech}
		}
	}
	return UploadRootVerdict{OK: true}
}
