package agentconfigsvc

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"

	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/regularfile"
)

// writeAtomic writes a vendor file atomically with fsync, keeping mode.
// A directory it must create is 0755 (vendor config dirs are readable by
// their tools, which run as the same user).
func writeAtomic(path string, b []byte, mode os.FileMode) error {
	if mode == 0 {
		mode = 0o600
	}
	return fsatomic.WriteFile(path, b, fsatomic.Options{
		TempPattern: ".observer-edit-*.tmp", Fsync: true, DirPerm: 0o755, FilePerm: mode,
	})
}

// pinnedTarget is the symlink pin (the internal/hook F6 rule, same
// semantics): resolve once after the lock, write the resolved file, and
// refuse when the link moved between the read and the write.
type pinnedTarget struct {
	path, target string
	isSymlink    bool
	linkValue    string
}

func pinTarget(path string) pinnedTarget {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		return pinnedTarget{path: path, target: path}
	}
	link, err := os.Readlink(path)
	if err != nil {
		return pinnedTarget{path: path, target: path}
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved == "" {
		return pinnedTarget{path: path, target: path, isSymlink: true, linkValue: link}
	}
	return pinnedTarget{path: path, target: resolved, isSymlink: true, linkValue: link}
}

func (p pinnedTarget) verifyUnmoved() error {
	fi, err := os.Lstat(p.path)
	if err != nil {
		if p.isSymlink {
			return fmt.Errorf("%s: the symlink disappeared while Observer was preparing the write; refusing", p.path)
		}
		return nil
	}
	isLink := fi.Mode()&os.ModeSymlink != 0
	if isLink != p.isSymlink {
		return fmt.Errorf("%s: changed between read and write (symlink-ness changed); refusing", p.path)
	}
	if !p.isSymlink {
		return nil
	}
	link, err := os.Readlink(p.path)
	if err != nil || link != p.linkValue {
		return fmt.Errorf("%s: the symlink was retargeted while Observer was preparing the write; refusing", p.path)
	}
	return nil
}

// statRegular stats a regular file (nil, nil when it does not exist).
func statRegular(path string) (os.FileInfo, error) {
	fi, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return fi, nil
}

// DefaultMaxFileBytes is the read cap of a vendor settings file (2 MiB): the
// snapshot reader's default (Options.MaxFileBytes) and the hook-switch
// reader's cap (internal/diag.ReadHookSwitchFile). A real settings file is a
// few KiB; anything past this is not one Observer should hold in memory.
const DefaultMaxFileBytes int64 = 2 << 20

// ReadRegularFile is the one capped regular-file read of a vendor settings
// file: a shim over regularfile.Read (moved there so internal/proxyroute and
// internal/hook use the same reader), with the same contract.
func ReadRegularFile(path string, maxBytes int64) ([]byte, error) {
	return regularfile.Read(path, maxBytes)
}

// errProjectLinkEscapes is the refusal of a project-scope file that is (or
// sits under) a symlink resolving outside its project root.
var errProjectLinkEscapes = errors.New("refused: a symlink that resolves outside the project root (a repository can commit a link to any file the developer can read)")

// errProjectPathUnresolved is the refusal of a project-scope edit target
// whose path cannot be resolved (a permission error, a file used as a
// directory), so it cannot be proven inside the project root (FU-182).
var errProjectPathUnresolved = errors.New("refused: the path cannot be resolved, so it cannot be proven inside the project root")

// isProjectScope reports a project-scope file row (shared or local).
func isProjectScope(sc agentconfig.Scope) bool {
	return sc == agentconfig.ScopeProjectShared || sc == agentconfig.ScopeProjectLocal
}

// projectLinkEscapes reports whether path, a file of the project rooted at
// project, resolves through a symlink to a place outside that root
// (AGENTCFG-READ-1). A cloned repository can commit .claude/settings.json or
// .github/copilot/settings.json as a link to any file the developer can
// read, so a project-scope read refuses such a link, as the vendor
// policy-cache reader refuses a link leaving its cache directory
// (VENDOR-POLICY-CACHE-1). A user-scope link (a dotfile manager's) is still
// followed.
//
// A path that does not exist yet (its leaf, a tail of directories, or a
// dangling link on the way) is judged where a write would land it
// (orchestrator follow-up H1): resolveWritePath walks it one component at a
// time as the kernel would, so a first save of .vscode/settings.json under a
// committed .vscode -> ~/elsewhere link is refused like an existing file
// there. A link chain longer than maxLinkHops escapes (it cannot be judged,
// and a project-scope file must be proven inside). A path that cannot be
// resolved for another reason (a permission error, a file used as a
// directory) does not escape here: a read then reports its own error. An
// edit target is judged by projectLinkCheck, which refuses that case.
func projectLinkEscapes(path, project string) bool {
	return errors.Is(projectLinkCheck(path, project), errProjectLinkEscapes)
}

// projectLinkCheck is projectLinkEscapes for an edit target (the raw view,
// a preview, a save), failing closed (FU-182): nil when path is proven
// inside the project root (or there is no project), an error wrapping
// errProjectLinkEscapes when it resolves outside, and an error wrapping
// errProjectPathUnresolved, naming the path, when it cannot be resolved at
// all.
func projectLinkCheck(path, project string) error {
	if project == "" {
		return nil
	}
	resolved, st := resolveWritePath(path)
	switch st {
	case resolveTooDeep:
		return errProjectLinkEscapes
	case resolveFailed:
		return fmt.Errorf("%w: %s", errProjectPathUnresolved, path)
	}
	root, err := filepath.EvalSymlinks(project)
	if err != nil {
		root = filepath.Clean(project)
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errProjectLinkEscapes
	}
	return nil
}

// maxLinkHops bounds the links resolveWritePath follows for one path.
const maxLinkHops = 16

// resolveStatus is resolveWritePath's outcome.
type resolveStatus int

const (
	resolveOK resolveStatus = iota
	// resolveFailed: an error other than a missing component.
	resolveFailed
	// resolveTooDeep: more than maxLinkHops links.
	resolveTooDeep
)

// resolveWritePath is the physical path a write to path would reach. An
// existing path is filepath.EvalSymlinks'. Otherwise the path is walked one
// component at a time from its root (or from the resolved working
// directory): an existing component is kept, a link is replaced by its
// target walked the same way from the link's own directory (so a relative
// target's ".." climbs from where the link really points, not lexically),
// a missing component is kept as named (the write creates it), and ".."
// climbs from the physical directory reached so far. A rooted target with no
// volume (Windows `\foo`) is rooted on the volume of the link's directory.
func resolveWritePath(path string) (string, resolveStatus) {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved, resolveOK
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", resolveFailed
	}
	base := ""
	if _, _, rooted := splitRooted(path); !rooted {
		wd, err := os.Getwd()
		if err != nil {
			return "", resolveFailed
		}
		if base, err = filepath.EvalSymlinks(wd); err != nil {
			return "", resolveFailed
		}
	}
	hops := maxLinkHops
	return walkWritePath(base, path, &hops)
}

// splitRooted splits p into its volume, the rest, and whether the rest is
// rooted (starts with a separator).
func splitRooted(p string) (vol, rest string, rooted bool) {
	vol = filepath.VolumeName(p)
	rest = p[len(vol):]
	return vol, rest, len(rest) > 0 && os.IsPathSeparator(rest[0])
}

// walkWritePath resolves p against base (the physical directory a relative
// p is read from) as resolveWritePath describes.
func walkWritePath(base, p string, hops *int) (string, resolveStatus) {
	vol, rest, rooted := splitRooted(p)
	cur := base
	switch {
	case rooted:
		if vol == "" {
			vol = filepath.VolumeName(base)
		}
		cur = vol + string(filepath.Separator)
	case vol != "":
		// A drive-relative Windows path (`C:foo`): read from that volume's
		// root, the closest physical anchor without the per-drive cwd.
		cur = vol + string(filepath.Separator)
	}
	for _, c := range strings.FieldsFunc(rest, func(r rune) bool { return r < 0x80 && os.IsPathSeparator(uint8(r)) }) {
		switch c {
		case ".":
			continue
		case "..":
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, c)
		fi, err := os.Lstat(next)
		if errors.Is(err, fs.ErrNotExist) {
			cur = next
			continue
		}
		if err != nil {
			return "", resolveFailed
		}
		if fi.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0 {
			cur = next
			continue
		}
		target, err := os.Readlink(next)
		if err != nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return "", resolveFailed
			}
			// An irregular entry that is no link (a Windows reparse point
			// of another kind): kept as named.
			cur = next
			continue
		}
		if *hops--; *hops < 0 {
			return "", resolveTooDeep
		}
		resolved, st := walkWritePath(cur, target, hops)
		if st != resolveOK {
			return "", st
		}
		cur = resolved
	}
	return cur, resolveOK
}
