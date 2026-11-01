package workspace

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// gitexec.go is the return-step and live-run defence in depth against a box
// that planted, inside a git dir it could write, a path that steers which
// config the host's git reads or which program it runs (sandbox plan v2
// section 6; live Mac D1, ledger SBX-BE-16). The mount-time overlays
// (sandbox.WorkspaceExecState, one owner) stop the box writing these paths
// at all; this is the belt-and-braces check Observer runs BEFORE any host
// git command touches a box-written git dir, and the end-of-run comparison a
// live workspace warns on. It is pure: it reads the filesystem through os
// and runs no subprocess (CLAUDE.md rule 1; internal/workspace stays free of
// os/exec), so the host never has to run git to learn a git dir is unsafe.

// gitExecRiskFileSlashRels is the git-dir-relative execution-risk FILES the
// scan fingerprints (the hooks directory is scanned on its own,
// gitExecRiskHooksDir). It is the git-dir-relative mirror of the mount-time
// owner sandbox.WorkspaceExecState (".git/config", ".git/commondir",
// ".git/config.worktree", ".git/info/attributes", ".git/objects/info/alternates")
// plus the dumb-HTTP object redirector http-alternates (which worktree.go's
// own common-dir protect list carries too). It is kept here, not imported
// from internal/sandbox, so this pure node package does not reach across the
// isolation component boundary (the components fence); the two lists are
// cross-referenced in both files and in docs/sandboxed-terminals.md.
var gitExecRiskFileSlashRels = []string{
	"config",
	"commondir",
	"config.worktree",
	"info/attributes",
	"objects/info/alternates",
	"objects/info/http-alternates",
}

// gitExecRiskFileRels returns those rels in the host's path syntax.
func gitExecRiskFileRels() []string {
	out := make([]string, len(gitExecRiskFileSlashRels))
	for i, rel := range gitExecRiskFileSlashRels {
		out[i] = filepath.FromSlash(rel)
	}
	return out
}

// gitExecRiskHooksDir is the hooks directory's git-dir-relative name.
const gitExecRiskHooksDir = "hooks"

// gitExecRiskRecurseCap bounds the linked-worktree and submodule git dirs the
// scan descends into, so a planted fan-out of thousands of worktrees/modules
// cannot make the scan walk forever.
const gitExecRiskRecurseCap = 256

// gitExecRiskFileCap bounds the bytes of one execution-risk file the scan
// fingerprints; a file over it is fingerprinted by its first gitExecRiskFileCap
// bytes plus its size, which still changes when the tail changes on a rewrite.
const gitExecRiskFileCap = 1 << 20

// ScanGitDirExecRisk returns a fingerprint per execution-risk path PRESENT
// under gitDir, keyed by its git-dir-relative slash path: each file git may
// read for config or a program (config, config.worktree, commondir,
// info/attributes, objects/info/{,http-}alternates), each non-sample hook
// (hooks/<name>), and the same set inside every linked-worktree git dir
// (worktrees/<id>/...) and submodule git dir (modules/.../...), recursively
// and capped. A missing path is simply absent from the map. The fingerprint
// is sha256 over the file's bytes (capped) and its size, so a change or a
// replacement shows; a directory that only needs its presence noted (none
// today) would key to its sorted listing. Pure: os reads only, no subprocess.
func ScanGitDirExecRisk(gitDir string) (map[string]string, error) {
	out := map[string]string{}
	budget := gitExecRiskRecurseCap
	if err := scanGitDirExecRiskInto(gitDir, "", out, &budget); err != nil {
		return nil, err
	}
	return out, nil
}

// scanGitDirExecRiskInto scans one git dir, keying under prefix, and descends
// into its linked-worktree and submodule git dirs while the budget lasts.
func scanGitDirExecRiskInto(gitDir, prefix string, out map[string]string, budget *int) error {
	for _, rel := range gitExecRiskFileRels() {
		fp, ok, err := fingerprintFile(filepath.Join(gitDir, rel))
		if err != nil {
			return err
		}
		if ok {
			out[joinKey(prefix, filepath.ToSlash(rel))] = fp
		}
	}
	if err := scanHooks(filepath.Join(gitDir, gitExecRiskHooksDir), prefix, out); err != nil {
		return err
	}
	for _, sub := range []string{"worktrees", "modules"} {
		if err := scanNestedGitDirs(filepath.Join(gitDir, sub), joinKey(prefix, sub), out, budget); err != nil {
			return err
		}
	}
	return nil
}

// scanHooks fingerprints every hook that is not one of git's own .sample
// templates (a .sample never runs); a planted or renamed-into-place hook is
// recorded so the host-git refusal and the live warning name it.
func scanHooks(hooksDir, prefix string, out map[string]string) error {
	entries, err := os.ReadDir(hooksDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return nil // an unreadable hooks dir is handled by the overlays; do not fail the scan
	}
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".sample") {
			continue
		}
		fp, ok, err := fingerprintFile(filepath.Join(hooksDir, e.Name()))
		if err != nil {
			return err
		}
		if ok {
			out[joinKey(prefix, gitExecRiskHooksDir+"/"+e.Name())] = fp
		}
	}
	return nil
}

// scanNestedGitDirs walks root (a worktrees or modules tree) for nested git
// dirs and scans each; it never follows a symlink and stops when the recursion
// budget is spent, so a planted deep or wide tree cannot run the scan away.
func scanNestedGitDirs(root, prefix string, out map[string]string, budget *int) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil // absent or unreadable: nothing to descend
	}
	for _, e := range entries {
		if *budget <= 0 {
			return nil
		}
		if e.Type()&os.ModeSymlink != 0 || !e.IsDir() {
			continue
		}
		*budget--
		child := filepath.Join(root, e.Name())
		childPrefix := joinKey(prefix, e.Name())
		if looksLikeGitDir(child) {
			if err := scanGitDirExecRiskInto(child, childPrefix, out, budget); err != nil {
				return err
			}
			// A submodule's own modules folder holds nested submodule git
			// dirs; scanGitDirExecRiskInto already descended worktrees and
			// modules under it, so nothing more here.
			continue
		}
		// Not itself a git dir: a submodule named a/b keeps its git dir a
		// level down, so keep walking.
		if err := scanNestedGitDirs(child, childPrefix, out, budget); err != nil {
			return err
		}
	}
	return nil
}

// looksLikeGitDir reports whether dir is a git dir by git's own test (a HEAD
// file, an objects dir and a refs dir; setup.c is_git_directory).
func looksLikeGitDir(dir string) bool {
	head, herr := os.Lstat(filepath.Join(dir, "HEAD"))
	objects, oerr := os.Lstat(filepath.Join(dir, "objects"))
	refs, rerr := os.Lstat(filepath.Join(dir, "refs"))
	return herr == nil && head.Mode().IsRegular() &&
		oerr == nil && objects.IsDir() &&
		rerr == nil && refs.IsDir()
}

// fingerprintFile returns a content fingerprint for a regular file, ok=false
// when it is absent, and an error only when it exists but cannot be read. A
// path that is not a regular file (a dir, a symlink) is fingerprinted by its
// type so a box that swaps a file for a link still shows a change.
func fingerprintFile(path string) (string, bool, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("workspace.ScanGitDirExecRisk: stat %s: %w", path, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return "symlink:" + hashString(path), true, nil
	}
	if fi.IsDir() {
		return "dir", true, nil
	}
	if !fi.Mode().IsRegular() {
		return "special", true, nil
	}
	f, err := os.Open(path) //nolint:gosec // G304: a named execution-risk path under a git dir Observer is about to run git on
	if err != nil {
		return "", false, fmt.Errorf("workspace.ScanGitDirExecRisk: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	buf := make([]byte, 32<<10)
	read := int64(0)
	for read < gitExecRiskFileCap {
		n, rerr := f.Read(buf)
		if n > 0 {
			if int64(n) > gitExecRiskFileCap-read {
				n = int(gitExecRiskFileCap - read)
			}
			h.Write(buf[:n])
			read += int64(n)
		}
		if rerr != nil {
			break
		}
	}
	return fmt.Sprintf("%d:%s", fi.Size(), hex.EncodeToString(h.Sum(nil))), true, nil
}

func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// joinKey joins two slash key components, skipping an empty prefix.
func joinKey(prefix, leaf string) string {
	if prefix == "" {
		return leaf
	}
	return prefix + "/" + leaf
}

// GitDirExecRiskChanged returns, sorted, the execution-risk paths that are
// NEW in after or whose fingerprint changed from before. A path that
// disappeared is not an execution risk and is not reported. This is what a
// live workspace compares its launch-time snapshot against at the end of a
// run, to warn the developer even when the box could not write the path.
func GitDirExecRiskChanged(before, after map[string]string) []string {
	var out []string
	for rel, fp := range after {
		if prev, ok := before[rel]; !ok || prev != fp {
			out = append(out, rel)
		}
	}
	sort.Strings(out)
	return out
}

// uploadPackHookKeys are config key substrings a box could set so the host's
// `git fetch`/`ls-remote` from the box's copy runs a program while serving it
// (git-upload-pack reads the served repo's own config). core.hooksPath and
// core.fsmonitor redirect git at a program on an ordinary command; the
// uploadpack/pack hooks run during the serve itself. Matched case-folded on
// the copy's config so a planted key refuses the return before any host git
// touches the copy. The parsed scan (copyConfigTextViolations, over
// execConfigKeyRules) is the main text check; this substring pass stays as
// the cheap backstop for spellings the small parser does not follow.
var uploadPackHookKeys = []string{
	"packobjectshook",
	"core.hookspath",
	"core.fsmonitor",
	"fsmonitor",
}

// execConfigKeyRule is one row of the execution-capable config key table: a
// key whose section (and, when set, whose last part) match names a program
// git may run, or makes git read more config (include, includeIf). An empty
// leaf matches every key of the section; sub says whether the row needs a
// subsection (filter.<driver>.clean, 1) or must have none (core.editor, -1).
type execConfigKeyRule struct {
	section string
	leaf    string
	sub     int
}

// execConfigKeyRules is the closed table, walked top-down (lane SBX-P3C
// audit finding 1 and the Linux live re-check 4 DEFECT D4): the keys a clean
// `git clone` never writes into a repository's own config, each of which can
// make a later host git command run a program the box chose, or (include,
// includeIf) read config the box chose. Keys are compared lower-cased on the
// section and the last part; a subsection only by its presence.
var execConfigKeyRules = []execConfigKeyRule{
	{section: "include"},
	{section: "includeif"},
	{section: "alias"},
	{section: "core", leaf: "hookspath", sub: -1},
	{section: "core", leaf: "fsmonitor", sub: -1},
	{section: "core", leaf: "fsmonitorhookversion", sub: -1},
	{section: "core", leaf: "sshcommand", sub: -1},
	{section: "core", leaf: "gitproxy", sub: -1},
	{section: "core", leaf: "editor", sub: -1},
	{section: "core", leaf: "pager", sub: -1},
	{section: "core", leaf: "askpass", sub: -1},
	{section: "core", leaf: "alternaterefscommand", sub: -1},
	{section: "core", leaf: "worktree", sub: -1},
	{section: "uploadpack", leaf: "packobjectshook"},
	{section: "pager"},
	{section: "filter", leaf: "clean", sub: 1},
	{section: "filter", leaf: "smudge", sub: 1},
	{section: "filter", leaf: "process", sub: 1},
	{section: "diff", leaf: "external", sub: -1},
	{section: "diff", leaf: "textconv", sub: 1},
	{section: "diff", leaf: "command", sub: 1},
	{section: "merge", leaf: "driver", sub: 1},
	{section: "credential", leaf: "helper"},
	{section: "gpg", leaf: "program"},
	{section: "sequence", leaf: "editor", sub: -1},
	{section: "remote", leaf: "uploadpack", sub: 1},
	{section: "remote", leaf: "receivepack", sub: 1},
	{section: "submodule", leaf: "update", sub: 1},
	{section: "difftool", leaf: "cmd", sub: 1},
	{section: "mergetool", leaf: "cmd", sub: 1},
	{section: "browser", leaf: "cmd", sub: 1},
	{section: "man", leaf: "cmd", sub: 1},
	{section: "web", leaf: "browser", sub: -1},
	{section: "protocol", leaf: "allow"},
}

// ExecConfigKey reports whether a git config key (section[.subsection].key,
// as `git config --list` prints it) is execution-capable by
// execConfigKeyRules: a key that names a program git may run or makes git
// read more config.
func ExecConfigKey(key string) bool {
	first := strings.Index(key, ".")
	last := strings.LastIndex(key, ".")
	if first <= 0 || last == len(key)-1 {
		return false
	}
	section := strings.ToLower(key[:first])
	leaf := strings.ToLower(key[last+1:])
	hasSub := last > first
	for _, r := range execConfigKeyRules {
		if r.section != section || (r.leaf != "" && r.leaf != leaf) {
			continue
		}
		if (r.sub == 1 && !hasSub) || (r.sub == -1 && hasSub) {
			continue
		}
		return true
	}
	return false
}

// copyConfigTextViolations parses one config file of a copy (config or
// config.worktree) the way git reads its sections and keys, and names every
// execution-capable key it sets; an include or includeIf section names the
// directive itself (the file it pulls in is never read by this scan, and git
// would read it). Pure: text only. The parse is deliberately small (section
// headers in both spellings, a key on the header line, comments); anything
// it does not follow is still seen by the effective-config read git itself
// makes (EffectiveConfigViolations) before any other host git step runs.
func copyConfigTextViolations(name string, data []byte) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	section, sub := "", ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "[") {
			end := strings.Index(line, "]")
			if end < 0 {
				continue
			}
			section, sub = parseConfigHeader(line[1:end])
			switch section {
			case "include", "includeif":
				add(name + " (" + section + " directive)")
			}
			line = strings.TrimSpace(line[end+1:])
		}
		if line == "" || line[0] == '#' || line[0] == ';' || section == "" {
			continue
		}
		key := line
		if keyEnd := strings.IndexAny(line, "= \t"); keyEnd >= 0 {
			key = line[:keyEnd]
		}
		key = strings.ToLower(key)
		full := section + "." + key
		if sub != "" {
			full = section + "." + sub + "." + key
		}
		if ExecConfigKey(full) {
			add(name + " (sets " + section + "." + key + ")")
		}
	}
	return out
}

// parseConfigHeader returns the lower-cased section and the subsection of a
// header's inside: `name "sub"` or the older `name.sub`.
func parseConfigHeader(h string) (string, string) {
	h = strings.TrimSpace(h)
	if i := strings.IndexAny(h, " \t\""); i >= 0 {
		name := strings.ToLower(strings.TrimSpace(h[:i]))
		rest := strings.TrimSpace(h[i:])
		rest = strings.TrimSuffix(strings.TrimPrefix(rest, "\""), "\"")
		return name, rest
	}
	if i := strings.Index(h, "."); i >= 0 {
		return strings.ToLower(h[:i]), strings.ToLower(h[i+1:])
	}
	return strings.ToLower(h), ""
}

// copyConfigFiles are the config files of a copy's git dir the text scan
// reads (config.worktree is also refused by its mere presence).
var copyConfigFiles = []string{"config", "config.worktree"}

// CopyReturnGitDirViolations returns, sorted and human-named, the
// execution-risk paths a box planted in a clone's git dir that a clean
// `git clone --no-hardlinks` would never carry, so the return step can refuse
// to run the host's git on the copy and name what it refused. A clean clone
// has config (allowed, but scanned for an execution-capable key, an include
// or includeIf directive, and an upload-pack hook), only .sample hooks, and
// no commondir, config.worktree, info/attributes, object alternates, linked
// worktrees or submodule git dirs; any of those present is box-planted. A
// config that is not a regular file is refused too (a link is never
// followed). Pure: os reads only.
func CopyReturnGitDirViolations(gitDir string) ([]string, error) {
	risk, err := ScanGitDirExecRisk(gitDir)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for rel, fp := range risk {
		// config is legitimate in a clone; it is checked for dangerous keys
		// below, not by its mere presence, but only as a regular file.
		if rel == "config" {
			if strings.HasPrefix(fp, "symlink:") || fp == "dir" || fp == "special" {
				add("config (not a regular file)")
			}
			continue
		}
		add(rel)
	}
	for _, name := range copyConfigFiles {
		p := filepath.Join(gitDir, name)
		if fi, lerr := os.Lstat(p); lerr != nil || !fi.Mode().IsRegular() {
			continue
		}
		cfgBytes, rerr := readCappedFile(p, gitExecRiskFileCap)
		if rerr != nil {
			return nil, rerr
		}
		for _, v := range copyConfigTextViolations(name, cfgBytes) {
			add(v)
		}
		if name != "config" {
			continue
		}
		low := strings.ToLower(string(cfgBytes))
		low = strings.ReplaceAll(low, " ", "")
		low = strings.ReplaceAll(low, "\t", "")
		for _, k := range uploadPackHookKeys {
			if strings.Contains(low, k) {
				add("config (sets " + k + ")")
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// CopyConfigListStep is the one host git step the return's scan runs on a
// copy, after the text scan passed and before any other: git itself lists
// the config it would read for the copy's git dir, includes followed, with
// origins (`git --git-dir=<copy>/.git config --list --show-origin --includes
// -z`). Reading config runs nothing (config --list starts no hook, no
// fsmonitor, no filter and no pager). The step is Hardened and NeutralHome:
// no system or global config, HOME and XDG_CONFIG_HOME an empty directory,
// so every file origin it reports is the copy's own config or a file that
// config pulled in. The explicit --git-dir means no repository discovery
// runs above the copy.
func CopyConfigListStep(copyDir string) Step {
	return Step{
		Argv: []string{
			"git", "--git-dir=" + filepath.Join(copyDir, ".git"), "--no-pager",
			"config", "--list", "--show-origin", "--includes", "-z",
		},
		Hardened:    true,
		NeutralHome: true,
	}
}

// EffectiveConfigViolations names every execution-capable key (ExecConfigKey)
// in the output of CopyConfigListStep whose origin is anything but the
// runner's own command-line settings: with no system or global config and an
// empty HOME, such an origin is the copy's own config or something its config
// pulled in. Output that does not parse is an error (the return refuses).
// Pure.
func EffectiveConfigViolations(out []byte) ([]string, error) {
	if len(out) == 0 {
		return nil, nil
	}
	parts := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
	if len(parts)%2 != 0 {
		return nil, fmt.Errorf("workspace.EffectiveConfigViolations: git config output is not origin and entry pairs")
	}
	seen := map[string]bool{}
	var res []string
	for i := 0; i < len(parts); i += 2 {
		origin, entry := parts[i], parts[i+1]
		if strings.HasPrefix(origin, "command line:") {
			continue
		}
		key := entry
		if j := strings.IndexByte(entry, '\n'); j >= 0 {
			key = entry[:j]
		}
		if !ExecConfigKey(key) {
			continue
		}
		v := fmt.Sprintf("%s (sets %s)", strings.TrimPrefix(origin, "file:"), strings.ToLower(key))
		if !seen[v] {
			seen[v] = true
			res = append(res, v)
		}
	}
	sort.Strings(res)
	return res, nil
}

// readCappedFile reads at most limit bytes of path; a missing file is empty,
// an unreadable existing file is an error.
func readCappedFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: a git dir's own config, named, about to be served to the host git
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("workspace.CopyReturnGitDirViolations: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, limit)
	n, _ := f.Read(buf)
	return buf[:n], nil
}
