package sectrust

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Bounds: the check is bounded by construction (no walk, capped reads).
const (
	// MaxFileBytes is the read cap per file; a larger file is reported as
	// file_over_cap, untrusted until its whole-file digest is accepted, and
	// not judged.
	MaxFileBytes = 256 << 10
	// MaxHashBytes caps what one whole-file digest streams: a table file or
	// a file a command names that holds more is file_over_hash_cap, which no
	// accept can lower.
	MaxHashBytes = 64 << 20
	// maxNamedFiles caps the repository files one command's digest folds in.
	maxNamedFiles = 16
	// maxGlobFiles caps the files one glob or directory row yields.
	maxGlobFiles = 64
	// maxDirEntries caps the entries read from one directory listing.
	maxDirEntries = 256
	// MaxRoots caps the directories visited between the repository root
	// and the launch directory (both included).
	MaxRoots = 32
	// maxExcerpt caps an excerpt, in runes.
	maxExcerpt = 100
	// maxLeaves caps the key paths flattened from one structured file.
	maxLeaves = 4096
)

// hashCap is MaxHashBytes, a variable only so a test can reach the
// over-hash-cap path without writing 64 MiB.
var hashCap int64 = MaxHashBytes

// ErrLaunchOutsideRepo is returned when the launch directory is not inside
// the repository root.
var ErrLaunchOutsideRepo = errors.New("sectrust: the launch directory is outside the repository root")

// Request is one check.
type Request struct {
	// LaunchRel is the launch directory, slash-separated and relative to
	// the repository root; "" is the root itself.
	LaunchRel string
	// Accepted reports whether the developer accepted a digest. Nil accepts
	// nothing.
	Accepted func(digest string) bool
	// Paths is the path table; nil means agentconfig.TrustPaths().
	Paths []agentconfig.TrustPath
	// HostPins are the plugin host's pinned paths by variable name
	// (OBSERVER_BIN, OBSERVER_CONFIG) on a managed node, and HostEnv the
	// launch environment's values of the same names. A variable set to
	// something other than its pin is plugin_host_override (security
	// pillar plan section 5.1 item 6). Nil pins check nothing.
	HostPins map[string]string
	HostEnv  map[string]string
	// Own, when set, reports a reason that is Observer's own entry (a hook
	// Observer registered, its MCP server, its plugin): Reason.Observer is
	// set on it. The user-scope config baseline sets it so Observer's own
	// registrations never read as something new an agent runs (plans
	// decision log P-037). Nil marks nothing. It never changes a level.
	Own func(OwnItem) bool
	// Devcontainer parses a .devcontainer row (a conditional row of the
	// path table, N2); the caller that passes that row passes the container
	// driver's parser here. Nil leaves such a file judged as one reason.
	Devcontainer DevcontainerParser
}

// OwnItem is what Request.Own sees of one reason: its code, file and key
// and the exact content its digest covers when that is a command a
// repository-run reason names or a plugin file's bytes ("" otherwise).
type OwnItem struct {
	Code, File, Key, Content string
}

// Check runs the repository trust check over fsys. It returns an error only
// for a malformed request or a cancelled context; an unreadable file is
// simply absent.
func Check(ctx context.Context, fsys FS, req Request) (Result, error) {
	launch, err := cleanRel(req.LaunchRel)
	if err != nil {
		return Result{}, err
	}
	paths := req.Paths
	if paths == nil {
		paths = agentconfig.TrustPaths()
	}
	c := &checker{fsys: fsys, accepted: req.Accepted, own: req.Own, devcontainerParse: req.Devcontainer, res: Result{Reasons: []Reason{}}}
	c.res.Roots = rootsBetween(launch, &c.res.Truncated)
	if c.res.Truncated {
		c.truncate(launch, false)
	}
	for _, root := range c.res.Roots {
		for _, p := range paths {
			if err := ctx.Err(); err != nil {
				return Result{}, fmt.Errorf("sectrust.Check: %w", err)
			}
			if p.RepoRootOnly && root != "" {
				continue
			}
			c.res.PathsTried++
			c.root = root
			c.visit(root, p)
		}
	}
	c.class = ""
	c.hostPins(req.HostPins, req.HostEnv)
	c.class = agentconfig.TrustGitAttributes
	c.finishGit()
	c.finish()
	return c.res, nil
}

// hostPins raises plugin_host_override for each pinned variable the launch
// environment sets to another value.
func (c *checker) hostPins(pins, env map[string]string) {
	names := make([]string, 0, len(pins))
	for n := range pins {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		v := strings.TrimSpace(env[n])
		if v != "" && path.Clean(strings.ReplaceAll(v, `\`, "/")) != path.Clean(strings.ReplaceAll(pins[n], `\`, "/")) {
			c.add(Reason{Code: "plugin_host_override", File: "(environment)", Key: n, Excerpt: excerpt(v)})
		}
	}
}

// cleanRel validates a slash path relative to the repository root.
func cleanRel(rel string) (string, error) {
	rel = strings.Trim(strings.ReplaceAll(rel, `\`, "/"), "/")
	if rel == "" || rel == "." {
		return "", nil
	}
	clean := path.Clean(rel)
	if clean == ".." || strings.HasPrefix(clean, "../") || path.IsAbs(clean) {
		return "", ErrLaunchOutsideRepo
	}
	return clean, nil
}

// rootsBetween lists the repository root, the launch directory and every
// directory between them, outermost first, capped at MaxRoots (the root
// and the innermost directories are kept).
func rootsBetween(launch string, truncated *bool) []string {
	roots := []string{""}
	if launch != "" {
		segs := strings.Split(launch, "/")
		for i := range segs {
			roots = append(roots, strings.Join(segs[:i+1], "/"))
		}
	}
	if len(roots) > MaxRoots {
		*truncated = true
		roots = append([]string{""}, roots[len(roots)-(MaxRoots-1):]...)
	}
	return roots
}

// checker carries one run's state.
type checker struct {
	fsys     FS
	accepted func(string) bool
	// own is Request.Own.
	own func(OwnItem) bool
	// devcontainerParse is Request.Devcontainer.
	devcontainerParse DevcontainerParser
	res               Result
	// gitAttr holds driver names (filter.x, diff.x, merge.x) the
	// .gitattributes files name; gitDefined those the repository's
	// .git/config defines, each with the definition's keys and values (what
	// a gitattributes_driver_defined digest covers).
	gitAttr    map[string]string
	gitDefined map[string]string
	// class is the class of the table row being visited; add stamps it on
	// every reason that does not name its own.
	class agentconfig.TrustClass
	// root is the root being visited ("" is the repository root): a
	// command's relative file names resolve against it first.
	root string
	// truncatedAt holds the listings already reported as cut short.
	truncatedAt map[string]bool
	// named caches what namedFiles found at a path: nil for a path that
	// names no regular file (a miss), so a word repeated across commands
	// costs one Lstat.
	named       map[string]*namedFile
	namedExists map[string]bool
}

// namedFile is one repository file a command names, as the digest folds it.
type namedFile struct {
	// folded is the "path=sha256:<hex>:<size>" entry (or a marker for a
	// file nothing could hash).
	folded string
}

// truncate records that a bound cut a read short at rel: the result is
// marked truncated and a reason raises the verdict (a truncated listing
// may hide a file the table names). A cut-short plugin or custom tool
// listing hides code the agent may load, so it is untrusted.
func (c *checker) truncate(rel string, code bool) {
	c.res.Truncated = true
	if c.truncatedAt == nil {
		c.truncatedAt = map[string]bool{}
	}
	key := fmt.Sprintf("%v\x00%s", code, rel)
	if c.truncatedAt[key] {
		return
	}
	c.truncatedAt[key] = true
	reason := "truncated"
	if code {
		reason = "truncated_code"
	}
	c.add(Reason{Code: reason, File: rel})
}

// visit reads one table path at one root and dispatches on its class.
func (c *checker) visit(root string, p agentconfig.TrustPath) {
	rel := joinRel(root, p.Rel)
	c.class = p.Class
	if p.Class == agentconfig.TrustConfigDir {
		c.configDir(strings.TrimSuffix(rel, "/"))
		return
	}
	var files []string
	code := p.Class == agentconfig.TrustCode
	switch {
	case strings.HasSuffix(rel, "/"):
		files = c.listDir(strings.TrimSuffix(rel, "/"), code)
	case strings.Contains(rel, "*"):
		files = c.glob(rel, code)
	default:
		files = []string{rel}
	}
	for _, f := range files {
		data, ok := c.read(f)
		if !ok {
			continue
		}
		switch p.Class {
		case agentconfig.TrustStructured:
			c.structured(f, p.Rel, data)
		case agentconfig.TrustCode:
			c.code(f, data)
		case agentconfig.TrustProse:
			c.hiddenUnicode(f, data)
		case agentconfig.TrustEnv:
			c.envFile(f, data)
		case agentconfig.TrustGitConfig:
			c.gitConfig(f, data)
		case agentconfig.TrustGitAttributes:
			c.gitAttributes(f, data)
		case agentconfig.TrustTasks:
			c.tasks(f, data)
		case agentconfig.TrustDevcontainer:
			c.devcontainer(f, data)
		}
	}
}

func joinRel(root, rel string) string {
	if root == "" {
		return rel
	}
	return root + "/" + rel
}

// read returns a file's bytes when it is a regular file inside the
// repository and under the cap. A symlink that leaves the repository is a
// reason, never followed.
func (c *checker) read(rel string) ([]byte, bool) {
	fi, err := c.fsys.Lstat(rel)
	if err != nil {
		return nil, false
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		if c.fsys.Escapes(rel) {
			c.symlinkEscape(rel, "")
			return nil, false
		}
		if fi, err = c.fsys.Stat(rel); err != nil {
			return nil, false
		}
	}
	if !fi.Mode().IsRegular() {
		return nil, false
	}
	if fi.Size() > MaxFileBytes {
		c.wholeFile("file_over_cap", rel, fmt.Sprintf("%d bytes", fi.Size()))
		return nil, false
	}
	data, err := c.fsys.ReadFile(rel, MaxFileBytes)
	switch {
	case errors.Is(err, errTooLarge):
		// The file grew past the cap between Lstat and the read: it is
		// judged like any file over the cap, never skipped.
		c.wholeFile("file_over_cap", rel, "grew past the read cap while it was read")
		return nil, false
	case errors.Is(err, fs.ErrNotExist):
		// Removed between Lstat and the read: absent.
		return nil, false
	case err != nil:
		c.unreadable(rel, "the file exists but could not be read")
		return nil, false
	}
	sum := sha256.Sum256(data)
	c.seenFile(rel, hex.EncodeToString(sum[:]), int64(len(data)))
	c.res.FilesRead++
	c.res.BytesRead += int64(len(data))
	return data, true
}

// wholeFile raises a reason about a file nothing judged (over the read cap,
// or not parsing): untrusted until the developer accepts the digest of the
// file's exact bytes, or file_over_hash_cap when even the digest cannot
// cover it.
func (c *checker) wholeFile(code, rel, why string) {
	sum, size, err := c.fsys.HashFile(rel, hashCap)
	switch {
	case err != nil && size > hashCap:
		c.add(Reason{Code: "file_over_hash_cap", File: rel, Excerpt: fmt.Sprintf("more than %d bytes", hashCap)})
		return
	case err != nil:
		// Any other failure (no permission, removed, an I/O error) leaves
		// the file unjudged with nothing to accept: a reason, never silence.
		c.unreadable(rel, "the file exists but could not be hashed")
		return
	}
	c.seenFile(rel, sum, size)
	c.add(Reason{Code: code, File: rel, Excerpt: excerpt(why), Digest: FileDigest(code, rel, sum, size)})
}

// unreadable raises file_unreadable for a file that exists but nothing
// could read or hash. Its digest covers the reason itself (the code, the path
// and why), so the developer can accept a file they know is unreadable (a
// socket, a file another account owns); once the file reads, it is judged
// like any other and the accept no longer applies.
//
// When the file can be described, the digest also covers its size and
// modification time, so an accept covers that one unreadable state of the
// path, not every later one (plans decision log P-029).
func (c *checker) unreadable(rel, why string) {
	value := "unreadable:" + why
	fi, err := c.fsys.Stat(rel)
	if err != nil {
		fi, err = c.fsys.Lstat(rel)
	}
	if err == nil {
		value += "\x00size:" + strconv.FormatInt(fi.Size(), 10) + "\x00mtime:" + strconv.FormatInt(fi.ModTime().UnixNano(), 10)
	}
	c.add(Reason{Code: "file_unreadable", File: rel, Excerpt: why, value: value})
}

// seenFile records a table file in the snapshot, once.
func (c *checker) seenFile(rel, sum string, size int64) {
	for _, f := range c.res.Files {
		if f.Rel == rel {
			return
		}
	}
	c.res.Files = append(c.res.Files, FileState{Rel: rel, Class: string(c.class), SHA256: sum, Size: size, Local: ownFile(rel)})
}

// configDir checks a configuration directory and its direct children for
// symlinks that leave the repository.
func (c *checker) configDir(rel string) {
	fi, err := c.fsys.Lstat(rel)
	if err != nil {
		return
	}
	if fi.Mode()&fs.ModeSymlink != 0 && c.fsys.Escapes(rel) {
		c.symlinkEscape(rel, "")
		return
	}
	ents, err := c.fsys.ReadDir(rel)
	if err != nil {
		return
	}
	for i, e := range ents {
		if i >= maxDirEntries {
			c.truncate(rel, false)
			break
		}
		child := rel + "/" + e.Name()
		if e.Type()&fs.ModeSymlink != 0 && c.fsys.Escapes(child) {
			c.symlinkEscape(child, "")
		}
	}
}

// listDir lists the files of a directory row; withSub also lists one level
// of subdirectories (a plugin directory holds plugin packages).
func (c *checker) listDir(rel string, withSub bool) []string {
	var out []string
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		ents, err := c.fsys.ReadDir(dir)
		if err != nil {
			return
		}
		for i, e := range ents {
			if i >= maxDirEntries || len(out) >= maxGlobFiles {
				c.truncate(rel, withSub)
				return
			}
			child := dir + "/" + e.Name()
			if e.IsDir() {
				if withSub && depth == 0 {
					walk(child, 1)
				}
				continue
			}
			out = append(out, child)
		}
	}
	walk(rel, 0)
	return out
}

// glob expands a path whose segments may hold "*" patterns, reading one
// directory per patterned segment and never more than maxGlobFiles files.
func (c *checker) glob(rel string, code bool) []string {
	segs := strings.Split(rel, "/")
	cur := []string{""}
	for i, seg := range segs {
		var next []string
		for _, base := range cur {
			if !strings.ContainsAny(seg, "*?[") {
				next = append(next, joinRel(base, seg))
				continue
			}
			ents, err := c.fsys.ReadDir(base)
			if err != nil {
				continue
			}
			for j, e := range ents {
				if j >= maxDirEntries {
					c.truncate(rel, code)
					break
				}
				if ok, _ := path.Match(seg, e.Name()); !ok {
					continue
				}
				if i < len(segs)-1 && !e.IsDir() && e.Type()&fs.ModeSymlink == 0 {
					continue
				}
				next = append(next, joinRel(base, e.Name()))
			}
		}
		if len(next) > maxGlobFiles {
			c.truncate(rel, code)
			next = next[:maxGlobFiles]
		}
		cur = next
	}
	return cur
}

// add appends a reason, filling its level from the code table and the
// digest rule.
func (c *checker) add(r Reason) {
	row, ok := codeIndex[r.Code]
	if !ok {
		// A code outside the table is a programming error; report it as
		// untrusted rather than drop it.
		row = CodeRow{Code: r.Code, Level: LevelUntrusted, Fixed: true}
	}
	r.Level = row.Level
	if r.Class == "" {
		r.Class = c.class
	}
	r.Local = ownFile(r.File)
	if c.own != nil && c.own(OwnItem{Code: r.Code, File: r.File, Key: r.Key, Content: r.ownContent}) {
		r.Observer = true
	}
	// The digest rule (docs/repository-trust.md "Verdicts and the digest
	// rule"): a repository-run command and an Acceptable code always carry
	// a digest, and so does every reason in one of the developer's own
	// files (own.go); a Fixed code never does, nor a command whose named
	// files overflowed the fold.
	// An information reason has nothing to lower, so it is never offered.
	acceptable := !row.Fixed && !r.noDigest && row.Level > LevelInfo && (row.RepositoryRun || row.Acceptable || r.Local)
	switch {
	case !acceptable:
		r.Digest = ""
	case r.Digest == "":
		r.Digest = Digest(r.Code, r.File, r.Key, r.value)
	}
	if r.Digest != "" && c.accepted != nil && c.accepted(r.Digest) {
		r.Accepted = true
		switch {
		case r.Local && !runsCode(row, r):
			// An accepted item in one of the developer's own files is their
			// own setting, read and accepted: information, so it does not
			// warn at every launch (plans decision log P-022). Any change
			// makes a new digest and asks again.
			r.Level = LevelInfo
		case r.Level > LevelInfo:
			// Anywhere else, and for code that runs even in the developer's
			// own files (a hook in a force-committed local settings file,
			// NODE_OPTIONS=--require or PYTHONPATH in a .env), an accept
			// lowers one level: the S-705 warning stays at every launch,
			// because the digest cannot cover the files that code loads
			// indirectly (plans decision log P-029).
			r.Level--
		}
	}
	c.res.Reasons = append(c.res.Reasons, r)
}

// runsCode reports whether a reason names code a process runs or loads: a
// repository-run code, or a reason its rule marked (runs).
func runsCode(row CodeRow, r Reason) bool { return row.RepositoryRun || r.runs }

// symlinkEscape raises symlink_escape for a link at rel that resolves
// outside the repository. Its digest covers the link's own target text and,
// when the target is a file that can be hashed, the target's bytes, so an
// accepted link asks again when either changes.
func (c *checker) symlinkEscape(rel, excerptText string) {
	value := "link:"
	if lr, ok := c.fsys.(linkReader); ok {
		if target, err := lr.Readlink(rel); err == nil {
			value += target
		}
	}
	if sum, size, err := c.fsys.HashFile(rel, hashCap); err == nil {
		value += "\x00file:sha256:" + sum + ":" + strconv.FormatInt(size, 10)
	}
	c.add(Reason{Code: "symlink_escape", File: rel, Excerpt: excerptText, value: value})
}

// addRun appends a reason for a command the repository makes the agent run:
// it carries the digest of content and the indicators that word it. The
// digest also folds in the bytes of every repository file the command
// names (namedFiles), so a hook that runs `node scripts/setup.js` asks
// again when setup.js changes, not only when the command text does.
func (c *checker) addRun(code, file, key, content string, withIndicators bool) {
	digestContent := content
	files, folded, overflow := c.namedFiles(content)
	if len(folded) > 0 {
		digestContent = content + "\x00files\x00" + strings.Join(folded, "\x00")
	}
	r := Reason{Code: code, File: file, Key: key, Excerpt: excerpt(content), Digest: Digest(code, file, key, digestContent), Files: files, ownContent: content}
	if withIndicators {
		r.Indicators = indicators(content)
	}
	if overflow {
		// More files than the fold covers: decoy names could push the
		// payload past the cap, so the command can never be accepted and
		// the cut is untrusted (truncated_code), never flagged.
		r.noDigest = true
		c.res.Truncated = true
		c.add(Reason{Code: "truncated_code", File: file, Key: key, Excerpt: fmt.Sprintf("the command names more than %d repository files", maxNamedFiles)})
	}
	c.add(r)
}

// finish sets the verdict and orders the reasons: most severe first, then
// by file, code and key, so the output is stable.
func (c *checker) finish() {
	top := LevelInfo
	for _, r := range c.res.Reasons {
		if r.Level > top {
			top = r.Level
		}
	}
	c.res.Verdict = verdictFor(top)
	sort.SliceStable(c.res.Reasons, func(i, j int) bool {
		a, b := c.res.Reasons[i], c.res.Reasons[j]
		if a.Level != b.Level {
			return a.Level > b.Level
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		return a.Key < b.Key
	})
}

// digestVersion prefixes every digest's input, so a change to what a
// digest covers re-asks instead of silently matching an old accept.
const digestVersion = "sectrust/v1"

// Digest is the content digest of one repository-run command: its code,
// the file and key it sits at, and its exact content. The developer accepts
// this value; any change to the command makes a new one.
func Digest(code, file, key, content string) string {
	h := sha256.New()
	for _, part := range []string{digestVersion, code, file, key, content} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// FileDigest is the digest of a whole file nothing judged (over the read
// cap, or not parsing): its code, its path and its exact bytes (sum is
// their hex SHA-256, size their count).
func FileDigest(code, file, sum string, size int64) string {
	return Digest(code, file, "", fmt.Sprintf("file:sha256:%s:%d", sum, size))
}

// excerpt is a short, single-line, secret-masked view of a value.
func excerpt(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	s, _ = scrub.MaskSecrets(s, func(scrub.TypedFinding) bool { return true })
	if utf8.RuneCountInString(s) > maxExcerpt {
		r := []rune(s)
		s = string(r[:maxExcerpt]) + "..."
	}
	return s
}
