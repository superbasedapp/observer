package sectrust

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
)

// parseError raises parse_error for a file that does not parse: the agent
// may still read it (a lenient parser, a later version), so it is untrusted
// until the developer accepts the digest of its exact bytes.
func (c *checker) parseError(file string, data []byte, err error) {
	sum := sha256.Sum256(data)
	c.add(Reason{
		Code: "parse_error", File: file, Excerpt: excerpt(err.Error()),
		Digest: FileDigest("parse_error", file, hex.EncodeToString(sum[:]), int64(len(data))),
	})
}

// projectDirPrefixes are the spellings a command uses for the project
// directory; a token starting with one names a path from that directory.
var projectDirPrefixes = []string{
	"$CLAUDE_PROJECT_DIR/", "${CLAUDE_PROJECT_DIR}/", `%CLAUDE_PROJECT_DIR%\`, `%CLAUDE_PROJECT_DIR%/`,
	"${workspaceFolder}/", `${workspaceFolder}\`, "$PWD/", "${PWD}/",
	"${GEMINI_PROJECT_DIR}/", "$GEMINI_PROJECT_DIR/", "${CURSOR_PROJECT_DIR}/",
}

// namedFiles finds the repository files a command names and returns their
// paths and the "path=sha256:<hex>:<size>" entries a digest folds in, both
// sorted. A token names a file when, after the project-directory spellings
// and a leading "./" are dropped (and a "--flag=" or "NAME=" prefix is cut),
// it is a relative path that resolves, at the visited root or at the
// repository root, to a regular file inside the repository. A name whose
// symlink leaves the repository raises symlink_escape; a named file over
// the hash cap raises file_over_hash_cap. overflow reports a command that
// names more than maxNamedFiles files: the fold does not cover them all, so
// the caller withholds the digest (decoy names must not hide a payload). What
// is not covered (a file the named script itself loads, a package name, a
// path built at run time) is the residual docs/repository-trust.md names.
// Lookups are cached per check (checker.named), misses included, so a word
// repeated across commands costs one Lstat.
func (c *checker) namedFiles(command string) (files, folded []string, overflow bool) {
	seen := map[string]bool{}
	for _, tok := range commandTokens(command) {
		for _, rel := range candidateRels(tok, c.root) {
			if seen[rel] {
				continue
			}
			nf, ok := c.lookupNamed(rel)
			if !ok {
				continue
			}
			seen[rel] = true
			if nf == nil {
				break
			}
			if len(files) >= maxNamedFiles {
				overflow = true
				break
			}
			folded = append(folded, nf.folded)
			files = append(files, rel)
			break
		}
	}
	sort.Strings(files)
	sort.Strings(folded)
	return files, folded, overflow
}

// lookupNamed resolves one candidate path a command names, once per check.
// ok is false when nothing exists there (try the next candidate); a nil
// file with ok set is a path that exists but names no file the digest can
// fold (a directory, a link out of the repository, which raised its reason).
func (c *checker) lookupNamed(rel string) (*namedFile, bool) {
	if c.named == nil {
		c.named = map[string]*namedFile{}
	}
	if nf, hit := c.named[rel]; hit {
		return nf, nf != nil || c.namedExists[rel]
	}
	nf, exists := c.resolveNamed(rel)
	c.named[rel] = nf
	if exists && nf == nil {
		if c.namedExists == nil {
			c.namedExists = map[string]bool{}
		}
		c.namedExists[rel] = true
	}
	return nf, exists
}

// resolveNamed is lookupNamed uncached.
func (c *checker) resolveNamed(rel string) (*namedFile, bool) {
	fi, err := c.fsys.Lstat(rel)
	if err != nil {
		return nil, false
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		if c.fsys.Escapes(rel) {
			c.symlinkEscape(rel, "a file a command runs")
			return nil, true
		}
		if fi, err = c.fsys.Stat(rel); err != nil {
			return nil, true
		}
	}
	if !fi.Mode().IsRegular() {
		return nil, true
	}
	sum, size, err := c.fsys.HashFile(rel, hashCap)
	switch {
	case err == nil:
		return &namedFile{folded: rel + "=sha256:" + sum + ":" + strconv.FormatInt(size, 10)}, true
	case size > hashCap:
		c.add(Reason{Code: "file_over_hash_cap", File: rel, Excerpt: "a file a command runs"})
		return &namedFile{folded: rel + "=over-hash-cap"}, true
	default:
		return &namedFile{folded: rel + "=unreadable"}, true
	}
}

// unquote drops the quote characters, the way a shell joins `"$X"/y` into
// one word.
var unquote = strings.NewReplacer(`"`, "", "'", "", "`", "")

// commandTokens splits a command into words on white space and the shell's
// separators, quotes dropped; a "--flag=value" or "NAME=value" word yields
// its value as well.
func commandTokens(command string) []string {
	words := strings.FieldsFunc(unquote.Replace(command), func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', ';', '|', '&', '(', ')', '<', '>', ',':
			return true
		}
		return false
	})
	var out []string
	for _, w := range words {
		out = append(out, w)
		if i := strings.IndexByte(w, '='); i >= 0 && i+1 < len(w) {
			out = append(out, w[i+1:])
		}
	}
	return out
}

// candidateRels turns one token into the repository-relative paths it may
// name: from the visited root first, then from the repository root. A token
// that is a URL, an option, an absolute or home path, or that climbs out of
// the repository names nothing.
func candidateRels(tok, root string) []string {
	for _, p := range projectDirPrefixes {
		if strings.HasPrefix(tok, p) {
			tok = tok[len(p):]
			break
		}
	}
	tok = strings.ReplaceAll(tok, `\`, "/")
	if tok == "" || strings.Contains(tok, "://") || strings.ContainsAny(tok, "*?[$%{}~") ||
		strings.HasPrefix(tok, "-") || strings.HasPrefix(tok, "/") || (len(tok) > 1 && tok[1] == ':') {
		return nil
	}
	tok = strings.TrimPrefix(tok, "./")
	clean := path.Clean(tok)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return nil
	}
	if root == "" {
		return []string{clean}
	}
	inner := path.Clean(root + "/" + clean)
	if strings.HasPrefix(inner, "../") {
		return []string{clean}
	}
	return []string{inner, clean}
}
