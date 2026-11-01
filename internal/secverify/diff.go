package secverify

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ChangeStatus is how a file changed between base and head.
type ChangeStatus string

// The closed change vocabulary (`git diff --name-status --no-renames`).
const (
	StatusAdded       ChangeStatus = "added"
	StatusModified    ChangeStatus = "modified"
	StatusDeleted     ChangeStatus = "deleted"
	StatusTypeChanged ChangeStatus = "type_changed"
)

// nameStatusCodes maps git's one-letter codes to ChangeStatus. Renames and
// copies cannot appear: the cmd layer passes --no-renames, so a rename is a
// delete plus an add and both sides are judged.
var nameStatusCodes = map[string]ChangeStatus{
	"A": StatusAdded,
	"M": StatusModified,
	"D": StatusDeleted,
	"T": StatusTypeChanged,
}

// AddedLine is one line the change adds, with its line number in the head
// version of the file.
type AddedLine struct {
	N    int
	Text string
}

// ChangedFile is one file of the diff.
type ChangedFile struct {
	Path   string
	Status ChangeStatus
	// Binary is true when git reports the file as binary; it has no lines.
	Binary bool
	Added  []AddedLine
	// Removed are the removed lines, numbered in the base file (the
	// test-tampering rules compare them with the added ones). They have a
	// per-file byte cap of their own (Limits.MaxFileRemovedBytes), so a
	// large deletion never crowds the added lines out of their cap.
	Removed []AddedLine
	// Partial is true when a cap cut the file's added or removed lines
	// short, so a detector that reads them cannot claim to have read the
	// whole change.
	Partial bool
}

// Limits caps what the parser keeps.
type Limits struct {
	// MaxFiles caps the number of changed files; more is an error (the
	// verdict becomes unknown).
	MaxFiles int
	// MaxFileAddedBytes caps the added text kept per file; past it the file
	// is Partial.
	MaxFileAddedBytes int
	// MaxFileRemovedBytes caps the removed text kept per file, apart from
	// the added text; past it the file is Partial. Zero uses
	// MaxFileAddedBytes.
	MaxFileRemovedBytes int
	// MaxLineBytes caps one added line; a longer line is cut and the file
	// is Partial.
	MaxLineBytes int
}

// DefaultLimits are the parser caps when the policy sets none.
func DefaultLimits() Limits {
	return Limits{MaxFiles: 5000, MaxFileAddedBytes: 4 << 20, MaxLineBytes: 256 << 10}
}

// ErrInconsistentDiff is returned when the patch names a file the name
// list does not, or the reverse is malformed.
var ErrInconsistentDiff = errors.New("secverify: the patch and the file list disagree")

// ParseDiff joins `git diff --name-status -z --no-renames` output with the
// matching `git diff -U0 --no-renames` patch into one row per changed file,
// sorted by path.
func ParseDiff(nameStatus, patch []byte, lim Limits) ([]ChangedFile, error) {
	files, err := ParseNameStatus(nameStatus, lim)
	if err != nil {
		return nil, err
	}
	byPath := make(map[string]*ChangedFile, len(files))
	for i := range files {
		byPath[files[i].Path] = &files[i]
	}
	if err := parsePatch(patch, byPath, lim); err != nil {
		return nil, err
	}
	return files, nil
}

// ParseNameStatus parses `git diff --name-status -z --no-renames` output:
// status and path alternate, each NUL-terminated.
func ParseNameStatus(b []byte, lim Limits) ([]ChangedFile, error) {
	if len(b) == 0 {
		return nil, nil
	}
	fields := bytes.Split(bytes.TrimSuffix(b, []byte{0}), []byte{0})
	if len(fields)%2 != 0 {
		return nil, fmt.Errorf("secverify.ParseNameStatus: %d fields, want pairs: %w", len(fields), ErrInconsistentDiff)
	}
	if lim.MaxFiles > 0 && len(fields)/2 > lim.MaxFiles {
		return nil, fmt.Errorf("secverify.ParseNameStatus: %d changed files over the cap of %d", len(fields)/2, lim.MaxFiles)
	}
	out := make([]ChangedFile, 0, len(fields)/2)
	seen := map[string]bool{}
	for i := 0; i < len(fields); i += 2 {
		code := string(fields[i])
		st, ok := nameStatusCodes[code]
		if !ok {
			return nil, fmt.Errorf("secverify.ParseNameStatus: status %q is not one verify judges: %w", clipSafe(code, 8), ErrInconsistentDiff)
		}
		p := string(fields[i+1])
		if err := ValidRelPath(p); err != nil {
			return nil, fmt.Errorf("secverify.ParseNameStatus: %w", err)
		}
		if seen[p] {
			return nil, fmt.Errorf("secverify.ParseNameStatus: %q listed twice: %w", QuotePath(p), ErrInconsistentDiff)
		}
		seen[p] = true
		out = append(out, ChangedFile{Path: p, Status: st})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// parsePatch walks the unified diff and fills the Added lines and the
// Binary flag of the matching rows.
func parsePatch(patch []byte, byPath map[string]*ChangedFile, lim Limits) error {
	var cur *ChangedFile
	var curBytes, rmBytes, newLine, oldLine int
	inHunk := false
	maxRemoved := lim.MaxFileRemovedBytes
	if maxRemoved <= 0 {
		maxRemoved = lim.MaxFileAddedBytes
	}
	for len(patch) > 0 {
		var line []byte
		if i := bytes.IndexByte(patch, '\n'); i >= 0 {
			line, patch = patch[:i], patch[i+1:]
		} else {
			line, patch = patch, nil
		}
		switch {
		case bytes.HasPrefix(line, []byte("diff --git ")):
			p, err := headerPath(string(line[len("diff --git "):]))
			if err != nil {
				return err
			}
			f, ok := byPath[p]
			if !ok {
				return fmt.Errorf("secverify.parsePatch: %q is in the patch but not the file list: %w", QuotePath(p), ErrInconsistentDiff)
			}
			cur, curBytes, rmBytes, inHunk = f, 0, 0, false
		case cur == nil:
			// Nothing before the first header is meaningful.
		case bytes.HasPrefix(line, []byte("@@ ")):
			n, err := hunkNewStart(string(line))
			if err != nil {
				return err
			}
			newLine, oldLine, inHunk = n, hunkOldStart(string(line)), true
		case !inHunk:
			if bytes.HasPrefix(line, []byte("Binary files ")) || bytes.HasPrefix(line, []byte("GIT binary patch")) {
				cur.Binary = true
			}
		case len(line) > 0 && line[0] == '+':
			text := line[1:]
			if lim.MaxLineBytes > 0 && len(text) > lim.MaxLineBytes {
				text = text[:lim.MaxLineBytes]
				cur.Partial = true
			}
			if lim.MaxFileAddedBytes > 0 && curBytes+len(text) > lim.MaxFileAddedBytes {
				cur.Partial = true
			} else {
				cur.Added = append(cur.Added, AddedLine{N: newLine, Text: string(text)})
				curBytes += len(text)
			}
			newLine++
		case len(line) > 0 && line[0] == '-':
			text := line[1:]
			if lim.MaxLineBytes > 0 && len(text) > lim.MaxLineBytes {
				text = text[:lim.MaxLineBytes]
				cur.Partial = true
			}
			if maxRemoved > 0 && rmBytes+len(text) > maxRemoved {
				cur.Partial = true
			} else {
				cur.Removed = append(cur.Removed, AddedLine{N: oldLine, Text: string(text)})
				rmBytes += len(text)
			}
			oldLine++
		case len(line) > 0 && line[0] == ' ':
			newLine++
			oldLine++
		default:
			// The "\ No newline at end of file" marker moves no counter.
		}
	}
	return nil
}

// headerPath extracts the path from a `diff --git a/P b/P` header. With
// --no-renames both sides name the same path, which makes the unquoted form
// unambiguous even when P holds spaces; git C-quotes a path with special
// characters, and both sides are then quoted.
func headerPath(rest string) (string, error) {
	if strings.HasPrefix(rest, `"`) {
		a, tail, err := cutQuoted(rest)
		if err != nil {
			return "", err
		}
		tail = strings.TrimPrefix(tail, " ")
		b, _, err := cutQuoted(tail)
		if err != nil {
			return "", err
		}
		return samePathPair(a, b)
	}
	if (len(rest)-5)%2 != 0 || len(rest) < 7 {
		return "", fmt.Errorf("secverify.headerPath: unreadable diff header: %w", ErrInconsistentDiff)
	}
	n := (len(rest) - 5) / 2
	return samePathPair(rest[:2+n], rest[2+n+1:])
}

func samePathPair(a, b string) (string, error) {
	if !strings.HasPrefix(a, "a/") || !strings.HasPrefix(b, "b/") || a[2:] != b[2:] {
		return "", fmt.Errorf("secverify.headerPath: the two sides of a diff header differ: %w", ErrInconsistentDiff)
	}
	return a[2:], nil
}

// cutQuoted reads one git C-quoted string from the front of s.
func cutQuoted(s string) (string, string, error) {
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			v, err := strconv.Unquote(s[:i+1])
			if err != nil {
				return "", "", fmt.Errorf("secverify.cutQuoted: %w", ErrInconsistentDiff)
			}
			return v, s[i+1:], nil
		}
	}
	return "", "", fmt.Errorf("secverify.cutQuoted: unterminated quoted path: %w", ErrInconsistentDiff)
}

// hunkOldStart reads the base-file start line of a hunk header
// "@@ -a,b +c,d @@" (best effort: 1 when unreadable; it only numbers the
// removed lines).
func hunkOldStart(h string) int {
	rest, ok := strings.CutPrefix(h, "@@ -")
	if !ok {
		return 1
	}
	end := strings.IndexAny(rest, ", ")
	if end < 0 {
		return 1
	}
	n, err := strconv.Atoi(rest[:end])
	if err != nil || n < 1 {
		return 1
	}
	return n
}

// hunkNewStart reads c from "@@ -a,b +c,d @@".
func hunkNewStart(h string) (int, error) {
	i := strings.Index(h, " +")
	if i < 0 {
		return 0, fmt.Errorf("secverify.hunkNewStart: unreadable hunk header: %w", ErrInconsistentDiff)
	}
	rest := h[i+2:]
	end := strings.IndexAny(rest, ", ")
	if end < 0 {
		return 0, fmt.Errorf("secverify.hunkNewStart: unreadable hunk header: %w", ErrInconsistentDiff)
	}
	n, err := strconv.Atoi(rest[:end])
	if err != nil || n < 0 {
		return 0, fmt.Errorf("secverify.hunkNewStart: unreadable hunk header: %w", ErrInconsistentDiff)
	}
	return n, nil
}
