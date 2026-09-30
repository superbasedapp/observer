package commitlog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/loc"
)

// recordSep is git's %x1e escape — the ASCII Record Separator — used as
// the record boundary between commits in logFormat's output. It cannot
// appear in any of the fields we split on (SHA, dates, subject), which is
// exactly why it was chosen over a printable delimiter.
const recordSep = 0x1e

// authorHashLen is the number of hex characters of sha256(author name)
// kept as Commit.AuthorHash — enough to be a stable per-repo join key
// without carrying the full 64-char digest around.
const authorHashLen = 16

// ParseLog decodes the output of a `git log` invocation built with Args
// into a slice of Commit.
//
// When overflow is true, out was truncated by an upstream byte cap
// (gitview.RunReadOnly's cappedBuffer) and may end mid-record; the
// trailing, possibly-partial record is dropped rather than risk parsing
// a commit with a truncated file list or a chopped-off subject as if it
// were complete. This mirrors internal/gitview's dropTrailingPartial
// idea (gitview.go:252) but is reimplemented here because commitlog must
// stay free of any internal/gitview import (doc.go) and, unlike
// gitview's terminator-style separator, recordSep here PREFIXES each
// record rather than terminating it, so the trim logic differs (see
// dropTrailingPartial below).
func ParseLog(out []byte, overflow bool) ([]Commit, error) {
	if overflow {
		out = dropTrailingPartial(out)
	}
	var commits []Commit
	for _, rec := range splitRecords(out) {
		c, err := parseRecord(rec)
		if err != nil {
			return nil, err
		}
		commits = append(commits, c)
	}
	return commits, nil
}

// dropTrailingPartial discards the final record when the stream may have
// been cut mid-record by a byte cap. Because recordSep marks the START
// of a record (not its end), the safe trim point is everything BEFORE
// the last recordSep byte: the record beginning at that last separator
// is ambiguous — it may be complete (the cap landed exactly on the next
// boundary) or truncated (the cap landed inside it) — and there is no
// cheap way to tell the two apart, so it is always dropped. Losing at
// most one commit per capped scan is the accepted cost (plan R2).
//
// Returns nil when recordSep never occurs at all (the cap cut before
// even the first record completed).
func dropTrailingPartial(data []byte) []byte {
	if i := bytes.LastIndexByte(data, recordSep); i >= 0 {
		return data[:i]
	}
	return nil
}

// splitRecords splits raw git output on recordSep, dropping the empty
// leading chunk (everything before the first separator — normally
// nothing, since logFormat starts with recordSep) and any other
// all-whitespace chunk (a trailing newline after the last record, or the
// empty result of dropTrailingPartial cutting exactly on a boundary).
func splitRecords(data []byte) [][]byte {
	var records [][]byte
	for _, chunk := range bytes.Split(data, []byte{recordSep}) {
		if len(bytes.TrimSpace(chunk)) == 0 {
			continue
		}
		records = append(records, chunk)
	}
	return records
}

// parseRecord decodes one record: a NUL-separated header line followed
// by zero or more --numstat lines (with a possible blank separator line
// git inserts between the header and the numstat block — parseNumstat
// tolerates it).
func parseRecord(rec []byte) (Commit, error) {
	headerLine := rec
	var rest []byte
	if nl := bytes.IndexByte(rec, '\n'); nl >= 0 {
		headerLine = rec[:nl]
		rest = rec[nl+1:]
	}

	// SplitN(..., 6): the subject (the 6th and last field) is the one
	// field that could legitimately contain more NULs in a pathological
	// commit message; capping at 6 keeps any such bytes inside the
	// subject rather than manufacturing a 7th field.
	fields := strings.SplitN(string(headerLine), "\x00", 6)
	if len(fields) < 6 {
		return Commit{}, fmt.Errorf("commitlog: malformed header, want 6 NUL-separated fields got %d: %q",
			len(fields), string(headerLine))
	}
	sha, parentsField, authorName, authoredField, committedField, subject := fields[0], fields[1], fields[2], fields[3], fields[4], fields[5]

	authoredAt, err := time.Parse(time.RFC3339, authoredField)
	if err != nil {
		return Commit{}, fmt.Errorf("commitlog: parsing author date %q for %s: %w", authoredField, sha, err)
	}
	committedAt, err := time.Parse(time.RFC3339, committedField)
	if err != nil {
		return Commit{}, fmt.Errorf("commitlog: parsing committer date %q for %s: %w", committedField, sha, err)
	}

	parents := strings.Fields(parentsField)
	files := parseNumstat(rest)

	return Commit{
		SHA:         sha,
		Parents:     parents,
		AuthorHash:  hashAuthor(authorName),
		AuthoredAt:  authoredAt,
		CommittedAt: committedAt,
		Subject:     subject,
		IsMerge:     len(parents) > 1,
		Files:       files,
	}, nil
}

// hashAuthor hashes a trimmed author display name so the raw name never
// leaves this package (doc.go / types.go). It is deliberately NOT salted
// per-repo — plan R12/COMMIT-2 records this as inadequate pseudonymization
// for any future org projection, tracked in docs/security.md.
func hashAuthor(name string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(name)))
	return hex.EncodeToString(sum[:])[:authorHashLen]
}

// HashAuthorName is the exported form of the author hashing above, so a
// caller that resolves the repository's LOCAL identity (the configured
// user.name, which is what a local commit records as %an) can compare it
// with a stored Commit.AuthorHash under exactly the same rule (review
// 2026-09-29 finding 8, the foreign_author ownership gate). An empty or
// all-whitespace name returns "" (unknown), never the hash of the empty
// string, so an unset identity can never match or mismatch anything.
func HashAuthorName(name string) string {
	if strings.TrimSpace(name) == "" {
		return ""
	}
	return hashAuthor(name)
}

// parseNumstat decodes the --numstat lines following a commit's header
// line. Each line is "<added>\t<deleted>\t<path>"; a binary file reports
// "-\t-\t<path>". Blank lines (the separator git inserts between the
// header and the numstat block, and between commits) are skipped. A line
// that doesn't parse as three tab-separated fields, or whose added/
// deleted counts aren't both integers or both "-", is skipped rather
// than failing the whole commit — --numstat is well-formed in practice,
// and a best-effort skip is safer than discarding an otherwise-good
// commit over one odd line.
func parseNumstat(rest []byte) []CommitFile {
	if len(bytes.TrimSpace(rest)) == 0 {
		return nil
	}
	var files []CommitFile
	for _, lineB := range bytes.Split(rest, []byte("\n")) {
		line := strings.TrimRight(string(lineB), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) != 3 {
			continue
		}
		addedStr, deletedStr, path := parts[0], parts[1], parts[2]

		f := CommitFile{RelPath: path, PathHash: loc.PathHash("", path)}
		if addedStr == "-" && deletedStr == "-" {
			f.Binary = true
		} else {
			added, errA := strconv.Atoi(addedStr)
			deleted, errD := strconv.Atoi(deletedStr)
			if errA != nil || errD != nil {
				continue
			}
			f.Added = added
			f.Deleted = deleted
		}
		files = append(files, f)
	}
	return files
}
