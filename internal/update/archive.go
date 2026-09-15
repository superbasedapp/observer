package update

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

// EntryKind is what an archive entry is. The extractor's safety rules
// differ per kind, so the kind is part of the DATA it reasons over
// rather than something re-derived from a mode bit at each check.
type EntryKind string

const (
	// EntryFile is a regular file.
	EntryFile EntryKind = "file"
	// EntryDir is a directory entry.
	EntryDir EntryKind = "dir"
	// EntrySymlink is a symbolic link; LinkTarget carries its target.
	EntrySymlink EntryKind = "symlink"
	// EntryOther is anything else a tar can carry — a hardlink, a
	// device node, a fifo. It is never selected and never tolerated.
	EntryOther EntryKind = "other"
)

// Entry is one archive member, ABSTRACTED away from archive/tar and
// archive/zip on purpose: every safety rule below is then a pure
// function over a slice of these, testable without writing a byte to a
// filesystem, and identical for both archive shapes.
type Entry struct {
	// Name is the entry's path inside the archive, as the archive
	// records it (a "./" prefix and either separator are tolerated and
	// normalized; a traversal is not).
	Name string `json:"name"`
	// Kind is what the entry is.
	Kind EntryKind `json:"kind"`
	// LinkTarget is the symlink target, empty for every other kind.
	LinkTarget string `json:"link_target,omitempty"`
	// Size is the entry's uncompressed size in bytes. Zero is allowed
	// (the caller enforces the archive-level ceiling); it is carried so
	// the selection result can be reported without a second lookup.
	Size int64 `json:"size,omitempty"`
}

// Archive-safety failures. Each is a distinct sentinel because each is
// a distinct thing to say to an operator, and because a test asserts
// one rule at a time.
var (
	// ErrMemberMissing means the manifest's member is not in the archive.
	ErrMemberMissing = errors.New("archive does not contain the manifest's member")
	// ErrMemberNotRegular means the member exists but is not a regular
	// file (a symlink named as the member would let an archive point
	// the "binary" anywhere).
	ErrMemberNotRegular = errors.New("archive member is not a regular file")
	// ErrUnlistedMember means the archive carries an entry that is
	// neither the member nor a declared alias. Per §3.1 this is a
	// FAILURE, not a skip: a new member appearing in an archive must be
	// noticed, not silently ignored.
	ErrUnlistedMember = errors.New("archive contains a member the manifest does not name")
	// ErrAbsolutePath means an entry name is absolute (unix root, a
	// leading backslash, or a Windows drive letter).
	ErrAbsolutePath = errors.New("archive entry has an absolute path")
	// ErrPathTraversal means an entry name contains a ".." element.
	ErrPathTraversal = errors.New("archive entry escapes the extraction root")
	// ErrEscapingSymlink means a symlink resolves outside the
	// extraction root, or points somewhere other than the member.
	ErrEscapingSymlink = errors.New("archive symlink escapes the extraction root")
	// ErrSymlinkInZip means a zip carried a symlink. The pipeline ships
	// the win32 alias as a byte COPY precisely because zip symlink
	// support is unreliable (npm-release.yml:1186-1189), so a symlink
	// here is either a different producer or an attack.
	ErrSymlinkInZip = errors.New("zip archives may not contain symlinks")
	// ErrDuplicateEntry means the same name appears twice. Zip permits
	// it; extractors disagree about which one wins, so it is refused.
	ErrDuplicateEntry = errors.New("archive contains a duplicate entry")
	// ErrUnsupportedEntryKind means an entry is a hardlink, device node
	// or similar.
	ErrUnsupportedEntryKind = errors.New("archive contains an unsupported entry kind")
)

// Selection is the outcome of walking an archive's entry list against
// the manifest's artifact row.
type Selection struct {
	// Member is the entry holding the real binary — the ONE entry the
	// caller extracts.
	Member Entry
	// Aliases are the declared alias entries that were found and are to
	// be SKIPPED. They are reported so an apply can log what it ignored
	// rather than silently discarding it.
	Aliases []Entry
}

// SelectMember walks an archive's entry list top-down against one
// artifact row and returns the single member to extract, or the first
// safety failure.
//
// The rules, in the order the plan states them (§3.1 "Archive shapes
// are not uniform", §3.7 step 4):
//
//  1. every entry name is relative, separator-normalized, and free of
//     ".." — an absolute path or a traversal fails immediately;
//  2. no name appears twice;
//  3. only the member, a declared alias, or an ancestor DIRECTORY of
//     one of those may appear — any other entry fails
//     (ErrUnlistedMember), because a manifest that does not name a file
//     has not vouched for it;
//  4. the member must be present and a regular file;
//  5. an alias may be a regular file (both shapes) or a symlink (tar
//     only) whose target resolves, relative to the alias's own
//     directory, to the member and stays inside the root;
//  6. hardlinks, device nodes and every other exotic kind fail.
//
// It performs no I/O and takes no root path: "inside the root" is
// decided structurally on the names, which is precisely why the rule
// can be unit-tested for both archive types.
func SelectMember(a Artifact, entries []Entry) (Selection, error) {
	member, err := normalizeEntryName(a.Member)
	if err != nil {
		return Selection{}, fmt.Errorf("update.SelectMember: manifest member %q: %w", a.Member, err)
	}
	aliases := map[string]bool{}
	for _, al := range a.AliasMembers {
		n, err := normalizeEntryName(al)
		if err != nil {
			return Selection{}, fmt.Errorf("update.SelectMember: manifest alias %q: %w", al, err)
		}
		aliases[n] = true
	}
	allowedDirs := ancestorDirs(member)
	for al := range aliases {
		for d := range ancestorDirs(al) {
			allowedDirs[d] = true
		}
	}

	var sel Selection
	seen := map[string]bool{}
	foundMember := false
	for _, e := range entries {
		name, err := normalizeEntryName(e.Name)
		if err != nil {
			return Selection{}, fmt.Errorf("update.SelectMember: entry %q: %w", e.Name, err)
		}
		if seen[name] {
			return Selection{}, fmt.Errorf("update.SelectMember: %q: %w", name, ErrDuplicateEntry)
		}
		seen[name] = true
		norm := e
		norm.Name = name

		switch {
		case name == member:
			if norm.Kind != EntryFile {
				return Selection{}, fmt.Errorf("update.SelectMember: %q: %w", name, ErrMemberNotRegular)
			}
			sel.Member = norm
			foundMember = true
		case aliases[name]:
			if err := checkAlias(a.ArchiveType, norm, member); err != nil {
				return Selection{}, fmt.Errorf("update.SelectMember: alias %q: %w", name, err)
			}
			sel.Aliases = append(sel.Aliases, norm)
		case norm.Kind == EntryDir && allowedDirs[name]:
			// An ancestor directory of a declared member is structural,
			// not content: it carries no bytes and cannot smuggle one.
		default:
			return Selection{}, fmt.Errorf("update.SelectMember: %q: %w", name, ErrUnlistedMember)
		}
	}
	if !foundMember {
		return Selection{}, fmt.Errorf("update.SelectMember: %q: %w", member, ErrMemberMissing)
	}
	return sel, nil
}

// checkAlias applies the per-archive-type alias rules.
func checkAlias(archiveType string, e Entry, member string) error {
	switch e.Kind {
	case EntryFile:
		return nil
	case EntrySymlink:
		if archiveType == ArchiveZip {
			return ErrSymlinkInZip
		}
		return checkSymlinkTarget(e, member)
	case EntryDir:
		return fmt.Errorf("%w: alias is a directory", ErrUnsupportedEntryKind)
	default:
		return ErrUnsupportedEntryKind
	}
}

// checkSymlinkTarget resolves a symlink target relative to the link's
// own directory and requires it to land exactly on the member, inside
// the root. Both halves matter: an absolute target ("/bin/sh") and a
// relative escape ("../../bin/sh") are the same attack with different
// spellings.
func checkSymlinkTarget(e Entry, member string) error {
	target := strings.TrimSpace(e.LinkTarget)
	if target == "" {
		return fmt.Errorf("%w: empty target", ErrEscapingSymlink)
	}
	if IsAbsArchivePath(target) {
		return fmt.Errorf("%w: absolute target %q", ErrEscapingSymlink, target)
	}
	resolved := path.Clean(path.Join(path.Dir(e.Name), toSlash(target)))
	if resolved == ".." || strings.HasPrefix(resolved, "../") || resolved == "." {
		return fmt.Errorf("%w: target %q resolves outside the root", ErrEscapingSymlink, target)
	}
	if resolved != member {
		return fmt.Errorf("%w: target %q resolves to %q, not the member %q",
			ErrEscapingSymlink, target, resolved, member)
	}
	return nil
}

// normalizeEntryName folds an archive entry name to a clean, relative,
// slash-separated path, or fails. It is the single gate rules 1 and 3
// share, so no caller can compare a raw name against a normalized one.
func normalizeEntryName(name string) (string, error) {
	n := strings.TrimSpace(name)
	if n == "" {
		return "", errors.New("empty entry name")
	}
	if IsAbsArchivePath(n) {
		return "", ErrAbsolutePath
	}
	n = strings.TrimSuffix(toSlash(n), "/")
	if n == "" {
		return "", errors.New("empty entry name")
	}
	if hasTraversal(n) {
		return "", ErrPathTraversal
	}
	n = path.Clean(n)
	if n == "." || n == "/" {
		return "", errors.New("empty entry name")
	}
	return n, nil
}

// IsAbsArchivePath reports whether an archive entry name or symlink
// target is absolute in ANY of the three spellings that matter: a unix
// root, a Windows drive ("C:\..."), or a leading backslash (a
// drive-relative Windows root). A tar written on one OS is routinely
// extracted on another, so all three are checked regardless of GOOS —
// filepath.IsAbs would answer only for the host (a real gotcha this
// repo has been bitten by before).
func IsAbsArchivePath(name string) bool {
	if name == "" {
		return false
	}
	if name[0] == '/' || name[0] == '\\' {
		return true
	}
	if len(name) >= 2 && name[1] == ':' {
		c := name[0]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return true
		}
	}
	return false
}

// hasTraversal reports whether a slash- or backslash-separated path has
// a ".." element anywhere.
func hasTraversal(name string) bool {
	for _, part := range strings.Split(toSlash(name), "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

// toSlash converts backslashes to slashes. A zip produced on Windows
// may use either, and treating "\" as an ordinary character would let
// "..\..\evil" through every "/"-based check.
func toSlash(s string) string { return strings.ReplaceAll(s, `\`, "/") }

// ancestorDirs returns the set of directory paths above a member.
func ancestorDirs(name string) map[string]bool {
	out := map[string]bool{}
	for d := path.Dir(name); d != "." && d != "/" && d != ""; d = path.Dir(d) {
		out[d] = true
	}
	return out
}
