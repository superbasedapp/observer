package gitmodules

import (
	"path"
	"sort"
	"strings"
)

// gitlinkMode is a gitlink's index mode: a submodule's pinned commit.
const gitlinkMode = "160000"

// LsFilesArgs is the git argv (after "git" itself and the caller's -C, as
// internal/gitview's read-only runners take it) that lists the index
// entries at the given submodule paths: `--literal-pathspecs` so a path is
// never read as a glob, `--stage` for the mode and object id, `-z` for
// NUL-terminated records. It reads the index only (the pins the next
// commit records, including a bump not yet committed); it fetches nothing
// and enters no submodule.
func LsFilesArgs(paths []string) []string {
	args := []string{"--literal-pathspecs", "ls-files", "--stage", "-z", "--"}
	return append(args, paths...)
}

// Gitlink is one gitlink entry of the index: the submodule's path (relative
// to the directory git ran in, forward slashes) and the object id it pins.
type Gitlink struct {
	Path   string
	Object string
}

// ParseLsFiles decodes `git ls-files --stage -z` output into its gitlink
// entries: records "<mode> <object> <stage>\t<path>", mode 160000 and
// stage 0 only (an unmerged submodule pins nothing yet). A record that does
// not split into those four pieces is skipped.
func ParseLsFiles(out []byte) []Gitlink {
	var links []Gitlink
	for _, rec := range strings.Split(string(out), "\x00") {
		header, p, ok := strings.Cut(rec, "\t")
		if !ok || p == "" {
			continue
		}
		fields := strings.Fields(header)
		if len(fields) != 3 || fields[0] != gitlinkMode || fields[2] != "0" {
			continue
		}
		links = append(links, Gitlink{Path: p, Object: strings.ToLower(fields[1])})
	}
	return links
}

// ValidCommit reports whether s is a full SHA-1 commit id OSV can match:
// 40 lower-case hex digits, not all zeros. An abbreviated id makes OSV
// refuse the whole request (spike CPP-0 (a)), and a SHA-256 repository's
// 64-digit ids name no commit OSV has indexed.
func ValidCommit(s string) bool {
	if len(s) != 40 || strings.Trim(s, "0") == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// Pin is one submodule the superproject pins: its path relative to the
// project root (forward slashes), its local name (the .gitmodules section
// name, or the path when that is not fit to show) and the commit id. Only
// Commit ever leaves the machine.
type Pin struct {
	Path   string
	Name   string
	Commit string
}

// Join pairs a .gitmodules file's entries with the gitlinks git listed in
// the file's directory dir (relative to the project root, "." for the
// root). It returns the pins, sorted by path, and the paths whose gitlink
// names no commit OSV can match (Unmatchable: a SHA-256 id, a malformed
// one), which the caller reports as a gap. An entry with no gitlink in the
// index pins nothing (a stale declaration) and is neither.
func Join(dir string, entries []Entry, links []Gitlink) (pins []Pin, unmatchable []string) {
	byPath := map[string]string{}
	for _, l := range links {
		if p, ok := CleanRel(l.Path); ok {
			byPath[p] = l.Object
		}
	}
	for _, e := range entries {
		obj, ok := byPath[e.Path]
		if !ok {
			continue
		}
		full := path.Join(dir, e.Path)
		if !ValidCommit(obj) {
			unmatchable = append(unmatchable, full)
			continue
		}
		name := e.Name
		if dir != "." && dir != "" && name == e.Path {
			name = full
		}
		pins = append(pins, Pin{Path: full, Name: name, Commit: obj})
	}
	sort.Slice(pins, func(i, j int) bool { return pins[i].Path < pins[j].Path })
	sort.Strings(unmatchable)
	return pins, unmatchable
}

// Paths returns the entries' paths, the pathspecs LsFilesArgs takes.
func Paths(entries []Entry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Path)
	}
	return out
}
