package depscan

import (
	"errors"
	"path"
	"sort"
	"strings"
)

// artifacts.go is depscan's half of the artifact extractors (OS and CI
// vulnerability scanning plan section 14.6, M3L-2 item 4): Go build info,
// Java archives, Python wheels and eggs, and the dependency list cargo
// auditable embeds in a Rust binary, read by the SCALIBR facade in the
// same scan child, under security.scan.scalibr.
//
// Artifact scanning is opt-in per folder (operator ruling 2026-11-05):
// candidate artifact folders are discovered (internal/secscan/artifactfind:
// the DefaultCandidateDirs below plus what a bounded walk finds) and shown,
// and nothing under one is read until the developer turns that folder on
// (`observer security scan artifacts enable <dir>`, the Scanners card) or
// names it for one run (`observer security scan --artifacts <dir>`). The
// enabled folders are ChildRequest.ArtifactDirs; the candidates that are
// NOT enabled are ChildRequest.ArtifactOff, under which even a Java archive
// or a wheel found by name is left alone. An executable is read only under
// an enabled folder and only by its header, never by name or mode bits.
// Every artifact file is held to a size cap (MaxArtifactBytes); a larger
// one is a gap (ReasonArtifactTooLarge), so the run is partial, never clean.

// DefaultCandidateDirs are the build output folders always offered as
// artifact candidates, relative to the project root. They are only a
// starting list: nothing under one is scanned until it is turned on.
var DefaultCandidateDirs = []string{"bin", "dist", "target/release"}

// MaxArtifactBytes is the size cap of one artifact file (an executable, a
// Java archive, a wheel or egg). The scan child's memory cap is 1.5 GiB;
// the extractors read an executable through its section table, not whole.
const MaxArtifactBytes int64 = 256 << 20

// MaxArtifactDirs caps the named directories of one scan.
const MaxArtifactDirs = 32

// ReasonArtifactTooLarge is the gap an artifact over MaxArtifactBytes
// leaves: it was not read.
const ReasonArtifactTooLarge = "artifact_too_large"

// ArtifactKind is the ExtractorInfo kind of the four artifact extractors.
const ArtifactKind = "artifact"

// ErrArtifactDir is what CleanArtifactDirs answers for a directory that is
// not a plain path inside the project.
var ErrArtifactDir = errors.New("an artifact directory must be a path inside the project")

// CleanArtifactDirs cleans the named artifact directories (relative to the
// project root, forward slashes): each is cleaned, and one that is
// absolute, empty, the root itself or leaves the root ("..") is refused.
// The result is sorted and deduplicated; at most MaxArtifactDirs.
func CleanArtifactDirs(dirs []string) ([]string, error) {
	if len(dirs) > MaxArtifactDirs {
		return nil, errors.New("too many artifact directories")
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		d = strings.ReplaceAll(strings.TrimSpace(d), `\`, "/")
		c := path.Clean(d)
		switch {
		case d == "", c == ".", path.IsAbs(c), c == "..", strings.HasPrefix(c, "../"), len(c) > 1 && c[1] == ':':
			return nil, ErrArtifactDir
		}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out, nil
}

// ArtifactDirs is the list of artifact folders a scan reads: the ones the
// developer turned on or named (already cleaned by CleanArtifactDirs; one
// that is not clean is left out), sorted, without duplicates. There is no
// implicit default: an empty list reads no executable.
func ArtifactDirs(named []string) []string {
	clean, err := CleanArtifactDirs(named)
	if err != nil {
		clean = nil
		for _, d := range named {
			if c, err := CleanArtifactDirs([]string{d}); err == nil {
				clean = append(clean, c...)
			}
		}
	}
	out, _ := CleanArtifactDirs(clean)
	return out
}

// UnderArtifactDir reports whether rel (a path relative to the project
// root, forward slashes) lies under one of dirs.
func UnderArtifactDir(rel string, dirs []string) bool {
	rel = strings.ReplaceAll(rel, `\`, "/")
	for _, d := range dirs {
		if strings.HasPrefix(rel, d+"/") {
			return true
		}
	}
	return false
}

// executableMagic is the header table an executable is detected by (never
// the mode bits, which Windows does not carry, and never the extension):
// ELF, PE, Mach-O (both byte orders, 32 and 64 bit), universal Mach-O, and
// WebAssembly (cargo auditable writes its section there too).
var executableMagic = []struct {
	Format string
	Prefix string
	// Offset is where Prefix starts.
	Offset int
}{
	{"elf", "\x7fELF", 0},
	{"pe", "MZ", 0},
	{"macho", "\xfe\xed\xfa", 0},
	{"macho", "\xfa\xed\xfe", 1},
	{"macho-universal", "\xca\xfe\xba\xbe", 0},
	{"macho-universal", "\xca\xfe\xba\xbf", 0},
	{"wasm", "\x00asm", 0},
}

// ExecutableHeaderBytes is how many leading bytes ExecutableFormat needs.
const ExecutableHeaderBytes = 8

// maxFatArches is the universal Mach-O arch count below which 0xCAFEBABE
// is a universal binary; a Java class file shares the magic and carries its
// version there instead (major 45 or more), as file(1) tells them apart.
const maxFatArches = 20

// ExecutableFormat names the executable format of a file's first bytes,
// "" when they are not an executable's.
func ExecutableFormat(head []byte) string {
	for _, m := range executableMagic {
		if len(head) < m.Offset+len(m.Prefix) || string(head[m.Offset:m.Offset+len(m.Prefix)]) != m.Prefix {
			continue
		}
		if m.Format == "macho-universal" {
			if len(head) < 8 {
				return ""
			}
			n := uint32(head[4])<<24 | uint32(head[5])<<16 | uint32(head[6])<<8 | uint32(head[7])
			if n == 0 || n >= maxFatArches {
				return ""
			}
		}
		return m.Format
	}
	return ""
}
