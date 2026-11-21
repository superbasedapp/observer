package artifactfind

import (
	"io"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
)

// Bounds on one discovery (every one is a fixed number, so a hostile or
// huge tree cannot make the card or the CLI slow).
const (
	// MaxDirEntries is how many entries of one directory are read.
	MaxDirEntries = 2000
	// MaxCandidates caps the folders reported.
	MaxCandidates = 64
	// MaxFilesPerFolder caps the files looked at in one candidate folder.
	MaxFilesPerFolder = 1000
	// MaxFolderDepth is how many directory levels below a candidate folder
	// are looked into.
	MaxFolderDepth = 3
	// HeaderBytes is how many leading bytes of a file are read; the file's
	// contents are never read past them.
	HeaderBytes = depscan.ExecutableHeaderBytes
)

// The artifact kinds a folder holds, as Folder.Counts keys.
const (
	KindELF   = "elf"
	KindPE    = "pe"
	KindMachO = "macho"
	KindWasm  = "wasm"
	KindJAR   = "jar"
	KindWheel = "wheel"
)

// kindWords names each kind in the folder's summary, in display order.
var kindWords = []struct{ Kind, Singular, Plural string }{
	{KindELF, "ELF executable", "ELF executables"},
	{KindPE, "PE executable", "PE executables"},
	{KindMachO, "Mach-O executable", "Mach-O executables"},
	{KindWasm, "WebAssembly module", "WebAssembly modules"},
	{KindJAR, "JAR", "JARs"},
	{KindWheel, "wheel or egg", "wheels or eggs"},
}

// Folder is one candidate artifact folder: where it is and what its file
// headers say it holds. It is data about names and headers only.
type Folder struct {
	// Dir is the folder, relative to the project root, forward slashes.
	Dir string `json:"dir"`
	// Default marks a folder of the default list
	// (depscan.DefaultCandidateDirs), listed because it is there, whatever
	// it holds.
	Default bool `json:"default,omitempty"`
	// Counts is how many files of each kind (the Kind constants) the
	// folder holds.
	Counts map[string]int `json:"counts"`
	// Bytes is the total size of the counted files.
	Bytes int64 `json:"bytes"`
	// Skipped is how many entries were not looked at: symbolic links
	// (refused), unreadable files and entries past a bound.
	Skipped int `json:"skipped,omitempty"`
	// Truncated reports that a bound ended the look early, so the counts
	// are a floor.
	Truncated bool `json:"truncated,omitempty"`
}

// Total is how many artifact files the folder holds.
func (f Folder) Total() int {
	n := 0
	for _, c := range f.Counts {
		n += c
	}
	return n
}

// Summary is the folder's content in words ("2 ELF executables, 1 JAR";
// "no executables, JARs or wheels" when it holds none).
func (f Folder) Summary() string {
	var parts []string
	for _, k := range kindWords {
		switch n := f.Counts[k.Kind]; {
		case n == 1:
			parts = append(parts, "1 "+k.Singular)
		case n > 1:
			parts = append(parts, strconv.Itoa(n)+" "+k.Plural)
		}
	}
	if len(parts) == 0 {
		return "no executables, JARs or wheels"
	}
	s := strings.Join(parts, ", ")
	if f.Truncated {
		s += " or more"
	}
	return s
}

// skipDirs are directory names discovery never looks into: dependency and
// tool trees, whose files are not the project's build output (they are
// scanned by their lockfiles, or not at all).
var skipDirs = map[string]bool{
	"node_modules": true, ".git": true, ".hg": true, ".svn": true, "vendor": true,
	"third_party": true, "site-packages": true, ".venv": true, "venv": true, "env": true,
	"__pycache__": true, ".tox": true, ".gradle": true, ".idea": true, ".vscode": true,
	".cache": true, ".terraform": true, "bower_components": true,
}

// candidateRule is one row of the candidate table: a folder (by its path
// relative to the root) is a candidate when a row's Match holds. The table
// is walked top-down on each directory down to two levels from the root;
// one test case per row.
type candidateRule struct {
	Name  string
	Match func(rel string) bool
}

// outputNames are the folder names that mean "build output", at the top of
// the project or one level down.
var outputNames = map[string]bool{"bin": true, "dist": true, "build": true, "out": true, "release": true}

// candidateRules decides which folders are candidates.
var candidateRules = []candidateRule{
	{"default list", func(rel string) bool {
		for _, d := range depscan.DefaultCandidateDirs {
			if rel == d {
				return true
			}
		}
		return false
	}},
	{"cargo profile", func(rel string) bool { return rel == "target/release" || rel == "target/debug" }},
	{"build output name", func(rel string) bool { return outputNames[path.Base(rel)] }},
}

func isCandidate(rel string) (matched string, ok bool) {
	for _, r := range candidateRules {
		if r.Match(rel) {
			return r.Name, true
		}
	}
	return "", false
}

// Discover walks the top two levels of the project fsys (rooted at the
// project) for candidate artifact folders and counts, by header only, what
// each holds. It reads directory names and the first HeaderBytes of the
// files inside a candidate folder, never more, never a file outside one, and
// never follows a symbolic link. A default-list folder that exists is
// always reported; any other candidate only when it holds an artifact. The
// result is sorted by Dir.
func Discover(fsys fs.FS) ([]Folder, error) {
	var out []Folder
	top, err := readDirs(fsys, ".")
	if err != nil {
		return nil, err
	}
	visit := func(rel string) {
		if len(out) >= MaxCandidates {
			return
		}
		name, ok := isCandidate(rel)
		if !ok {
			return
		}
		f := lookInside(fsys, rel)
		f.Default = name == "default list"
		if f.Default || f.Total() > 0 {
			out = append(out, f)
		}
	}
	for _, d1 := range top {
		visit(d1)
		if skipDirs[path.Base(d1)] {
			continue
		}
		second, err := readDirs(fsys, d1)
		if err != nil {
			continue
		}
		for _, d2 := range second {
			if !skipDirs[path.Base(d2)] {
				visit(d2)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dir < out[j].Dir })
	return out, nil
}

// readDirs returns the real (not symbolic-link) subdirectory paths of dir,
// sorted, at most MaxDirEntries entries read.
func readDirs(fsys fs.FS, dir string) ([]string, error) {
	ents, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	if len(ents) > MaxDirEntries {
		ents = ents[:MaxDirEntries]
	}
	var out []string
	for _, e := range ents {
		if !e.IsDir() || e.Type()&fs.ModeSymlink != 0 {
			continue
		}
		p := e.Name()
		if dir != "." {
			p = path.Join(dir, e.Name())
		}
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

// Inspect counts, by header only, what one named folder of the project holds
// (a folder the developer turned on that no rule discovered). Its Dir is rel
// as given; Default is set when rel is on the default list.
func Inspect(fsys fs.FS, rel string) Folder {
	f := lookInside(fsys, rel)
	name, ok := isCandidate(rel)
	f.Default = ok && name == "default list"
	return f
}

// lookInside counts the artifacts under one candidate folder.
func lookInside(fsys fs.FS, rel string) Folder {
	f := Folder{Dir: rel, Counts: map[string]int{}}
	files := 0
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		ents, err := fs.ReadDir(fsys, dir)
		if err != nil {
			f.Skipped++
			return
		}
		if len(ents) > MaxDirEntries {
			ents = ents[:MaxDirEntries]
			f.Truncated = true
		}
		for _, e := range ents {
			p := path.Join(dir, e.Name())
			switch {
			case e.Type()&fs.ModeSymlink != 0:
				// Refused: a link could lead out of the project.
				f.Skipped++
			case e.IsDir():
				if depth < MaxFolderDepth && !skipDirs[e.Name()] {
					walk(p, depth+1)
				}
			case e.Type().IsRegular():
				if files >= MaxFilesPerFolder {
					f.Truncated = true
					continue
				}
				files++
				info, err := e.Info()
				if err != nil || info.Size() < int64(HeaderBytes) {
					continue
				}
				kind, ok := sniff(fsys, p, e.Name())
				if !ok {
					if kind == "unreadable" {
						f.Skipped++
					}
					continue
				}
				f.Counts[kind]++
				f.Bytes += info.Size()
			}
		}
	}
	walk(rel, 1)
	return f
}

// archiveExts are the file name extensions of the archives counted, with
// their kind: the name only picks which files get the header check, the
// header decides.
var archiveExts = map[string]string{
	".jar": KindJAR, ".war": KindJAR, ".ear": KindJAR,
	".whl": KindWheel, ".egg": KindWheel,
}

// zipMagic starts every zip archive (a JAR, a wheel, an egg).
const zipMagic = "PK\x03\x04"

// sniff reads the first HeaderBytes of a regular file and names its kind:
// an executable by its format header (depscan.ExecutableFormat, never by
// name or mode bits), a JAR or a wheel by a zip header under an archive
// extension. kind "unreadable" with ok false means the open failed.
func sniff(fsys fs.FS, p, name string) (kind string, ok bool) {
	file, err := fsys.Open(p)
	if err != nil {
		return "unreadable", false
	}
	defer func() { _ = file.Close() }()
	head := make([]byte, HeaderBytes)
	n, _ := io.ReadFull(file, head)
	head = head[:n]
	if fm := depscan.ExecutableFormat(head); fm != "" {
		switch fm {
		case "elf":
			return KindELF, true
		case "pe":
			return KindPE, true
		case "macho", "macho-universal":
			return KindMachO, true
		case "wasm":
			return KindWasm, true
		}
	}
	if k, has := archiveExts[strings.ToLower(path.Ext(name))]; has && strings.HasPrefix(string(head), zipMagic) {
		return k, true
	}
	return "", false
}
