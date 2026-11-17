package secassess

import "strings"

// The self-check line of a task names a command the agent runs to check its own
// result file. A bare `observer` resolves only when the folder of the daemon's
// binary is on the PATH the agent's shell has, and on a development build or a
// copy that was never put on the PATH it is not: the first live runs (2026-11-16)
// both answered "observer: command not found", and the retest agent then guessed
// the host path that the sandbox binds the binary at and ran that. So the task
// names the daemon's own binary by that path, and this file decides, in a table,
// when it may.

// MaxSelfCheckBinBytes bounds the path the self-check line spells (the line sits
// in a task that has a byte budget: TestPromptBudget builds it at this length).
// A longer path is not spelled; the line names the bare command.
const MaxSelfCheckBinBytes = 128

// selfCheckBare is the command name the line falls back to.
const selfCheckBare = "observer"

// BinaryFacts is what the caller knows about the daemon's own binary and the
// place the agent runs, as plain data (the pure package reads no file).
type BinaryFacts struct {
	// Path is the daemon's executable path as the operating system reports it,
	// "" when the caller could not read it or the file is not there.
	Path string
	// Backend is the sandbox backend the run is confined by ("" none, or not
	// decided: the agent then runs on the host).
	Backend string
}

// hostBinaryBackends is the grounded table of sandbox backends that put the
// daemon's own binary inside the box at the SAME path it has on the host, so a
// path the daemon reports resolves there. A backend is listed only with the
// place that grounds it. A backend that is not listed (a container or a virtual
// machine with its own copy of the binary at another path) makes the task name
// the bare command, as it always did.
var hostBinaryBackends = []struct {
	ID     string
	Ground string
}{
	{ID: "bwrap", Ground: "internal/sandbox/plan.go roBinaryArgs binds Request.ObserverBin (the daemon's os.Executable) read-only at its own path; live: the retest agent of 2026-11-16 ran the host path inside the box"},
}

// bindsHostBinary says whether a sandbox backend holds the daemon's binary at
// its host path.
func bindsHostBinary(backend string) bool {
	for _, b := range hostBinaryBackends {
		if b.ID == backend {
			return true
		}
	}
	return false
}

// selfCheckBinRows are the reasons the line names the bare command instead of
// the path, in the order they are asked; the first that holds wins. One test
// case per row (TestSelfCheckBinaryRows).
var selfCheckBinRows = []struct {
	ID      string
	Refuses func(BinaryFacts) bool
}{
	// B1: the daemon could not read its own path, or the file is not there.
	{"B1", func(f BinaryFacts) bool { return f.Path == "" }},
	// B2: the binary was replaced or removed while the daemon ran; the system
	// then reports the path with " (deleted)" after it, and a box binds nothing.
	{"B2", func(f BinaryFacts) bool { return strings.HasSuffix(f.Path, " (deleted)") }},
	// B3: not a path the line can spell without quoting: absolute with forward
	// slashes, plain characters, within the byte bound.
	{"B3", func(f BinaryFacts) bool { return !plainBinaryPath(f.Path) }},
	// B4: the file is not named observer, so the guard would not read the line
	// as Observer's own command (it reads the file name, as it does for the
	// bare spelling).
	{"B4", func(f BinaryFacts) bool { return f.Path[strings.LastIndexByte(f.Path, '/')+1:] != selfCheckBare }},
	// B5: the run is in a sandbox that does not hold the binary at that path.
	{"B5", func(f BinaryFacts) bool { return f.Backend != "" && !bindsHostBinary(f.Backend) }},
}

// SelfCheckBinary is the command word the self-check line starts with: the
// daemon's own path when every row lets it, else the bare command. The second
// result is the id of the row that refused ("" when the path is used), for the
// caller's log and the tests.
func SelfCheckBinary(f BinaryFacts) (string, string) {
	for _, r := range selfCheckBinRows {
		if r.Refuses(f) {
			return selfCheckBare, r.ID
		}
	}
	return f.Path, ""
}

// plainBinaryPath reports whether p is an absolute POSIX path of at most
// MaxSelfCheckBinBytes bytes made only of letters, digits and . _ - + @ % : = ,
// with no empty, "." or ".." folder: a word a shell reads as itself.
func plainBinaryPath(p string) bool {
	if len(p) < 2 || len(p) > MaxSelfCheckBinBytes || p[0] != '/' || strings.HasSuffix(p, "/") {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("/._-+@%:=,", c) >= 0:
		default:
			return false
		}
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}
