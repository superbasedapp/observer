package update

import (
	"fmt"
	"path"
	"strings"
)

// Method is how the running binary got onto this machine. It decides
// whether the node may replace itself at all (§3.7 install-method
// table, ruling R6).
type Method string

const (
	// MethodBinary is a standalone binary this uid can replace — the
	// only self-applying method.
	MethodBinary Method = "binary"
	// MethodBinaryReadOnly is a standalone binary this uid may NOT
	// replace (a root-owned /usr/local/bin install run as a user).
	MethodBinaryReadOnly Method = "binary_readonly"
	// MethodNPM is an npm-owned install (@superbased/observer plus a
	// platform package).
	MethodNPM Method = "npm"
	// MethodPip is a PyPI/venv-owned install (superbased-observer).
	MethodPip Method = "pip"
	// MethodVSCode is the copy the VS Code extension manages.
	MethodVSCode Method = "vscode"
	// MethodBrew is a Homebrew/Linuxbrew Cellar install.
	MethodBrew Method = "brew"
	// MethodAPT is a dpkg-owned install.
	MethodAPT Method = "apt"
	// MethodRPM is an rpm-owned install.
	MethodRPM Method = "rpm"
	// MethodUnknown is the honest zero value: nothing was resolvable
	// (no executable path). It never self-applies.
	MethodUnknown Method = "unknown"
)

// PathProbe is the FS-shaped question the install-method table needs,
// injected rather than performed. Production passes real os.Stat /
// dpkg -S implementations from cmd/observer; tests pass a fake path
// resolver, which is the whole reason this package can decide install
// method without importing os/exec (imports_test.go pins that out).
type PathProbe struct {
	// ExecPath is os.Executable() with symlinks resolved by the caller.
	ExecPath string
	// GOOS is the running platform, so a test can exercise the Windows
	// rows on Linux.
	GOOS string
	// Writable reports whether BOTH the executable and its directory
	// are writable by this uid — the swap needs to rename a file into
	// that directory, so directory write permission is the real test,
	// not the file's mode.
	Writable bool
	// SiblingExists answers "does <dir>/<name> exist", used only for
	// the virtualenv marker. Nil means "no" for every question.
	SiblingExists func(dir, name string) bool
	// PackageOwner answers "does a system package manager own this
	// path" (dpkg -S / rpm -qf). It returns the owning method and true,
	// or false when nothing owns it. Nil means "nothing owns it", which
	// is the correct answer on a machine with neither tool.
	PackageOwner func(execPath string) (Method, bool)
}

// Detection is the install-method verdict for one node.
type Detection struct {
	// Method is the winning row's method.
	Method Method
	// SelfApply reports whether the node may replace its own binary.
	SelfApply bool
	// Rule names the table row that matched, so `observer update
	// status` can explain the verdict instead of asserting it.
	Rule string
	// Advice is what the surfaces tell the operator to run instead when
	// SelfApply is false. Empty when the node self-applies.
	Advice string
}

// installRule is one row of the §3.7 table. Rows are evaluated
// top-down and the first match wins; the ordering is the specification
// (an npm platform package also lives under a writable directory, so
// "npm" must be tested before "binary").
type installRule struct {
	name    string
	method  Method
	self    bool
	advice  string
	matches func(p PathProbe, lower string) bool
}

// installRules is the §3.7 install-method table, in order. It is DATA
// walked top-down (CLAUDE.md #5), one test case per row, so adding a
// packaging channel is a row and not a new branch in a ladder.
//
// `lower` is the executable path lowercased and slash-normalized, which
// is what every path rule matches against: case-insensitive matching is
// required on Windows and macOS and is harmless on Linux (no legitimate
// install differs from these markers only by case).
var installRules = []installRule{
	{
		name:   "npm-package-path",
		method: MethodNPM,
		advice: "npm i -g @superbased/observer@<version>",
		matches: func(_ PathProbe, lower string) bool {
			return strings.Contains(lower, "node_modules/@superbased/observer")
		},
	},
	{
		name:   "npm-node-modules-bin",
		method: MethodNPM,
		advice: "npm i -g @superbased/observer@<version>",
		matches: func(_ PathProbe, lower string) bool {
			return strings.Contains(lower, "/node_modules/.bin/") ||
				strings.Contains(lower, "/node_modules/observer")
		},
	},
	{
		name:   "vscode-extension",
		method: MethodVSCode,
		advice: "update the SuperBased Observer extension in VS Code",
		matches: func(_ PathProbe, lower string) bool {
			return strings.Contains(lower, "superbased.superbased-observer") ||
				strings.Contains(lower, "globalstorage/superbased") ||
				(strings.Contains(lower, ".vscode") && strings.Contains(lower, "/extensions/superbased"))
		},
	},
	{
		name:   "python-site-packages",
		method: MethodPip,
		advice: "pip install -U superbased-observer",
		matches: func(_ PathProbe, lower string) bool {
			return strings.Contains(lower, "/site-packages/") ||
				strings.Contains(lower, "/dist-packages/")
		},
	},
	{
		name:   "python-venv-bin",
		method: MethodPip,
		advice: "pip install -U superbased-observer",
		matches: func(p PathProbe, lower string) bool {
			dir := path.Dir(lower)
			base := path.Base(dir)
			if base != "bin" && base != "scripts" {
				return false
			}
			// A venv is identified by its own marker file, never by the
			// mere presence of a bin/ directory — /usr/local/bin would
			// otherwise read as a virtualenv.
			return p.sibling(path.Dir(dir), "pyvenv.cfg") || p.sibling(dir, "activate")
		},
	},
	{
		name:   "homebrew-cellar",
		method: MethodBrew,
		advice: "brew upgrade superbased-observer",
		matches: func(_ PathProbe, lower string) bool {
			return strings.Contains(lower, "/cellar/") ||
				strings.Contains(lower, "/opt/homebrew/") ||
				strings.Contains(lower, "/home/linuxbrew/")
		},
	},
	{
		name:   "system-package-owned",
		method: MethodAPT, // replaced by the probe's answer
		advice: "use the system package manager to upgrade this package",
		matches: func(p PathProbe, _ string) bool {
			if p.PackageOwner == nil {
				return false
			}
			_, owned := p.PackageOwner(p.ExecPath)
			return owned
		},
	},
}

// sibling is the nil-safe form of the SiblingExists seam.
func (p PathProbe) sibling(dir, name string) bool {
	if p.SiblingExists == nil {
		return false
	}
	return p.SiblingExists(dir, name)
}

// Detect walks the install-method table top-down and returns the first
// matching row's verdict, falling through to the two standalone-binary
// rows.
//
// A non-self-applying method is NOT a failure: the node reports
// state=blocked with the method, the org board shows it, and the admin
// learns which slice of the fleet needs MDM or npm instead (§3.7,
// ruling R6). That is the honest-disabled-copy discipline — never a
// silent "up to date".
func Detect(p PathProbe) Detection {
	if strings.TrimSpace(p.ExecPath) == "" {
		return Detection{
			Method: MethodUnknown, SelfApply: false, Rule: "no-executable-path",
			Advice: "the running executable could not be located; update this node manually",
		}
	}
	lower := strings.ToLower(toSlash(p.ExecPath))
	for _, r := range installRules {
		if !r.matches(p, lower) {
			continue
		}
		method := r.method
		if r.name == "system-package-owned" {
			if owner, ok := p.PackageOwner(p.ExecPath); ok {
				method = owner
			}
		}
		return Detection{Method: method, SelfApply: r.self, Rule: r.name, Advice: r.advice}
	}
	if p.Writable {
		return Detection{Method: MethodBinary, SelfApply: true, Rule: "standalone-writable"}
	}
	return Detection{
		Method: MethodBinaryReadOnly, SelfApply: false, Rule: "standalone-readonly",
		Advice: fmt.Sprintf("the binary at %s is not writable by this user", p.ExecPath),
	}
}

// selfUpdatableMethods is the METHOD-only half of the install-method table:
// which methods could ever replace their own binary, judged from the method
// name alone rather than from a live PathProbe.
//
// [Detect] is the authority ON THE NODE, where the filesystem is present.
// This table exists for the ORG SERVER, which holds only the reported method
// string and must still answer "how many of these nodes would a `refuse` skew
// policy strand with no automatic remediation" (§6 O5). Keeping it a table
// beside the rules above — rather than a second opinion buried in a handler —
// is what stops the two answers from drifting.
//
// Only MethodBinary is self-updatable. binary_readonly is deliberately NOT:
// the binary exists but this uid cannot replace it, which is exactly the
// stranding case an admin needs counted.
var selfUpdatableMethods = map[Method]bool{
	MethodBinary:         true,
	MethodBinaryReadOnly: false,
	MethodNPM:            false,
	MethodPip:            false,
	MethodVSCode:         false,
	MethodBrew:           false,
	MethodAPT:            false,
	MethodRPM:            false,
	MethodUnknown:        false,
}

// MethodSelfUpdatable reports whether a node reporting this install method
// could apply an update on its own.
//
// An UNRECOGNISED method answers false: "we do not know that this node can fix
// itself" is the honest reading, and it is also the safe one — it counts the
// node into the stranding warning rather than out of it.
func MethodSelfUpdatable(m Method) bool { return selfUpdatableMethods[m] }

// KnownMethod reports whether m is a method this agent publishes.
func KnownMethod(m Method) bool {
	_, ok := selfUpdatableMethods[m]
	return ok
}

// AdviceFor renders a detection's advice for a concrete target version,
// substituting the "<version>" placeholder the table carries. It is the
// one place the placeholder is expanded, so no surface prints a command
// with a literal "<version>" in it.
func AdviceFor(d Detection, targetVersion string) string {
	if d.Advice == "" {
		return ""
	}
	if targetVersion == "" {
		return d.Advice
	}
	return strings.ReplaceAll(d.Advice, "<version>", strings.TrimPrefix(targetVersion, "v"))
}
