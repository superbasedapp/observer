package toolinstall

import (
	"bufio"
	"strings"
)

// prereq.go is the PREREQUISITE table behind a guided install: before the
// dashboard runs a vendor installer it checks the host programs that installer
// is grounded to need (integration.InstallHint.Requires, e.g. kiro-cli's
// script exits with "Missing required dependencies: unzip"), and when one is
// absent it refuses up front with the package-manager command that fixes it,
// instead of letting the vendor script fail half-way in a terminal.
//
// Everything here is pure: the caller injects the program lookup and the
// /etc/os-release text. Observer never runs the fix itself (it would need
// sudo); it only names it.

// AltSep separates alternatives inside one Requires entry: "sha256sum|shasum"
// is satisfied by either program.
const AltSep = "|"

// MissingPrereqs returns the Requires entries none of whose alternatives
// resolves through has, in declaration order. A nil has reports nothing
// missing (a caller that cannot look programs up must not block an install on
// a guess).
func MissingPrereqs(requires []string, has func(program string) bool) []string {
	if has == nil {
		return nil
	}
	var missing []string
	for _, req := range requires {
		req = strings.TrimSpace(req)
		if req == "" {
			continue
		}
		ok := false
		for _, alt := range strings.Split(req, AltSep) {
			if alt = strings.TrimSpace(alt); alt != "" && has(alt) {
				ok = true
				break
			}
		}
		if !ok {
			missing = append(missing, req)
		}
	}
	return missing
}

// ParseOSRelease reads the KEY=value lines of an os-release(5) file. Quotes
// around a value are stripped; comments and malformed lines are ignored.
func ParseOSRelease(content string) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return out
}

// PackageManager is how prerequisite programs are installed on one host
// family. A zero PackageManager (Name == "") means the family is unknown and
// the remedy falls back to "your system package manager".
type PackageManager struct {
	// Name is the package manager key used by the package-name table.
	Name string
	// Install is the command prefix the package names are appended to.
	Install string
	// Family is the human label of the host family ("Debian/Ubuntu").
	Family string
}

// pmRule is one row of the host-family table: the first row whose ids match
// os-release ID or any ID_LIKE token wins.
type pmRule struct {
	ids []string
	pm  PackageManager
}

var linuxPackageManagers = []pmRule{
	{[]string{"debian", "ubuntu"}, PackageManager{Name: "apt", Install: "sudo apt-get install -y", Family: "Debian/Ubuntu"}},
	{[]string{"fedora", "rhel", "centos", "rocky", "almalinux", "amzn"}, PackageManager{Name: "dnf", Install: "sudo dnf install -y", Family: "Fedora/RHEL"}},
	{[]string{"alpine"}, PackageManager{Name: "apk", Install: "sudo apk add", Family: "Alpine"}},
	{[]string{"arch"}, PackageManager{Name: "pacman", Install: "sudo pacman -S --needed", Family: "Arch"}},
	{[]string{"opensuse", "suse", "sles"}, PackageManager{Name: "zypper", Install: "sudo zypper install -y", Family: "openSUSE/SLES"}},
}

// brewPackageManager is the macOS row PackageManagerFor answers.
var brewPackageManager = PackageManager{Name: "brew", Install: "brew install", Family: "macOS, Homebrew"}

// PackageManagerByName returns the package manager row for a channel name
// (apt, dnf, apk, pacman, zypper, brew); ok is false for any other name.
func PackageManagerByName(name string) (PackageManager, bool) {
	if name == brewPackageManager.Name {
		return brewPackageManager, true
	}
	for _, row := range linuxPackageManagers {
		if row.pm.Name == name {
			return row.pm, true
		}
	}
	return PackageManager{}, false
}

// InstallArgvFor builds the install argv for packages on pm's channel: the
// channel's program, its install verb and its non-interactive flags, then
// the packages, under sudo when the channel is Elevated (the OS package
// managers). It is the one builder the sandbox setup planner and its runner
// use, so the argv a setup terminal runs is the argv PlanUninstall reads
// back. ok is false when pm has no channel row with a program (an unknown
// family, the zero PackageManager), when packages is empty, when a package
// name is not a plain name (empty, starting with "-", or holding whitespace
// or a shell metacharacter), or when the channel takes one package and more
// are given.
func InstallArgvFor(pm PackageManager, packages []string) (channel string, argv []string, ok bool) {
	r, found := channelTable[pm.Name]
	if !found || r.Program == "" || len(packages) == 0 {
		return "", nil, false
	}
	if len(packages) > 1 && !r.MultiPackage {
		return "", nil, false
	}
	for _, p := range packages {
		if !plainPackageName(p) {
			return "", nil, false
		}
	}
	argv = make([]string, 0, 2+len(r.InstallVerb)+len(r.InstallFlags)+len(packages))
	if r.Elevated {
		argv = append(argv, sudoProgram)
	}
	argv = append(argv, r.Program)
	argv = append(argv, r.InstallVerb...)
	argv = append(argv, r.InstallFlags...)
	argv = append(argv, packages...)
	return pm.Name, argv, true
}

// plainPackageName reports whether p is a package name a builder may put on
// an argv: non-empty, not a flag, and free of whitespace and shell
// metacharacters (the argv is never run through a shell, but a name that
// needs quoting is not a package name any of the tables holds).
func plainPackageName(p string) bool {
	if p == "" || strings.HasPrefix(p, "-") {
		return false
	}
	return !strings.ContainsAny(p, " \t\r\n\"'`$;&|<>()*?![]{}\\")
}

// PackageManagerFor picks the package manager for a host. darwin is Homebrew;
// Linux is decided by os-release ID then ID_LIKE through the table above;
// anything else (Windows, an unknown distro) yields the zero value.
func PackageManagerFor(goos string, osRelease map[string]string) PackageManager {
	if goos == "darwin" {
		return brewPackageManager
	}
	if goos != "linux" {
		return PackageManager{}
	}
	tokens := []string{strings.ToLower(osRelease["ID"])}
	tokens = append(tokens, strings.Fields(strings.ToLower(osRelease["ID_LIKE"]))...)
	for _, tok := range tokens {
		if tok == "" {
			continue
		}
		for _, row := range linuxPackageManagers {
			for _, id := range row.ids {
				if tok == id {
					return row.pm
				}
			}
		}
	}
	return PackageManager{}
}

// packageNames maps a prerequisite PROGRAM to the package that provides it,
// per package manager, where the two differ. A program absent from this table
// is assumed to ship in a package of the same name (curl, unzip, tar, bzip2,
// git, xz on every family covered).
var packageNames = map[string]map[string]string{
	"sha256sum": {"apt": "coreutils", "dnf": "coreutils", "apk": "coreutils", "pacman": "coreutils", "zypper": "coreutils", "brew": "coreutils"},
	"shasum":    {"apt": "perl", "dnf": "perl-Digest-SHA", "apk": "perl-utils", "pacman": "perl", "zypper": "perl"},
	"xz":        {"apt": "xz-utils", "dnf": "xz", "apk": "xz", "pacman": "xz", "zypper": "xz"},
}

// PackageFor returns the package that provides a prerequisite entry under a
// package manager. For an alternatives entry the FIRST alternative is the one
// recommended.
func PackageFor(entry string, pm PackageManager) string {
	prog := strings.TrimSpace(strings.Split(entry, AltSep)[0])
	if byPM, ok := packageNames[prog]; ok {
		if pkg, ok := byPM[pm.Name]; ok {
			return pkg
		}
	}
	return prog
}

// DisplayPrereq renders one Requires entry for people: "sha256sum|shasum"
// becomes "sha256sum or shasum".
func DisplayPrereq(entry string) string {
	parts := strings.Split(entry, AltSep)
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return strings.Join(parts, " or ")
}

// PrereqRemedy is the one sentence the dashboard shows (and the install route
// refuses with) when a guided install's prerequisites are missing. It names
// the missing programs, the exact command for the detected host family, and
// the next step. Empty when nothing is missing.
func PrereqRemedy(missing []string, pm PackageManager) string {
	if len(missing) == 0 {
		return ""
	}
	names := make([]string, 0, len(missing))
	pkgs := make([]string, 0, len(missing))
	seen := map[string]bool{}
	for _, m := range missing {
		names = append(names, DisplayPrereq(m))
		if pkg := PackageFor(m, pm); !seen[pkg] {
			seen[pkg] = true
			pkgs = append(pkgs, pkg)
		}
	}
	verb, pron := "is", "it"
	if len(names) > 1 {
		verb, pron = "are", "them"
	}
	head := "The installer needs " + joinAnd(names) + ", which " + verb + " not installed on this machine. "
	if pm.Name == "" {
		return head + "Install " + joinAnd(pkgs) + " with your system package manager, then press Re-check."
	}
	return head + "Install " + pron + " with: " + pm.Install + " " + strings.Join(pkgs, " ") + " (" + pm.Family + "), then press Re-check."
}

// joinAnd joins items as "a", "a and b" or "a, b and c".
func joinAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	default:
		return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
	}
}
