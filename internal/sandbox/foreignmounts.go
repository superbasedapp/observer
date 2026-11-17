package sandbox

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
)

// foreignmounts.go finds the foreign-OS drives a Linux host has mounted, from
// the host's own mount table, so every box can blind them (the A1 mask,
// BuildPlan step 3). It is pure: the table text is passed in, nothing is
// read here.
//
// Why the mount table and not the foreign AI-tool homes. The first A1 mask
// set came from the foreign homes crossmount detects, taking the /mnt/<drive>
// prefix of each. A drive with no foreign AI-tool home on it (a data drive
// such as D:, or C: when HOME is a scratch home, where crossmount detects
// nothing at all) was never masked, and `--ro-bind / /` left the whole
// Windows drive readable inside the box (live confinement check 2026-11-15,
// ledger SBX-BE-24). The mount table names every Windows drive wherever it is
// mounted, including an automount root other than /mnt, so the mask set is
// built from it; the foreign homes stay as a second source (BuildMaskRoots).

// Mount is one parsed entry of a Linux mount table (/proc/self/mountinfo or
// /proc/mounts).
type Mount struct {
	// Point is where the filesystem is mounted, octal escapes decoded.
	Point string
	// FSType is the kernel's filesystem type name ("9p", "drvfs", "ext4").
	FSType string
	// Source is the device, tag or share the kernel reports, escapes decoded
	// (a WSL Windows drive reports "C:\\").
	Source string
	// Options are the mount options and the filesystem's own options,
	// comma-joined, as the table prints them.
	Options string
}

// foreignDriveRule is one row of how a mount is recognised as a foreign-OS
// drive: the first matching row names the mount. The table is data, one test
// row per entry (foreignmounts_test.go).
type foreignDriveRule struct {
	// ID names the row in errors and tests.
	ID string
	// Match reports whether the mount is a foreign-OS drive by this row.
	Match func(Mount) bool
}

// foreignDriveRules are the Windows-drive spellings of a mount, in the order
// they are tried. Grounded means seen on a live host; the others are
// defensive spellings of the same fact.
//
//   - drvfs-fstype: the filesystem type is "drvfs", the name WSL gives its
//     Windows-drive filesystem (WSL1 reports it as the type). NOT seen in
//     the mount tables of the WSL2 host of 2026-11-15, which report 9p; kept
//     because it is the filesystem's own name.
//   - 9p-aname-drvfs: a 9p mount whose aname option is "drvfs" (GROUNDED,
//     WSL2 kernel 6.18.58.1-microsoft-standard-WSL2, WSL 3.0.5.0, 2026-11-15:
//     "9p C:\\134 rw,aname=drvfs;path=C:\\;uid=1000;...").
//   - windows-drive-source: a 9p or virtiofs mount whose source is a Windows
//     drive or UNC path ("C:\\", "\\\\server\\share"). NOT grounded: no host
//     was seen to mount a Windows drive over virtiofs, though the kernel on
//     that host lists the filesystem; it keeps a future WSL transport from
//     reopening the hole.
//
// Deliberately NOT a row: 9p with aname=drivers at /usr/lib/wsl/drivers. It
// is a Windows-side mount (Windows' driver store), not a user drive, and
// WSL's GPU stack reads its driver from it, so hiding it would be expected
// to break GPU compute in the box (not tested); it is named in
// docs/sandboxed-terminals.md and ledger SBX-BE-24.
var foreignDriveRules = []foreignDriveRule{
	{"drvfs-fstype", func(m Mount) bool { return m.FSType == "drvfs" }},
	{"9p-aname-drvfs", func(m Mount) bool { return m.FSType == "9p" && optionValue(m.Options, "aname") == "drvfs" }},
	{"windows-drive-source", func(m Mount) bool {
		return (m.FSType == "9p" || m.FSType == "virtiofs") && looksLikeWindowsSource(m.Source)
	}},
}

// ForeignDrive reports which rule recognises the mount as a foreign-OS
// drive, and false when none does.
func (m Mount) ForeignDrive() (rule string, ok bool) {
	for _, r := range foreignDriveRules {
		if r.Match(m) {
			return r.ID, true
		}
	}
	return "", false
}

// optionValue returns the value of the named option in a comma-joined option
// list: the text after "name=" up to the next ';' (the 9p option string packs
// its own sub-options with ';', as in "aname=drvfs;path=C:\\;uid=1000").
// It returns "" when the option is absent or has no value.
func optionValue(options, name string) string {
	prefix := name + "="
	for _, tok := range strings.Split(options, ",") {
		if !strings.HasPrefix(tok, prefix) {
			continue
		}
		v := tok[len(prefix):]
		if i := strings.IndexByte(v, ';'); i >= 0 {
			v = v[:i]
		}
		return v
	}
	return ""
}

// looksLikeWindowsSource reports a mount source spelled as a Windows drive
// ("C:" or "C:\\...") or a UNC share ("\\\\server\\share").
func looksLikeWindowsSource(s string) bool {
	if strings.HasPrefix(s, `\\`) {
		return true
	}
	if len(s) >= 2 && s[1] == ':' && (s[0] >= 'A' && s[0] <= 'Z' || s[0] >= 'a' && s[0] <= 'z') {
		return len(s) == 2 || s[2] == '\\' || s[2] == '/'
	}
	return false
}

// ParseMountTable parses the text of /proc/self/mountinfo or /proc/mounts
// into mounts. A non-blank line it cannot read as a mount entry is returned
// in unparsed, whole, so the caller decides whether that is fatal (see
// ForeignDriveRoots: a line that names drvfs is).
//
// mountinfo lines are "id parent major:minor root point options [optional
// fields] - fstype source super-options"; mounts lines are "source point
// fstype options dump pass". The two are told apart by the " - " separator
// field, which only mountinfo has.
func ParseMountTable(table []byte) (mounts []Mount, unparsed []string) {
	for _, line := range strings.Split(string(table), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if m, ok := parseMountLine(line); ok {
			mounts = append(mounts, m)
		} else {
			unparsed = append(unparsed, line)
		}
	}
	return mounts, unparsed
}

// parseMountLine reads one mount-table line of either format.
func parseMountLine(line string) (Mount, bool) {
	f := strings.Fields(line)
	sep := -1
	for i := 6; i < len(f); i++ {
		if f[i] == "-" {
			sep = i
			break
		}
	}
	var m Mount
	switch {
	case sep >= 0:
		// mountinfo: fstype and source must follow the separator.
		if sep+2 >= len(f) {
			return Mount{}, false
		}
		m = Mount{Point: unescapeMountField(f[4]), FSType: f[sep+1], Source: unescapeMountField(f[sep+2]), Options: f[5]}
		if sep+3 < len(f) {
			m.Options += "," + f[sep+3]
		}
	case len(f) >= 4 && len(f) <= 6:
		// /proc/mounts.
		m = Mount{Point: unescapeMountField(f[1]), FSType: f[2], Source: unescapeMountField(f[0]), Options: f[3]}
	default:
		return Mount{}, false
	}
	if !path.IsAbs(m.Point) || m.FSType == "" {
		return Mount{}, false
	}
	return m, true
}

// unescapeMountField decodes the kernel's octal escapes in a mount point or
// source: a space is "\040", a tab "\011", a newline "\012" and a backslash
// "\134". A backslash not followed by three octal digits is kept literally.
func unescapeMountField(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && isOctal(s[i+1]) && isOctal(s[i+2]) && isOctal(s[i+3]) {
			v := int(s[i+1]-'0')<<6 | int(s[i+2]-'0')<<3 | int(s[i+3]-'0')
			b.WriteByte(byte(v & 0xff))
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// isOctal reports an octal digit.
func isOctal(c byte) bool { return c >= '0' && c <= '7' }

// ForeignDriveRoots returns the mount points to mask for a host whose mount
// table is table: every foreign-OS drive mount (foreignDriveRules), united
// with the extra roots the caller derived another way (the foreign AI-tool
// homes), de-duplicated, a root inside another dropped, and sorted so the
// argv is deterministic.
//
// It fails closed rather than return a short list:
//
//   - a table with no readable mount in it (an empty or garbled read) is an
//     error, because nothing can be said about what is mounted;
//   - a line it cannot parse that names drvfs is an error, because it may be
//     the Windows drive itself;
//   - a Windows drive mounted at "/" or at a path no bwrap argument can carry
//     (a control character, whitespace, a leading '-', a '..' segment) is an
//     error naming the mount, because it can be neither masked nor ignored.
//
// Any other unparseable line is skipped: it carries no recognisable Windows
// drive spelling.
func ForeignDriveRoots(table []byte, extra []string) ([]string, error) {
	mounts, unparsed := ParseMountTable(table)
	if len(mounts) == 0 {
		return nil, errors.New("sandbox.ForeignDriveRoots: the mount table lists no mount, so the foreign-OS drives cannot be found")
	}
	for _, l := range unparsed {
		if strings.Contains(strings.ToLower(l), "drvfs") {
			return nil, fmt.Errorf("sandbox.ForeignDriveRoots: a mount-table line names drvfs but cannot be read, so the Windows drive it may mount cannot be masked: %q", clip(l, 160))
		}
	}
	var roots []string
	for _, m := range mounts {
		rule, ok := m.ForeignDrive()
		if !ok {
			continue
		}
		p := path.Clean(m.Point)
		if err := maskableMountPoint(p); err != nil {
			return nil, fmt.Errorf("sandbox.ForeignDriveRoots: the foreign-OS drive mounted at %q (%s) cannot be masked: %w", m.Point, rule, err)
		}
		roots = append(roots, p)
	}
	return BuildMaskRoots(roots, extra), nil
}

// maskableMountPoint reports why a cleaned mount point cannot be handed to
// bwrap as a --tmpfs destination: the same rules BuildPlan applies to a mask
// path (validateAbs), kept here with POSIX path rules so the check does not
// depend on the host this code is built for.
func maskableMountPoint(p string) error {
	switch {
	case p == "/":
		return errors.New("the root cannot be masked")
	case strings.HasPrefix(p, "-"):
		return fmt.Errorf("%q must not begin with '-'", p)
	case badCharIndex(p) >= 0:
		return fmt.Errorf("%q contains a NUL, whitespace, or control character", p)
	case hasDotDot(p):
		return fmt.Errorf("%q must not contain a '..' segment", p)
	case !path.IsAbs(p):
		return fmt.Errorf("%q must be absolute", p)
	}
	return nil
}

// BuildMaskRoots unites lists of mask roots into the argv-ready set: each
// cleaned, relative and empty entries dropped, de-duplicated, an entry that
// lies inside another dropped (a tmpfs on the parent already hides it), and
// sorted. It is the one place the foreign-OS mask set takes its order.
func BuildMaskRoots(lists ...[]string) []string {
	seen := map[string]bool{}
	var all []string
	for _, l := range lists {
		for _, p := range l {
			p = strings.TrimSpace(p)
			if p == "" || !path.IsAbs(p) {
				continue
			}
			p = path.Clean(p)
			if p == "/" || seen[p] {
				continue // a mask of the root would blind the whole box
			}
			seen[p] = true
			all = append(all, p)
		}
	}
	sort.Strings(all)
	var out []string
	for _, p := range all {
		inside := false
		for _, q := range out {
			if p == q || strings.HasPrefix(p, q+"/") {
				inside = true
				break
			}
		}
		if !inside {
			out = append(out, p)
		}
	}
	return out
}

// clip shortens s to at most n bytes for an error message.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
