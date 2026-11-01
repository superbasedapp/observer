package sandbox

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// guestmounts.go is the in-guest mount check of the VM-class rows (one
// owner, lane SBX-P4; generalised from the Apple container row's
// sandboxapple/guestcheck.go, which is now a thin wrapper): before the
// agent starts, the guest's init reads its own mount table
// (/proc/self/mountinfo, passed in as bytes) and refuses the run unless
// every planned mount is a mount point and every planned read-only path a
// read-only one, judged on the topmost entry and not covered by a later
// mount on an ancestor; then the functional witness asks the kernel
// whether each read-only path may be written, which must answer EROFS (a
// virtio-fs share's read-only paths answer it from the host's own
// read-only bind, through virtiofsd). The guest's report can only lower
// what the host believes about a run, never raise it.

// MountEntry is one line of a mountinfo table: the mount point and whether
// its per-mount options make it read-only.
type MountEntry struct {
	Point    string
	ReadOnly bool
}

// maxGuestMountInfo caps the table read.
const maxGuestMountInfo = 4 << 20

// ParseGuestMountInfo reads /proc/self/mountinfo (proc(5)): per line,
// field 5 is the mount point (octal-escaped) and field 6 the per-mount
// options. The entries keep the table's order, which is mount order. A line
// it cannot read is an error, never skipped.
func ParseGuestMountInfo(b []byte) ([]MountEntry, error) {
	if len(b) > maxGuestMountInfo {
		return nil, fmt.Errorf("%d bytes is over the cap", len(b))
	}
	var out []MountEntry
	for i, line := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		f := strings.Fields(string(line))
		if len(f) < 7 || !strings.HasPrefix(f[4], "/") {
			return nil, fmt.Errorf("line %d is not a mountinfo line", i+1)
		}
		pt, err := unescapeMountPath(f[4])
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		ro := false
		for _, o := range strings.Split(f[5], ",") {
			ro = ro || o == "ro"
		}
		out = append(out, MountEntry{Point: pt, ReadOnly: ro})
	}
	return out, nil
}

// unescapeMountPath undoes the kernel's octal escapes (\040 space, \011
// tab, \012 newline, \134 backslash).
func unescapeMountPath(s string) (string, error) {
	if !strings.Contains(s, `\`) {
		return s, nil
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			sb.WriteByte(s[i])
			continue
		}
		if i+4 > len(s) {
			return "", fmt.Errorf("a truncated escape in %q", s)
		}
		n, err := strconv.ParseUint(s[i+1:i+4], 8, 8)
		if err != nil {
			return "", fmt.Errorf("a bad escape in %q", s)
		}
		sb.WriteByte(byte(n))
		i += 3
	}
	return sb.String(), nil
}

// GuestMountShortfalls judges the guest's own mount table against the
// plan and returns every shortfall, sorted (none: the table matches).
func GuestMountShortfalls(table []MountEntry, mounts, ro []string) []string {
	top := map[string]int{}
	for i, e := range table {
		top[e.Point] = i
	}
	var bad []string
	judge := func(p string, wantRO bool) {
		i, ok := top[p]
		if !ok {
			bad = append(bad, p+" is not mounted in the box")
			return
		}
		for j := i + 1; j < len(table); j++ {
			if q := table[j].Point; q != p && (q == "/" || strings.HasPrefix(p, strings.TrimSuffix(q, "/")+"/")) {
				bad = append(bad, p+" is covered by a later mount on "+q)
				return
			}
		}
		if wantRO && !table[i].ReadOnly {
			bad = append(bad, p+" is writable in the box, the plan made it read-only")
		}
	}
	for _, p := range mounts {
		judge(p, false)
	}
	for _, p := range ro {
		judge(p, true)
	}
	sort.Strings(bad)
	return bad
}

// ReadOnlyWitness is the functional witness: access(p, W_OK) through the
// injected call must answer EROFS for every read-only path. It returns
// every path that does not, sorted.
func ReadOnlyWitness(ro []string, access func(string) error) []string {
	var bad []string
	for _, p := range ro {
		if err := access(p); !errors.Is(err, syscall.EROFS) {
			bad = append(bad, fmt.Sprintf("%s is writable in the box (access: %v)", p, err))
		}
	}
	sort.Strings(bad)
	return bad
}

// ShareReadOnlyWitness is the write witness for read-only paths that lie
// inside a shared filesystem and are read-only only on the host side (a
// read-only bind in the host's confined virtiofsd, read back there): no
// guest mount point marks them, and access(W_OK) through virtio-fs answers
// 0 although a write is refused (the microVM row's first live run, D4), so
// probe makes a real write attempt that changes nothing when it is refused
// and must answer EROFS for every path. It returns every path that does
// not, sorted; a nil answer (the write was accepted) names it writable.
func ShareReadOnlyWitness(paths []string, probe func(string) error) []string {
	var bad []string
	for _, p := range paths {
		switch err := probe(p); {
		case errors.Is(err, syscall.EROFS):
		case err == nil:
			bad = append(bad, p+" is writable in the box through its share (a write was accepted)")
		default:
			bad = append(bad, fmt.Sprintf("%s did not prove read-only through its share (write witness: %v)", p, err))
		}
	}
	sort.Strings(bad)
	return bad
}

// GuestCheckShared is GuestCheck plus the share witness: shared are the
// host-enforced read-only paths inside the guest's shares, judged by
// ShareReadOnlyWitness through probe instead of the mount table.
func GuestCheckShared(mountInfo []byte, mounts, ro, shared []string, access, probe func(string) error) string {
	if why := GuestCheck(mountInfo, mounts, ro, access); why != "" {
		return why
	}
	if bad := ShareReadOnlyWitness(shared, probe); len(bad) > 0 {
		return "the box read its shares back weaker than planned: " + strings.Join(bad, "; ")
	}
	return ""
}

// GuestCheck runs the whole in-guest check: the mount table judge, then
// the witness. It returns the refusal's reason ("" passes).
func GuestCheck(mountInfo []byte, mounts, ro []string, access func(string) error) string {
	table, err := ParseGuestMountInfo(mountInfo)
	if err != nil {
		return "the box could not read its own mount table: " + err.Error()
	}
	if bad := GuestMountShortfalls(table, mounts, ro); len(bad) > 0 {
		return "the box read its own mounts back weaker than planned: " + strings.Join(bad, "; ")
	}
	if bad := ReadOnlyWitness(ro, access); len(bad) > 0 {
		return "the box read its own mounts back weaker than planned: " + strings.Join(bad, "; ")
	}
	return ""
}
