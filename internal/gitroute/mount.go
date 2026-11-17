package gitroute

import (
	"path"
	"strings"
)

// Mount is one entry of the mount table, as much of it as the route needs.
type Mount struct {
	// Point is the mount point (octal escapes decoded).
	Point string
	// Root is the directory of the mounted filesystem that appears at Point
	// ("/" for a whole drive; a bind of a subdirectory names it).
	Root string
	// FSType is the filesystem type.
	FSType string
	// DrvFs marks a WSL mount of a Windows drive (fstype drvfs, or 9p with
	// aname=drvfs), Drive its upper-case letter. A DrvFs mount of a UNC
	// share has no drive letter and is not DrvFs here: Windows git would
	// need the UNC spelling, which the scan does not build.
	DrvFs bool
	Drive byte
}

// ParseMountinfo reads /proc/self/mountinfo bytes. A malformed line is
// skipped.
//
// The format (proc(5)): "id parent major:minor root point options
// [optional...] - fstype source superoptions", with space, tab, newline and
// backslash in a path written as \040, \011, \012 and \134.
func ParseMountinfo(b []byte) []Mount {
	var out []Mount
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		sep := -1
		for i, f := range fields {
			if f == "-" {
				sep = i
				break
			}
		}
		if sep < 6 || len(fields) < sep+3 {
			continue
		}
		m := Mount{
			Root:   unescapeMountinfo(fields[3]),
			Point:  unescapeMountinfo(fields[4]),
			FSType: fields[sep+1],
		}
		source := unescapeMountinfo(fields[sep+2])
		super := ""
		if len(fields) > sep+3 {
			super = unescapeMountinfo(fields[sep+3])
		}
		m.DrvFs, m.Drive = drvfsDrive(m.FSType, source, super)
		out = append(out, m)
	}
	return out
}

// drvfsDrive reports whether a mount is a DrvFs mount of a Windows drive,
// and the drive letter: from the path= super option when present
// ("path=C:\"), else from the source ("C:\" or "C:").
func drvfsDrive(fstype, source, super string) (bool, byte) {
	isDrvFs := fstype == "drvfs"
	drivePath := ""
	for _, opt := range strings.FieldsFunc(super, func(r rune) bool { return r == ',' || r == ';' }) {
		switch {
		case opt == "aname=drvfs":
			if fstype == "9p" {
				isDrvFs = true
			}
		case strings.HasPrefix(opt, "path="):
			drivePath = strings.TrimPrefix(opt, "path=")
		}
	}
	if !isDrvFs {
		return false, 0
	}
	if drivePath == "" {
		drivePath = source
	}
	if d, ok := driveLetter(drivePath); ok {
		return true, d
	}
	return false, 0
}

// driveLetter reads "C:", "C:\" or "C:/" (any case) as drive C.
func driveLetter(p string) (byte, bool) {
	if len(p) < 2 || p[1] != ':' {
		return 0, false
	}
	if len(p) > 2 && p[2] != '\\' && p[2] != '/' {
		return 0, false
	}
	c := p[0]
	switch {
	case c >= 'a' && c <= 'z':
		return c - 'a' + 'A', true
	case c >= 'A' && c <= 'Z':
		return c, true
	}
	return 0, false
}

// unescapeMountinfo decodes mountinfo's three-digit octal escapes.
func unescapeMountinfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && isOctal(s[i+1:]) {
			v := (s[i+1]-'0')*64 + (s[i+2]-'0')*8 + (s[i+3] - '0')
			b.WriteByte(v)
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// isOctal reports three leading octal digits.
func isOctal(s string) bool {
	if len(s) < 3 {
		return false
	}
	for i := 0; i < 3; i++ {
		if s[i] < '0' || s[i] > '7' {
			return false
		}
	}
	return true
}

// MountFor returns the mount that holds root: the one whose mount point is
// the longest path prefix of root. Only an absolute, slash-separated root
// is matched. ok is false when no mount point holds it.
func MountFor(mounts []Mount, root string) (Mount, bool) {
	if !strings.HasPrefix(root, "/") {
		return Mount{}, false
	}
	root = path.Clean(root)
	best, found := Mount{}, false
	for _, m := range mounts {
		if !underPoint(root, m.Point) {
			continue
		}
		// The longest point wins; at an equal point the later line (a
		// mount stacked on top of the earlier one) does.
		if !found || len(m.Point) >= len(best.Point) {
			best, found = m, true
		}
	}
	return best, found
}

// underPoint reports whether p is the mount point or inside it.
func underPoint(p, point string) bool {
	if point == "/" {
		return true
	}
	point = strings.TrimRight(point, "/")
	return p == point || strings.HasPrefix(p, point+"/")
}

// WindowsPath spells root, which lies on the DrvFs mount m, the way a
// Windows process names it: the drive letter, a colon and backslashes
// ("/mnt/d/x y/z" on D: is `D:\x y\z`). ok is false when m is not a DrvFs
// drive mount or root is not on it.
func WindowsPath(m Mount, root string) (string, bool) {
	if !m.DrvFs || m.Drive == 0 || !strings.HasPrefix(root, "/") {
		return "", false
	}
	root = path.Clean(root)
	if !underPoint(root, m.Point) {
		return "", false
	}
	rel := strings.TrimPrefix(root, strings.TrimRight(m.Point, "/"))
	full := path.Join("/", m.Root, rel)
	if strings.ContainsAny(full, "\x00") {
		return "", false
	}
	return string(m.Drive) + ":" + strings.ReplaceAll(full, "/", `\`), true
}

// PrefixMount is the mount the default WSL layout gives a /mnt/<drive>
// path (automount root /mnt) when the mount table could not be read: the
// path-prefix reading R3-66 used. "/mnt/cfoo" is a directory named cfoo,
// not drive C.
func PrefixMount(root string) (Mount, bool) {
	const prefix = "/mnt/"
	if !strings.HasPrefix(root, prefix) || len(root) < len(prefix)+1 {
		return Mount{}, false
	}
	d, ok := driveLetter(root[len(prefix):len(prefix)+1] + ":")
	if !ok {
		return Mount{}, false
	}
	if rest := root[len(prefix)+1:]; rest != "" && rest[0] != '/' {
		return Mount{}, false
	}
	return Mount{Point: root[:len(prefix)+1], Root: "/", FSType: "drvfs", DrvFs: true, Drive: d}, true
}
