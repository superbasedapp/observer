package gitroute

import (
	"path"
	"strings"
)

// windowsGitInstallDirs are Git for Windows' install directories, relative
// to the C: drive: the machine-wide installer's cmd wrapper, the binary
// behind it, and the 32-bit installer's. They follow the interop PATH's
// own entries, so the developer's git is preferred and a daemon whose PATH
// lacks the Windows half (a systemd unit, appendWindowsPath=false) still
// finds the usual install.
var windowsGitInstallDirs = []string{
	"Program Files/Git/cmd",
	"Program Files/Git/mingw64/bin",
	"Program Files (x86)/Git/cmd",
}

// Candidates lists the git.exe paths to try, in order: each PATH directory
// that lies on a DrvFs drive mount (the Windows half of an interop PATH),
// then the fixed install directories on the C: drive. A PATH directory on
// the Linux filesystem is never a candidate (git.exe there is not Windows
// git, and a shim directory lives there). mounts may be nil when the table
// could not be read; the /mnt/<drive> layout is assumed then.
func Candidates(pathEnv string, mounts []Mount) []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, dir := range strings.Split(pathEnv, ":") {
		if dir == "" || !strings.HasPrefix(dir, "/") {
			continue
		}
		dir = path.Clean(dir)
		if m, ok := mountOf(mounts, dir); ok && m.DrvFs {
			add(path.Join(dir, "git.exe"))
		}
	}
	if c, ok := driveMount(mounts, 'C'); ok {
		for _, d := range windowsGitInstallDirs {
			add(path.Join(c, d, "git.exe"))
		}
	}
	return out
}

// mountOf is MountFor over a known table, or the /mnt/<drive> reading when
// the table is unknown (nil).
func mountOf(mounts []Mount, p string) (Mount, bool) {
	if mounts == nil {
		return PrefixMount(p)
	}
	return MountFor(mounts, p)
}

// driveMount returns the mount point of drive's whole-drive DrvFs mount
// ("/mnt/c"), or /mnt/<drive> when the table is unknown (nil).
func driveMount(mounts []Mount, drive byte) (string, bool) {
	if mounts == nil {
		return "/mnt/" + string(drive-'A'+'a'), true
	}
	for i := len(mounts) - 1; i >= 0; i-- {
		m := mounts[i]
		if m.DrvFs && m.Drive == drive && (m.Root == "/" || m.Root == "") {
			return m.Point, true
		}
	}
	return "", false
}

// IsWindowsGitVersion reports whether `git --version` output names a Git
// for Windows build ("git version 2.53.0.windows.2"): the program resolved
// is the real Windows git, not a wrapper, a shim or a Linux git renamed.
func IsWindowsGitVersion(out string) bool {
	line, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	line = strings.TrimSpace(line)
	return strings.HasPrefix(line, "git version ") && strings.Contains(line, ".windows.")
}
