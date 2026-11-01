//go:build linux

package host

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/extrun"
)

// rlimitDataHolds: Linux enforces RLIMIT_DATA (since 4.7 it counts every
// private writable mapping), so it is the memory fallback when the run's
// cgroup does not carry memory.max (JSP-12: a 2 GiB eater died at 512 MiB).
const rlimitDataHolds = true

// procSelfExe is the running executable's /proc link. A var so a test can
// point it at a fixture.
var procSelfExe = "/proc/self/exe"

// selfPath is the binary the trampoline starts. Started directly, it is the
// running executable through /proc/self/exe, so an upgrade that replaced the
// file on disk still starts this build (whose payload version matches).
// Behind a launcher (viaLauncher: systemd-run in front of the trampoline)
// /proc/self/exe would be read by the launcher's own process and name the
// launcher, so the link is resolved here first; a binary already replaced
// on disk cannot be named that way and the rung is refused.
func selfPath(viaLauncher bool) (string, error) {
	if !viaLauncher {
		return procSelfExe, nil
	}
	real, err := os.Readlink(procSelfExe)
	if err != nil {
		return "", err
	}
	if strings.HasSuffix(real, " (deleted)") || !filepath.IsAbs(real) {
		return "", fmt.Errorf("the running binary %q is no longer on disk, so a launcher cannot start it", real)
	}
	return real, nil
}

// The cgroup v2 file system. Vars so a test can point them at a fixture.
var (
	procSelfCgroup    = "/proc/self/cgroup"
	procSelfMountinfo = "/proc/self/mountinfo"
)

// cgroup2Mount returns the mount point of the cgroup v2 hierarchy: the
// whole /sys/fs/cgroup on a pure v2 host, /sys/fs/cgroup/unified on a
// hybrid one. Empty when there is none.
func cgroup2Mount() string {
	data, err := os.ReadFile(procSelfMountinfo)
	if err != nil {
		return ""
	}
	return parseCgroup2Mount(data)
}

// parseCgroup2Mount finds the first cgroup2 mount in a mountinfo table:
// "id parent maj:min root mountpoint options ... - fstype source opts".
func parseCgroup2Mount(data []byte) string {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		pre, post, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		if f := strings.Fields(post); len(f) == 0 || f[0] != "cgroup2" {
			continue
		}
		if f := strings.Fields(pre); len(f) >= 5 {
			return unescapeMount(f[4])
		}
	}
	return ""
}

// unescapeMount undoes mountinfo's octal escapes (\040 for a space).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// parseOwnCgroup returns the v2 path ("0::<path>") from a /proc/<pid>/cgroup
// table, or "" when the process has none.
func parseOwnCgroup(data []byte) string {
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// ownCgroupDir returns this process's cgroup v2 path and its directory.
func ownCgroupDir() (rel, dir string) {
	data, err := os.ReadFile(procSelfCgroup)
	if err != nil {
		return "", ""
	}
	rel = parseOwnCgroup(data)
	mnt := cgroup2Mount()
	if rel == "" || mnt == "" {
		return rel, ""
	}
	return rel, filepath.Join(mnt, rel)
}

// joinCgroup moves this process into dir (a cgroup v2 directory).
func joinCgroup(dir string) error {
	return os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0)
}

// cgroupCarries reads this process's own cgroup back and reports which caps
// it carries: memory when memory.max equals memoryBytes AND memory.swap.max
// is 0 (JSP-12 laptop half: memory.max alone let a 2 GiB eater swap past
// 512 MiB), pids when pids.max equals pidsMax. A cap that was not asked for
// is never reported.
func cgroupCarries(memoryBytes, pidsMax int64) (rel, memory, pids string) {
	rel, dir := ownCgroupDir()
	if dir == "" {
		return rel, "", ""
	}
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	if memoryBytes > 0 && read("memory.max") == strconv.FormatInt(memoryBytes, 10) && read("memory.swap.max") == "0" {
		memory = extrun.MechCgroup
	}
	if pidsMax > 0 && read("pids.max") == strconv.FormatInt(pidsMax, 10) {
		pids = extrun.MechCgroup
	}
	return rel, memory, pids
}
