//go:build linux

package host

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// fileID is a file's identity: its device and inode. It is the same seen
// from any pid or mount namespace, so a survivor inside an isolation
// namespace is still recognised (JSP-12: survivors by executable identity,
// never by pids the program reported).
type fileID struct{ dev, ino uint64 }

// idOf returns the identity of the file at path.
func idOf(path string) (fileID, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileID{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}, false
	}
	return fileID{dev: st.Dev, ino: st.Ino}, true
}

// bootTicks returns the time since boot in clock ticks (USER_HZ, 100 on
// every Linux the runner supports), the unit of a process's start time.
func bootTicks() uint64 {
	data, err := os.ReadFile(filepath.Join(procRoot, "uptime"))
	if err != nil {
		return 0
	}
	first, _, _ := strings.Cut(string(data), " ")
	secs, frac, _ := strings.Cut(first, ".")
	s, err := strconv.ParseUint(secs, 10, 64)
	if err != nil {
		return 0
	}
	f, _ := strconv.ParseUint((frac + "00")[:2], 10, 64)
	return s*100 + f
}

// survivors counts the processes still alive after the final kill that run
// one of the run's executables, belong to this user, started during the run,
// and are not part of another live run of this executor. They are reported,
// never killed here: outside the run's cgroup or group nothing proves a
// process with the same executable is the run's (another start of the same
// program by someone else in the same window is counted too).
func (e *Executor) survivors(l *launch) int {
	ids := map[fileID]bool{}
	for _, p := range l.identity {
		if p == "" {
			continue
		}
		if id, ok := idOf(p); ok {
			ids[id] = true
		}
	}
	if len(ids) == 0 || l.startTicks == 0 {
		return 0
	}
	otherGroups := map[int]bool{}
	otherCgroups := map[string]bool{}
	for _, o := range e.others(l) {
		if o.cmd != nil && o.cmd.Process != nil {
			otherGroups[o.cmd.Process.Pid] = true
		}
		if o.setup.cont.CgroupPath != "" {
			otherCgroups[o.setup.cont.CgroupPath] = true
		}
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return 0
	}
	self, uid := os.Getpid(), getuid()
	n := 0
	for _, ent := range entries {
		pid, err := strconv.Atoi(ent.Name())
		if err != nil || pid == self {
			continue
		}
		dir := filepath.Join(procRoot, ent.Name())
		id, ok := idOf(filepath.Join(dir, "exe"))
		if !ok || !ids[id] {
			continue
		}
		if fi, err := os.Stat(dir); err != nil {
			continue
		} else if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != uid {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, "stat"))
		if err != nil {
			continue
		}
		st, ok := parseProcStat(data)
		// One tick of slack: the start time and the uptime are read at
		// different instants.
		if !ok || !st.alive() || st.start+1 < l.startTicks || otherGroups[st.pgrp] {
			continue
		}
		if cg, err := os.ReadFile(filepath.Join(dir, "cgroup")); err == nil && otherCgroups[parseOwnCgroup(cg)] {
			continue
		}
		n++
	}
	return n
}

// others returns the other live runs.
func (e *Executor) others(self *launch) []*launch {
	e.activeMu.Lock()
	defer e.activeMu.Unlock()
	var out []*launch
	for l := range e.active {
		if l != self {
			out = append(out, l)
		}
	}
	return out
}
