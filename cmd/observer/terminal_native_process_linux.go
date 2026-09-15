//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/marmutapp/superbased-observer/internal/adapter"
)

type terminalProcStamp struct {
	Parent int
	Start  string
	Exe    string
	Device uint64
	Inode  uint64
}

func terminalNativeSession(ctx context.Context, pid int, birth string, a adapter.Adapter, resolver adapter.TerminalSessionResolver, binding terminalProcessBinding) (terminalNativeIdentity, error) {
	if birth == "" {
		return terminalNativeIdentity{}, errTerminalIdentityUncertain
	}
	return terminalSessionInProc(ctx, "/proc", pid, a, resolver, binding, birth)
}

func terminalProcessStamp(ctx context.Context, base string) (terminalProcStamp, error) {
	if err := ctx.Err(); err != nil {
		return terminalProcStamp{}, err
	}
	//nolint:gosec // base is procfs plus a validated terminal-descendant PID.
	raw, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		return terminalProcStamp{}, errTerminalIdentityUncertain
	}
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 {
		return terminalProcStamp{}, errTerminalIdentityUncertain
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" {
		return terminalProcStamp{}, errTerminalIdentityUncertain
	}
	parent, err := strconv.Atoi(fields[1])
	if err != nil || fields[19] == "0" {
		return terminalProcStamp{}, errTerminalIdentityUncertain
	}
	exe, err := os.Readlink(filepath.Join(base, "exe"))
	if err != nil {
		return terminalProcStamp{}, errTerminalIdentityUncertain
	}
	info, err := os.Stat(filepath.Join(base, "exe"))
	if err != nil {
		return terminalProcStamp{}, errTerminalIdentityUncertain
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return terminalProcStamp{}, errTerminalIdentityUncertain
	}
	return terminalProcStamp{Parent: parent, Start: fields[19], Exe: exe, Device: stat.Dev, Inode: stat.Ino}, nil
}

func terminalSessionInProc(ctx context.Context, procRoot string, rootPID int, a adapter.Adapter, resolver adapter.TerminalSessionResolver, binding terminalProcessBinding, expectedBirth ...string) (terminalNativeIdentity, error) {
	if rootPID <= 1 {
		return terminalNativeIdentity{}, errTerminalIdentityUncertain
	}
	type child struct{ pid, parent int }
	queue := []child{{pid: rootPID}}
	stamps := map[int]terminalProcStamp{}
	primaries := map[int]bool{}
	identities := map[string]string{}
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return terminalNativeIdentity{}, err
		}
		node := queue[0]
		queue = queue[1:]
		if _, seen := stamps[node.pid]; seen {
			continue
		}
		if len(stamps) >= 64 {
			return terminalNativeIdentity{}, errTerminalIdentityUncertain
		}
		base := filepath.Join(procRoot, strconv.Itoa(node.pid))
		stamp, err := terminalProcessStamp(ctx, base)
		if err != nil || (node.parent != 0 && stamp.Parent != node.parent) {
			return terminalNativeIdentity{}, errTerminalIdentityUncertain
		}
		if node.pid == rootPID && len(expectedBirth) > 0 && terminalProcessStartIdentity(procRoot, stamp.Start) != expectedBirth[0] {
			return terminalNativeIdentity{}, errTerminalIdentityUncertain
		}
		stamps[node.pid] = stamp
		primary, err := terminalProcessMatches(base, stamp.Exe, binding)
		if err != nil {
			return terminalNativeIdentity{}, err
		}
		if primary {
			primaries[node.pid] = true
			identity, err := terminalIdentityForProcess(ctx, base, node.pid, terminalProcessStartIdentity(procRoot, stamp.Start), a, resolver)
			if err != nil || identity.SessionID == "" {
				return terminalNativeIdentity{}, errTerminalIdentityUncertain
			}
			identities[identity.SessionID] = identity.Evidence
			continue // nested tools cannot identify their parent terminal
		}
		children, err := terminalProcessChildren(base)
		if err != nil || len(queue)+len(children) > 256 {
			return terminalNativeIdentity{}, errTerminalIdentityUncertain
		}
		for _, pid := range children {
			queue = append(queue, child{pid: pid, parent: node.pid})
		}
	}
	if len(identities) != 1 || len(primaries) != 1 {
		return terminalNativeIdentity{}, errTerminalIdentityUncertain
	}
	for pid, before := range stamps {
		base := filepath.Join(procRoot, strconv.Itoa(pid))
		after, err := terminalProcessStamp(ctx, base)
		if err != nil || before != after {
			return terminalNativeIdentity{}, errTerminalIdentityUncertain
		}
		if primaries[pid] {
			matches, err := terminalProcessMatches(base, after.Exe, binding)
			if err != nil || !matches {
				return terminalNativeIdentity{}, errTerminalIdentityUncertain
			}
		}
	}
	// Include process births in the comparison between the discovery pass and
	// its final write-boundary recheck, even if a reused PID opens the same file.
	proof, err := json.Marshal(stamps)
	if err != nil {
		return terminalNativeIdentity{}, err
	}
	for id, evidence := range identities {
		return terminalNativeIdentity{sessionID: id, evidence: fmt.Sprintf("%x:%s", sha256.Sum256(proof), evidence)}, nil
	}
	return terminalNativeIdentity{}, errTerminalIdentityUncertain
}

func terminalProcessMatches(base, executable string, binding terminalProcessBinding) (bool, error) {
	if binding.native(base) {
		return true, nil
	}
	if (binding.script == "" && len(binding.scripts) == 0) || filepath.Base(strings.TrimSuffix(executable, " (deleted)")) != binding.interpreter {
		return false, nil
	}
	// Read only the argument vector needed to bind the installed interpreter
	// entrypoint. Arguments are neither logged nor retained in the result.
	//nolint:gosec // base belongs to the validated terminal descendant.
	f, err := os.Open(filepath.Join(base, "cmdline"))
	if err != nil {
		return false, errTerminalIdentityUncertain
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 64*1024+1))
	if err != nil || len(raw) > 64*1024 {
		return false, errTerminalIdentityUncertain
	}
	args := strings.Split(string(raw), "\x00")
	scriptIndex := 1
	// Qwen's current installed wrapper uses this non-executing Node runtime
	// switch. Other runtime flags stay unclassified rather than guessed.
	if len(args) > 2 && binding.interpreter == "node" && args[1] == "--expose-gc" {
		scriptIndex = 2
	}
	if len(args) <= scriptIndex || args[scriptIndex] == "" || strings.HasPrefix(args[scriptIndex], "-") {
		return false, nil
	}
	path := args[scriptIndex]
	if !filepath.IsAbs(path) {
		cwd, err := os.Readlink(filepath.Join(base, "cwd"))
		if err != nil {
			return false, errTerminalIdentityUncertain
		}
		path = filepath.Join(cwd, path)
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false, nil
	}
	if binding.script != "" && real == binding.script {
		return true, nil
	}
	for _, path := range binding.scripts {
		if real == path {
			return true, nil
		}
	}
	return false, nil
}

func terminalProcessChildren(base string) ([]int, error) {
	tasks, err := terminalReadDir(filepath.Join(base, "task"), 256)
	if err != nil || len(tasks) > 256 {
		return nil, errTerminalIdentityUncertain
	}
	var children []int
	for _, task := range tasks {
		//nolint:gosec // Task names are enumerated from this process's procfs directory.
		raw, err := os.ReadFile(filepath.Join(base, "task", task.Name(), "children"))
		if err != nil {
			return nil, errTerminalIdentityUncertain
		}
		for _, field := range strings.Fields(string(raw)) {
			pid, err := strconv.Atoi(field)
			if err != nil || pid <= 1 || len(children) >= 256 {
				return nil, errTerminalIdentityUncertain
			}
			children = append(children, pid)
		}
	}
	return children, nil
}

func terminalProcessStartIdentity(procRoot, start string) string {
	//nolint:gosec // procRoot is the OS procfs root or an isolated test fixture.
	raw, err := os.ReadFile(filepath.Join(procRoot, "sys", "kernel", "random", "boot_id"))
	if err != nil {
		return ""
	}
	boot := strings.TrimSpace(string(raw))
	if boot == "" || strings.ContainsAny(boot, ":\x00\r\n") {
		return ""
	}
	return "linux:" + boot + ":" + start
}

func terminalIdentityForProcess(ctx context.Context, base string, pid int, start string, a adapter.Adapter, resolver adapter.TerminalSessionResolver) (adapter.TerminalSessionIdentity, error) {
	files, before, err := terminalSessionFiles(ctx, base, a)
	if err != nil {
		return adapter.TerminalSessionIdentity{}, err
	}
	identity, err := resolver.ResolveTerminalSession(ctx, adapter.TerminalProcess{PID: pid, StartIdentity: start, Files: files})
	if err != nil || identity.SessionID == "" || identity.Evidence == "" {
		return adapter.TerminalSessionIdentity{}, errTerminalIdentityUncertain
	}
	_, after, err := terminalSessionFiles(ctx, base, a)
	if err != nil || before != after {
		return adapter.TerminalSessionIdentity{}, errTerminalIdentityUncertain
	}
	identity.Evidence = before + ":" + identity.Evidence
	return identity, nil
}

func terminalSessionFiles(ctx context.Context, base string, a adapter.Adapter) ([]adapter.TerminalSessionFile, string, error) {
	fds, err := terminalReadDir(filepath.Join(base, "fd"), 1024)
	if err != nil || len(fds) > 1024 {
		return nil, "", errTerminalIdentityUncertain
	}
	var files []adapter.TerminalSessionFile
	proof := sha256.New()
	for _, fd := range fds {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		path := filepath.Join(base, "fd", fd.Name())
		target, err := os.Readlink(path)
		if err != nil {
			return nil, "", errTerminalIdentityUncertain
		}
		if !a.IsSessionFile(target) {
			continue
		}
		flags, err := terminalDescriptorFlags(filepath.Join(base, "fdinfo", fd.Name()))
		if err != nil {
			return nil, "", err
		}
		if flags&3 == 0 {
			continue // a history reader does not own that session
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return nil, "", errTerminalIdentityUncertain
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil, "", errTerminalIdentityUncertain
		}
		fmt.Fprintf(proof, "%s\x00%s\x00%d:%d:%d\n", fd.Name(), target, stat.Dev, stat.Ino, flags)
		files = append(files, adapter.TerminalSessionFile{Path: target, ReadPath: path, Writable: true, Append: flags&int64(os.O_APPEND) != 0})
	}
	return files, fmt.Sprintf("%x", proof.Sum(nil)), nil
}

func terminalDescriptorFlags(path string) (int64, error) {
	//nolint:gosec // path is an enumerated descriptor's procfs metadata.
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, errTerminalIdentityUncertain
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "flags:" {
			flags, err := strconv.ParseInt(fields[1], 8, 64)
			if err == nil {
				return flags, nil
			}
		}
	}
	return 0, errTerminalIdentityUncertain
}

func terminalNativeDiscoveryAvailable(a adapter.Adapter) bool {
	_, ok := a.(adapter.TerminalSessionResolver)
	return ok
}

// terminalReadDir bounds allocation before enumeration, then sorts descriptor
// names so repeated proofs are independent of kernel directory iteration order.
func terminalReadDir(path string, limit int) ([]os.DirEntry, error) {
	//nolint:gosec // path is beneath the validated process's procfs directory.
	f, err := os.Open(path)
	if err != nil {
		return nil, errTerminalIdentityUncertain
	}
	defer f.Close()
	entries, err := f.ReadDir(limit + 1)
	if (err != nil && !errors.Is(err, io.EOF)) || len(entries) > limit {
		return nil, errTerminalIdentityUncertain
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}
