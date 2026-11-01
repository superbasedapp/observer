//go:build windows

package sandboxmxcdll

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
)

// boxproc_windows.go reads, for the run's host helper, the processes under
// the wxc-exec it started, so the helper learns which AppContainer MXC put
// the box in (MXC 1.0.1 assigns the profile name itself and returns
// neither the name nor the SID; sandboxmxc/identity.go).

// maxTreeProcesses bounds ProcessTree's walk.
const maxTreeProcesses = 4096

// ProcessTree returns root (the process rootPID) and every process that
// descends from it by parent PID, each with its creation time, image path
// and AppContainer SID, read through handles this process opens and closes
// at once (PROCESS_QUERY_LIMITED_INFORMATION and TOKEN_QUERY, which the
// user's own processes, AppContainer ones included, grant). A process that
// exits meanwhile is skipped; sandboxmxc.BoxSID applies the creation-time
// rule.
func ProcessTree(rootPID uint32) (sandboxmxc.BoxProcess, []sandboxmxc.BoxProcess, error) {
	root, ok := readBoxProcess(rootPID, 0)
	if !ok {
		return sandboxmxc.BoxProcess{}, nil, fmt.Errorf("process %d cannot be read (it has exited)", rootPID)
	}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return root, nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer func() { _ = windows.CloseHandle(snap) }()
	children := map[uint32][]uint32{}
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if e.ProcessID != 0 && e.ProcessID != e.ParentProcessID {
			children[e.ParentProcessID] = append(children[e.ParentProcessID], e.ProcessID)
		}
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return root, nil, fmt.Errorf("Process32Next: %w", err)
	}
	var out []sandboxmxc.BoxProcess
	seen := map[uint32]bool{rootPID: true}
	queue := []uint32{rootPID}
	for len(queue) > 0 && len(seen) < maxTreeProcesses {
		pid := queue[0]
		queue = queue[1:]
		for _, c := range children[pid] {
			if seen[c] {
				continue
			}
			seen[c] = true
			queue = append(queue, c)
			if p, ok := readBoxProcess(c, pid); ok {
				out = append(out, p)
			}
		}
	}
	return root, out, nil
}

// readBoxProcess reads one process; ok=false when it cannot be opened or
// its creation time read.
func readBoxProcess(pid, parent uint32) (sandboxmxc.BoxProcess, bool) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return sandboxmxc.BoxProcess{}, false
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return sandboxmxc.BoxProcess{}, false
	}
	p := sandboxmxc.BoxProcess{PID: pid, ParentPID: parent, Created: int64(created.HighDateTime)<<32 | int64(created.LowDateTime)}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil {
		p.Image = windows.UTF16ToString(buf[:n])
	}
	var tok windows.Token
	if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok) == nil {
		if sid, inside := tokenAppContainerSID(tok); inside {
			p.AppContainerSID = sid
		}
		_ = tok.Close()
	}
	return p, true
}
