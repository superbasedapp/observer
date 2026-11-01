package sandboxmxc

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// identity.go answers which AppContainer a run's box runs in, for box
// detection (cmd/observer, audit finding F1). MXC 1.0.1 does not name the
// AppContainer profile after the document's containerId: the 1.0.0 wire
// contract calls containerId only an "externally assigned container
// identifier" (@microsoft/mxc-sdk 1.0.1 dist/generated/v1_0_0/wire.d.ts),
// its ProcessContainer section has no profile name (the SDK's own 1.0.0
// path refuses processContainer.name, dist/bindings/one-shot.js), and
// wxc-exec reports its container name as "(assigned by the backend)". The
// Windows 11 Pro rerun of 2026-10-22 saw a new AppContainer SID on every
// run, never the one derived from observer-<run id>. MXC hands its caller
// neither the profile name nor the SID, so the host helper reads the SID
// from the box process's own token, through handles it opens on the
// processes under the wxc-exec it started (BoxSID), and answers it on the
// run's port (BoxIdentity, StreamIdentity); a process in the box compares
// its own token against that answer.

// BoxProcess is one process under the run's wxc-exec, as the host read it.
type BoxProcess struct {
	PID       uint32
	ParentPID uint32
	// Created is the creation time (FILETIME 100 ns units on Windows); a
	// real child is never older than its parent.
	Created int64
	// Image is the full path of its executable ("" when unreadable).
	Image string
	// AppContainerSID is its token's AppContainer SID ("" when it holds no
	// AppContainer token or the token could not be read).
	AppContainerSID string
}

// BoxSID errors.
var (
	// ErrBoxNotStarted is BoxSID's answer while no AppContainer process
	// running the inner launch descends from wxc-exec.
	ErrBoxNotStarted = errors.New("sandboxmxc: no AppContainer process running the inner launch descends from wxc-exec yet")
	// ErrBoxAmbiguous is BoxSID's answer when such processes run in more
	// than one AppContainer: none of them is picked.
	ErrBoxAmbiguous = errors.New("sandboxmxc: processes under wxc-exec run the inner launch in more than one AppContainer")
)

// maxBoxProcesses bounds BoxSID's walk.
const maxBoxProcesses = 4096

// BoxSID picks the run's container SID from a process snapshot: the
// AppContainer SID of the processes that descend from root (the run's
// wxc-exec, whose handle the host holds, so its PID is not reused while it
// runs) and run the inner launch's executable (isImage). A child counts
// only when it is not older than its parent, so a process whose parent PID
// merely names a recycled number is never walked. No such process yet is
// ErrBoxNotStarted; two different SIDs are ErrBoxAmbiguous, never a pick.
func BoxSID(root BoxProcess, procs []BoxProcess, isImage func(string) bool) (string, error) {
	if isImage == nil {
		return "", errors.New("sandboxmxc: no inner image check")
	}
	children := map[uint32][]BoxProcess{}
	for _, p := range procs {
		if p.PID == 0 || p.PID == root.PID || p.PID == p.ParentPID {
			continue
		}
		children[p.ParentPID] = append(children[p.ParentPID], p)
	}
	seen := map[uint32]bool{root.PID: true}
	queue := []BoxProcess{root}
	sids := map[string]string{}
	// What the walk met, for a not-yet answer's diagnosis.
	walked, contained := 0, []string{}
	for len(queue) > 0 && len(seen) <= maxBoxProcesses {
		parent := queue[0]
		queue = queue[1:]
		for _, c := range children[parent.PID] {
			if seen[c.PID] || c.Created < parent.Created {
				continue
			}
			seen[c.PID] = true
			queue = append(queue, c)
			walked++
			if c.AppContainerSID != "" && len(contained) < 3 {
				contained = append(contained, c.Image)
			}
			if c.AppContainerSID != "" && c.Image != "" && isImage(c.Image) {
				// The first spelling seen (the walk meets the box process
				// before its children) is the one answered.
				if k := strings.ToUpper(c.AppContainerSID); sids[k] == "" {
					sids[k] = c.AppContainerSID
				}
			}
		}
	}
	list := make([]string, 0, len(sids))
	for _, s := range sids {
		list = append(list, s)
	}
	sort.Strings(list)
	switch len(list) {
	case 0:
		return "", fmt.Errorf("%w (%d processes under it, in an AppContainer: %q)", ErrBoxNotStarted, walked, contained)
	case 1:
		return list[0], nil
	}
	return "", fmt.Errorf("%w: %s", ErrBoxAmbiguous, strings.Join(list, ", "))
}

// BoxIdentityVersion is the identity answer's version.
const BoxIdentityVersion = 1

// BoxIdentity is the host's answer on the run's port to "which container is
// this run's box": the run, the containerId its document asked for, and
// the SID the host read from the box process's token, or why it has none.
type BoxIdentity struct {
	V           int    `json:"v"`
	RunID       string `json:"run_id"`
	ContainerID string `json:"container_id"`
	SID         string `json:"sid,omitempty"`
	Error       string `json:"error,omitempty"`
}
