package sandboxvm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
)

// sweep.go is the microVM orphan sweep's decisions (lane SBX-P4 decision
// 6): each run's 0700 state dir holds a process record the host helper
// writes as it starts each process (the VMM and every virtiofsd: pid,
// /proc start time, executable) and keeps locked for its life. The
// daemon's start sweep acts only on a record nobody holds (the helper is
// gone, even by SIGKILL) whose run is not under a live relay record, and
// kills only a recorded process whose start time AND executable still
// match (a reused pid is never touched). Then the run's sockets, disk
// copies and dir go; the placeholder ledger clears its placeholders.

// ProcRecordName is the record's file name in a run's state dir.
const ProcRecordName = "procs.json"

// ProcRole names what a recorded process is.
type ProcRole string

// The roles.
const (
	RoleVMM       ProcRole = "vmm"
	RoleVirtiofsd ProcRole = "virtiofsd"
	RoleBwrap     ProcRole = "bwrap"
)

// Proc is one recorded process.
type Proc struct {
	Role ProcRole `json:"role"`
	PID  int      `json:"pid"`
	// StartTicks is field 22 of /proc/<pid>/stat (clock ticks since boot).
	StartTicks uint64 `json:"start_ticks"`
	// Exe is the resolved /proc/<pid>/exe at start.
	Exe string `json:"exe"`
}

// ProcRecord is one run's record.
type ProcRecord struct {
	RunID string `json:"run_id"`
	Procs []Proc `json:"procs"`
}

// maxProcRecord caps the record.
const maxProcRecord = 64 << 10

// ParseProcRecord decodes a record; a malformed one is an error (the sweep
// then kills nothing for it).
func ParseProcRecord(b []byte) (ProcRecord, error) {
	if len(b) > maxProcRecord {
		return ProcRecord{}, errors.New("sandboxvm: a process record over the cap")
	}
	var r ProcRecord
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return ProcRecord{}, fmt.Errorf("sandboxvm: process record: %w", err)
	}
	if !tokenRE.MatchString(r.RunID) {
		return ProcRecord{}, errors.New("sandboxvm: a process record without a run id")
	}
	for _, p := range r.Procs {
		if p.PID <= 1 || p.StartTicks == 0 || !path.IsAbs(p.Exe) {
			return ProcRecord{}, errors.New("sandboxvm: a process record entry without a pid, start time or executable")
		}
	}
	return r, nil
}

// ProcFacts are what /proc says about a pid now.
type ProcFacts struct {
	Alive      bool
	StartTicks uint64
	Exe        string
}

// SweepInput is one run dir's facts.
type SweepInput struct {
	Record ProcRecord
	// Held: a live helper holds the record's lock.
	Held bool
	// RelayLive: the run is under a live relay record.
	RelayLive bool
	// Facts reads /proc for a pid.
	Facts func(pid int) ProcFacts
}

// SweepDecision is what the sweep does for one run.
type SweepDecision struct {
	// Kill are the pids to SIGKILL (matching start time and executable).
	Kill []int
	// Spared names each recorded process left alone and why.
	Spared []string
	// RemoveDir: remove the run's state dir (sockets, disk copies) and
	// clear its placeholders.
	RemoveDir bool
	Reason    string
}

// SweepRun decides one run.
func SweepRun(in SweepInput) SweepDecision {
	switch {
	case in.Held:
		return SweepDecision{Reason: "a live host helper holds the run"}
	case in.RelayLive:
		return SweepDecision{Reason: "the run is under a live relay record"}
	}
	d := SweepDecision{RemoveDir: true, Reason: "no helper holds the run"}
	for _, p := range in.Record.Procs {
		f := in.Facts(p.PID)
		switch {
		case !f.Alive:
			d.Spared = append(d.Spared, strconv.Itoa(p.PID)+" is gone")
		case f.StartTicks != p.StartTicks:
			d.Spared = append(d.Spared, strconv.Itoa(p.PID)+" is another process now (start time differs)")
		case f.Exe != p.Exe:
			d.Spared = append(d.Spared, strconv.Itoa(p.PID)+" is another program now ("+f.Exe+")")
		default:
			d.Kill = append(d.Kill, p.PID)
		}
	}
	sort.Ints(d.Kill)
	return d
}

// ParseProcStatStart reads field 22 (starttime) of a /proc/<pid>/stat
// line; the comm field may hold spaces and parentheses, so fields are
// counted after its last ')'.
func ParseProcStatStart(b []byte) (uint64, error) {
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, errors.New("sandboxvm: not a stat line")
	}
	f := strings.Fields(s[i+1:])
	// Field 3 (state) is f[0], so field 22 is f[19].
	if len(f) < 20 {
		return 0, errors.New("sandboxvm: a short stat line")
	}
	n, err := strconv.ParseUint(f[19], 10, 64)
	if err != nil || n == 0 {
		return 0, errors.New("sandboxvm: no start time in the stat line")
	}
	return n, nil
}

// LeftoverNames are the run-dir entries a SIGKILLed VMM leaves (EM spike
// 2026-10-24): the API socket and its lock, the vsock socket, its
// <socket>_<port> listeners and the namespace-mode virtiofsd's .pid files
// (namespace pids, untrusted: never read, only removed with the dir).
func LeftoverNames() []string {
	return []string{"api.sock", "api.sock.lock", "vsock.sock"}
}
