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

// guestspec.go is the guest init's half of a run plan (lane SBX-P4): the
// small JSON file on the run's read-only boot share that sandbox-vm-init
// reads as PID 1. It holds no secret (the per-run relay secret is its own
// 0600 file beside it, removed by the host helper after the handshake) and
// nothing the guest can use to reach the host but the two vsock ports.

// GuestSpecSchema is the spec's schema id.
const GuestSpecSchema = "sbo.sandbox-vm-init.v1"

// GuestSpecName and GuestSecretName are the boot share's files.
const (
	GuestSpecName   = "init.json"
	GuestSecretName = "secret"
	GuestBinaryName = "observer-guest"
)

// GuestWritableRoots are the directories the guest init mounts a fresh
// tmpfs on (the rootfs is read-only): every share target must lie under one
// of them.
var GuestWritableRoots = []string{"/home", "/root", "/srv", "/mnt", "/opt", "/tmp", "/var/tmp", "/workspace"}

// GuestHookBin is the fixed guest path of the verified guest observer: the
// guest init binds it there read-only on every run (/run is the guest's
// own tmpfs), so a host observer installed outside the writable roots (for
// example /usr/bin, /usr/local/bin or an npm global tree) still launches:
// its path is replaced by this one in the launch and named by the hook
// entries written for the guest.
const GuestHookBin = "/run/observer/observer"

// GuestHookBinFor is the observer path the guest's hooks and launch name
// for a host observer at hostBin: the host path itself when it lies under
// a writable guest root (the guest links it to GuestHookBin, so the hook
// entries the host already wrote resolve unchanged), else GuestHookBin.
func GuestHookBinFor(hostBin string) string {
	if guestPath(hostBin) && underWritableRoot(hostBin) {
		return hostBin
	}
	return GuestHookBin
}

// GuestMount is one virtio-fs share the guest mounts at Target.
type GuestMount struct {
	Tag      string `json:"tag"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"readonly,omitempty"`
}

// GuestDisk is one block device (a disk_image copy, the install cache) the
// guest mounts at Target.
type GuestDisk struct {
	Name   string `json:"name"`
	Target string `json:"target"`
}

// GuestSpec is the init spec.
type GuestSpec struct {
	Schema  string `json:"schema"`
	RunID   string `json:"run_id"`
	UID     int    `json:"uid"`
	GID     int    `json:"gid"`
	HostBin string `json:"host_bin"`
	// HookBin is the observer path the guest's hook entries and the launch
	// name (GuestHookBinFor; empty reads as HostBin, the first form).
	HookBin  string       `json:"hook_bin,omitempty"`
	Workdir  string       `json:"workdir"`
	Mounts   []GuestMount `json:"mounts,omitempty"`
	Disks    []GuestDisk  `json:"disks,omitempty"`
	ReadOnly []string     `json:"readonly_paths,omitempty"`
	// PTYPort is the vsock port of the PTY session (accepted once);
	// RelayPort the capture relay tunnel's (re-accepted after a drop).
	PTYPort   uint32 `json:"pty_port"`
	RelayPort uint32 `json:"relay_port"`
	Rows      uint16 `json:"rows"`
	Cols      uint16 `json:"cols"`
	// WantUserns: the verified descriptor declares unprivileged user
	// namespaces; the init's self-test must confirm it (N13).
	WantUserns bool     `json:"want_userns,omitempty"`
	Command    []string `json:"command"`
}

// maxGuestSpec caps the file.
const maxGuestSpec = 256 << 10

func underWritableRoot(p string) bool {
	for _, r := range GuestWritableRoots {
		if within(p, r) && p != r {
			return true
		}
	}
	return false
}

// guestPath reports a clean absolute path with no control byte.
func guestPath(p string) bool {
	if !path.IsAbs(p) || path.Clean(p) != p {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// Validate checks every field.
func (s GuestSpec) Validate() error {
	var bad []string
	if s.Schema != GuestSpecSchema {
		bad = append(bad, "schema "+strconv.Quote(s.Schema))
	}
	if !tokenRE.MatchString(s.RunID) {
		bad = append(bad, "the run id is not a plain token")
	}
	if s.UID < 1 || s.GID < 1 || s.UID > 1<<31 || s.GID > 1<<31 {
		bad = append(bad, "the agent's uid and gid must be unprivileged")
	}
	if !guestPath(s.HostBin) {
		bad = append(bad, "the host observer path "+strconv.Quote(s.HostBin)+" is not clean and absolute")
	}
	if hook := s.HookPath(); hook != GuestHookBin && (!guestPath(hook) || !underWritableRoot(hook)) {
		bad = append(bad, "the hook observer path "+strconv.Quote(hook)+" is neither "+GuestHookBin+" nor under a writable guest root "+strings.Join(GuestWritableRoots, ", "))
	}
	shares, workOK := s.validateTargets()
	bad = append(bad, shares...)
	if !guestPath(s.Workdir) || !workOK {
		bad = append(bad, "the workdir "+strconv.Quote(s.Workdir)+" is not inside a share or disk")
	}
	for _, p := range s.ReadOnly {
		if !guestPath(p) {
			bad = append(bad, "the read-only path "+strconv.Quote(p)+" is not clean and absolute")
		}
	}
	if s.PTYPort == 0 || s.RelayPort == 0 || s.PTYPort == s.RelayPort || s.PTYPort >= HostPortMin || s.RelayPort >= HostPortMin {
		bad = append(bad, "the vsock ports are zero, equal or in the host range")
	}
	if len(s.Command) == 0 || !guestPath(s.Command[0]) {
		bad = append(bad, "the command is empty or not an absolute program")
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return errors.New("sandboxvm: the guest spec is refused: " + strings.Join(bad, "; "))
	}
	return nil
}

// validateTargets checks the shares and disks and reports whether the
// workdir lies inside one of them.
func (s GuestSpec) validateTargets() ([]string, bool) {
	var bad []string
	seen := map[string]bool{}
	workOK := false
	for _, m := range s.Mounts {
		if !tagRE.MatchString(m.Tag) || m.Tag == BootTag || seen[m.Tag] {
			bad = append(bad, "the share tag "+strconv.Quote(m.Tag)+" is malformed, the boot tag or repeated")
		}
		seen[m.Tag] = true
		if !guestPath(m.Target) || !underWritableRoot(m.Target) {
			bad = append(bad, "the share target "+strconv.Quote(m.Target)+" is not under a writable guest root")
		}
		workOK = workOK || within(s.Workdir, m.Target)
	}
	for _, d := range s.Disks {
		if !tagRE.MatchString(d.Name) || seen["disk:"+d.Name] {
			bad = append(bad, "the disk "+strconv.Quote(d.Name)+" is malformed or repeated")
		}
		seen["disk:"+d.Name] = true
		if !guestPath(d.Target) || !underWritableRoot(d.Target) {
			bad = append(bad, "the disk target "+strconv.Quote(d.Target)+" is not under a writable guest root")
		}
		workOK = workOK || within(s.Workdir, d.Target)
	}
	return bad, workOK
}

// HookPath is the observer path the guest's hooks and launch name.
func (s GuestSpec) HookPath() string {
	if s.HookBin != "" {
		return s.HookBin
	}
	return s.HostBin
}

// HookLink is the path the guest init links to GuestHookBin ("" when the
// hooks name GuestHookBin itself).
func (s GuestSpec) HookLink() string {
	if p := s.HookPath(); p != GuestHookBin {
		return p
	}
	return ""
}

// Encode is the spec's file bytes.
func (s GuestSpec) Encode() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(s, "", "  ")
}

// ParseGuestSpec decodes and checks a spec; unknown fields are refused.
func ParseGuestSpec(b []byte) (GuestSpec, error) {
	if len(b) > maxGuestSpec {
		return GuestSpec{}, fmt.Errorf("sandboxvm: the guest spec is over %d bytes", maxGuestSpec)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var s GuestSpec
	if err := dec.Decode(&s); err != nil {
		return GuestSpec{}, fmt.Errorf("sandboxvm: guest spec: %w", err)
	}
	if dec.More() {
		return GuestSpec{}, errors.New("sandboxvm: guest spec: trailing data")
	}
	return s, s.Validate()
}

// GuestAccountName is the agent's user and group name in the guest when the
// image names neither its uid nor its gid.
const GuestAccountName = "agent"

// GuestAccounts returns the guest image's passwd and group files with an
// entry for the agent's uid and gid appended where the image names none (an
// id the image already names is left as it is). The name is
// GuestAccountName, or GuestAccountName-<id> when the image uses that name
// for another id; the home is home and the shell /bin/sh.
func GuestAccounts(passwd, group []byte, uid, gid int, home string) ([]byte, []byte) {
	if !accountsHaveID(passwd, uid) {
		name := accountName(passwd, uid)
		passwd = appendAccountLine(passwd, fmt.Sprintf("%s:x:%d:%d:Observer sandbox agent:%s:/bin/sh", name, uid, gid, home))
	}
	if !accountsHaveID(group, gid) {
		group = appendAccountLine(group, fmt.Sprintf("%s:x:%d:", accountName(group, gid), gid))
	}
	return passwd, group
}

// accountsHaveID reports whether a passwd or group file names id (its
// third field).
func accountsHaveID(b []byte, id int) bool {
	want := strconv.Itoa(id)
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Split(line, ":"); len(f) >= 3 && f[2] == want {
			return true
		}
	}
	return false
}

// accountName is GuestAccountName, or GuestAccountName-<id> when the file
// already uses it.
func accountName(b []byte, id int) string {
	for _, line := range strings.Split(string(b), "\n") {
		if name, _, _ := strings.Cut(line, ":"); name == GuestAccountName {
			return GuestAccountName + "-" + strconv.Itoa(id)
		}
	}
	return GuestAccountName
}

func appendAccountLine(b []byte, line string) []byte {
	out := append([]byte(nil), b...)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	return append(out, line+"\n"...)
}

// GuestMountPlan is the guest init's ordered mount list: a tmpfs on each
// writable root, then each share and disk, parents before children.
type GuestMountPlan struct {
	Tmpfs  []string
	Shares []GuestMount
	Disks  []GuestDisk
}

// PlanGuestMounts orders the spec's mounts.
func PlanGuestMounts(s GuestSpec) GuestMountPlan {
	p := GuestMountPlan{Tmpfs: append([]string(nil), GuestWritableRoots...)}
	p.Shares = append(p.Shares, s.Mounts...)
	sort.SliceStable(p.Shares, func(i, j int) bool { return len(p.Shares[i].Target) < len(p.Shares[j].Target) })
	p.Disks = append(p.Disks, s.Disks...)
	sort.SliceStable(p.Disks, func(i, j int) bool { return len(p.Disks[i].Target) < len(p.Disks[j].Target) })
	return p
}

// ExpectedGuestMounts are the in-guest mount judge's inputs: every share
// and disk target must be a mount point, and the read-only shares' targets
// and the guest observer's read-only bind at GuestHookBin read-only mounts.
// The spec's read-only paths are not among them: each is a read-only bind
// in the HOST's confined virtiofsd (read back there before and after boot),
// so the guest sees a plain path inside the share, never a mount point of
// its own (the first live run refused every live launch "built_below_plan:
// .../.git/config is not mounted in the box", D4); GuestShareReadOnly
// hands them to the write witness instead.
func ExpectedGuestMounts(s GuestSpec) (mounts, ro []string) {
	mounts = append(mounts, GuestHookBin)
	ro = append(ro, GuestHookBin)
	for _, m := range s.Mounts {
		mounts = append(mounts, m.Target)
		if m.ReadOnly {
			ro = append(ro, m.Target)
		}
	}
	for _, d := range s.Disks {
		mounts = append(mounts, d.Target)
	}
	return mounts, ro
}

// GuestShareReadOnly are the host-pinned read-only paths inside the shares
// (the spec's read-only paths), which the in-guest check judges by a write
// witness that must answer EROFS through virtio-fs (sandbox.GuestCheckShared).
func GuestShareReadOnly(s GuestSpec) []string {
	return append([]string(nil), s.ReadOnly...)
}
