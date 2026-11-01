package sandboxvm

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// config.go composes the vm.create body and the VMM's argv from a run plan
// (sandbox plan v2 sections 4.6 and 13 P4, lane SBX-P4 milestone 2). The
// body is Cloud Hypervisor 54's VmConfig: payload (kernel, initramfs,
// command line), disks, cpus, memory, fs, vsock, serial, console, rng; it
// never carries a net, vdpa, devices, user_devices or pmem entry. Every
// path is the run's own (state dir, verified image copies), absolute and
// clean; every command-line value comes from a closed set of shapes.

// The fixed device ids: the read-back matches a device by its id.
const (
	IDRootfs     = "rootfs"
	IDVerity     = "verity"
	IDVsock      = "vsock0"
	fsIDPrefix   = "fs-"
	diskIDPrefix = "disk-"
)

// The guest's fixed facts.
const (
	// GuestCIDMin is the lowest guest CID (0 to 2 are reserved).
	GuestCIDMin = 3
	// HostCID is the host's CID as the guest sees it.
	HostCID = 2
	// DefaultGuestPort is the AF_VSOCK port the guest init listens on.
	DefaultGuestPort = 1024
	// BootTag is the virtio-fs tag of the run's boot share (the verified
	// guest observer copy and the init spec).
	BootTag = "obsboot"
	// WorkspaceTag is the virtio-fs tag of a shared workspace.
	WorkspaceTag = "ws"
	// serialName is the run file the guest's serial console writes.
	serialName = "serial.log"
)

// Share is one virtio-fs share: its tag and the socket of the virtiofsd
// that serves it.
type Share struct {
	Tag    string `json:"tag"`
	Socket string `json:"socket"`
}

// Disk is one extra block device (a disk_image workspace copy, the install
// cache disk).
type Disk struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	ReadOnly bool   `json:"readonly"`
}

// Plan is one run's VM.
type Plan struct {
	RunID string `json:"run_id"`
	// StateDir is the run's 0700 directory: the API socket, the vsock
	// socket and the serial file live in it.
	StateDir string `json:"state_dir"`
	// SocketDir, when set, holds the run's sockets instead of StateDir: a
	// short 0700 directory used when StateDir is too deep for Linux's
	// socket path limit (MaxSocketPath).
	SocketDir string `json:"socket_dir,omitempty"`
	// Kernel, Initramfs, Rootfs and Verity are the run's verified copies of
	// the image set's entries.
	Kernel    string `json:"kernel"`
	Initramfs string `json:"initramfs"`
	Rootfs    string `json:"rootfs"`
	Verity    string `json:"verity"`
	// VerityRootHash is the signed root hash of the rootfs's hash tree
	// (64 hex), carried on the kernel command line.
	VerityRootHash string  `json:"verity_root_hash"`
	CID            uint32  `json:"cid"`
	GuestPort      uint32  `json:"guest_port"`
	VCPUs          int     `json:"vcpus"`
	MemoryMiB      int     `json:"memory_mib"`
	Shares         []Share `json:"shares"`
	Disks          []Disk  `json:"disks,omitempty"`
}

// APISocket, VsockSocket and SerialFile are the run's paths.
func (p Plan) APISocket() string   { return path.Join(p.sockDir(), "api.sock") }
func (p Plan) VsockSocket() string { return path.Join(p.sockDir(), "vsock.sock") }
func (p Plan) SerialFile() string  { return path.Join(p.StateDir, serialName) }

// ShareSocket is the socket of the virtiofsd serving tag.
func (p Plan) ShareSocket(tag string) string { return path.Join(p.sockDir(), "fs-"+tag+".sock") }

func (p Plan) sockDir() string {
	if p.SocketDir != "" {
		return p.SocketDir
	}
	return p.StateDir
}

// MaxSocketPath is Linux's sun_path budget for a socket path (108 bytes
// with the NUL). The VMM, virtiofsd and the host helper bind or dial every
// run socket by path, so a longer one fails at bind time.
const MaxSocketPath = 107

// vsockPortSuffix is the longest "_<port>" the VMM appends to the vsock
// socket for a guest-to-host listener.
const vsockPortSuffix = "_4294967295"

// SocketsTooLong lists the run sockets a socket dir would hold that exceed
// MaxSocketPath (none: dir fits): the API socket, the vsock socket with
// its longest port suffix and each share tag's socket.
func SocketsTooLong(dir string, tags []string) []string {
	p := Plan{StateDir: dir}
	names := []string{p.APISocket(), p.VsockSocket() + vsockPortSuffix}
	for _, t := range tags {
		names = append(names, p.ShareSocket(t))
	}
	var over []string
	for _, n := range names {
		if len(n) > MaxSocketPath {
			over = append(over, n+" is "+strconv.Itoa(len(n))+" bytes")
		}
	}
	return over
}

var (
	hex64RE = regexp.MustCompile(`^[a-f0-9]{64}$`)
	tagRE   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)
	tokenRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
)

// cleanAbs reports whether p is a clean absolute path with no comma or
// space (Cloud Hypervisor's own option syntax splits on them) and no
// control byte.
func cleanAbs(p string) bool {
	if !path.IsAbs(p) || path.Clean(p) != p || strings.ContainsAny(p, ", =\"'") {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// Validate checks every field of the plan.
func (p Plan) Validate() error {
	var bad []string
	if !tokenRE.MatchString(p.RunID) {
		bad = append(bad, "the run id is not a plain token")
	}
	for name, v := range map[string]string{"state dir": p.StateDir, "kernel": p.Kernel, "initramfs": p.Initramfs, "rootfs": p.Rootfs, "verity tree": p.Verity} {
		if !cleanAbs(v) {
			bad = append(bad, "the "+name+" path "+strconv.Quote(v)+" is not a clean absolute path")
		}
	}
	if !hex64RE.MatchString(p.VerityRootHash) {
		bad = append(bad, "the verity root hash is not 64 lowercase hex")
	}
	if p.CID < GuestCIDMin || p.CID > 1<<31 {
		bad = append(bad, "the guest CID is reserved or out of range")
	}
	if p.GuestPort == 0 || p.GuestPort >= 1<<30 {
		bad = append(bad, "the guest port is zero or in the host port range")
	}
	if p.VCPUs < 1 || p.VCPUs > 64 {
		bad = append(bad, "the vCPU count is not 1 to 64")
	}
	if p.MemoryMiB < 512 || p.MemoryMiB > 262144 {
		bad = append(bad, "the memory is not 512 to 262144 MiB")
	}
	if p.SocketDir != "" && !cleanAbs(p.SocketDir) {
		bad = append(bad, "the socket dir "+strconv.Quote(p.SocketDir)+" is not a clean absolute path")
	}
	var tags []string
	for _, s := range p.Shares {
		tags = append(tags, s.Tag)
	}
	if over := SocketsTooLong(p.sockDir(), tags); len(over) > 0 {
		bad = append(bad, VerdictSocketPathTooLong+": the run's sockets exceed the "+strconv.Itoa(MaxSocketPath)+"-byte socket path limit ("+strings.Join(over, ", ")+")")
	}
	bad = append(bad, p.shareAndDiskProblems()...)
	if len(bad) > 0 {
		sort.Strings(bad)
		return errors.New("sandboxvm: the VM plan is refused: " + strings.Join(bad, "; "))
	}
	return nil
}

// shareAndDiskProblems is Validate's check of the shares (well-formed,
// unrepeated tags, sockets in the run's state or socket dir, the boot share
// present) and the disks (well-formed, unrepeated names, clean paths).
func (p Plan) shareAndDiskProblems() []string {
	var bad []string
	seenTag, seenDisk := map[string]bool{}, map[string]bool{}
	boot := false
	for _, s := range p.Shares {
		if !tagRE.MatchString(s.Tag) || seenTag[s.Tag] {
			bad = append(bad, "the share tag "+strconv.Quote(s.Tag)+" is malformed or repeated")
		}
		seenTag[s.Tag] = true
		boot = boot || s.Tag == BootTag
		if !cleanAbs(s.Socket) || !(within(s.Socket, p.StateDir) || p.SocketDir != "" && within(s.Socket, p.SocketDir)) {
			bad = append(bad, "the share socket "+strconv.Quote(s.Socket)+" is not in the run's state or socket dir")
		}
		if len(s.Socket) > MaxSocketPath {
			bad = append(bad, VerdictSocketPathTooLong+": the share socket "+strconv.Quote(s.Socket)+" exceeds the socket path limit")
		}
	}
	if !boot {
		bad = append(bad, "the boot share is missing")
	}
	for _, d := range p.Disks {
		if !tagRE.MatchString(d.Name) || seenDisk[d.Name] {
			bad = append(bad, "the disk name "+strconv.Quote(d.Name)+" is malformed or repeated")
		}
		seenDisk[d.Name] = true
		if !cleanAbs(d.Path) {
			bad = append(bad, "the disk path "+strconv.Quote(d.Path)+" is not a clean absolute path")
		}
	}
	return bad
}

func within(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/")
}

// cmdlineRow is one row of the fixed kernel command line table: a key and
// how its value is taken from the plan (nil: a bare flag or a fixed value).
type cmdlineRow struct {
	key   string
	fixed string
	from  func(p Plan) string
}

// cmdlineTable is THE kernel command line: nothing else is ever appended.
// The guest image's initramfs opens the rootfs with dm-verity under the
// signed root hash and never waits for a network (the VM has no NIC; a
// network-online wait is 120 s).
var cmdlineTable = []cmdlineRow{
	{key: "console", fixed: "ttyS0"},
	{key: "reboot", fixed: "k"},
	{key: "panic", fixed: "-1"},
	{key: "ro"},
	{key: "quiet"},
	{key: "init", fixed: "/init"},
	{key: "observer.verity", from: func(p Plan) string { return p.VerityRootHash }},
	{key: "observer.boot", fixed: BootTag},
	{key: "observer.run", from: func(p Plan) string { return p.RunID }},
	{key: "observer.port", from: func(p Plan) string { return strconv.FormatUint(uint64(p.GuestPort), 10) }},
}

// Cmdline renders the kernel command line from the table.
func Cmdline(p Plan) string {
	parts := make([]string, 0, len(cmdlineTable))
	for _, r := range cmdlineTable {
		switch {
		case r.from != nil:
			parts = append(parts, r.key+"="+r.from(p))
		case r.fixed != "":
			parts = append(parts, r.key+"="+r.fixed)
		default:
			parts = append(parts, r.key)
		}
	}
	return strings.Join(parts, " ")
}

// The VmConfig shape (only the fields the driver sets or the read-back
// judges; Cloud Hypervisor answers more, which decoding ignores).
type (
	// VMConfig is the vm.create body and vm.info's config.
	VMConfig struct {
		CPUs    *CPUsConfig    `json:"cpus"`
		Memory  *MemoryConfig  `json:"memory"`
		Payload *PayloadConfig `json:"payload"`
		Disks   []DiskConfig   `json:"disks,omitempty"`
		FS      []FSConfig     `json:"fs,omitempty"`
		Vsock   *VsockConfig   `json:"vsock,omitempty"`
		Serial  *ConsoleConfig `json:"serial"`
		Console *ConsoleConfig `json:"console"`
		RNG     *RNGConfig     `json:"rng,omitempty"`
		// The devices a microVM sandbox never has: any entry is a
		// read-back refusal.
		Net         []json.RawMessage `json:"net,omitempty"`
		Vdpa        []json.RawMessage `json:"vdpa,omitempty"`
		Devices     []json.RawMessage `json:"devices,omitempty"`
		UserDevices []json.RawMessage `json:"user_devices,omitempty"`
		Pmem        []json.RawMessage `json:"pmem,omitempty"`
	}
	// CPUsConfig is the vCPU count.
	CPUsConfig struct {
		BootVCPUs int `json:"boot_vcpus"`
		MaxVCPUs  int `json:"max_vcpus"`
	}
	// MemoryConfig is the guest memory; Shared is required by virtio-fs.
	MemoryConfig struct {
		Size   int64 `json:"size"`
		Shared bool  `json:"shared"`
	}
	// PayloadConfig is the direct kernel boot.
	PayloadConfig struct {
		Kernel    string `json:"kernel"`
		Initramfs string `json:"initramfs,omitempty"`
		Cmdline   string `json:"cmdline"`
	}
	// DiskConfig is one block device. v54 needs image_type set (Raw).
	DiskConfig struct {
		Path      string `json:"path"`
		ReadOnly  bool   `json:"readonly"`
		ImageType string `json:"image_type"`
		ID        string `json:"id"`
	}
	// FSConfig is one virtio-fs device.
	FSConfig struct {
		Tag       string `json:"tag"`
		Socket    string `json:"socket"`
		NumQueues int    `json:"num_queues"`
		QueueSize int    `json:"queue_size"`
		ID        string `json:"id"`
	}
	// VsockConfig is the hybrid vsock device.
	VsockConfig struct {
		CID    uint32 `json:"cid"`
		Socket string `json:"socket"`
		ID     string `json:"id"`
	}
	// ConsoleConfig is the serial port or the virtio console.
	ConsoleConfig struct {
		Mode string `json:"mode"`
		File string `json:"file,omitempty"`
	}
	// RNGConfig is the entropy source.
	RNGConfig struct {
		Src string `json:"src"`
	}
)

// FSID and DiskID are a share's and a disk's device ids.
func FSID(tag string) string    { return fsIDPrefix + tag }
func DiskID(name string) string { return diskIDPrefix + name }

// CreateConfig is the vm.create body for p.
func CreateConfig(p Plan) (VMConfig, error) {
	if err := p.Validate(); err != nil {
		return VMConfig{}, err
	}
	c := VMConfig{
		CPUs:    &CPUsConfig{BootVCPUs: p.VCPUs, MaxVCPUs: p.VCPUs},
		Memory:  &MemoryConfig{Size: int64(p.MemoryMiB) << 20, Shared: true},
		Payload: &PayloadConfig{Kernel: p.Kernel, Initramfs: p.Initramfs, Cmdline: Cmdline(p)},
		Disks: []DiskConfig{
			{Path: p.Rootfs, ReadOnly: true, ImageType: "Raw", ID: IDRootfs},
			{Path: p.Verity, ReadOnly: true, ImageType: "Raw", ID: IDVerity},
		},
		Vsock:   &VsockConfig{CID: p.CID, Socket: p.VsockSocket(), ID: IDVsock},
		Serial:  &ConsoleConfig{Mode: "File", File: p.SerialFile()},
		Console: &ConsoleConfig{Mode: "Off"},
		RNG:     &RNGConfig{Src: "/dev/urandom"},
	}
	for _, d := range p.Disks {
		c.Disks = append(c.Disks, DiskConfig{Path: d.Path, ReadOnly: d.ReadOnly, ImageType: "Raw", ID: DiskID(d.Name)})
	}
	for _, s := range p.Shares {
		c.FS = append(c.FS, FSConfig{Tag: s.Tag, Socket: s.Socket, NumQueues: 1, QueueSize: 1024, ID: FSID(s.Tag)})
	}
	return c, nil
}

// CreateBody is the vm.create JSON.
func CreateBody(p Plan) ([]byte, error) {
	c, err := CreateConfig(p)
	if err != nil {
		return nil, err
	}
	return json.Marshal(c)
}

// EventMonitorFD is the descriptor number the VMM's event monitor writes
// to: the host helper passes the write end of a pipe as the first extra
// file (exec.Cmd.ExtraFiles[0] is fd 3).
const EventMonitorFD = 3

// VMMArgv is the VMM's argv: the API socket in the run's state dir and the
// event monitor on the inherited descriptor, nothing else (the VM itself
// is created through the API, so no device is ever on the command line).
func VMMArgv(bin string, p Plan) ([]string, error) {
	if !cleanAbs(bin) {
		return nil, fmt.Errorf("sandboxvm: the VMM path %q is not a clean absolute path", bin)
	}
	if !cleanAbs(p.StateDir) {
		return nil, fmt.Errorf("sandboxvm: the state dir %q is not a clean absolute path", p.StateDir)
	}
	return []string{bin, "--api-socket", "path=" + p.APISocket(), "--event-monitor", "fd=" + strconv.Itoa(EventMonitorFD)}, nil
}
