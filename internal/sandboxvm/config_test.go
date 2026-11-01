package sandboxvm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testRoot = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func testPlan() Plan {
	return Plan{
		RunID: "run-1", StateDir: "/home/u/.observer/sandbox-vm/runs/run-1",
		Kernel: "/home/u/.observer/sandbox-vm/runs/run-1/img/vmlinuz", Initramfs: "/home/u/.observer/sandbox-vm/runs/run-1/img/initrd.img",
		Rootfs: "/home/u/.observer/sandbox-vm/runs/run-1/img/rootfs.img", Verity: "/home/u/.observer/sandbox-vm/runs/run-1/img/rootfs.verity",
		VerityRootHash: testRoot, CID: 7, GuestPort: DefaultGuestPort, VCPUs: 2, MemoryMiB: 4096,
		Shares: []Share{
			{Tag: BootTag, Socket: "/home/u/.observer/sandbox-vm/runs/run-1/fs-obsboot.sock"},
			{Tag: WorkspaceTag, Socket: "/home/u/.observer/sandbox-vm/runs/run-1/fs-ws.sock"},
		},
	}
}

// TestCreateBodyMatchesTheRecordedShape: the vm.create body for a plan is
// the recorded one (testdata/vm_create.json), byte for byte.
func TestCreateBodyMatchesTheRecordedShape(t *testing.T) {
	got, err := CreateBody(testPlan())
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "vm_create.json"))
	if err != nil {
		t.Fatal(err)
	}
	var a, b any
	if err := json.Unmarshal(got, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(want, &b); err != nil {
		t.Fatal(err)
	}
	ga, _ := json.Marshal(a)
	gb, _ := json.Marshal(b)
	if string(ga) != string(gb) {
		t.Fatalf("body\n%s\nwant\n%s", ga, gb)
	}
}

// TestCreateBodyHasNoNetwork: no plan can produce a network device, and the
// rootfs and its hash tree are read-only raw disks, memory shared.
func TestCreateBodyHasNoNetwork(t *testing.T) {
	c, err := CreateConfig(testPlan())
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Net)+len(c.Vdpa)+len(c.Devices)+len(c.UserDevices)+len(c.Pmem) != 0 {
		t.Fatalf("devices %+v", c)
	}
	for _, d := range c.Disks[:2] {
		if !d.ReadOnly || d.ImageType != "Raw" {
			t.Fatalf("disk %+v", d)
		}
	}
	if !c.Memory.Shared || c.Memory.Size != 4096<<20 {
		t.Fatalf("memory %+v", c.Memory)
	}
	body, _ := CreateBody(testPlan())
	if strings.Contains(string(body), `"net"`) {
		t.Fatalf("the body names net: %s", body)
	}
}

// TestCmdlineIsTheFixedTable: the command line is exactly the table, with
// the signed root hash; nothing a plan holds adds a key.
func TestCmdlineIsTheFixedTable(t *testing.T) {
	want := "console=ttyS0 reboot=k panic=-1 ro quiet init=/init observer.verity=" + testRoot + " observer.boot=obsboot observer.run=run-1 observer.port=1024"
	if got := Cmdline(testPlan()); got != want {
		t.Fatalf("cmdline %q", got)
	}
}

// TestPlanValidation is one case per rule.
func TestPlanValidation(t *testing.T) {
	cases := map[string]func(*Plan){
		"run id":          func(p *Plan) { p.RunID = "a b" },
		"relative kernel": func(p *Plan) { p.Kernel = "vmlinuz" },
		"comma in path":   func(p *Plan) { p.Rootfs = "/x/a,readonly=off" },
		"unclean path":    func(p *Plan) { p.Initramfs = "/x/../y" },
		"root hash":       func(p *Plan) { p.VerityRootHash = "ABC" },
		"reserved cid":    func(p *Plan) { p.CID = 2 },
		"host port range": func(p *Plan) { p.GuestPort = 1 << 30 },
		"vcpus":           func(p *Plan) { p.VCPUs = 0 },
		"memory":          func(p *Plan) { p.MemoryMiB = 64 },
		"bad tag":         func(p *Plan) { p.Shares[1].Tag = "Bad Tag" },
		"repeated tag":    func(p *Plan) { p.Shares[1].Tag = BootTag },
		"socket outside":  func(p *Plan) { p.Shares[1].Socket = "/tmp/fs.sock" },
		"no boot share":   func(p *Plan) { p.Shares = p.Shares[1:] },
		"bad disk":        func(p *Plan) { p.Disks = []Disk{{Name: "ws", Path: "relative"}} },
	}
	for name, mut := range cases {
		p := testPlan()
		p.Shares = append([]Share(nil), p.Shares...)
		mut(&p)
		if _, err := CreateBody(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestVMMArgv: only the API socket and the event monitor on fd 3.
func TestVMMArgv(t *testing.T) {
	argv, err := VMMArgv("/usr/local/bin/cloud-hypervisor", testPlan())
	if err != nil {
		t.Fatal(err)
	}
	want := "/usr/local/bin/cloud-hypervisor --api-socket path=/home/u/.observer/sandbox-vm/runs/run-1/api.sock --event-monitor fd=3"
	if strings.Join(argv, " ") != want {
		t.Fatalf("argv %v", argv)
	}
	if _, err := VMMArgv("cloud-hypervisor", testPlan()); err == nil {
		t.Fatal("a relative VMM path was accepted")
	}
}

// TestPlanSocketBudget (audit finding 8): a state dir too deep for the
// 107-byte socket path limit is refused by name unless the plan names a
// short socket dir, which then holds every socket.
func TestPlanSocketBudget(t *testing.T) {
	p := testPlan()
	if over := SocketsTooLong(p.StateDir, []string{BootTag, WorkspaceTag}); len(over) != 0 {
		t.Fatalf("the usual state dir is over: %v", over)
	}
	deep := "/home/" + strings.Repeat("u", 70) + "/.observer/sandbox-vm/runs/run-1"
	d := testPlan()
	d.StateDir = deep
	for i := range d.Shares {
		d.Shares[i].Socket = d.ShareSocket(d.Shares[i].Tag)
	}
	if err := d.Validate(); err == nil || !strings.Contains(err.Error(), VerdictSocketPathTooLong) {
		t.Fatalf("a deep state dir: %v", err)
	}
	d.SocketDir = "/tmp/obvm-1000/run-1"
	for i := range d.Shares {
		d.Shares[i].Socket = d.ShareSocket(d.Shares[i].Tag)
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("with a short socket dir: %v", err)
	}
	if d.APISocket() != "/tmp/obvm-1000/run-1/api.sock" || d.VsockSocket() != "/tmp/obvm-1000/run-1/vsock.sock" || d.Shares[1].Socket != "/tmp/obvm-1000/run-1/fs-ws.sock" || !strings.HasPrefix(d.SerialFile(), deep) {
		t.Fatalf("paths %s %s %s %s", d.APISocket(), d.VsockSocket(), d.Shares[1].Socket, d.SerialFile())
	}
}
