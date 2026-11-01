package sandboxvm

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// readback.go judges what vm.info reports against the run's plan (sandbox
// plan v2 sections 4.4 and 7.1, decision 4 of lane SBX-P4): the VM is the
// one network owner (N8) with no NIC, so any network device, another vsock
// CID or socket, an unplanned share or disk, a writable rootfs, unshared
// memory or a changed payload is built_below_plan. A reshaped or truncated
// answer is built_below_plan too, never a pass. The read-back runs before
// the agent starts and again after boot (vm.add-fs hotplug exists).

// maxInfoBytes caps one vm.info answer.
const maxInfoBytes = 1 << 20

// Info is the vm.info answer.
type Info struct {
	Config     *VMConfig                  `json:"config"`
	State      string                     `json:"state"`
	DeviceTree map[string]DeviceTreeEntry `json:"device_tree"`
}

// DeviceTreeEntry is one node of the VMM's device tree.
type DeviceTreeEntry struct {
	ID       string   `json:"id"`
	Children []string `json:"children"`
}

// ParseInfo decodes a vm.info answer, refusing an oversized, truncated or
// reshaped one.
func ParseInfo(b []byte) (Info, error) {
	var in Info
	if len(b) > maxInfoBytes {
		return in, errReshaped("the answer is over the cap")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&in); err != nil {
		return in, errReshaped("the answer is not a vm.info object: " + err.Error())
	}
	if dec.More() {
		return in, errReshaped("the answer carries more than one object")
	}
	if in.Config == nil || in.Config.Payload == nil || in.Config.Memory == nil || in.Config.CPUs == nil {
		return in, errReshaped("the answer lacks the config, payload, memory or cpus")
	}
	return in, nil
}

type reshaped string

func (e reshaped) Error() string { return string(e) }

func errReshaped(why string) error { return reshaped(why) }

// netDevicePrefixes are the device-tree ids Cloud Hypervisor gives network
// devices it names itself.
var netDevicePrefixes = []string{"_net", "_vdpa", "_vfio", "_user_device", "_pmem"}

// readBackNotStarted ends a refusal before the agent starts.
const readBackNotStarted = "; the agent was not started"

// ReadBackWhileRunning is ReadBack once the run is under way (the timer and
// event loop's read-back, wantRunning set): a shortfall then ends a run
// whose agent may be running, so its reason says the run was ended, never
// that the agent was not started (the first live run's hotplug end, D9).
func ReadBackWhileRunning(p Plan, b []byte) Verdict {
	v := ReadBack(p, b, true)
	if !v.OK() {
		v.Reason = strings.TrimSuffix(v.Reason, readBackNotStarted) + "; the run was ended"
	}
	return v
}

// ReadBack judges the answer b against p. wantRunning additionally requires
// the state to be Running (the post-boot read).
func ReadBack(p Plan, b []byte, wantRunning bool) Verdict {
	below := func(bad []string) Verdict {
		sort.Strings(bad)
		return refuse(VerdictBuiltBelowPlan, "the VM read back weaker than planned: "+strings.Join(bad, "; ")+readBackNotStarted)
	}
	in, err := ParseInfo(b)
	if err != nil {
		return below([]string{err.Error()})
	}
	want, err := CreateConfig(p)
	if err != nil {
		return refuse(VerdictBuiltBelowPlan, err.Error())
	}
	c := in.Config
	var bad []string
	for name, n := range map[string]int{"network device": len(c.Net), "vDPA device": len(c.Vdpa), "passthrough device": len(c.Devices), "user device": len(c.UserDevices), "pmem device": len(c.Pmem)} {
		if n > 0 {
			bad = append(bad, strconv.Itoa(n)+" "+name+"(s) present")
		}
	}
	for id := range in.DeviceTree {
		for _, pre := range netDevicePrefixes {
			if strings.HasPrefix(id, pre) {
				bad = append(bad, "the device tree holds "+id)
			}
		}
	}
	if !c.Memory.Shared {
		bad = append(bad, "the memory is not shared")
	}
	if c.Memory.Size != want.Memory.Size {
		bad = append(bad, "the memory size differs")
	}
	if c.CPUs.BootVCPUs != want.CPUs.BootVCPUs || c.CPUs.MaxVCPUs != want.CPUs.MaxVCPUs {
		bad = append(bad, "the vCPU count differs")
	}
	if *c.Payload != *want.Payload {
		bad = append(bad, "the kernel, initramfs or command line differs from the plan")
	}
	switch {
	case c.Vsock == nil:
		bad = append(bad, "the vsock device is missing")
	case *c.Vsock != *want.Vsock:
		bad = append(bad, "the vsock device has another CID, socket or id")
	}
	if c.Serial == nil || *c.Serial != *want.Serial {
		bad = append(bad, "the serial port is not the planned run file")
	}
	if c.Console != nil && c.Console.Mode != "Off" {
		bad = append(bad, "the virtio console is on")
	}
	bad = append(bad, judgeDisks(c.Disks, want.Disks)...)
	bad = append(bad, judgeFS(c.FS, want.FS)...)
	if wantRunning && in.State != "Running" {
		bad = append(bad, "the VM is "+strconv.Quote(in.State)+", not Running")
	}
	if len(bad) > 0 {
		return below(bad)
	}
	return pass()
}

// judgeDisks requires exactly the planned disks, each with its planned path
// and mode (a writable rootfs is the case that matters).
func judgeDisks(got, want []DiskConfig) []string {
	var bad []string
	plan := map[string]DiskConfig{}
	for _, d := range want {
		plan[d.ID] = d
	}
	seen := map[string]bool{}
	for _, d := range got {
		w, ok := plan[d.ID]
		switch {
		case !ok:
			bad = append(bad, "an unplanned disk "+strconv.Quote(d.ID))
		case seen[d.ID]:
			bad = append(bad, "the disk "+strconv.Quote(d.ID)+" appears twice")
		case d.Path != w.Path:
			bad = append(bad, "the disk "+d.ID+" is another file")
		case d.ReadOnly != w.ReadOnly:
			bad = append(bad, "the disk "+d.ID+" has another mode (read-only "+strconv.FormatBool(d.ReadOnly)+")")
		}
		seen[d.ID] = true
	}
	for id := range plan {
		if !seen[id] {
			bad = append(bad, "the disk "+id+" is missing")
		}
	}
	return bad
}

// judgeFS requires exactly the planned shares (tag and socket).
func judgeFS(got, want []FSConfig) []string {
	var bad []string
	plan := map[string]FSConfig{}
	for _, f := range want {
		plan[f.ID] = f
	}
	seen := map[string]bool{}
	for _, f := range got {
		w, ok := plan[f.ID]
		switch {
		case !ok:
			bad = append(bad, "an unplanned share "+strconv.Quote(f.Tag))
		case seen[f.ID]:
			bad = append(bad, "the share "+f.Tag+" appears twice")
		case f.Tag != w.Tag || f.Socket != w.Socket:
			bad = append(bad, "the share "+f.ID+" has another tag or socket")
		}
		seen[f.ID] = true
	}
	for id := range plan {
		if !seen[id] {
			bad = append(bad, "the share "+id+" is missing")
		}
	}
	return bad
}
