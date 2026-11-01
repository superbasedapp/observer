package sandboxvm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// recordedInfo is the recorded Running vm.info answer for testPlan,
// reconstructed from Cloud Hypervisor 54's VmInfo and VmConfig API types.
func recordedInfo(t *testing.T) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "vm_info_running.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func cfgOf(m map[string]any) map[string]any { return m["config"].(map[string]any) }

func TestReadBackPassesTheRecordedAnswer(t *testing.T) {
	if v := ReadBack(testPlan(), marshal(t, recordedInfo(t)), true); !v.OK() {
		t.Fatalf("%+v", v)
	}
}

// TestReadBackRefusals is one case per decision-4 rule: each mutation of
// the recorded answer is built_below_plan naming why.
func TestReadBackRefusals(t *testing.T) {
	cases := []struct {
		name string
		mut  func(m map[string]any)
		says string
	}{
		{"a NIC", func(m map[string]any) {
			cfgOf(m)["net"] = []any{map[string]any{"tap": "tap0", "id": "_net0"}}
		}, "network device"},
		{"a NIC in the device tree only", func(m map[string]any) {
			m["device_tree"].(map[string]any)["_net1"] = map[string]any{"id": "_net1"}
		}, "_net1"},
		{"a VFIO device", func(m map[string]any) { cfgOf(m)["devices"] = []any{map[string]any{"path": "/sys/x"}} }, "passthrough"},
		{"another CID", func(m map[string]any) { cfgOf(m)["vsock"].(map[string]any)["cid"] = 9 }, "another CID"},
		{"no vsock", func(m map[string]any) { delete(cfgOf(m), "vsock") }, "vsock device is missing"},
		{"an unplanned share", func(m map[string]any) {
			fs := cfgOf(m)["fs"].([]any)
			cfgOf(m)["fs"] = append(fs, map[string]any{"tag": "home", "socket": "/tmp/x.sock", "id": "_fs9"})
		}, "unplanned share"},
		{"a missing share", func(m map[string]any) { cfgOf(m)["fs"] = cfgOf(m)["fs"].([]any)[:1] }, "fs-ws is missing"},
		{"an unplanned disk", func(m map[string]any) {
			d := cfgOf(m)["disks"].([]any)
			cfgOf(m)["disks"] = append(d, map[string]any{"path": "/home/u/.ssh.img", "readonly": false, "id": "_disk2"})
		}, "unplanned disk"},
		{"a writable rootfs", func(m map[string]any) {
			cfgOf(m)["disks"].([]any)[0].(map[string]any)["readonly"] = false
		}, "disk rootfs has another mode"},
		{"unshared memory", func(m map[string]any) { cfgOf(m)["memory"].(map[string]any)["shared"] = false }, "not shared"},
		{"another cmdline", func(m map[string]any) {
			cfgOf(m)["payload"].(map[string]any)["cmdline"] = "console=ttyS0 init=/bin/sh"
		}, "command line differs"},
		{"a virtio console", func(m map[string]any) { cfgOf(m)["console"].(map[string]any)["mode"] = "Tty" }, "console is on"},
		{"not running", func(m map[string]any) { m["state"] = "Created" }, "not Running"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := recordedInfo(t)
			tc.mut(m)
			v := ReadBack(testPlan(), marshal(t, m), true)
			if v.Code != VerdictBuiltBelowPlan || !strings.Contains(v.Reason, tc.says) {
				t.Fatalf("%+v, want built_below_plan naming %q", v, tc.says)
			}
		})
	}
}

// TestReadBackReshapedOrTruncated: an answer that is not a vm.info object
// is built_below_plan, never a pass.
func TestReadBackReshapedOrTruncated(t *testing.T) {
	full := marshal(t, recordedInfo(t))
	for name, b := range map[string][]byte{
		"truncated":   full[:len(full)/2],
		"empty":       nil,
		"array":       []byte(`[]`),
		"no config":   []byte(`{"state":"Running"}`),
		"disks shape": []byte(strings.Replace(string(full), `"disks":[`, `"disks":{"x":[`, 1)),
		"two objects": append(append([]byte(nil), full...), []byte(` {}`)...),
	} {
		if v := ReadBack(testPlan(), b, false); v.Code != VerdictBuiltBelowPlan {
			t.Errorf("%s: %+v", name, v)
		}
	}
}

// TestReadBackCreatedBeforeBoot: before vm.boot the state is Created and
// the pre-boot read passes.
func TestReadBackCreatedBeforeBoot(t *testing.T) {
	m := recordedInfo(t)
	m["state"] = "Created"
	if v := ReadBack(testPlan(), marshal(t, m), false); !v.OK() {
		t.Fatalf("%+v", v)
	}
}
