//go:build !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"reflect"
	"testing"
)

// TestMXCBoxTempEnv: inside a recognised box, TEMP and TMP point at the
// run's own temp directory (the inner log's) and the LOCALAPPDATA Windows
// derived under the run's box directory is created; a LOCALAPPDATA outside
// the run is never created (Windows 11 Pro rerun 2026-10-25, D1: the
// folders the box environment named did not exist).
func TestMXCBoxTempEnv(t *testing.T) {
	const box = `C:\Users\u\AppData\Local\Temp\observer-sbx-r1`
	const ac = box + `\localappdata\Packages\sandbox.{g}\AC`
	for _, c := range []struct {
		name  string
		env   map[string]string
		set   [][2]string
		mkdir []string
	}{
		{
			name:  "a box",
			env:   map[string]string{sandboxInnerLogEnv: box + `\tmp\observer-inner.log`, "LOCALAPPDATA": ac, "TEMP": ac + `\Temp`},
			set:   [][2]string{{"TEMP", box + `\tmp`}, {"TMP", box + `\tmp`}},
			mkdir: []string{ac},
		},
		{
			name: "LOCALAPPDATA outside the run",
			env:  map[string]string{sandboxInnerLogEnv: box + `\tmp\observer-inner.log`, "LOCALAPPDATA": `C:\Users\u\AppData\Local`},
			set:  [][2]string{{"TEMP", box + `\tmp`}, {"TMP", box + `\tmp`}},
		},
		{
			name: "no inner log, a relative LOCALAPPDATA",
			env:  map[string]string{"LOCALAPPDATA": `localappdata\x`},
		},
	} {
		set, mkdir := mxcBoxTempEnv(func(k string) string { return c.env[k] }, box)
		if !reflect.DeepEqual(set, c.set) || !reflect.DeepEqual(mkdir, c.mkdir) {
			t.Errorf("%s: set %v mkdir %v; want %v %v", c.name, set, mkdir, c.set, c.mkdir)
		}
	}
}
