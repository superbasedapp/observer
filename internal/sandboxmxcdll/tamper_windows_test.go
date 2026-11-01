//go:build windows

package sandboxmxcdll

import (
	"fmt"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// tamper_windows_test.go is the WINFIX4 audit's measurement of finding 1 as
// a test helper: from inside the box's job, open another process of the box
// with PROCESS_DUP_HANDLE (every process of a box shares its AppContainer,
// so the tool may), duplicate each of its handles, and try
// SetInformationJobObject(class 0) on every job handle among them.

var (
	ntdll             = windows.NewLazySystemDLL("ntdll.dll")
	procNtQueryObject = ntdll.NewProc("NtQueryObject")
)

// tamperResult is one tamper attempt.
type tamperResult struct {
	Opened  bool
	OpenErr error
	Jobs    int
	Lowered int
	Types   map[string]int
}

// String is the attempt's one line.
func (r tamperResult) String() string {
	if !r.Opened {
		return fmt.Sprintf("tamper opened false (%v)", r.OpenErr)
	}
	return fmt.Sprintf("tamper opened true, %d job handle(s), %d lowered", r.Jobs, r.Lowered)
}

// TypesText is the duplicated handles counted by object type, sorted.
func (r tamperResult) TypesText() string {
	var out []string
	for k, v := range r.Types {
		out = append(out, fmt.Sprintf("%s=%d", k, v))
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

// objectTypeName is a handle's object type (NtQueryObject, ObjectTypeInformation).
func objectTypeName(h windows.Handle) string {
	buf := make([]byte, 1024)
	var n uint32
	if r, _, _ := procNtQueryObject.Call(uintptr(h), 2, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&n))); r != 0 {
		return "?"
	}
	us := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0]))
	return us.String()
}

// tamperProcessJob tries to change a job through pid's handles. A lowering
// that succeeds is put back at once (the attempt proves the hole; it never
// leaves a box open).
func tamperProcessJob(pid uint32) tamperResult {
	r := tamperResult{Types: map[string]int{}}
	ph, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, pid)
	if err != nil {
		r.OpenErr = err
		return r
	}
	defer func() { _ = windows.CloseHandle(ph) }()
	r.Opened = true
	self := windows.CurrentProcess()
	for v := uintptr(4); v < 0x10000; v += 4 {
		var h windows.Handle
		if err := windows.DuplicateHandle(ph, windows.Handle(v), self, &h, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
			continue
		}
		r.Types[objectTypeName(h)]++
		var ui windows.JOBOBJECT_BASIC_UI_RESTRICTIONS
		if err := windows.QueryInformationJobObject(h, windows.JobObjectBasicUIRestrictions, uintptr(unsafe.Pointer(&ui)), uint32(unsafe.Sizeof(ui)), nil); err == nil {
			r.Jobs++
			zero := windows.JOBOBJECT_BASIC_UI_RESTRICTIONS{}
			if _, err := windows.SetInformationJobObject(h, windows.JobObjectBasicUIRestrictions, uintptr(unsafe.Pointer(&zero)), uint32(unsafe.Sizeof(zero))); err == nil {
				r.Lowered++
				_, _ = windows.SetInformationJobObject(h, windows.JobObjectBasicUIRestrictions, uintptr(unsafe.Pointer(&ui)), uint32(unsafe.Sizeof(ui)))
			}
		}
		_ = windows.CloseHandle(h)
	}
	return r
}
