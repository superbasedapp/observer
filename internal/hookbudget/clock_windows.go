//go:build windows

package hookbudget

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// The Windows harness clock: QueryPerformanceCounter, whose tick is 100 ns
// on current Windows (a 10 MHz frequency), against the about 0.52 ms step
// of Go's monotonic clock there (JSP-2 laptop half).
var (
	procQPC = windows.NewLazySystemDLL("kernel32.dll").NewProc("QueryPerformanceCounter")
	procQPF = windows.NewLazySystemDLL("kernel32.dll").NewProc("QueryPerformanceFrequency")
)

// platformClock returns QueryPerformanceCounter, or ok false when the
// frequency cannot be read (never on a supported Windows; the fallback is
// Go's monotonic clock).
func platformClock() (clock, bool) {
	if procQPC.Find() != nil || procQPF.Find() != nil {
		return clock{}, false
	}
	var freq int64
	if r, _, _ := procQPF.Call(uintptr(unsafe.Pointer(&freq))); r == 0 || freq <= 0 {
		return clock{}, false
	}
	return clock{source: "QueryPerformanceCounter", freq: freq, read: readQPC}, true
}

// readQPC reads the counter. QueryPerformanceCounter cannot fail on
// Windows XP and later (platformClock already proved it resolves).
func readQPC() int64 {
	var c int64
	_, _, _ = procQPC.Call(uintptr(unsafe.Pointer(&c)))
	return c
}
