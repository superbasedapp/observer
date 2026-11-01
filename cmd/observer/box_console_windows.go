//go:build windows

package main

import "golang.org/x/sys/windows"

// boxConsoleWindow says what this process's console is: "visible",
// "hidden" (a console with no shown window: a pseudo console's, or one
// Windows made without a window) or "none".
func boxConsoleWindow() string {
	k := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleWindow")
	h, _, _ := k.Call()
	if h == 0 {
		return "none (GetConsoleWindow 0: a console without a window)"
	}
	u := windows.NewLazySystemDLL("user32.dll")
	if err := u.Load(); err != nil {
		return "present (visibility unknown: user32 does not load)"
	}
	if v, _, _ := u.NewProc("IsWindowVisible").Call(h); v != 0 {
		return "visible"
	}
	return "hidden"
}
