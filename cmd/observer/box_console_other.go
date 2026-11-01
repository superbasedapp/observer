//go:build !windows

package main

// boxConsoleWindow is not read off Windows (the console field is the MXC
// driver's, a Windows box).
func boxConsoleWindow() string { return "not read on this OS" }
