//go:build !windows && !linux && !darwin

package main

// platformGUIInstanceRunning cannot tell on this OS: false keeps the launch
// verdict as it was.
func platformGUIInstanceRunning(string) bool { return false }
