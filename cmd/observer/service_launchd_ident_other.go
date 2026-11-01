//go:build !darwin

package main

// launchdProcessIdentity: launchd runs on macOS only, so elsewhere no
// identity is read and the stop path (exercised by tests with fakes) judges
// by the pid alone.
func launchdProcessIdentity(int) (string, bool) { return "", false }
