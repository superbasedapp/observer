//go:build !windows

package sandboxrelayd

// claimOwnership has nothing to do off Windows: a created file is owned by
// the creating user (owner_windows.go has the elevated-token case).
func claimOwnership(string) error { return nil }
