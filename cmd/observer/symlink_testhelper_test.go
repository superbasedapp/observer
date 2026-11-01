package main

import (
	"os"
	"testing"
)

// testSymlink is os.Symlink for a test that needs a symbolic link. On a
// Windows account without Developer Mode (or the create-symbolic-link
// privilege) no link can be made at all, so the test skips with that reason
// instead of failing (Windows 11 Pro live run, PT-02 group "symlink
// privilege"). Every other error is returned to the caller unchanged.
func testSymlink(t *testing.T, oldname, newname string) error {
	t.Helper()
	err := os.Symlink(oldname, newname)
	if err != nil && symlinkPrivilegeMissing(err) {
		t.Skipf("creating a symbolic link needs Windows Developer Mode or the create-symbolic-link privilege on this account: %v", err)
	}
	return err
}
