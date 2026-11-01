//go:build windows

package crossmount

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// TestWSLExePathIgnoresSystemRoot (FU-209): the path comes from
// GetSystemDirectory, so a doctored %SystemRoot% does not move it.
func TestWSLExePathIgnoresSystemRoot(t *testing.T) {
	t.Setenv("SystemRoot", `D:\Elsewhere`)
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	got := wslExePath()
	if got != dir+`\wsl.exe` || strings.HasPrefix(strings.ToLower(got), `d:\elsewhere`) {
		t.Errorf("wslExePath() = %q, want %q (GetSystemDirectory), never under %%SystemRoot%%", got, dir+`\wsl.exe`)
	}
}
