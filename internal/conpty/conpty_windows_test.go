//go:build windows

package conpty

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestConsoleCarriesAChildsOutput: a child started on the pseudo console
// (PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, NULL standard handles) prints into
// Out, and the tail arrives after CloseConsoleKeepOutput.
func TestConsoleCarriesAChildsOutput(t *testing.T) {
	c, err := New(100, 30)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Resize(120, 40); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	var got bytes.Buffer
	done := make(chan struct{})
	go func() { _, _ = io.Copy(&got, c.Out); close(done) }()
	al, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		t.Fatal(err)
	}
	defer al.Delete()
	if err := al.Update(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, AttrValue(&c.HPC), unsafe.Sizeof(c.HPC)); err != nil {
		t.Fatal(err)
	}
	var si windows.StartupInfoEx
	si.Cb = uint32(unsafe.Sizeof(si))
	si.ProcThreadAttributeList = al.List()
	si.Flags = windows.STARTF_USESTDHANDLES
	cmd := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	line, _ := windows.UTF16PtrFromString(`cmd.exe /d /c echo SBO-CONPTY-LINE`)
	app, _ := windows.UTF16PtrFromString(cmd)
	var pi windows.ProcessInformation
	if err := windows.CreateProcess(app, line, nil, nil, false, windows.EXTENDED_STARTUPINFO_PRESENT, nil, nil, &si.StartupInfo, &pi); err != nil {
		t.Fatal(err)
	}
	_, _ = windows.WaitForSingleObject(pi.Process, 10_000)
	_ = windows.CloseHandle(pi.Thread)
	_ = windows.CloseHandle(pi.Process)
	c.CloseConsoleKeepOutput()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the output did not end")
	}
	_ = c.Out.Close()
	if !strings.Contains(got.String(), "SBO-CONPTY-LINE") {
		t.Fatalf("output %q lacks the child's line", got.String())
	}
}
