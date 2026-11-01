//go:build windows

package conpty

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ErrUnsupported is New's error on a Windows without CreatePseudoConsole
// (before Windows 10 1809).
var ErrUnsupported = errors.New("conpty: this Windows has no CreatePseudoConsole")

// available reports whether kernel32 exposes CreatePseudoConsole.
var available = sync.OnceValue(func() bool {
	return windows.NewLazySystemDLL("kernel32.dll").NewProc("CreatePseudoConsole").Find() == nil
})

// Available reports whether this Windows can create a pseudo console.
func Available() bool { return available() }

// Console is one pseudo console: In takes the child's input (keystrokes,
// VT input), Out yields its terminal output (VT), HPC is the handle a child
// is started on (AttrValue).
type Console struct {
	HPC windows.Handle
	In  *os.File
	Out *os.File

	once sync.Once
}

// New creates a cols x rows pseudo console (80 x 24 for a zero size).
func New(cols, rows int) (*Console, error) {
	if !available() {
		return nil, ErrUnsupported
	}
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}
	// Two pipes: one feeds the child's input (we keep the write end), one
	// drains its output (we keep the read end). ConPTY takes the opposite
	// ends and holds its own references, so ours are closed after
	// CreatePseudoConsole.
	var inRead, inWrite, outRead, outWrite windows.Handle
	if err := windows.CreatePipe(&inRead, &inWrite, nil, 0); err != nil {
		return nil, fmt.Errorf("conpty: create input pipe: %w", err)
	}
	if err := windows.CreatePipe(&outRead, &outWrite, nil, 0); err != nil {
		_ = windows.CloseHandle(inRead)
		_ = windows.CloseHandle(inWrite)
		return nil, fmt.Errorf("conpty: create output pipe: %w", err)
	}
	var hpc windows.Handle
	err := windows.CreatePseudoConsole(windows.Coord{X: clamp(cols), Y: clamp(rows)}, inRead, outWrite, 0, &hpc)
	_ = windows.CloseHandle(inRead)
	_ = windows.CloseHandle(outWrite)
	if err != nil {
		_ = windows.CloseHandle(inWrite)
		_ = windows.CloseHandle(outRead)
		return nil, fmt.Errorf("conpty: create pseudoconsole: %w", err)
	}
	return &Console{
		HPC: hpc,
		In:  os.NewFile(uintptr(inWrite), "conpty-in"),
		Out: os.NewFile(uintptr(outRead), "conpty-out"),
	}, nil
}

func clamp(n int) int16 {
	if n > 32767 {
		return 32767
	}
	return int16(n) //nolint:gosec // G115: bounded above
}

// Resize sets the pseudo console's size (80 x 24 for a zero size).
func (c *Console) Resize(cols, rows int) error {
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}
	return windows.ResizePseudoConsole(c.HPC, windows.Coord{X: clamp(cols), Y: clamp(rows)})
}

// AttrValue is the lpValue UpdateProcThreadAttribute expects for
// PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE: the HPCON itself (Microsoft's own
// sample passes hPC, not &hPC), read through the handle variable's memory
// so no unsafe.Pointer is made from an integer (go vet's unsafeptr check).
func AttrValue(h *windows.Handle) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(h))
}

// Close releases the pseudo console and both pipe ends once.
//
// ORDER IS LOAD-BEARING: ClosePseudoConsole flushes the remaining output
// and, per its documentation, the caller must either close the output pipe
// first or keep reading it until ClosePseudoConsole has returned; on builds
// before 26100 it otherwise waits indefinitely. Close is called with
// nothing guaranteed to be draining, so the OUTPUT pipe closes first, then
// the pseudo console, then the input pipe. A caller that wants the last
// output reads Out to EOF after CloseConsoleKeepOutput instead.
func (c *Console) Close() {
	c.once.Do(func() {
		_ = c.Out.Close()
		windows.ClosePseudoConsole(c.HPC)
		_ = c.In.Close()
	})
}

// CloseConsoleKeepOutput closes the pseudo console and the input pipe but
// keeps Out open, for a caller whose reader is still copying Out: the
// reader then sees the flushed tail and EOF, and must close Out itself.
// ClosePseudoConsole returns once the output is drained, so the reader must
// be running.
func (c *Console) CloseConsoleKeepOutput() {
	c.once.Do(func() {
		windows.ClosePseudoConsole(c.HPC)
		_ = c.In.Close()
	})
}
