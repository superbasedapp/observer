//go:build !windows

package conpty

import (
	"errors"
	"os"
)

// ErrUnsupported is New's error off Windows.
var ErrUnsupported = errors.New("conpty: a pseudo console exists only on Windows")

// Console is a pseudo console (Windows only).
type Console struct {
	// In takes the child's input; Out yields its terminal output.
	In, Out *os.File
}

// New is unsupported off Windows.
func New(cols, rows int) (*Console, error) { return nil, ErrUnsupported }

// Resize is unsupported off Windows.
func (c *Console) Resize(cols, rows int) error { return ErrUnsupported }

// Close is a no-op off Windows.
func (c *Console) Close() {}
