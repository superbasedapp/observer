//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"io"

	"github.com/marmutapp/superbased-observer/internal/termfilter"
)

// copyConsoleOutput copies a pseudo console's output to w until r fails,
// calling seen after each read that returned bytes. With stripOSC52 every
// OSC 52 sequence is removed, also one split across reads (ruling P-175).
func copyConsoleOutput(w io.Writer, r io.Reader, stripOSC52 bool, seen func()) error {
	var f *termfilter.OSC52Stripper
	if stripOSC52 {
		f = &termfilter.OSC52Stripper{}
	}
	buf := make([]byte, 32*1024)
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			seen()
			b := buf[:n]
			if f != nil {
				b = f.Write(b)
			}
			if len(b) > 0 {
				if _, werr := w.Write(b); werr != nil {
					return werr
				}
			}
		}
		if rerr != nil {
			if f != nil {
				if rest := f.Flush(); len(rest) > 0 {
					_, _ = w.Write(rest)
				}
			}
			return rerr
		}
	}
}
