// Package conpty is the one owner of a Windows pseudo console (ConPTY): the
// two pipes, CreatePseudoConsole, the proc-thread attribute a child is
// started with, ResizePseudoConsole and the load-bearing close order.
//
// The dashboard's embedded terminal (internal/termsession) hosts every
// daemon-owned terminal in one; the mxc-process host helper hosts a CLI
// launch's box in one (Windows 11 Pro run 3 RERUN2, D1: a box started from
// a classic console window got a console of its own with no window, so
// nothing it printed reached the user). Off Windows, New returns
// ErrUnsupported.
package conpty
