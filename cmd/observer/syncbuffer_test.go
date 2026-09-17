package main

import (
	"bytes"
	"sync"
)

// syncBuffer is a mutex-guarded bytes.Buffer for tests that capture a cobra
// command's combined stdout/stderr while the command itself writes from more
// than one goroutine. `observer start` is the case in point: its daemon
// loop logs from both the cobra goroutine and an errgroup worker goroutine,
// so a plain bytes.Buffer (safe only for single-goroutine use) trips
// `go test -race`'s data-race detector the moment two of those writes land
// concurrently. This type adds only the mutex bytes.Buffer itself doesn't
// provide; String() is likewise safe to call from the test goroutine while
// the command under test is still writing.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}
