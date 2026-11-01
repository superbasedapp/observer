package relaymux

import (
	"io"
	"sync"
)

// pipeEnd is one end of an in-memory duplex pipe: what one end writes the
// other reads. CloseWrite ends this end's writing only (a half close).
type pipeEnd struct {
	r    *io.PipeReader
	w    *io.PipeWriter
	once sync.Once
}

// newPipePair returns two connected ends.
func newPipePair() (*pipeEnd, *pipeEnd) {
	ar, bw := io.Pipe()
	br, aw := io.Pipe()
	return &pipeEnd{r: ar, w: aw}, &pipeEnd{r: br, w: bw}
}

func (p *pipeEnd) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *pipeEnd) Write(b []byte) (int, error) { return p.w.Write(b) }

// CloseWrite tells the other end no more bytes come.
func (p *pipeEnd) CloseWrite() error { return p.w.Close() }

// Close ends both directions.
func (p *pipeEnd) Close() error {
	p.once.Do(func() {
		_ = p.w.Close()
		_ = p.r.Close()
	})
	return nil
}
