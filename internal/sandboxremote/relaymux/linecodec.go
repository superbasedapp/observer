package relaymux

import (
	"bufio"
	"encoding/base64"
	"errors"
	"io"
	"sync"
)

// linecodec.go carries the mux's bytes as base64 lines, so a vendor stream
// that is text-only (Vercel's command logs are UTF-8 strings), line-buffered
// or base64 already (E2B's process events) still delivers every byte
// unchanged. Each line is one chunk: base64 of at most MaxLineChunk bytes,
// then '\n'. A line longer than the codec's cap is a hostile or broken peer
// and closes the channel (ErrLineTooLong).

// MaxLineChunk is the most raw bytes one line carries.
const MaxLineChunk = 48 << 10

// maxLine is the longest encoded line accepted (with its newline).
var maxLine = base64.StdEncoding.EncodedLen(MaxLineChunk) + 1

// ErrLineTooLong reports a line over the cap.
var ErrLineTooLong = errors.New("relaymux: line over the cap")

// ErrBadLine reports a line that is not base64.
var ErrBadLine = errors.New("relaymux: line is not base64")

// LineReader decodes base64 lines into a byte stream.
type LineReader struct {
	r       *bufio.Reader
	pending []byte
	dec     []byte
}

// NewLineReader wraps r.
func NewLineReader(r io.Reader) *LineReader {
	return &LineReader{r: bufio.NewReaderSize(r, maxLine+16), dec: make([]byte, MaxLineChunk)}
}

// Read returns decoded bytes.
func (l *LineReader) Read(p []byte) (int, error) {
	for len(l.pending) == 0 {
		line, err := l.r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) || len(line) > maxLine {
			return 0, ErrLineTooLong
		}
		if err != nil {
			if err == io.EOF && len(line) > 0 {
				return 0, io.ErrUnexpectedEOF
			}
			return 0, err
		}
		line = line[:len(line)-1]
		if n := len(line); n > 0 && line[n-1] == '\r' {
			line = line[:n-1]
		}
		if len(line) == 0 {
			continue
		}
		n, derr := base64.StdEncoding.Decode(l.dec, line)
		if derr != nil {
			return 0, ErrBadLine
		}
		l.pending = l.dec[:n]
	}
	n := copy(p, l.pending)
	l.pending = l.pending[n:]
	return n, nil
}

// LineWriter encodes a byte stream as base64 lines. Safe for concurrent use
// (one Write is one or more whole lines).
type LineWriter struct {
	mu  sync.Mutex
	w   io.Writer
	buf []byte
}

// NewLineWriter wraps w.
func NewLineWriter(w io.Writer) *LineWriter { return &LineWriter{w: w} }

// Write encodes p.
func (l *LineWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	done := 0
	for done < len(p) {
		chunk := p[done:]
		if len(chunk) > MaxLineChunk {
			chunk = chunk[:MaxLineChunk]
		}
		n := base64.StdEncoding.EncodedLen(len(chunk))
		if cap(l.buf) < n+1 {
			l.buf = make([]byte, n+1)
		}
		b := l.buf[:n+1]
		base64.StdEncoding.Encode(b, chunk)
		b[n] = '\n'
		if _, err := l.w.Write(b); err != nil {
			return done, err
		}
		done += len(chunk)
	}
	return done, nil
}
