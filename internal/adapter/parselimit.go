package adapter

import (
	"bufio"
	"context"
	"errors"
	"io"
)

// BOUNDED TAIL PARSES (T-413).
//
// The watcher's MaxFileBytes DoS guard bounds how much one parse may read.
// For a seek-and-stream file it compares the UNREAD TAIL against the cap,
// and before this seam it SKIPPED a file whose tail was over the cap. That
// is permanent capture loss the moment the watcher falls behind: the tail
// only grows, so the gate never reopens (the 2026-10-05 node had three
// transcripts frozen this way, 59 to 72 MB behind).
//
// An adapter that declares FileCursorSemantics.ChunkedTail instead honours a
// per-call byte limit carried on the parse context: it reads at most that
// many bytes past fromOffset and stops at the last complete record inside
// the window, which is exactly how it already stops at the current end of a
// file that is still being written. The watcher then catches up one window
// per pass, and one parse never reads more than the cap.

type parseByteLimitKey struct{}

// WithParseByteLimit returns ctx carrying a per-parse read limit of n bytes
// past the parse's fromOffset. n <= 0 means unlimited (ctx is returned
// unchanged). Only adapters that declared ChunkedTail read it.
func WithParseByteLimit(ctx context.Context, n int64) context.Context {
	if n <= 0 {
		return ctx
	}
	return context.WithValue(ctx, parseByteLimitKey{}, n)
}

// ParseByteLimit returns the read limit WithParseByteLimit put on ctx, or 0
// (unlimited) when none was set.
func ParseByteLimit(ctx context.Context) int64 {
	if ctx == nil {
		return 0
	}
	n, _ := ctx.Value(parseByteLimitKey{}).(int64)
	return n
}

// LimitTail wraps r (positioned at the parse's fromOffset) so it ends after
// the ctx's ParseByteLimit bytes. With no limit it returns r unchanged. A
// record cut by the limit reads exactly like an unterminated record at the
// end of a file that is still being written, which every ChunkedTail
// adapter already defers whole to its next parse.
func LimitTail(ctx context.Context, r io.Reader) io.Reader {
	if n := ParseByteLimit(ctx); n > 0 {
		return io.LimitReader(r, n)
	}
	return r
}

// ReadRecord reads one '\n'-terminated record from r under the maxBytes
// memory-safety bound, growing its buffer only as far as the bound (never
// loading a pathologically large line whole). It is the one bounded line
// reader behind the over-long-record rule (ADAPT-LZ-4; docs/adapters.md
// rule 5), shared by the codex and gemini parsers.
//
// It returns the record bytes INCLUDING the terminating '\n' when one was
// present, the total bytes consumed from the stream for the record (used
// to advance the byte cursor even when the record is skipped), whether the
// record exceeded maxBytes (in which case data is nil and its bytes have
// been fully drained), and the terminating read error (io.EOF on the final
// read). A clean end of stream yields consumed == 0 (and io.EOF).
//
// The err return is the terminator signal callers rely on: bufio's
// ReadSlice reports a nil error the moment it locates '\n' and io.EOF only
// when the stream ends before one is found. So a record returned with
// consumed > 0 AND err == io.EOF is an UNTERMINATED trailing fragment (the
// tool has not finished writing it); one returned with err == nil is
// '\n'-terminated and complete. Callers defer unterminated trailing
// records uniformly: only a terminated record may move the byte cursor.
//
// Compared with bufio.Scanner, a record larger than the bound degrades to
// a per-record skip instead of a whole-file failure, and consumed is the
// exact terminator-inclusive length, so cursor arithmetic is CRLF-correct.
func ReadRecord(r *bufio.Reader, maxBytes int64) (data []byte, consumed int64, oversized bool, err error) {
	var buf []byte
	for {
		frag, readErr := r.ReadSlice('\n')
		consumed += int64(len(frag))
		if !oversized {
			if int64(len(buf))+int64(len(frag)) > maxBytes {
				// The record crossed the bound: stop accumulating, drop
				// what we have, and keep draining to the terminator so the
				// cursor advances past the whole record.
				oversized = true
				buf = nil
			} else {
				// frag aliases r's internal buffer (valid only until the
				// next read); append copies it out immediately.
				buf = append(buf, frag...)
			}
		}
		if errors.Is(readErr, bufio.ErrBufferFull) {
			continue
		}
		if oversized {
			return nil, consumed, true, readErr
		}
		return buf, consumed, false, readErr
	}
}

// TailChunkable reports whether the watcher may read this file's oversize
// tail in bounded windows instead of skipping it: the adapter declared
// ChunkedTail AND the delta gate applies (a seek-and-stream byte cursor).
func (s FileCursorSemantics) TailChunkable() bool {
	return s.ChunkedTail && s.DeltaGateMeaningful()
}
