package adapter

import (
	"bufio"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestLimitTail(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		limit int64
		want  string
	}{
		{"no limit reads everything", 0, "line1\nline2\nline3\n"},
		{"negative limit is no limit", -5, "line1\nline2\nline3\n"},
		{"limit cuts mid-line", 8, "line1\nli"},
		{"limit past the end reads everything", 1 << 20, "line1\nline2\nline3\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := WithParseByteLimit(context.Background(), tc.limit)
			if tc.limit <= 0 && ctx != context.Background() {
				t.Fatal("a non-positive limit must leave the context unchanged")
			}
			b, err := io.ReadAll(LimitTail(ctx, strings.NewReader("line1\nline2\nline3\n")))
			if err != nil {
				t.Fatal(err)
			}
			if string(b) != tc.want {
				t.Fatalf("read %q, want %q", b, tc.want)
			}
		})
	}
	if ParseByteLimit(nil) != 0 { //nolint:staticcheck // SA1012: nil is the case under test.
		t.Fatal("nil context must report no limit")
	}
}

func TestTailChunkable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		sem  FileCursorSemantics
		want bool
	}{
		{"zero value", FileCursorSemantics{}, false},
		{"streams but not declared", FileCursorSemantics{StreamsFromCursor: true}, false},
		{"declared without streaming", FileCursorSemantics{ChunkedTail: true}, false},
		{"streaming byte cursor, declared", FileCursorSemantics{StreamsFromCursor: true, ChunkedTail: true}, true},
		{"watermark cursor never chunks", FileCursorSemantics{Kind: CursorWatermark, StreamsFromCursor: true, ChunkedTail: true}, false},
	}
	for _, tc := range cases {
		if got := tc.sem.TailChunkable(); got != tc.want {
			t.Errorf("%s: TailChunkable = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestReadRecord(t *testing.T) {
	// A 16-byte bufio buffer forces the long record through ErrBufferFull.
	r := bufio.NewReaderSize(strings.NewReader("ab\r\n"+strings.Repeat("x", 40)+"\nok\ntail"), 16)
	type rec struct {
		data      string
		consumed  int64
		oversized bool
		eof       bool
	}
	var got []rec
	for {
		data, consumed, oversized, err := ReadRecord(r, 32)
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("ReadRecord: %v", err)
		}
		got = append(got, rec{string(data), consumed, oversized, errors.Is(err, io.EOF)})
		if err != nil {
			break
		}
	}
	want := []rec{
		{"ab\r\n", 4, false, false}, // CRLF counted in consumed
		{"", 41, true, false},       // over the bound: drained, data dropped
		{"ok\n", 3, false, false},   // the reader is back in step
		{"tail", 4, false, true},    // unterminated trailing fragment
	}
	if len(got) != len(want) {
		t.Fatalf("records = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("record %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if _, consumed, _, err := ReadRecord(bufio.NewReader(strings.NewReader("")), 32); consumed != 0 || !errors.Is(err, io.EOF) {
		t.Errorf("clean end = consumed %d err %v, want 0 and io.EOF", consumed, err)
	}
}
