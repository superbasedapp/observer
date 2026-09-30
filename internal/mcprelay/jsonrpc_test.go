package mcprelay

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// fragReader hands out a stream in fixed-size fragments.
type fragReader struct {
	data []byte
	n    int
}

func (f *fragReader) Read(p []byte) (int, error) {
	if len(f.data) == 0 {
		return 0, io.EOF
	}
	k := f.n
	if k > len(f.data) {
		k = len(f.data)
	}
	if k > len(p) {
		k = len(p)
	}
	copy(p, f.data[:k])
	f.data = f.data[k:]
	return k, nil
}

func TestFrameReaderByteExactUnderFragmentation(t *testing.T) {
	frames := [][]byte{
		[]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","arguments":{"s":"tab\t and unicode ✓"}}}`),
		[]byte(`{"jsonrpc":"2.0","id":2,"method":"ping"}` + "\r"),
		[]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`),
	}
	var stream bytes.Buffer
	for _, f := range frames {
		stream.Write(f)
		stream.WriteByte('\n')
	}
	stream.WriteString("\n\n") // blank lines between messages are legal
	for _, n := range []int{1, 3, 7, 64, 100000} {
		t.Run("fragment", func(t *testing.T) {
			fr := NewFrameReader(&fragReader{data: append([]byte(nil), stream.Bytes()...), n: n}, 0)
			for i, want := range frames {
				got, err := fr.Next()
				if err != nil {
					t.Fatalf("frame %d (n=%d): %v", i, n, err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("frame %d (n=%d): bytes differ:\n%q\n%q", i, n, got, want)
				}
			}
			if _, err := fr.Next(); !errors.Is(err, io.EOF) {
				t.Fatalf("want EOF, got %v", err)
			}
		})
	}
}

func TestFrameReaderCapAndUnterminated(t *testing.T) {
	fr := NewFrameReader(strings.NewReader(strings.Repeat("x", 100)), 10)
	if _, err := fr.Next(); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("want ErrFrameTooLarge, got %v", err)
	}
	fr = NewFrameReader(strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`), 0)
	got, err := fr.Next()
	if err != nil || string(got) != `{"jsonrpc":"2.0","id":1,"method":"ping"}` {
		t.Fatalf("unterminated final line: %q %v", got, err)
	}
}

func TestWriteFrameRefusesEmbeddedNewline(t *testing.T) {
	var b bytes.Buffer
	if err := WriteFrame(&b, []byte("a\nb")); err == nil {
		t.Fatal("embedded newline accepted")
	}
	if err := WriteFrame(&b, []byte(`{"x":1}`)); err != nil || b.String() != "{\"x\":1}\n" {
		t.Fatalf("frame write: %q %v", b.String(), err)
	}
}

func TestParseMessageAndClassify(t *testing.T) {
	cases := []struct {
		name   string
		raw    string
		err    error
		class  MethodClass
		target string
		event  string
	}{
		{"tools/call", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"gh_search"}}`, nil, ClassGoverned, "gh_search", "mcp_call"},
		{"resources/read", `{"jsonrpc":"2.0","id":"a","method":"resources/read","params":{"uri":"file:///x"}}`, nil, ClassGoverned, "file:///x", "mcp_read"},
		{"completion ref", `{"jsonrpc":"2.0","id":2,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"p"}}}`, nil, ClassGoverned, "p", "mcp_read"},
		{"tasks/get", `{"jsonrpc":"2.0","id":3,"method":"tasks/get","params":{"taskId":"t1"}}`, nil, ClassGoverned, "t1", "mcp_task"},
		{"tools/list", `{"jsonrpc":"2.0","id":4,"method":"tools/list"}`, nil, ClassCatalogue, "", "mcp_list"},
		{"initialize", `{"jsonrpc":"2.0","id":5,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`, nil, ClassProtocol, "", "mcp_list"},
		{"notification", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, nil, ClassProtocol, "", "mcp_list"},
		{"unknown", `{"jsonrpc":"2.0","id":6,"method":"vendor/x"}`, nil, ClassProtocol, "", "mcp_list"},
		{"batch", `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`, ErrBatch, "", "", ""},
		{"bad version", `{"jsonrpc":"1.0","id":1,"method":"ping"}`, errors.New("x"), "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := ParseMessage([]byte(tc.raw))
			if tc.err != nil {
				if err == nil || (errors.Is(tc.err, ErrBatch) && !errors.Is(err, ErrBatch)) {
					t.Fatalf("want error %v, got %v", tc.err, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			row, target, _ := classify(m)
			if row.Class != tc.class || target != tc.target || row.EventKind != tc.event {
				t.Fatalf("got class=%s target=%q event=%s", row.Class, target, row.EventKind)
			}
		})
	}
}

func TestReadSSE(t *testing.T) {
	body := ": comment\nevent: message\ndata: {\"a\":1}\n\ndata: line1\ndata: line2\n\n"
	evs, err := readSSE(strings.NewReader(body), 1<<20)
	if err != nil || len(evs) != 2 {
		t.Fatalf("%v %d", err, len(evs))
	}
	if evs[0].Event != "message" || string(evs[0].Data) != `{"a":1}` || string(evs[1].Data) != "line1\nline2" {
		t.Fatalf("%+v", evs)
	}
}
