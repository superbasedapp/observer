//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// partBox is a fake box that runs the exec uploader's two scripts in Go: a
// part write stores the one-shot stdin, the unpack joins the parts, checks
// the digest and reads the tar. It records how many execs were in flight.
type partBox struct {
	sandboxremote.Client
	parts     map[string][]byte
	files     map[string][]byte
	inFlight  atomic.Int32
	maxFlight int32
	maxPart   int
}

type doneProc struct {
	io.Reader
	code int
}

func (p doneProc) Write([]byte) (int, error)                    { return 0, errors.New("no stdin") }
func (p doneProc) PID() string                                  { return "" }
func (p doneProc) Resize(context.Context, uint16, uint16) error { return nil }
func (p doneProc) Wait(context.Context) (int, error)            { return p.code, nil }
func (p doneProc) Kill(context.Context) error                   { return nil }
func (p doneProc) Close() error                                 { return nil }

func (b *partBox) Exec(_ context.Context, _ string, spec sandboxremote.ExecSpec) (sandboxremote.Process, error) {
	n := b.inFlight.Add(1)
	defer b.inFlight.Add(-1)
	if n > b.maxFlight {
		b.maxFlight = n
	}
	if spec.Stdin {
		return nil, errors.New("the uploader asked for a streaming stdin")
	}
	switch spec.Argv[2] {
	case hostedExecPartScript:
		b.parts[spec.Argv[4]] = append([]byte(nil), spec.StdinData...)
		b.maxPart = max(b.maxPart, len(spec.StdinData))
		return doneProc{Reader: strings.NewReader(""), code: 0}, nil
	case hostedExecUnpackScript:
		want := spec.Argv[5]
		var joined []byte
		for _, p := range spec.Argv[7:] {
			joined = append(joined, b.parts[p]...)
		}
		sum := sha256.Sum256(joined)
		if hex.EncodeToString(sum[:]) != want {
			return doneProc{Reader: strings.NewReader("observer upload: digest mismatch\n"), code: 3}, nil
		}
		tr := tar.NewReader(bytes.NewReader(joined))
		for {
			h, err := tr.Next()
			if err != nil {
				break
			}
			data, _ := io.ReadAll(tr)
			b.files["/"+h.Name] = data
		}
		return doneProc{Reader: strings.NewReader(""), code: 0}, nil
	}
	return nil, errors.New("unexpected exec")
}

// TestHostedExecWriteFilesOnePartInFlight (lane G4): the exec uploader
// sends bounded one-shot parts one at a time and the box gets every file
// byte-exact after the digest check.
func TestHostedExecWriteFilesOnePartInFlight(t *testing.T) {
	old := hostedExecPartBytes
	hostedExecPartBytes = 1000
	defer func() { hostedExecPartBytes = old }()
	box := &partBox{parts: map[string][]byte{}, files: map[string][]byte{}}
	big := bytes.Repeat([]byte("x"), 5000)
	files := []sandboxremote.UploadFile{
		{Path: "/home/sandbox/ws/a.txt", Mode: 0o644, Size: 3, Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("abc")), nil }},
		{Path: "/home/sandbox/ws/big.bin", Mode: 0o755, Size: int64(len(big)), Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(big)), nil }},
	}
	if err := hostedExecWriteFiles(context.Background(), box, "box", "/home/sandbox/.observer-box/run", nil, hostedExecPartBytes, files); err != nil {
		t.Fatal(err)
	}
	if box.maxFlight != 1 || box.maxPart > 1000 || len(box.parts) < 6 {
		t.Errorf("in flight %d, largest part %d, parts %d", box.maxFlight, box.maxPart, len(box.parts))
	}
	if string(box.files["/home/sandbox/ws/a.txt"]) != "abc" || !bytes.Equal(box.files["/home/sandbox/ws/big.bin"], big) {
		t.Errorf("files %v", len(box.files))
	}
	// A path that is not clean and absolute is refused before anything is sent.
	bad := []sandboxremote.UploadFile{{Path: "/home/sandbox/../etc/x", Size: 0, Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("")), nil }}}
	if err := hostedExecWriteFiles(context.Background(), box, "box", "/tmp", nil, hostedExecPartBytes, bad); err == nil {
		t.Error("an unclean path was uploaded")
	}
}
