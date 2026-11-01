package hookbridgesvc

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestRunPassesStreamsAndCodes runs a real child (this test binary in a
// helper mode) in place of wsl.exe: stdin reaches it byte for byte, its
// stdout and stderr come back byte for byte, its exit code is reported, and
// a program that cannot start is Started=false.
func TestRunPassesStreamsAndCodes(t *testing.T) {
	if os.Getenv("HOOKBRIDGE_HELPER") == "1" {
		return
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("{\"tool\":\"Bash\",\"x\":\"é\\u0000\r\n\"}\n")
	t.Setenv("HOOKBRIDGE_HELPER", "1")
	res := Run(context.Background(), self, []string{"-test.run=TestHelperProcess", "--", "exit=86"}, bytes.NewReader(payload))
	if !res.Run.Started || res.Run.ExitCode != 86 || res.Run.OutputOverflow {
		t.Fatalf("run = %+v", res.Run)
	}
	if !bytes.Equal(res.Stdout, append([]byte("OUT:"), payload...)) {
		t.Fatalf("stdout = %q", res.Stdout)
	}
	if string(res.Stderr) != "ERR\r\n" {
		t.Fatalf("stderr = %q", res.Stderr)
	}
	missing := filepath.Join(t.TempDir(), "no-such-wsl")
	if runtime.GOOS == "windows" {
		missing += ".exe"
	}
	if r := Run(context.Background(), missing, nil, strings.NewReader("")); r.Run.Started {
		t.Fatalf("a missing program must read as not started: %+v", r.Run)
	}
}

// TestHelperProcess is the child: it echoes stdin to stdout behind "OUT:",
// writes "ERR\r\n" to stderr and exits with the code after "exit=".
func TestHelperProcess(t *testing.T) {
	if os.Getenv("HOOKBRIDGE_HELPER") != "1" {
		return
	}
	for _, a := range os.Args {
		if a == "hang" {
			time.Sleep(time.Minute)
		}
	}
	in, _ := io.ReadAll(os.Stdin)
	_, _ = os.Stdout.Write(append([]byte("OUT:"), in...))
	_, _ = os.Stderr.WriteString("ERR\r\n")
	code := 0
	for _, a := range os.Args {
		if v, ok := strings.CutPrefix(a, "exit="); ok {
			for _, c := range v {
				code = code*10 + int(c-'0')
			}
		}
	}
	os.Exit(code)
}

// TestRunTimesOutAHangingChild pins the bridge deadline (second audit item
// 2): a child that never answers is killed when ctx's deadline fires and
// the run reads TimedOut, well before the child would have finished.
func TestRunTimesOutAHangingChild(t *testing.T) {
	if os.Getenv("HOOKBRIDGE_HELPER") == "1" {
		return
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOOKBRIDGE_HELPER", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	res := Run(ctx, self, []string{"-test.run=TestHelperProcess", "--", "hang"}, strings.NewReader(""))
	if !res.Run.Started || !res.Run.TimedOut {
		t.Fatalf("run = %+v, want started and timed out", res.Run)
	}
	if took := time.Since(start); took > 20*time.Second {
		t.Fatalf("the hanging child was not killed at the deadline (took %v)", took)
	}
}

func TestCappedBuffer(t *testing.T) {
	b := &cappedBuffer{max: 4}
	n, err := b.Write([]byte("abcdef"))
	if n != 6 || err != nil || string(b.buf) != "abcd" || !b.overflow {
		t.Fatalf("n %d err %v buf %q overflow %v", n, err, b.buf, b.overflow)
	}
}
