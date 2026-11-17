package instabox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// exec.go runs processes. A one-shot command is POST .../exec (it blocks
// until the command exits; the vendor caps it at 600 s). A process with a
// streaming stdin rides the terminal WebSocket (GET .../terminal), in a
// fresh session whose PTY a start script puts in raw mode before it execs
// the program, so the stream is byte-transparent.

// execTimeoutSeconds is the most one exec may run (the vendor's maximum).
const execTimeoutSeconds = 600

// maxExecStdin is the most a one-shot stdin carries (1 MiB of UTF-8).
const maxExecStdin = 1 << 20

// wsChunk is the most one terminal message carries (the vendor documents no
// message limit; the client stays well under any common default).
const wsChunk = 32 << 10

// wsReadLimit bounds one terminal message read.
const wsReadLimit = 4 << 20

// maxPreamble bounds what is kept while looking for the start marker (the
// login banner, the prompt and the typed line's echo).
const maxPreamble = 64 << 10

// stderrTail is the most of a streamed process's stderr file read back.
const stderrTail = 64 << 10

// envName is the exec envs rule (OpenAPI ExecRequest.envs).
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// execResult is the exec answer (OpenAPI ExecResult, the fields read).
type execResult struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exitCode"`
	TimedOut bool   `json:"timedOut"`
}

// Exec starts a process. A vendor PTY is refused: the guest helper owns the
// PTY on this row. Without a streaming stdin the command runs to its end
// through POST .../exec (a root step through sudo -n); with one it runs
// over the terminal WebSocket as the box user.
func (c *Client) Exec(ctx context.Context, id string, spec sandboxremote.ExecSpec) (sandboxremote.Process, error) {
	if spec.PTY {
		return nil, fmt.Errorf("instabox: a vendor terminal for the agent: %w", sandboxremote.ErrNotSupported)
	}
	if len(spec.Argv) == 0 || spec.Argv[0] == "" {
		return nil, errors.New("instabox: exec needs an argv")
	}
	for k := range spec.Env {
		if !envName.MatchString(k) {
			return nil, fmt.Errorf("instabox: environment name %q is not one exec accepts", k)
		}
	}
	if spec.Stdin {
		if spec.AsRoot {
			return nil, fmt.Errorf("instabox: a streamed root process: %w", sandboxremote.ErrNotSupported)
		}
		return c.execStream(ctx, id, spec)
	}
	return c.execOnce(ctx, id, spec)
}

// execOnce runs a command to its end and returns a finished process.
func (c *Client) execOnce(ctx context.Context, id string, spec sandboxremote.ExecSpec) (sandboxremote.Process, error) {
	argv := spec.Argv
	if spec.AsRoot {
		argv = append([]string{"sudo", "-n", "--"}, argv...)
	}
	body := map[string]any{"argv": argv, "timeoutSeconds": execTimeoutSeconds}
	if spec.Cwd != "" {
		body["cwd"] = spec.Cwd
	}
	if len(spec.Env) > 0 {
		body["envs"] = spec.Env
	}
	if len(spec.StdinData) > 0 {
		// The stdin is a JSON string: bytes that are not UTF-8 would reach
		// the command as U+FFFD with no error, so they are refused here.
		if !utf8.Valid(spec.StdinData) {
			return nil, errors.New("instabox: a one-shot stdin must be UTF-8 text")
		}
		if len(spec.StdinData) > maxExecStdin {
			return nil, fmt.Errorf("instabox: a one-shot stdin is over %d bytes", maxExecStdin)
		}
		body["stdin"] = string(spec.StdinData)
	}
	var out execResult
	if err := c.doJSON(ctx, request{method: http.MethodPost, path: "/v1/machines/" + url.PathEscape(id) + "/exec"}, body, &out); err != nil {
		return nil, fmt.Errorf("instabox: exec: %w", err)
	}
	if spec.Stderr != nil && out.Stderr != "" {
		_, _ = io.WriteString(spec.Stderr, out.Stderr)
	}
	return &doneProcess{r: strings.NewReader(out.Stdout), code: out.ExitCode}, nil
}

// doneProcess is a one-shot command that has already ended.
type doneProcess struct {
	r    io.Reader
	code int
}

func (p *doneProcess) Read(b []byte) (int, error) { return p.r.Read(b) }

func (p *doneProcess) Write([]byte) (int, error) {
	return 0, errors.New("instabox: the command took no streaming stdin")
}

func (p *doneProcess) PID() string { return "" }

func (p *doneProcess) Resize(context.Context, uint16, uint16) error {
	return fmt.Errorf("instabox: resize: %w", sandboxremote.ErrNotSupported)
}

func (p *doneProcess) Wait(context.Context) (int, error) { return p.code, nil }

func (p *doneProcess) Kill(context.Context) error { return nil }

func (p *doneProcess) Close() error { return nil }

// shellQuote quotes s for sh.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// startScript is the streamed process's start script: it removes itself,
// puts the PTY in raw mode with no echo (so the stream carries every byte
// unchanged), exports the environment, changes to the working directory,
// records its pid (Kill reads it), prints the marker and execs the program
// with stderr to a file.
func startScript(dir, nonce string, spec sandboxremote.ExecSpec) string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("rm -f -- " + shellQuote(dir+"/start.sh") + "\n")
	b.WriteString("stty raw -echo || exit 97\n")
	keys := make([]string, 0, len(spec.Env))
	for k := range spec.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString("export " + k + "=" + shellQuote(spec.Env[k]) + "\n")
	}
	if spec.Cwd != "" {
		b.WriteString("cd -- " + shellQuote(spec.Cwd) + " || exit 96\n")
	}
	b.WriteString("echo $$ > " + shellQuote(dir+"/pid") + "\n")
	b.WriteString("printf 'OBS-%s-READY\\n' " + shellQuote(nonce) + "\n")
	b.WriteString("exec")
	for _, a := range spec.Argv {
		b.WriteString(" " + shellQuote(a))
	}
	b.WriteString(" 2>>" + shellQuote(dir+"/err") + "\n")
	return b.String()
}

// startMarker is what the start script prints just before the exec; the
// typed line's echo cannot contain it (the script prints it from a format).
func startMarker(nonce string) []byte { return []byte("OBS-" + nonce + "-READY\n") }

// terminalURL is the terminal WebSocket of machine id, in a new session.
func (c *Client) terminalURL(id, session string) string {
	q := url.Values{"session": {session}, "restart": {"1"}, "cols": {"200"}, "rows": {"50"}}
	return c.o.Endpoint + "/v1/machines/" + url.PathEscape(id) + "/terminal?" + q.Encode()
}

// execStream starts a process with a streaming stdin over the terminal
// WebSocket and returns once the program runs (its start marker seen).
func (c *Client) execStream(ctx context.Context, id string, spec sandboxremote.ExecSpec) (sandboxremote.Process, error) {
	nonce, err := c.nonce(8)
	if err != nil {
		return nil, err
	}
	session := "obs-" + nonce
	dir := "/tmp/observer-instabox-" + nonce
	script := startScript(dir, nonce, spec)
	if err := c.WriteFiles(ctx, id, []sandboxremote.UploadFile{{
		Path: dir + "/start.sh", Mode: 0o700, Size: int64(len(script)),
		Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(script)), nil },
	}}); err != nil {
		return nil, fmt.Errorf("instabox: place the start script: %w", err)
	}
	conn, resp, err := websocket.Dial(ctx, c.terminalURL(id, session), &websocket.DialOptions{
		HTTPClient: c.http, HTTPHeader: http.Header{"X-API-Key": {c.o.Key}},
	})
	if err != nil {
		if resp != nil && resp.StatusCode >= 400 {
			ae := c.readError(resp)
			if resp.StatusCode == http.StatusNotFound {
				return nil, fmt.Errorf("instabox: open the terminal: %w: %w", sandboxremote.ErrNotFound, ae)
			}
			if resp.StatusCode == http.StatusTooManyRequests {
				return nil, fmt.Errorf("instabox: open the terminal: %w: %w", sandboxremote.ErrRateLimited, ae)
			}
			return nil, fmt.Errorf("instabox: open the terminal: %w", ae)
		}
		return nil, fmt.Errorf("instabox: open the terminal: %s", c.redact(err.Error()))
	}
	conn.SetReadLimit(wsReadLimit)
	pctx, cancel := context.WithCancel(ctx)
	pr, pw := io.Pipe()
	p := &termProcess{
		c: c, id: id, session: session, dir: dir, conn: conn, ctx: pctx, cancel: cancel,
		pr: pr, pw: pw, stderr: spec.Stderr, started: make(chan struct{}), done: make(chan struct{}),
	}
	go p.readLoop(startMarker(nonce))
	if err := p.send([]byte(" exec sh " + shellQuote(dir+"/start.sh") + "\n")); err != nil {
		_ = p.Close()
		return nil, fmt.Errorf("instabox: start the process: %w", err)
	}
	t := time.NewTimer(c.o.StartWait)
	defer t.Stop()
	select {
	case <-p.started:
		return p, nil
	case <-p.done:
		code, werr := p.result()
		_ = p.Close()
		if werr != nil {
			return nil, fmt.Errorf("instabox: the process did not start: %w", werr)
		}
		return nil, fmt.Errorf("instabox: the start script exited %d before the program started", code)
	case <-t.C:
		_ = p.Close()
		return nil, errors.New("instabox: the process did not start in time (no start marker on the terminal)")
	case <-ctx.Done():
		_ = p.Close()
		return nil, ctx.Err()
	}
}

// termProcess is a program running in a terminal session.
type termProcess struct {
	c       *Client
	id      string
	session string
	dir     string
	conn    *websocket.Conn
	ctx     context.Context
	cancel  context.CancelFunc
	pr      *io.PipeReader
	pw      *io.PipeWriter
	stderr  io.Writer
	started chan struct{}
	done    chan struct{}

	wmu sync.Mutex

	mu       sync.Mutex
	code     int
	haveCode bool
	err      error

	closeOnce  sync.Once
	stderrOnce sync.Once
}

// control is one text message of the terminal (a JSON control).
type control struct {
	Type    string `json:"type"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// readLoop reads the terminal: binary messages are the program's output
// (everything before the start marker is dropped), text messages are
// controls (exit carries the code; error and taken end the stream).
func (p *termProcess) readLoop(marker []byte) {
	defer close(p.done)
	var pre []byte
	started := false
	for {
		typ, b, err := p.conn.Read(p.ctx)
		if err != nil {
			p.mu.Lock()
			have := p.haveCode
			if !have && p.err == nil {
				p.err = errors.New("instabox: the terminal closed without an exit status: " + p.c.redact(err.Error()))
			}
			ferr := p.err
			p.mu.Unlock()
			if have {
				_ = p.pw.Close()
			} else {
				_ = p.pw.CloseWithError(ferr)
			}
			return
		}
		if typ == websocket.MessageText {
			if !p.control(b) {
				continue
			}
			// The shell (the program itself) ended, or the server ended the
			// session: nothing more comes.
			if _, cerr := p.result(); cerr == nil {
				_ = p.pw.Close()
			} else {
				_ = p.pw.CloseWithError(cerr)
			}
			_ = p.conn.CloseNow()
			return
		}
		if !started {
			pre = append(pre, b...)
			i := bytes.Index(pre, marker)
			if i < 0 {
				if len(pre) > maxPreamble {
					pre = append([]byte(nil), pre[len(pre)-len(marker):]...)
				}
				continue
			}
			started = true
			close(p.started)
			rest := pre[i+len(marker):]
			pre = nil
			if len(rest) == 0 {
				continue
			}
			b = rest
		}
		if _, err := p.pw.Write(b); err != nil {
			return // the reader side was closed
		}
	}
}

// control applies one control message and reports whether it ends the
// stream (exit, error, taken; a session message does not).
func (p *termProcess) control(b []byte) bool {
	var m control
	if json.Unmarshal(b, &m) != nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	switch m.Type {
	case "exit":
		p.code, p.haveCode = m.Code, true
	case "error":
		p.err = errors.New("instabox: the terminal ended: " + p.c.redact(m.Message))
	case "taken":
		p.err = errors.New("instabox: the terminal session was opened elsewhere")
	default:
		return false
	}
	return true
}

func (p *termProcess) result() (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.haveCode {
		return p.code, nil
	}
	if p.err == nil {
		return -1, errors.New("instabox: the terminal closed without an exit status")
	}
	return -1, p.err
}

// send writes b as binary messages of at most wsChunk bytes, in order.
func (p *termProcess) send(b []byte) error {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	for len(b) > 0 {
		n := min(len(b), wsChunk)
		if err := p.conn.Write(p.ctx, websocket.MessageBinary, b[:n]); err != nil {
			return errors.New(p.c.redact(err.Error()))
		}
		b = b[n:]
	}
	return nil
}

// Read returns the program's output.
func (p *termProcess) Read(b []byte) (int, error) { return p.pr.Read(b) }

// Write feeds the program's stdin.
func (p *termProcess) Write(b []byte) (int, error) {
	if err := p.send(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// PID is the terminal session's name.
func (p *termProcess) PID() string { return p.session }

// Resize: the PTY is raw and the guest helper owns the agent's PTY.
func (p *termProcess) Resize(context.Context, uint16, uint16) error {
	return fmt.Errorf("instabox: resize: %w", sandboxremote.ErrNotSupported)
}

// Wait returns the exit code once the program ends, after copying its
// stderr file (a bounded tail) to the spec's Stderr.
func (p *termProcess) Wait(ctx context.Context) (int, error) {
	select {
	case <-p.done:
	case <-ctx.Done():
		return -1, ctx.Err()
	}
	code, err := p.result()
	if p.stderr != nil {
		p.stderrOnce.Do(func() {
			if b, rerr := p.c.ReadFile(context.WithoutCancel(ctx), p.id, p.dir+"/err", stderrTail); rerr == nil && len(b) > 0 {
				_, _ = p.stderr.Write(b)
			}
		})
	}
	return code, err
}

// killScript kills the program by the pid its start script recorded.
const killScript = `p=$(cat "$1" 2>/dev/null) && [ -n "$p" ] && kill -KILL "$p" 2>/dev/null; exit 0`

// Kill ends the program (a one-shot kill of its recorded pid; the terminal
// session's shell is the program itself) and closes the stream.
func (p *termProcess) Kill(ctx context.Context) error {
	kp, err := p.c.execOnce(ctx, p.id, sandboxremote.ExecSpec{Argv: []string{"sh", "-c", killScript, "sh", p.dir + "/pid"}})
	_ = p.Close()
	if err != nil {
		return err
	}
	if code, _ := kp.Wait(ctx); code != 0 {
		return errors.New("instabox: the kill exited " + strconv.Itoa(code))
	}
	return nil
}

// Close releases the stream. The vendor keeps a session's shell running when
// its connection ends, so a program still running keeps running until Kill
// or the box's delete.
func (p *termProcess) Close() error {
	p.closeOnce.Do(func() {
		_ = p.conn.Close(websocket.StatusNormalClosure, "")
		p.cancel()
		_ = p.pr.Close()
	})
	return nil
}
