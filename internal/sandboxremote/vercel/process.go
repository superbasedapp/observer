package vercel

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// process.go is a command: started with POST .../cmd, its output read from
// the NDJSON log stream, its stdin fed through POST .../stdin (base64 with an
// offset) by one pump that coalesces writes, because every stdin POST counts
// against the control-plane quota (Hobby 1,000 a minute).

// stdinChunk is the most one stdin POST carries (the body limit is 1 MB
// after base64).
const stdinChunk = 512 << 10

// stdinBuffer bounds the bytes a Write may queue before it blocks.
const stdinBuffer = 1 << 20

// logReconnects bounds the re-requests of a dropped log stream (the SDK's).
const logReconnects = 2

// Exec starts a command. A vendor PTY is refused: the documented command is
// a pipe, not a terminal, and the guest helper owns the PTY.
func (c *Client) Exec(ctx context.Context, name string, spec sandboxremote.ExecSpec) (sandboxremote.Process, error) {
	if spec.PTY {
		return nil, fmt.Errorf("vercel: a vendor terminal: %w", sandboxremote.ErrNotSupported)
	}
	if len(spec.Argv) == 0 {
		return nil, errors.New("vercel: exec needs an argv")
	}
	sid, err := c.session(ctx, name)
	if err != nil {
		return nil, err
	}
	body := map[string]any{"command": spec.Argv[0], "args": spec.Argv[1:], "sudo": spec.AsRoot, "attachStdin": spec.Stdin}
	if spec.Cwd != "" {
		body["cwd"] = spec.Cwd
	}
	if len(spec.Env) > 0 {
		body["env"] = spec.Env
	}
	var out struct {
		Command struct {
			ID string `json:"id"`
		} `json:"command"`
	}
	if err := c.doJSON(ctx, request{method: http.MethodPost, path: sessionPath(sid, "/cmd")}, body, &out); err != nil {
		return nil, err
	}
	if out.Command.ID == "" {
		return nil, errors.New("vercel: the command answer carried no id")
	}
	pctx, cancel := context.WithCancel(ctx)
	p := &process{c: c, ctx: pctx, cancel: cancel, sid: sid, id: out.Command.ID, stderr: spec.Stderr}
	if spec.Stdin {
		p.pump = newStdinPump(p)
	}
	return p, nil
}

// process is one command.
type process struct {
	c      *Client
	ctx    context.Context
	cancel context.CancelFunc
	sid    string
	id     string
	pump   *stdinPump
	// stderr receives the command's stderr (nil discards it); errSeen
	// counts the bytes already passed on, so a re-requested log stream
	// (which replays from the start) does not pass them twice.
	stderr  io.Writer
	errSeen int64
	errSkip int64

	// The log stream (Read is called from one goroutine; Close may run
	// beside it, so the body is held under bmu).
	bmu       sync.Mutex
	closed    bool
	body      io.ReadCloser
	lines     *bufio.Reader
	pending   []byte
	delivered int64
	skip      int64
	tries     int
	done      bool
}

func (p *process) cmdPath(rest string) string {
	return sessionPath(p.sid, "/cmd/"+url.PathEscape(p.id)+rest)
}

// open requests the log stream; after a drop it is re-requested and the
// stdout bytes already delivered are skipped (the stream replays from the
// command's start).
func (p *process) open() error {
	resp, err := p.c.do(p.ctx, request{method: http.MethodGet, path: p.cmdPath("/logs"), noRetry: true})
	if err != nil {
		return err
	}
	p.bmu.Lock()
	defer p.bmu.Unlock()
	if p.closed {
		_ = resp.Body.Close()
		return io.EOF
	}
	p.body = resp.Body
	p.lines = bufio.NewReaderSize(resp.Body, 64<<10)
	p.skip = p.delivered
	p.errSkip = p.errSeen
	return nil
}

// dropBody closes the current log stream.
func (p *process) dropBody() {
	p.bmu.Lock()
	if p.body != nil {
		_ = p.body.Close()
		p.body = nil
	}
	p.bmu.Unlock()
}

// logLine is one NDJSON line: stdout or stderr text, or an error object.
type logLine struct {
	Stream string          `json:"stream"`
	Data   json.RawMessage `json:"data"`
}

func (p *process) Read(b []byte) (int, error) {
	for len(p.pending) == 0 {
		if p.done {
			return 0, io.EOF
		}
		if p.lines == nil {
			if err := p.open(); err != nil {
				return 0, err
			}
		}
		line, err := p.lines.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			if perr := p.take(line); perr != nil {
				return 0, perr
			}
		}
		if err == nil {
			continue
		}
		p.dropBody()
		p.lines = nil
		if errors.Is(err, io.EOF) {
			p.done = true
			continue
		}
		if p.ctx.Err() != nil || p.tries >= logReconnects {
			return 0, errors.New(p.c.redact("vercel: log stream: " + err.Error()))
		}
		p.tries++
	}
	n := copy(b, p.pending)
	p.pending = p.pending[n:]
	return n, nil
}

// take handles one log line.
func (p *process) take(line []byte) error {
	var l logLine
	if err := json.Unmarshal(line, &l); err != nil {
		return fmt.Errorf("vercel: log stream: %w", err)
	}
	switch l.Stream {
	case "stdout":
		var s string
		if err := json.Unmarshal(l.Data, &s); err != nil {
			return fmt.Errorf("vercel: log stream: %w", err)
		}
		data := []byte(s)
		if p.skip > 0 {
			k := min(p.skip, int64(len(data)))
			data, p.skip = data[k:], p.skip-k
		}
		p.delivered += int64(len(data))
		p.pending = append(p.pending, data...)
	case "stderr":
		if p.stderr == nil {
			return nil
		}
		var s string
		if err := json.Unmarshal(l.Data, &s); err != nil {
			return nil
		}
		data := []byte(s)
		if p.errSkip > 0 {
			k := min(p.errSkip, int64(len(data)))
			data, p.errSkip = data[k:], p.errSkip-k
		}
		p.errSeen += int64(len(data))
		_, _ = p.stderr.Write(data)
	case "error":
		var e struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(l.Data, &e)
		return fmt.Errorf("vercel: log stream: %s: %s", p.c.redact(e.Code), p.c.redact(e.Message))
	}
	return nil // stderr goes to spec.Stderr, or nowhere (sandboxremote.Process)
}

func (p *process) Write(b []byte) (int, error) {
	if p.pump == nil {
		return 0, errors.New("vercel: the command was started without stdin")
	}
	return p.pump.write(b)
}

// PID is the command id (no reattach is documented, so nothing reuses it).
func (p *process) PID() string { return p.id }

func (p *process) Resize(context.Context, uint16, uint16) error {
	return fmt.Errorf("vercel: resize: %w", sandboxremote.ErrNotSupported)
}

// Wait blocks until the command ends (GET with wait=true).
func (p *process) Wait(ctx context.Context) (int, error) {
	for {
		var out struct {
			Command struct {
				ExitCode *int `json:"exitCode"`
			} `json:"command"`
		}
		if err := p.c.doJSON(ctx, request{method: http.MethodGet, path: p.cmdPath(""), query: url.Values{"wait": {"true"}}}, nil, &out); err != nil {
			return 0, err
		}
		if out.Command.ExitCode != nil {
			return *out.Command.ExitCode, nil
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
	}
}

// Kill sends SIGTERM (the documented kill takes a signal number).
func (p *process) Kill(ctx context.Context) error {
	return p.c.doJSON(ctx, request{method: http.MethodPost, path: p.cmdPath("/kill")}, map[string]int{"signal": 15}, nil)
}

// Close flushes and closes stdin, then drops the log stream.
func (p *process) Close() error {
	var err error
	if p.pump != nil {
		err = p.pump.close()
	}
	p.cancel()
	p.bmu.Lock()
	p.closed = true
	p.bmu.Unlock()
	p.dropBody()
	return err
}

// stdinPump queues stdin and sends it in as few POSTs as it can: one
// request in flight, everything written meanwhile goes in the next.
type stdinPump struct {
	p       *process
	mu      sync.Mutex
	cond    *sync.Cond
	buf     []byte
	closing bool
	closed  bool
	err     error
	offset  int64
	posts   int
}

func newStdinPump(p *process) *stdinPump {
	s := &stdinPump{p: p}
	s.cond = sync.NewCond(&s.mu)
	go s.run()
	go func() {
		<-p.ctx.Done()
		s.mu.Lock()
		if s.err == nil && !s.closed {
			s.err = p.ctx.Err()
		}
		s.cond.Broadcast()
		s.mu.Unlock()
	}()
	return s
}

func (s *stdinPump) write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.buf) >= stdinBuffer && s.err == nil && !s.closing {
		s.cond.Wait()
	}
	if s.err != nil {
		return 0, s.err
	}
	if s.closing {
		return 0, errors.New("vercel: stdin is closed")
	}
	s.buf = append(s.buf, b...)
	s.cond.Broadcast()
	return len(b), nil
}

// close sends what is queued, then the close.
func (s *stdinPump) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closing = true
	s.cond.Broadcast()
	for !s.closed && s.err == nil {
		s.cond.Wait()
	}
	if s.closed {
		return nil
	}
	return s.err
}

func (s *stdinPump) run() {
	for {
		s.mu.Lock()
		for len(s.buf) == 0 && !s.closing && s.err == nil {
			s.cond.Wait()
		}
		if s.err != nil {
			s.mu.Unlock()
			return
		}
		n := min(len(s.buf), stdinChunk)
		chunk := bytes.Clone(s.buf[:n])
		closeNow := s.closing && n == len(s.buf)
		offset := s.offset
		s.mu.Unlock()

		written, err := s.post(chunk, offset, closeNow)

		s.mu.Lock()
		s.posts++
		if err != nil {
			s.err = err
			s.cond.Broadcast()
			s.mu.Unlock()
			return
		}
		s.buf = s.buf[written:]
		s.offset += int64(written)
		if closeNow && written == len(chunk) {
			s.closed = true
			s.cond.Broadcast()
			s.mu.Unlock()
			return
		}
		s.cond.Broadcast()
		s.mu.Unlock()
	}
}

// post sends one stdin request and returns how many bytes the vendor took
// (a 504 says the process was not reading for 30 s and carries the count it
// did take; the rest goes in the next request).
func (s *stdinPump) post(chunk []byte, offset int64, closeNow bool) (int, error) {
	body := map[string]any{"data": base64.StdEncoding.EncodeToString(chunk), "offset": offset}
	if closeNow {
		body["close"] = true
	}
	var out struct {
		BytesWritten *int64 `json:"bytesWritten"`
	}
	err := s.p.c.doJSON(s.p.ctx, request{method: http.MethodPost, path: s.p.cmdPath("/stdin")}, body, &out)
	var ae *apiError
	switch {
	case errors.As(err, &ae) && ae.status == http.StatusGatewayTimeout:
		return int(min(max(ae.bytesWritten, 0), int64(len(chunk)))), nil
	case err != nil:
		return 0, err
	case out.BytesWritten == nil:
		return len(chunk), nil
	}
	return int(min(max(*out.BytesWritten, 0), int64(len(chunk)))), nil
}
