package e2b

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// process.go is envd's process service (spec/envd/process/process.proto,
// docs.e2b.dev/openapi-public.yaml): Start and Connect are Connect-RPC
// server streams over application/connect+json (each frame one flag byte, a
// 4-byte big-endian length and a JSON message; flag 0x02 ends the stream
// with a trailer that may carry an error while HTTP stays 200); SendInput,
// Update, SendSignal and CloseStdin are unary JSON calls.

// The Connect frame flags.
const (
	flagData      = 0x00
	flagEndStream = 0x02
	// maxFrame bounds one Connect frame from envd.
	maxFrame = 4 << 20
)

// connectPrefix is the process service's path.
const connectPrefix = "/process.Process/"

// processConfig is ProcessConfig.
type processConfig struct {
	Cmd  string            `json:"cmd"`
	Args []string          `json:"args"`
	Envs map[string]string `json:"envs,omitempty"`
	Cwd  string            `json:"cwd,omitempty"`
}

type ptySize struct {
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

type ptyReq struct {
	Size ptySize `json:"size"`
}

type startReq struct {
	Process processConfig `json:"process"`
	PTY     *ptyReq       `json:"pty,omitempty"`
	Stdin   bool          `json:"stdin"`
}

type selector struct {
	PID uint32 `json:"pid"`
}

type connectReq struct {
	Process selector `json:"process"`
}

// event is ProcessEvent (one oneof key set).
type event struct {
	Event struct {
		Start *struct {
			PID uint32 `json:"pid"`
		} `json:"start"`
		Data *struct {
			Stdout string `json:"stdout"`
			Stderr string `json:"stderr"`
			PTY    string `json:"pty"`
		} `json:"data"`
		End *struct {
			ExitCode int32  `json:"exitCode"`
			Exited   bool   `json:"exited"`
			Status   string `json:"status"`
			Error    string `json:"error"`
		} `json:"end"`
		Keepalive *struct{} `json:"keepalive"`
	} `json:"event"`
}

// endStream is the final frame's payload.
type endStream struct {
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// envelope frames one JSON message for a Connect stream request.
func envelope(msg any) ([]byte, error) {
	b, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 5+len(b))
	out[0] = flagData
	binary.BigEndian.PutUint32(out[1:5], uint32(len(b))) //nolint:gosec // G115: a request message far below 4 GiB
	copy(out[5:], b)
	return out, nil
}

// readFrame reads one Connect frame.
func readFrame(r *bufio.Reader) (byte, []byte, error) {
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(h[1:])
	if n > maxFrame {
		return 0, nil, fmt.Errorf("e2b: a stream frame of %d bytes is over the cap", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, nil, err
	}
	return h[0], b, nil
}

// Exec starts a process (with a PTY when spec.PTY) and returns its stream.
func (c *Client) Exec(ctx context.Context, id string, spec sandboxremote.ExecSpec) (sandboxremote.Process, error) {
	if len(spec.Argv) == 0 {
		return nil, errors.New("e2b: empty argv")
	}
	req := startReq{Process: processConfig{Cmd: spec.Argv[0], Args: spec.Argv[1:], Envs: spec.Env, Cwd: spec.Cwd}, Stdin: spec.Stdin}
	if req.Process.Args == nil {
		req.Process.Args = []string{}
	}
	if spec.PTY {
		req.PTY = &ptyReq{Size: ptySize{Cols: spec.Cols, Rows: spec.Rows}}
	}
	return c.stream(ctx, id, "Start", req, spec.PTY, spec.AsRoot, spec.Stderr)
}

// Reattach reconnects to a running process by its pid (envd's Connect).
func (c *Client) Reattach(ctx context.Context, id, pid string) (sandboxremote.Process, error) {
	n, err := strconv.ParseUint(pid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("e2b: pid %q", pid)
	}
	return c.stream(ctx, id, "Connect", connectReq{Process: selector{PID: uint32(n)}}, true, false, nil)
}

// stream opens a server-streaming call and waits for the start event.
func (c *Client) stream(ctx context.Context, id, rpc string, msg any, pty, asRoot bool, stderr io.Writer) (sandboxremote.Process, error) {
	body, err := envelope(msg)
	if err != nil {
		return nil, err
	}
	sctx, cancel := context.WithCancel(ctx)
	req, token, err := c.envdRequest(sctx, id, http.MethodPost, connectPrefix+rpc, bytes.NewReader(body), asRoot)
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set("Content-Type", "application/connect+json")
	req.Header.Set("Connect-Protocol-Version", "1")
	resp, err := c.http.Do(req)
	if err != nil {
		cancel()
		return nil, errors.New(c.redact(err.Error()))
	}
	if resp.StatusCode != http.StatusOK {
		cancel()
		return nil, c.envdError(resp, token)
	}
	pr, pw := io.Pipe()
	p := &process{c: c, box: id, pty: pty, asRoot: asRoot, cancel: cancel, body: resp.Body, out: pr, stderr: stderr, done: make(chan struct{}), started: make(chan struct{})}
	go p.readEvents(bufio.NewReaderSize(resp.Body, 64<<10), pw, token)
	select {
	case <-p.started:
		return p, nil
	case <-p.done:
		// A short process can start and end before this select runs, so
		// both channels are ready and either case may be chosen. A process
		// that started is handed back (its output reads to EOF and Wait
		// reports the exit); only a stream that ended before any start is
		// an error, and never a nil process with a nil error.
		select {
		case <-p.started:
			return p, nil
		default:
		}
		cancel()
		p.mu.Lock()
		err := p.err
		p.mu.Unlock()
		if err == nil {
			err = errors.New("e2b: the process stream ended before the process started")
		}
		return nil, err
	case <-ctx.Done():
		cancel()
		return nil, ctx.Err()
	}
}

// process is one envd process stream.
type process struct {
	c      *Client
	box    string
	pty    bool
	asRoot bool
	cancel context.CancelFunc
	body   io.ReadCloser
	out    *io.PipeReader
	// stderr receives a non-PTY process's stderr (nil discards it).
	stderr io.Writer

	mu      sync.Mutex
	pid     uint32
	code    int
	err     error
	started chan struct{}
	done    chan struct{}
	once    sync.Once
}

// readEvents turns the event stream into the output pipe.
func (p *process) readEvents(r *bufio.Reader, out *io.PipeWriter, token string) {
	finish := func(code int, err error) {
		p.mu.Lock()
		p.code, p.err = code, err
		p.mu.Unlock()
		p.once.Do(func() { close(p.done) })
		_ = out.CloseWithError(err)
	}
	for {
		flag, b, err := readFrame(r)
		if err != nil {
			// A dropped stream: the process may still run (reattach with
			// Connect where the caller can).
			finish(-1, fmt.Errorf("e2b: the process stream ended: %s", p.c.redact(err.Error())))
			return
		}
		if flag&flagEndStream != 0 {
			var es endStream
			_ = json.Unmarshal(b, &es)
			p.mu.Lock()
			code := p.code
			p.mu.Unlock()
			if es.Error != nil {
				finish(code, fmt.Errorf("e2b: %s: %s", es.Error.Code, sandboxremote.Redact(es.Error.Message, []string{p.c.o.APIKey, token})))
				return
			}
			finish(code, nil)
			return
		}
		var ev event
		if err := json.Unmarshal(b, &ev); err != nil {
			finish(-1, fmt.Errorf("e2b: a process event did not parse: %w", err))
			return
		}
		switch {
		case ev.Event.Start != nil:
			p.mu.Lock()
			p.pid = ev.Event.Start.PID
			p.mu.Unlock()
			select {
			case <-p.started:
			default:
				close(p.started)
			}
		case ev.Event.Data != nil:
			if e := ev.Event.Data.Stderr; e != "" && !p.pty && p.stderr != nil {
				if eb, err := base64.StdEncoding.DecodeString(e); err == nil {
					_, _ = p.stderr.Write(eb)
				}
			}
			raw := ev.Event.Data.Stdout
			if p.pty {
				raw = ev.Event.Data.PTY
			}
			if raw == "" {
				continue
			}
			b, err := base64.StdEncoding.DecodeString(raw)
			if err != nil {
				finish(-1, errors.New("e2b: process output is not base64"))
				return
			}
			if _, err := out.Write(b); err != nil {
				return
			}
		case ev.Event.End != nil:
			p.mu.Lock()
			p.code = int(ev.Event.End.ExitCode)
			p.mu.Unlock()
			select {
			case <-p.started:
			default:
				close(p.started)
			}
		}
	}
}

func (p *process) Read(b []byte) (int, error) { return p.out.Read(b) }

// PID is the envd pid.
func (p *process) PID() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strconv.FormatUint(uint64(p.pid), 10)
}

// unary sends one unary envd call about this process.
func (p *process) unary(ctx context.Context, rpc string, msg any) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	req, token, err := p.c.envdRequest(ctx, p.box, http.MethodPost, connectPrefix+rpc, bytes.NewReader(b), p.asRoot)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connect-Protocol-Version", "1")
	resp, err := p.c.http.Do(req)
	if err != nil {
		return errors.New(p.c.redact(err.Error()))
	}
	if resp.StatusCode != http.StatusOK {
		return p.c.envdError(resp, token)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
	return nil
}

func (p *process) sel() selector {
	p.mu.Lock()
	defer p.mu.Unlock()
	return selector{PID: p.pid}
}

// Write sends input (SendInput: the pty or stdin field, base64).
func (p *process) Write(b []byte) (int, error) {
	in := map[string]string{"stdin": base64.StdEncoding.EncodeToString(b)}
	if p.pty {
		in = map[string]string{"pty": base64.StdEncoding.EncodeToString(b)}
	}
	if err := p.unary(context.Background(), "SendInput", map[string]any{"process": p.sel(), "input": in}); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Resize changes the PTY size (Update).
func (p *process) Resize(ctx context.Context, rows, cols uint16) error {
	if !p.pty {
		return sandboxremote.ErrNotSupported
	}
	return p.unary(ctx, "Update", map[string]any{"process": p.sel(), "pty": ptyReq{Size: ptySize{Cols: cols, Rows: rows}}})
}

// Wait returns the exit code once the stream ends.
func (p *process) Wait(ctx context.Context) (int, error) {
	select {
	case <-p.done:
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.code, p.err
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

// Kill sends SIGKILL (SendSignal).
func (p *process) Kill(ctx context.Context) error {
	return p.unary(ctx, "SendSignal", map[string]any{"process": p.sel(), "signal": "SIGNAL_SIGKILL"})
}

// Close drops the stream; the process keeps running in the box (reattach
// with Reattach).
func (p *process) Close() error {
	p.cancel()
	_ = p.out.Close()
	return p.body.Close()
}
