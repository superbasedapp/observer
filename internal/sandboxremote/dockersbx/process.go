package dockersbx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// subprotocol is the interact stream's WebSocket subprotocol (the API
// reference's x-websocket block).
const subprotocol = "sandboxes.v1"

// Stream limits: the read limit of one server frame, the reconnects a
// dropped stream gets, the wait of one frame write, and the longest a write
// waits for a re-attached stream.
const (
	frameReadLimit = 8 << 20
	reconnects     = 3
	writeWait      = 30 * time.Second
	reattachWait   = 60 * time.Second
)

// flexInt is a 64-bit integer the API returns as a JSON string or number.
type flexInt int64

// UnmarshalJSON accepts a number or a decimal string.
func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}
	*f = flexInt(n)
	return nil
}

// processJSON is the Process schema, the fields the client reads.
type processJSON struct {
	Name               string  `json:"name"`
	UID                string  `json:"uid"`
	State              string  `json:"state"`
	ExitCode           *int    `json:"exitCode"`
	LastStreamSequence flexInt `json:"lastStreamSequence"`
}

// createProcessBody is CreateProcessRequest.
type createProcessBody struct {
	Cmd        []string          `json:"cmd"`
	Env        map[string]string `json:"env,omitempty"`
	WorkingDir string            `json:"workingDir,omitempty"`
	User       string            `json:"user,omitempty"`
	PTY        *ptyConfig        `json:"pty,omitempty"`
}

type ptyConfig struct {
	InitialSize *termSize `json:"initialSize,omitempty"`
}

type termSize struct {
	Rows int `json:"rows"`
	Cols int `json:"cols"`
}

// The interact frames (InteractRequest; one arm each).
type (
	attachFrame struct {
		Attach struct {
			Name       string `json:"name"`
			ResumeFrom int64  `json:"resumeFrom"`
		} `json:"attach"`
	}
	stdinFrame struct {
		Stdin []byte `json:"stdin"`
	}
	closeStdinFrame struct {
		CloseStdin bool `json:"closeStdin"`
	}
	resizeFrame struct {
		Resize termSize `json:"resize"`
	}
)

// outputFrame is ProcessOutput, or the terminal Error frame sent before a
// close.
type outputFrame struct {
	Chunk *struct {
		Stream         string  `json:"stream"`
		Data           []byte  `json:"data"`
		StreamSequence flexInt `json:"streamSequence"`
	} `json:"chunk"`
	Exited *struct {
		ExitCode int    `json:"exitCode"`
		Reason   string `json:"reason"`
	} `json:"exited"`
	Heartbeat *struct{} `json:"heartbeat"`
	Code      string    `json:"code"`
	Message   string    `json:"message"`
}

// processUID is the path id of a process name (processes/<uid>).
func processUID(name string) string { return strings.TrimPrefix(name, "processes/") }

// Exec starts an interactive process (CreateProcess under an
// Idempotency-Key, so a lost answer is safely repeated) and attaches to its
// stream. AsRoot runs as root; a PTY gets the initial size; a process with
// neither a streaming stdin nor a PTY has its stdin closed at once (a
// one-shot StdinData is sent first).
func (c *Client) Exec(ctx context.Context, box string, spec sandboxremote.ExecSpec) (sandboxremote.Process, error) {
	if len(spec.Argv) == 0 {
		return nil, errors.New("dockersbx: exec: no argv")
	}
	if len(spec.StdinData) > 0 && spec.Stdin {
		return nil, errors.New("dockersbx: exec: a one-shot stdin with a streaming one")
	}
	c.mu.Lock()
	env := maps.Clone(c.env[box])
	c.mu.Unlock()
	if env == nil {
		env = map[string]string{}
	}
	maps.Copy(env, spec.Env)
	body := createProcessBody{Cmd: spec.Argv, Env: env, WorkingDir: spec.Cwd}
	if len(body.Env) == 0 {
		body.Env = nil
	}
	if spec.AsRoot {
		body.User = "root"
	}
	if spec.PTY {
		body.PTY = &ptyConfig{}
		if spec.Rows > 0 && spec.Cols > 0 {
			body.PTY.InitialSize = &termSize{Rows: int(spec.Rows), Cols: int(spec.Cols)}
		}
	}
	var pj processJSON
	if _, _, err := c.doJSON(ctx, request{
		plane: planeBox, box: box, method: http.MethodPost, path: "/v1/processes", idempotent: true,
		header: http.Header{"Idempotency-Key": {newIdem("observer-process-")}},
	}, body, &pj); err != nil {
		return nil, fmt.Errorf("dockersbx: exec: %w", err)
	}
	name := pj.Name
	if name == "" && pj.UID != "" {
		name = "processes/" + pj.UID
	}
	if name == "" {
		return nil, errors.New("dockersbx: exec: the answer names no process")
	}
	p, err := c.attach(ctx, box, name, 0, spec.PTY, spec.Stderr)
	if err != nil {
		return nil, err
	}
	switch {
	case len(spec.StdinData) > 0:
		if _, err := p.Write(spec.StdinData); err != nil {
			_ = p.Close()
			return nil, fmt.Errorf("dockersbx: exec: stdin: %w", err)
		}
		fallthrough
	case !spec.Stdin && !spec.PTY:
		if err := p.send(closeStdinFrame{CloseStdin: true}); err != nil {
			_ = p.Close()
			return nil, fmt.Errorf("dockersbx: exec: close stdin: %w", err)
		}
	}
	return p, nil
}

// Reattach re-opens the stream of a process by its name (the PID), from the
// last stream sequence this client received for it (none: the process's
// own last sequence, so earlier output is not replayed). The stream is
// taken as a terminal; stderr chunks are dropped.
func (c *Client) Reattach(ctx context.Context, box, pid string) (sandboxremote.Process, error) {
	if !strings.HasPrefix(pid, "processes/") || processUID(pid) == "" {
		return nil, fmt.Errorf("dockersbx: reattach: %q is not a process name", pid)
	}
	c.mu.Lock()
	from, known := c.seq[pid]
	c.mu.Unlock()
	if !known {
		var pj processJSON
		if _, _, err := c.doJSON(ctx, request{plane: planeBox, box: box, method: http.MethodGet, path: "/v1/processes/" + url.PathEscape(processUID(pid)), idempotent: true}, nil, &pj); err != nil {
			return nil, fmt.Errorf("dockersbx: reattach: %w", err)
		}
		from = int64(pj.LastStreamSequence)
	}
	return c.attach(ctx, box, pid, from, true, nil)
}

// attach dials the process's interact stream and starts its reader.
func (c *Client) attach(ctx context.Context, box, name string, from int64, pty bool, stderr io.Writer) (*process, error) {
	pr, pw := io.Pipe()
	rctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	p := &process{c: c, box: box, name: name, pty: pty, stderr: stderr, pr: pr, pw: pw, ctx: rctx, cancel: cancel, seq: from, done: make(chan struct{}), changed: make(chan struct{})}
	conn, err := p.dial(ctx, false)
	if err != nil {
		cancel()
		return nil, err
	}
	p.conn = conn
	go p.run()
	return p, nil
}

// process is one attached process stream.
type process struct {
	c      *Client
	box    string
	name   string
	pty    bool
	stderr io.Writer
	pr     *io.PipeReader
	pw     *io.PipeWriter
	ctx    context.Context
	cancel context.CancelFunc

	mu sync.Mutex
	// conn is the current stream; changed is closed and replaced each time
	// it changes or the process ends.
	conn    *websocket.Conn
	changed chan struct{}
	seq     int64
	// reattaches counts the streams re-opened after a drop.
	reattaches int
	// lastCode is the code of the last error frame received.
	lastCode string

	writeMu sync.Mutex

	once sync.Once
	done chan struct{}
	code int
	err  error
}

// dial opens the interact stream with an endpoint grant (minted again when
// force) and sends the attach frame with the resume point.
func (p *process) dial(ctx context.Context, force bool) (*websocket.Conn, error) {
	for try := 0; try < 2; try++ {
		g, err := p.c.grant(ctx, p.box, force || try > 0)
		if err != nil {
			return nil, err
		}
		target := strings.TrimSuffix(g.base, "/") + "/v1/processes/" + url.PathEscape(processUID(p.name)) + "/interact"
		conn, resp, err := websocket.Dial(ctx, target, &websocket.DialOptions{
			HTTPClient:   p.c.http,
			HTTPHeader:   http.Header{"Authorization": {authorization(g.scope)}},
			Subprotocols: []string{subprotocol},
		})
		if err != nil {
			if resp != nil && resp.StatusCode == http.StatusUnauthorized && try == 0 {
				continue
			}
			if resp != nil && resp.StatusCode == http.StatusNotFound {
				return nil, fmt.Errorf("dockersbx: interact: %w", sandboxremote.ErrNotFound)
			}
			return nil, fmt.Errorf("dockersbx: interact: %s", p.c.redact(err.Error()))
		}
		if conn.Subprotocol() != subprotocol {
			_ = conn.Close(websocket.StatusProtocolError, "no subprotocol")
			return nil, errors.New("dockersbx: interact: the service negotiated no sandboxes.v1 subprotocol")
		}
		conn.SetReadLimit(frameReadLimit)
		var a attachFrame
		a.Attach.Name = p.name
		p.mu.Lock()
		a.Attach.ResumeFrom = p.seq
		p.mu.Unlock()
		if err := writeJSON(ctx, conn, a); err != nil {
			_ = conn.Close(websocket.StatusInternalError, "attach")
			return nil, fmt.Errorf("dockersbx: interact: attach: %s", p.c.redact(err.Error()))
		}
		return conn, nil
	}
	return nil, errors.New("dockersbx: interact: the endpoint refused the grant")
}

func writeJSON(ctx context.Context, conn *websocket.Conn, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, writeWait)
	defer cancel()
	return conn.Write(wctx, websocket.MessageText, b)
}

// current returns the stream and its change channel.
func (p *process) current() (*websocket.Conn, chan struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.conn, p.changed
}

// swap installs a new stream and wakes the writers waiting on the old one.
func (p *process) swap(conn *websocket.Conn) {
	p.mu.Lock()
	old := p.conn
	p.conn = conn
	close(p.changed)
	p.changed = make(chan struct{})
	p.reattaches++
	p.mu.Unlock()
	if old != nil {
		_ = old.CloseNow()
	}
}

// run reads frames until the process exits or the stream cannot be
// re-attached: chunks after the last sequence go to the reader (stderr of a
// pipe process to its sink), an exited frame ends the stream with its code.
func (p *process) run() {
	for {
		conn, _ := p.current()
		typ, data, err := conn.Read(p.ctx)
		if err == nil {
			if typ != websocket.MessageText {
				continue
			}
			if p.handle(data) {
				return
			}
			continue
		}
		if p.ctx.Err() != nil {
			p.finish(-1, io.ErrClosedPipe)
			return
		}
		if rerr := p.reconnect(); rerr != nil {
			p.finishLost(err, rerr)
			return
		}
	}
}

// handle applies one frame; it reports whether the process ended.
func (p *process) handle(data []byte) bool {
	var f outputFrame
	if json.Unmarshal(data, &f) != nil {
		return false
	}
	switch {
	case f.Chunk != nil:
		seq := int64(f.Chunk.StreamSequence)
		p.mu.Lock()
		dup := seq != 0 && seq <= p.seq
		if !dup && seq != 0 {
			p.seq = seq
		}
		p.mu.Unlock()
		if dup {
			return false
		}
		if seq != 0 {
			p.c.mu.Lock()
			p.c.seq[p.name] = seq
			p.c.mu.Unlock()
		}
		if f.Chunk.Stream == "stderr" && !p.pty {
			if p.stderr != nil {
				_, _ = p.stderr.Write(f.Chunk.Data)
			}
			return false
		}
		if _, err := p.pw.Write(f.Chunk.Data); err != nil {
			p.finish(-1, err)
			return true
		}
	case f.Exited != nil:
		p.finish(f.Exited.ExitCode, nil)
		conn, _ := p.current()
		_ = conn.Close(websocket.StatusNormalClosure, "")
		return true
	case f.Code != "":
		p.mu.Lock()
		p.lastCode = f.Code
		p.mu.Unlock()
	}
	return false
}

// reconnect re-attaches a dropped stream with a fresh grant from the last
// sequence received, unless the service refused it for good.
func (p *process) reconnect() error {
	p.mu.Lock()
	code := p.lastCode
	p.lastCode = ""
	p.mu.Unlock()
	switch code {
	case "notFound":
		return fmt.Errorf("dockersbx: interact: %w", sandboxremote.ErrNotFound)
	case "permissionDenied", "invalidArgument", "failedPrecondition":
		return fmt.Errorf("dockersbx: interact: %w (%s)", sandboxremote.ErrRefused, code)
	}
	var last error
	for attempt := 0; attempt < reconnects; attempt++ {
		if attempt > 0 {
			if err := p.c.o.Sleep(p.ctx, backoff(attempt-1)); err != nil {
				return err
			}
		}
		conn, err := p.dial(p.ctx, true)
		if err == nil {
			p.swap(conn)
			return nil
		}
		last = err
		if errors.Is(err, sandboxremote.ErrNotFound) {
			break
		}
	}
	return last
}

// finishLost ends a stream that could not be re-attached: the process's
// own state decides (an exited process keeps its code), else the error.
func (p *process) finishLost(readErr, rerr error) {
	var pj processJSON
	_, _, err := p.c.doJSON(context.WithoutCancel(p.ctx), request{plane: planeBox, box: p.box, method: http.MethodGet, path: "/v1/processes/" + url.PathEscape(processUID(p.name)), idempotent: true}, nil, &pj)
	if err == nil && pj.State == "exited" && pj.ExitCode != nil {
		p.finish(*pj.ExitCode, nil)
		return
	}
	p.finish(-1, fmt.Errorf("dockersbx: the process stream was cut (%s) and could not be re-attached: %w", p.c.redact(readErr.Error()), rerr))
}

// finish records the end once and ends the reader (EOF on a clean exit).
func (p *process) finish(code int, err error) {
	p.once.Do(func() {
		p.code, p.err = code, err
		p.pw.CloseWithError(err)
		p.mu.Lock()
		close(p.changed)
		p.changed = make(chan struct{})
		p.mu.Unlock()
		close(p.done)
	})
}

func (p *process) ended() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// send writes one control frame on the current stream, once more on a
// re-attached one if the write failed.
func (p *process) send(v any) error {
	for attempt := 0; ; attempt++ {
		if p.ended() {
			return io.ErrClosedPipe
		}
		conn, changed := p.current()
		p.writeMu.Lock()
		err := writeJSON(p.ctx, conn, v)
		p.writeMu.Unlock()
		if err == nil {
			return nil
		}
		if attempt > 0 || p.ctx.Err() != nil {
			return errors.New(p.c.redact(err.Error()))
		}
		select {
		case <-changed:
		case <-time.After(reattachWait):
			return errors.New(p.c.redact(err.Error()))
		}
	}
}

// Read returns the process's output (the terminal for a PTY).
func (p *process) Read(b []byte) (int, error) { return p.pr.Read(b) }

// Write sends stdin. A frame whose write failed is sent once more on the
// re-attached stream (the service never replays stdin itself).
func (p *process) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if err := p.send(stdinFrame{Stdin: append([]byte(nil), b...)}); err != nil {
		return 0, err
	}
	return len(b), nil
}

// PID is the process's resource name (processes/<uid>).
func (p *process) PID() string { return p.name }

// Resize sends the terminal size (a PTY only).
func (p *process) Resize(_ context.Context, rows, cols uint16) error {
	if !p.pty {
		return sandboxremote.ErrNotSupported
	}
	return p.send(resizeFrame{Resize: termSize{Rows: int(rows), Cols: int(cols)}})
}

// Wait returns the exit code once the process ends.
func (p *process) Wait(ctx context.Context) (int, error) {
	select {
	case <-p.done:
		return p.code, p.err
	case <-ctx.Done():
		return -1, ctx.Err()
	}
}

// Kill sends the kill signal (an absent process is already gone).
func (p *process) Kill(ctx context.Context) error {
	_, _, err := p.c.doJSON(ctx, request{
		plane: planeBox, box: p.box, method: http.MethodPost, path: "/v1/processes/" + url.PathEscape(processUID(p.name)) + "/signal", noRetry: true,
	}, struct {
		Signal string `json:"signal"`
	}{"kill"}, nil)
	if errors.Is(err, sandboxremote.ErrNotFound) {
		return nil
	}
	return err
}

// Close releases the stream; the process keeps running in the box.
func (p *process) Close() error {
	conn, _ := p.current()
	p.cancel()
	if conn != nil {
		_ = conn.Close(websocket.StatusNormalClosure, "")
	}
	p.finish(-1, io.ErrClosedPipe)
	return p.pr.Close()
}

// ---- multipart upload ---------------------------------------------------------

// multipartStream builds the body of one /v1/files/upload request: for each
// file a metadata part (FileHeader as JSON) and a content part (raw bytes),
// streamed through a pipe so no file is held whole in memory. A file that
// grew past its listed size aborts the stream.
func multipartStream(files []sandboxremote.UploadFile) (string, func() io.Reader) {
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	ctype := mw.FormDataContentType()
	return ctype, func() io.Reader {
		go func() {
			pw.CloseWithError(writeParts(mw, files))
		}()
		return pr
	}
}

func writeParts(mw *multipart.Writer, files []sandboxremote.UploadFile) error {
	for _, f := range files {
		mode := f.Mode & 0o777
		if mode == 0 {
			mode = 0o644
		}
		meta, err := json.Marshal(struct {
			Path string `json:"path"`
			Mode uint32 `json:"mode"`
		}{f.Path, mode})
		if err != nil {
			return err
		}
		h := textproto.MIMEHeader{}
		h.Set("Content-Disposition", `form-data; name="metadata"`)
		h.Set("Content-Type", "application/json")
		w, err := mw.CreatePart(h)
		if err != nil {
			return err
		}
		if _, err := w.Write(meta); err != nil {
			return err
		}
		h = textproto.MIMEHeader{}
		h.Set("Content-Disposition", `form-data; name="content"`)
		h.Set("Content-Type", "application/octet-stream")
		if w, err = mw.CreatePart(h); err != nil {
			return err
		}
		if err := copyFile(w, f); err != nil {
			return err
		}
	}
	return mw.Close()
}

// copyFile copies one file's content, refusing one that grew past its size.
func copyFile(w io.Writer, f sandboxremote.UploadFile) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	n, err := io.Copy(w, io.LimitReader(rc, f.Size+1))
	if err != nil {
		return err
	}
	if n > f.Size {
		return fmt.Errorf("dockersbx: %s grew past %d bytes while uploading", f.Path, f.Size)
	}
	return nil
}

// sortedKeys returns a set's keys in order (directories are made shortest
// first, so a parent precedes its children).
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// cleanSlash is path.Clean for an absolute slash path.
func cleanSlash(p string) string {
	var out []string
	for _, s := range strings.Split(p, "/") {
		switch s {
		case "", ".":
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, s)
		}
	}
	return "/" + strings.Join(out, "/")
}

// dirOf is the parent directory of a clean absolute path.
func dirOf(p string) string {
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return "/"
	}
	return p[:i]
}
