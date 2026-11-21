package daytona

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// process.go is a command: one SSH exec channel on the box's SSH
// connection (ssh.go), so stdout, stdin, stdin's close, stderr and the exit
// status are the SSH connection protocol's own (RFC 4254 section 6), not a
// vendor framing. The command is a shell string (the exec request's
// command), so the argv is single-quoted here, and it runs under `sh -c`
// that records its pid, so Kill can signal it with a second exec (the
// gateway's support for the signal request is not documented).

// envNameRE is a portable environment variable name.
var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// shellQuote single-quotes s for a POSIX shell.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// commandLine builds the exec command for spec: `sh -c` (under `sudo -n`
// for AsRoot) running a script that records its pid, changes to the cwd and
// execs the argv with the env (sent in the command, because an SSH server
// may refuse env requests), stdin from /dev/null unless the process reads a
// streaming stdin.
func commandLine(spec sandboxremote.ExecSpec, pidPath string) (string, error) {
	if len(spec.Argv) == 0 {
		return "", errors.New("daytona: exec needs an argv")
	}
	var b strings.Builder
	b.WriteString("echo $$ >" + shellQuote(pidPath) + " && ")
	if spec.Cwd != "" {
		b.WriteString("cd -- " + shellQuote(spec.Cwd) + " && ")
	}
	b.WriteString("exec")
	if len(spec.Env) > 0 {
		if strings.Contains(spec.Argv[0], "=") {
			return "", fmt.Errorf("daytona: program %q has an = in its name", spec.Argv[0])
		}
		b.WriteString(" env")
		keys := make([]string, 0, len(spec.Env))
		for k := range spec.Env {
			if !envNameRE.MatchString(k) {
				return "", fmt.Errorf("daytona: environment name %q is not a portable name", k)
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			b.WriteString(" " + shellQuote(k+"="+spec.Env[k]))
		}
	}
	for _, a := range spec.Argv {
		b.WriteString(" " + shellQuote(a))
	}
	if !spec.Stdin {
		b.WriteString(" </dev/null")
	}
	line := "sh -c " + shellQuote(b.String())
	if spec.AsRoot {
		line = "sudo -n -- " + line
	}
	return line, nil
}

// pidPathFor is where a command records its pid in the box.
func pidPathFor(id string) string { return "/tmp/.observer-exec-" + id + ".pid" }

// Exec starts a command on its own SSH exec channel. A vendor PTY is
// refused (the guest helper owns the PTY, so the terminal and its sizes
// cross the relay mux); a one-shot stdin is refused too (this row has a
// file API, so UploadViaExec is not set).
func (c *Client) Exec(ctx context.Context, id string, spec sandboxremote.ExecSpec) (sandboxremote.Process, error) {
	if spec.PTY {
		return nil, fmt.Errorf("daytona: a vendor terminal: %w", sandboxremote.ErrNotSupported)
	}
	if len(spec.StdinData) > 0 {
		return nil, fmt.Errorf("daytona: a one-shot stdin: %w", sandboxremote.ErrNotSupported)
	}
	tag, err := newTag()
	if err != nil {
		return nil, err
	}
	pidPath := pidPathFor(tag)
	line, err := commandLine(spec, pidPath)
	if err != nil {
		return nil, err
	}
	sess, err := c.session(ctx, id)
	if err != nil {
		return nil, err
	}
	p := &process{c: c, box: id, sess: sess, pidPath: pidPath, asRoot: spec.AsRoot, waited: make(chan struct{})}
	if spec.Stderr != nil {
		sess.Stderr = spec.Stderr
	} else {
		sess.Stderr = io.Discard
	}
	if p.stdout, err = sess.StdoutPipe(); err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("daytona: exec: %w", err)
	}
	if spec.Stdin {
		if p.stdin, err = sess.StdinPipe(); err != nil {
			_ = sess.Close()
			return nil, fmt.Errorf("daytona: exec: %w", err)
		}
	}
	if err := sess.Start(line); err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("daytona: exec: %s", c.redact(err.Error()))
	}
	go p.wait()
	return p, nil
}

// process is one command on an SSH exec channel.
type process struct {
	c       *Client
	box     string
	sess    *ssh.Session
	stdout  io.Reader
	stdin   io.WriteCloser
	pidPath string
	asRoot  bool

	// The exit, once the channel says it (Session.Wait is called once, by
	// wait).
	waited chan struct{}
	code   int
	werr   error

	cmu    sync.Mutex
	closed bool
}

func (p *process) wait() {
	err := p.sess.Wait()
	var ee *ssh.ExitError
	switch {
	case err == nil:
		p.code = 0
	case errors.As(err, &ee):
		p.code = ee.ExitStatus()
	default:
		// The channel closed with no exit status (a cut connection, or a
		// process ended by a signal the server did not report).
		p.werr = fmt.Errorf("daytona: the command ended without an exit status: %s", p.c.redact(err.Error()))
	}
	close(p.waited)
}

// Read returns the command's stdout.
func (p *process) Read(b []byte) (int, error) { return p.stdout.Read(b) }

// Write feeds the command's stdin.
func (p *process) Write(b []byte) (int, error) {
	if p.stdin == nil {
		return 0, errors.New("daytona: the command was started without stdin")
	}
	return p.stdin.Write(b)
}

// CloseWrite closes stdin only (the box reads EOF while stdout stays open):
// the SSH channel's EOF (sandboxremote.HalfCloser).
func (p *process) CloseWrite() error {
	if p.stdin == nil {
		return nil
	}
	return p.stdin.Close()
}

// PID is the command's tag (no reattach is documented, so nothing reuses
// it).
func (p *process) PID() string {
	return strings.TrimSuffix(strings.TrimPrefix(p.pidPath, "/tmp/.observer-exec-"), ".pid")
}

func (p *process) Resize(context.Context, uint16, uint16) error {
	return fmt.Errorf("daytona: resize: %w", sandboxremote.ErrNotSupported)
}

// Wait blocks until the command ends and returns its exit status.
func (p *process) Wait(ctx context.Context) (int, error) {
	select {
	case <-p.waited:
		return p.code, p.werr
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

// Kill sends SIGTERM to the recorded pid through a second exec, then
// closes the channel.
func (p *process) Kill(ctx context.Context) error {
	select {
	case <-p.waited:
		return p.Close()
	default:
	}
	line := "kill -TERM \"$(cat " + shellQuote(p.pidPath) + ")\""
	if p.asRoot {
		line = "sudo -n -- sh -c " + shellQuote(line)
	}
	var err error
	if sess, serr := p.c.session(ctx, p.box); serr == nil {
		sess.Stdout, sess.Stderr = io.Discard, io.Discard
		done := make(chan error, 1)
		go func() { done <- sess.Run(line) }()
		select {
		case err = <-done:
		case <-ctx.Done():
			err = ctx.Err()
		}
		_ = sess.Close()
	} else {
		err = serr
	}
	_ = p.Close()
	if err != nil {
		var ee *ssh.ExitError
		if errors.As(err, &ee) {
			return nil // the process had already gone
		}
		return fmt.Errorf("daytona: kill: %s", p.c.redact(err.Error()))
	}
	return nil
}

// Close releases the channel (the server ends a non-PTY command whose
// channel closed as it sees fit; Kill ends it on purpose).
func (p *process) Close() error {
	p.cmu.Lock()
	defer p.cmu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	err := p.sess.Close()
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}
