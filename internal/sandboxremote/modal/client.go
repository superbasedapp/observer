// Package modal is the Modal wire client of the hosted sandbox rows (sandbox
// plan v2 section 13 P7 R3, lane SBX-P7). Modal declares its gRPC API
// non-public, so the client speaks it only through Modal's own Go SDK
// (github.com/modal-labs/modal-client/go v0.11.1, Apache-2.0), behind the
// sbo_omit_terminals_sandbox_modal build tag. It is one of the three
// packages that talk to a vendor (an egress lane row in
// tests/invariant/egress_lanes_test.go) and is imported only by
// cmd/observer (tests/invariant/sandbox_remote_egress_test.go). The call
// table is in docs/sandboxed-terminals.md ("Hosted sandboxes", Modal).
//
// It implements sandboxremote.Client and nothing more: no SDK type leaves
// the package (sdk.go is the only file that names one). A token is held only
// in memory for the client's life and never appears in an error.
//
// What Modal does not document, the client does not pretend: a process has
// no reattach and no terminal resize (the guest helper owns the PTY), the
// SDK has no per-process kill (Kill closes stdin; the box's terminate ends
// the rest), and a box's region is the one asked for, not one read back.
package modal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// DefaultApp is the Modal App every box is created under (made if missing).
const DefaultApp = "observer-sandboxes"

// DefaultImage is the registry image a box starts from when the user named
// no template: a Debian image with git, curl and npm, so the internet tier
// can install an agent CLI at first start (a template is the other path).
const DefaultImage = "node:22-bookworm"

// maxUpload caps one uploaded file read into memory (the SDK writes bytes).
const maxUpload = 256 << 20

// Options configure a client.
type Options struct {
	// Endpoint is the control-plane origin the token is bound to
	// (https://api.modal.com:443).
	Endpoint    string
	TokenID     string
	TokenSecret string
	// App names the Modal App boxes are created under (default DefaultApp).
	App string
	// backend replaces the SDK (tests).
	backend backend
}

// Client is the Modal wire client.
type Client struct {
	o  Options
	be backend
	// secrets are redacted from every error the client returns.
	secrets []string
}

// New builds a client. It makes no call (the SDK dials on first use).
func New(o Options) (*Client, error) {
	if strings.TrimSpace(o.TokenID) == "" || strings.TrimSpace(o.TokenSecret) == "" {
		return nil, errors.New("modal: no token id and secret")
	}
	if o.App == "" {
		o.App = DefaultApp
	}
	c := &Client{o: o, secrets: []string{o.TokenID, o.TokenSecret}}
	if o.backend != nil {
		c.be = o.backend
		return c, nil
	}
	be, err := newSDKBackend(o)
	if err != nil {
		return nil, c.wrap("modal: client", err)
	}
	c.be = be
	return c, nil
}

var _ sandboxremote.Client = (*Client)(nil)

// boxState is what the backend reports of one box.
type boxState struct {
	id      string
	running bool
	tags    map[string]string
}

// createSpec is a create call, already mapped to Modal's vocabulary.
type createSpec struct {
	app            string
	image          string
	timeoutSeconds int
	blockNetwork   bool
	regions        []string
	tags           map[string]string
	env            map[string]string
}

// execSpec is one exec call.
type execSpec struct {
	argv []string
	env  map[string]string
	cwd  string
	// stderr receives the process's stderr (nil: the SDK ignores it).
	stderr io.Writer
}

// proc is one running exec.
type proc interface {
	io.Reader
	io.Writer
	closeStdin() error
	closeStdout() error
	wait(ctx context.Context) (int, error)
}

// backend is the SDK seam: sdk.go implements it over the Modal SDK, the
// tests over a scripted fake.
type backend interface {
	create(ctx context.Context, s createSpec) (string, error)
	get(ctx context.Context, id string) (boxState, error)
	list(ctx context.Context, tags map[string]string) ([]boxState, error)
	terminate(ctx context.Context, id string) error
	exec(ctx context.Context, id string, s execSpec) (proc, error)
	write(ctx context.Context, id, p string, data []byte) error
	read(ctx context.Context, id, p string) ([]byte, error)
}

// Backend errors the client maps (sdk.go classifies SDK and gRPC errors into
// these; the fake returns them directly).
var (
	errNotFound   = errors.New("not found")
	errRateLimit  = errors.New("resource exhausted")
	errLostAnswer = errors.New("answer lost")
)

// wrap maps a backend error onto the seam's errors and redacts the token.
func (c *Client) wrap(what string, err error) error {
	if err == nil {
		return nil
	}
	msg := sandboxremote.Redact(err.Error(), c.secrets)
	switch {
	case errors.Is(err, errNotFound):
		return fmt.Errorf("%s: %w", what, sandboxremote.ErrNotFound)
	case errors.Is(err, sandboxremote.ErrCredentialEndpointMismatch):
		return fmt.Errorf("%s: %w", what, sandboxremote.ErrCredentialEndpointMismatch)
	case errors.Is(err, errRateLimit):
		return fmt.Errorf("%s: %w (%s)", what, sandboxremote.ErrRateLimited, msg)
	}
	return fmt.Errorf("%s: %s", what, msg)
}

// Create makes a box: gVisor runtime, the vendor timeout, the run's tags,
// network blocked for every tier but internet, no ports, no snapshot.
func (c *Client) Create(ctx context.Context, spec sandboxremote.BoxSpec) (sandboxremote.BoxInfo, error) {
	if spec.TimeoutSeconds <= 0 {
		return sandboxremote.BoxInfo{}, errors.New("modal: a box needs a timeout")
	}
	tags := maps.Clone(spec.Labels)
	if tags == nil {
		tags = map[string]string{}
	}
	tags[sandboxremote.LabelKey] = spec.RunID
	s := createSpec{
		app: c.o.App, image: spec.Template, timeoutSeconds: spec.TimeoutSeconds,
		blockNetwork: spec.Tier != vocab.TierInternet, tags: tags, env: maps.Clone(spec.Env),
	}
	if s.image == "" {
		s.image = DefaultImage
	}
	if spec.Region != "" && spec.Region != sandboxremote.ProviderChosen {
		s.regions = []string{spec.Region}
	}
	id, err := c.be.create(ctx, s)
	if err != nil {
		if errors.Is(err, errLostAnswer) {
			return sandboxremote.BoxInfo{}, fmt.Errorf("modal: create: %w", sandboxremote.ErrCreateUnknown)
		}
		return sandboxremote.BoxInfo{}, c.wrap("modal: create", err)
	}
	region := spec.Region
	if region == "" {
		region = sandboxremote.ProviderChosen
	}
	return sandboxremote.BoxInfo{ID: id, Region: region, Running: true, Labels: tags, Extra: map[string]string{"app": c.o.App, "image": s.image}}, nil
}

// Get reads one box.
func (c *Client) Get(ctx context.Context, id string) (sandboxremote.BoxInfo, error) {
	st, err := c.be.get(ctx, id)
	if err != nil {
		return sandboxremote.BoxInfo{}, c.wrap("modal: get", err)
	}
	return sandboxremote.BoxInfo{ID: st.id, Running: st.running, Labels: st.tags}, nil
}

// ListByLabel lists the running boxes carrying key=value.
func (c *Client) ListByLabel(ctx context.Context, key, value string) ([]sandboxremote.BoxInfo, error) {
	list, err := c.be.list(ctx, map[string]string{key: value})
	if err != nil {
		return nil, c.wrap("modal: list", err)
	}
	out := make([]sandboxremote.BoxInfo, 0, len(list))
	for _, st := range list {
		if st.tags[key] != value {
			continue // the filter is the vendor's; never trust it alone
		}
		out = append(out, sandboxremote.BoxInfo{ID: st.id, Running: st.running, Labels: st.tags})
	}
	return out, nil
}

// Delete terminates a box (Modal keeps no stopped box to delete).
func (c *Client) Delete(ctx context.Context, id string) error {
	return c.wrap("modal: terminate", c.be.terminate(ctx, id))
}

// WriteFiles writes each file, then sets every mode other than the SDK's
// default with one chmod per mode (the SDK takes no mode).
func (c *Client) WriteFiles(ctx context.Context, id string, files []sandboxremote.UploadFile) error {
	byMode := map[uint32][]string{}
	for _, f := range files {
		if !path.IsAbs(f.Path) {
			return fmt.Errorf("modal: upload path %q is not absolute", f.Path)
		}
		data, err := readUpload(f)
		if err != nil {
			return err
		}
		if err := c.be.write(ctx, id, f.Path, data); err != nil {
			return c.wrap("modal: write "+f.Path, err)
		}
		if f.Mode != 0 && f.Mode != 0o644 {
			byMode[f.Mode] = append(byMode[f.Mode], f.Path)
		}
	}
	modes := slices.Collect(maps.Keys(byMode))
	sort.Slice(modes, func(i, j int) bool { return modes[i] < modes[j] })
	for _, m := range modes {
		paths := byMode[m]
		for len(paths) > 0 {
			n := min(len(paths), 200)
			argv := append([]string{"chmod", strconv.FormatUint(uint64(m), 8), "--"}, paths[:n]...)
			if err := c.run(ctx, id, argv); err != nil {
				return err
			}
			paths = paths[n:]
		}
	}
	return nil
}

func readUpload(f sandboxremote.UploadFile) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	limit := int64(maxUpload)
	if f.Size > 0 && f.Size < limit {
		limit = f.Size
	}
	data, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("modal: %s grew past %d bytes while uploading", f.Path, limit)
	}
	return data, nil
}

// run executes argv with no stdin and requires exit 0.
func (c *Client) run(ctx context.Context, id string, argv []string) error {
	p, err := c.be.exec(ctx, id, execSpec{argv: argv})
	if err != nil {
		return c.wrap("modal: exec "+argv[0], err)
	}
	_ = p.closeStdin()
	_, _ = io.Copy(io.Discard, io.LimitReader(p, 64<<10))
	code, err := p.wait(ctx)
	_ = p.closeStdout()
	if err != nil {
		return c.wrap("modal: exec "+argv[0], err)
	}
	if code != 0 {
		return fmt.Errorf("modal: %s exited %d", argv[0], code)
	}
	return nil
}

// ReadFile reads one file, refusing one over max bytes.
func (c *Client) ReadFile(ctx context.Context, id, p string, max int64) ([]byte, error) {
	b, err := c.be.read(ctx, id, p)
	if err != nil {
		return nil, c.wrap("modal: read "+p, err)
	}
	if max > 0 && int64(len(b)) > max {
		return nil, fmt.Errorf("modal: %s is over %d bytes", p, max)
	}
	return b, nil
}

// Exec starts a process. Modal documents no terminal resize, so a PTY is
// refused here and the guest helper owns it (registry PTYGuestHelper).
func (c *Client) Exec(ctx context.Context, id string, spec sandboxremote.ExecSpec) (sandboxremote.Process, error) {
	if spec.PTY {
		return nil, fmt.Errorf("modal: a vendor terminal: %w", sandboxremote.ErrNotSupported)
	}
	if len(spec.Argv) == 0 {
		return nil, errors.New("modal: exec needs an argv")
	}
	p, err := c.be.exec(ctx, id, execSpec{argv: spec.Argv, env: spec.Env, cwd: spec.Cwd, stderr: spec.Stderr})
	if err != nil {
		return nil, c.wrap("modal: exec", err)
	}
	if !spec.Stdin {
		_ = p.closeStdin()
	}
	return &process{c: c, p: p}, nil
}

// Reattach: Modal documents no reattach to a running exec, so Observer has
// none; its SDK re-dials and resumes a cut exec stream itself (live run 2,
// 2026-10-23: no loss after a TCP cut of every tunnel), and a stream it
// cannot resume ends the run, the agent's own resume picking it up (A7).
func (c *Client) Reattach(context.Context, string, string) (sandboxremote.Process, error) {
	return nil, fmt.Errorf("modal: reattach: %w", sandboxremote.ErrNotSupported)
}

// process adapts one exec to sandboxremote.Process.
type process struct {
	c *Client
	p proc
}

func (p *process) Read(b []byte) (int, error) {
	n, err := p.p.Read(b)
	if err != nil && !errors.Is(err, io.EOF) {
		err = p.c.wrap("modal: stdout", err)
	}
	return n, err
}

func (p *process) Write(b []byte) (int, error) {
	n, err := p.p.Write(b)
	return n, p.c.wrap("modal: stdin", err)
}

// PID is empty: the SDK exposes no handle a later call could reattach by.
func (p *process) PID() string { return "" }

func (p *process) Resize(context.Context, uint16, uint16) error {
	return fmt.Errorf("modal: resize: %w", sandboxremote.ErrNotSupported)
}

func (p *process) Wait(ctx context.Context) (int, error) {
	code, err := p.p.wait(ctx)
	return code, p.c.wrap("modal: wait", err)
}

// Kill closes stdin: the SDK has no per-process signal, and every process
// the run starts ends on stdin EOF or with the box.
func (p *process) Kill(context.Context) error { return p.p.closeStdin() }

func (p *process) Close() error {
	_ = p.p.closeStdin()
	return p.p.closeStdout()
}
