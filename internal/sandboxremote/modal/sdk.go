package modal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"

	modalsdk "github.com/modal-labs/modal-client/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// sdk.go is the one file that names a Modal SDK type: sdkBackend implements
// the backend seam over github.com/modal-labs/modal-client/go.
//
// The SDK would read its profile file (~/.modal.toml, or MODAL_CONFIG_PATH),
// a credential file outside the keystore seam. It never does here: the
// client passes an empty profile set (ClientParams.Config, noProfileFile),
// which the SDK uses in place of the file, and the credential goes in
// explicitly from the keystore seam (orchestrator ruling F7 at the SBX-P7
// merge). If a later SDK drops that field the client refuses to start
// rather than let the file be read. The SDK still reads MODAL_SERVER_URL, so
// the client guards the binding itself (SBX-GOV-4): a MODAL_SERVER_URL other
// than the bound endpoint is refused up front, and an interceptor on every
// control- and input-plane call refuses a connection to any host outside the
// bound endpoint's domain before the call (and its token headers) leaves.
// The per-box command router the SDK dials for exec carries a per-task token
// the control plane issued, never the account token.

// sdkBackend is the backend over the Modal SDK.
type sdkBackend struct {
	c *modalsdk.Client
}

// boundHosts returns the guard's test: the endpoint's host, or a host under
// its registrable domain (api.modal.com binds *.modal.com).
func boundHosts(endpoint string) (func(string) bool, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, fmt.Errorf("endpoint %q is not an https origin", endpoint)
	}
	host := strings.ToLower(u.Hostname())
	labels := strings.Split(host, ".")
	domain := host
	if len(labels) > 2 {
		domain = strings.Join(labels[len(labels)-2:], ".")
	}
	return func(target string) bool {
		h := target
		if i := strings.Index(h, "///"); i >= 0 {
			h = h[i+3:]
		}
		if hh, _, err := net.SplitHostPort(h); err == nil {
			h = hh
		}
		h = strings.ToLower(h)
		return h == host || h == domain || strings.HasSuffix(h, "."+domain)
	}, nil
}

// guards builds the interceptors that refuse an unbound host.
func guards(ok func(string) bool) (grpc.UnaryClientInterceptor, grpc.StreamClientInterceptor) {
	unary := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if !ok(cc.Target()) {
			return sandboxremote.ErrCredentialEndpointMismatch
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
	stream := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		if !ok(cc.Target()) {
			return nil, sandboxremote.ErrCredentialEndpointMismatch
		}
		return streamer(ctx, desc, cc, method, opts...)
	}
	return unary, stream
}

// newSDKBackend builds the SDK client with the explicit token (which clears
// any OAuth or file credential), a discarding logger and the binding guard.
func newSDKBackend(o Options) (*sdkBackend, error) {
	ok, err := boundHosts(o.Endpoint)
	if err != nil {
		return nil, err
	}
	if env := os.Getenv("MODAL_SERVER_URL"); env != "" && !sameOrigin(env, o.Endpoint) {
		return nil, sandboxremote.ErrCredentialEndpointMismatch
	}
	unary, stream := guards(ok)
	params := &modalsdk.ClientParams{
		TokenID: o.TokenID, TokenSecret: o.TokenSecret,
		Logger:                 slog.New(slog.DiscardHandler),
		GRPCUnaryInterceptors:  []grpc.UnaryClientInterceptor{unary},
		GRPCStreamInterceptors: []grpc.StreamClientInterceptor{stream},
	}
	if err := noProfileFile(params); err != nil {
		return nil, err
	}
	c, err := modalsdk.NewClientWithOptions(params)
	if err != nil {
		return nil, err
	}
	return &sdkBackend{c: c}, nil
}

// errProfileFileRead refuses a Modal SDK whose profile-file read cannot be
// switched off.
var errProfileFileRead = errors.New("modal: this Modal SDK has no way to skip its profile file (~/.modal.toml); the Modal driver refuses to start rather than let the SDK read that credential file")

// noProfileFile sets ClientParams.Config to an empty profile set, which the
// SDK uses in place of reading ~/.modal.toml (or MODAL_CONFIG_PATH). The
// field's type is unexported, so it is set through reflection; a later SDK
// without the field fails closed (errProfileFileRead).
func noProfileFile(p *modalsdk.ClientParams) error {
	f := reflect.ValueOf(p).Elem().FieldByName("Config")
	if !f.IsValid() || !f.CanSet() || f.Kind() != reflect.Pointer || f.Type().Elem().Kind() != reflect.Map {
		return errProfileFileRead
	}
	empty := reflect.New(f.Type().Elem())
	empty.Elem().Set(reflect.MakeMap(f.Type().Elem()))
	f.Set(empty)
	return nil
}

// sameOrigin compares two origins by scheme and host, the default port
// folded in.
func sameOrigin(a, b string) bool {
	ua, ea := url.Parse(a)
	ub, eb := url.Parse(b)
	if ea != nil || eb != nil {
		return false
	}
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		return "443"
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Hostname(), ub.Hostname()) && port(ua) == port(ub)
}

// classify maps an SDK or gRPC error onto the backend errors.
func classify(err error) error {
	if err == nil {
		return nil
	}
	var nf modalsdk.NotFoundError
	var fnf modalsdk.SandboxFilesystemNotFoundError
	var re modalsdk.ResourceExhaustedError
	switch {
	case errors.Is(err, sandboxremote.ErrCredentialEndpointMismatch):
		return err
	case errors.As(err, &nf), errors.As(err, &fnf), status.Code(err) == codes.NotFound:
		return fmt.Errorf("%w: %w", errNotFound, err)
	case errors.As(err, &re), status.Code(err) == codes.ResourceExhausted:
		return fmt.Errorf("%w: %w", errRateLimit, err)
	}
	return err
}

// lost reports a create whose answer may have been lost after the request
// left (the box may exist under its tags).
func lost(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	switch status.Code(err) {
	case codes.Unavailable, codes.DeadlineExceeded, codes.Unknown, codes.Aborted:
		return true
	}
	return false
}

func (b *sdkBackend) create(ctx context.Context, s createSpec) (string, error) {
	app, err := b.c.Apps.FromName(ctx, s.app, &modalsdk.AppFromNameParams{CreateIfMissing: true})
	if err != nil {
		return "", classify(err)
	}
	img := b.c.Images.FromRegistry(s.image, nil)
	sb, err := b.c.Sandboxes.Create(ctx, app, img, &modalsdk.SandboxCreateParams{
		Timeout:      time.Duration(s.timeoutSeconds) * time.Second,
		Runtime:      modalsdk.SandboxRuntimeGVisor,
		BlockNetwork: s.blockNetwork,
		Regions:      s.regions,
		Tags:         s.tags,
		Env:          s.env,
	})
	if err != nil {
		if lost(err) {
			return "", fmt.Errorf("%w: %w", errLostAnswer, err)
		}
		return "", classify(err)
	}
	id := sb.SandboxID
	_ = sb.Detach()
	return id, nil
}

func (b *sdkBackend) get(ctx context.Context, id string) (boxState, error) {
	sb, err := b.c.Sandboxes.FromID(ctx, id, nil)
	if err != nil {
		return boxState{}, classify(err)
	}
	defer func() { _ = sb.Detach() }()
	code, err := sb.Poll(ctx, nil)
	if err != nil {
		return boxState{}, classify(err)
	}
	st := boxState{id: id, running: code == nil}
	if st.running {
		if tags, terr := sb.GetTags(ctx, nil); terr == nil {
			st.tags = tags
		}
	}
	return st, nil
}

func (b *sdkBackend) list(ctx context.Context, tags map[string]string) ([]boxState, error) {
	seq, err := b.c.Sandboxes.List(ctx, &modalsdk.SandboxListParams{Tags: tags})
	if err != nil {
		return nil, classify(err)
	}
	var out []boxState
	for sb, err := range seq {
		if err != nil {
			return nil, classify(err)
		}
		st := boxState{id: sb.SandboxID, running: true}
		if t, terr := sb.GetTags(ctx, nil); terr == nil {
			st.tags = t
		}
		_ = sb.Detach()
		out = append(out, st)
	}
	return out, nil
}

func (b *sdkBackend) terminate(ctx context.Context, id string) error {
	sb, err := b.c.Sandboxes.FromID(ctx, id, nil)
	if err != nil {
		return classify(err)
	}
	defer func() { _ = sb.Detach() }()
	_, err = sb.Terminate(ctx, nil)
	return classify(err)
}

func (b *sdkBackend) exec(ctx context.Context, id string, s execSpec) (proc, error) {
	sb, err := b.c.Sandboxes.FromID(ctx, id, nil)
	if err != nil {
		return nil, classify(err)
	}
	stderr := modalsdk.Ignore
	if s.stderr != nil {
		stderr = modalsdk.Pipe
	}
	cp, err := sb.Exec(ctx, s.argv, &modalsdk.SandboxExecParams{
		Stdout: modalsdk.Pipe, Stderr: stderr, Workdir: s.cwd, Env: s.env,
	})
	if err != nil {
		_ = sb.Detach()
		return nil, classify(err)
	}
	if s.stderr != nil && cp.Stderr != nil {
		go func() { _, _ = io.Copy(s.stderr, cp.Stderr) }()
	}
	return &sdkProc{sb: sb, cp: cp}, nil
}

func (b *sdkBackend) write(ctx context.Context, id, p string, data []byte) error {
	sb, err := b.c.Sandboxes.FromID(ctx, id, nil)
	if err != nil {
		return classify(err)
	}
	defer func() { _ = sb.Detach() }()
	return classify(sb.Filesystem.WriteBytes(ctx, data, p, nil))
}

func (b *sdkBackend) read(ctx context.Context, id, p string) ([]byte, error) {
	sb, err := b.c.Sandboxes.FromID(ctx, id, nil)
	if err != nil {
		return nil, classify(err)
	}
	defer func() { _ = sb.Detach() }()
	data, err := sb.Filesystem.ReadBytes(ctx, p, nil)
	return data, classify(err)
}

// sdkProc is one SDK exec.
type sdkProc struct {
	sb *modalsdk.Sandbox
	cp *modalsdk.ContainerProcess
}

func (p *sdkProc) Read(b []byte) (int, error)  { return p.cp.Stdout.Read(b) }
func (p *sdkProc) Write(b []byte) (int, error) { return p.cp.Stdin.Write(b) }
func (p *sdkProc) closeStdin() error           { return p.cp.Stdin.Close() }

func (p *sdkProc) closeStdout() error {
	err := p.cp.Stdout.Close()
	_ = p.sb.Detach()
	return err
}

func (p *sdkProc) wait(ctx context.Context) (int, error) {
	code, err := p.cp.Wait(ctx, nil)
	return code, classify(err)
}
