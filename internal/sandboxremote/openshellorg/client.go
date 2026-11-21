package openshellorg

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	osorg "github.com/marmutapp/superbased-observer/internal/openshellorg"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// HealthService is the front's gRPC health service name (design 7.6 F1).
const HealthService = "superbased.openshell.front"

// The response trailers the front's health answer carries (design 7.6 F1).
const (
	TrailerGatewayVersion = "x-observer-gateway-version"
	TrailerSync           = "x-observer-sync"
)

// Options configure one client: one run, one front.
type Options struct {
	// FrontURL is the org-published front origin (https only).
	FrontURL string
	// SPKISHA256 pins the front's certificate (lowercase hex of the SHA-256
	// of its SubjectPublicKeyInfo); "" uses the system roots alone.
	SPKISHA256 string
	// Source mints the run's tokens (purpose from the call's context).
	Source sandboxremote.CredentialSource
	// RunID is the node's run id (the box's ledger key until a resume).
	RunID string
	// BoxName is the box the org named at mint (every call is forced to it
	// by the front anyway).
	BoxName string
	// Dialer, when set, replaces the network dial (the bufconn fake). The
	// transport then still requires the per-RPC credential's security
	// check, so tests use Insecure with it.
	Dialer func(ctx context.Context, addr string) (net.Conn, error)
	// Insecure skips TLS (tests over an in-process listener only; New
	// refuses it with a real dial).
	Insecure bool
	// Now is the clock (time.Now when nil).
	Now func() time.Time
	// Heartbeat is how long an interactive stream may carry no frame from
	// this side before it sends a heartbeat (zero means
	// osorg.StreamHeartbeat; a negative value sends none, for the test that
	// shows the cut it prevents).
	Heartbeat time.Duration
}

// Client is the wire client of one run against the org's front. It
// implements sandboxremote.Client.
type Client struct {
	opts Options
	conn *grpc.ClientConn
	api  pb.OpenShellClient
}

var _ sandboxremote.Client = (*Client)(nil)

// ErrNoRootExec refuses an exec that asks for root: the org row has none.
var ErrNoRootExec = errors.New("openshellorg: the org-hosted box runs every exec as the box user; a root exec is not offered")

// ErrFrontURL refuses a front URL that is not an https origin.
var ErrFrontURL = errors.New("openshellorg: the front URL is not an https origin")

// New builds the client. It dials lazily (grpc.NewClient makes no
// connection until the first call), so building it calls nothing.
func New(opts Options) (*Client, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Source == nil {
		return nil, errors.New("openshellorg: no token source")
	}
	u, err := url.Parse(opts.FrontURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || (u.Path != "" && u.Path != "/") || u.User != nil || u.RawQuery != "" {
		return nil, ErrFrontURL
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	if opts.Insecure && opts.Dialer == nil {
		return nil, errors.New("openshellorg: an insecure transport is for an in-process test listener only")
	}
	tc, err := transportCreds(u.Hostname(), opts)
	if err != nil {
		return nil, err
	}
	dopts := []grpc.DialOption{
		grpc.WithTransportCredentials(tc),
		grpc.WithPerRPCCredentials(tokenCreds{src: opts.Source, insecure: opts.Insecure}),
	}
	if opts.Dialer != nil {
		dopts = append(dopts, grpc.WithContextDialer(opts.Dialer))
		host = "passthrough:///" + host
	}
	conn, err := grpc.NewClient(host, dopts...)
	if err != nil {
		return nil, fmt.Errorf("openshellorg: %w", err)
	}
	return &Client{opts: opts, conn: conn, api: pb.NewOpenShellClient(conn)}, nil
}

// Close releases the connection.
func (c *Client) Close() error { return c.conn.Close() }

// transportCreds is TLS 1.2+ with the system roots, plus the org's SPKI pin
// when published (G1-A12).
func transportCreds(serverName string, opts Options) (credentials.TransportCredentials, error) {
	if opts.Insecure {
		return insecure.NewCredentials(), nil
	}
	pin := strings.ToLower(strings.TrimSpace(opts.SPKISHA256))
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}
	if pin != "" {
		if len(pin) != 64 {
			return nil, errors.New("openshellorg: front_tls_spki_sha256 is not 64 hex characters")
		}
		// VerifyConnection runs on every handshake, a resumed session
		// included, so the pin cannot be skipped by session resumption.
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) > 0 && spkiHex(cs.PeerCertificates[0]) == pin {
				return nil
			}
			return errors.New("openshellorg: the front's certificate does not match the published pin")
		}
	}
	return credentials.NewTLS(cfg), nil
}

func spkiHex(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// tokenCreds puts the run token on every RPC as a bearer, minted for the
// call's purpose. The token is never logged or wrapped into an error.
type tokenCreds struct {
	src      sandboxremote.CredentialSource
	insecure bool
}

func (t tokenCreds) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	tok, err := t.src.Token(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]string{"authorization": "Bearer " + tok}, nil
}

func (t tokenCreds) RequireTransportSecurity() bool { return !t.insecure }

// ---- the sandbox calls ------------------------------------------------------

// AdmissionLimitWords is what the node says when the gateway refuses a call
// past the member's admission budget.
var AdmissionLimitWords = fmt.Sprintf("your organization's OpenShell gateway admits at most %d box creates, deletes and provider changes per member in %d h, and yours are used up; it refuses every new box until the oldest expire (tell your organization's admin)", osorg.GatewayAdmissionsPerCaller, osorg.GatewayAdmissionHours)

// mapErr turns a gRPC status into the sandboxremote errors the core branches
// on. The not-found rule is exact: only codes.NotFound is ErrNotFound (a
// message that merely says "not found" under another code is not; the
// reaper's exact not-found rule, design 7.4).
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	switch st.Code() {
	case codes.NotFound:
		return fmt.Errorf("%w: %s", sandboxremote.ErrNotFound, st.Message())
	case codes.ResourceExhausted:
		if osorg.IsAdmissionLimit(st.Message()) {
			// The gateway's per-caller budget, named (FX3 item 2, F-L3P4-6),
			// never a generic failure.
			return fmt.Errorf("%w: %s: %s (the gateway's answer: %s)", sandboxremote.ErrRateLimited, osorg.ReasonGatewayAdmissionLimit, AdmissionLimitWords, st.Message())
		}
		return fmt.Errorf("%w: %s", sandboxremote.ErrRateLimited, st.Message())
	case codes.Unimplemented:
		return fmt.Errorf("%w: %s", sandboxremote.ErrNotSupported, st.Message())
	}
	if osorg.Reason(st.Message()).Valid() {
		// One of the organization's closed refusals (the run's end, a
		// revoke, a drain): a purposeful end, never a transport cut
		// (FX3-A3). The text stays as before.
		return fmt.Errorf("openshellorg: %s: %s: %w", st.Code(), st.Message(), sandboxremote.ErrRefused)
	}
	return fmt.Errorf("openshellorg: %s: %s", st.Code(), st.Message())
}

// boxInfo builds the core's view of a sandbox answer.
func (c *Client) boxInfo(r *pb.SandboxResponse) sandboxremote.BoxInfo {
	info := sandboxremote.BoxInfo{ID: c.opts.BoxName, Extra: map[string]string{"box_name": c.opts.BoxName}}
	sb := r.GetSandbox()
	if sb == nil {
		return info
	}
	if n := sb.GetMetadata().GetName(); n != "" {
		info.ID = n
	}
	info.Running = sb.GetStatus().GetPhase() == pb.SandboxPhase_SANDBOX_PHASE_READY
	info.Labels = sb.GetMetadata().GetLabels()
	return info
}

// Create asks the front for the run's box. The request carries the run's
// box name and label, an at-most-once request id derived from the run id,
// and no template content and no driver config: the front creates the spec
// the org compiled at mint (design 3.2 step 5), and a caller's driver config
// never reaches the box (OB-077). A lost answer is ErrCreateUnknown; the core
// then looks the box up by name (ListByLabel) and a retry with the same
// request id is the same create.
func (c *Client) Create(ctx context.Context, spec sandboxremote.BoxSpec) (sandboxremote.BoxInfo, error) {
	if sandboxremote.TokenPurpose(ctx) == "" {
		// Row F2 admits a create only with a create token.
		ctx = sandboxremote.WithTokenPurpose(ctx, string(osorg.PurposeCreate))
	}
	req := c.createRequest(spec)
	r, err := c.api.CreateSandbox(ctx, req)
	if err != nil {
		if st, ok := status.FromError(err); ok && (st.Code() == codes.Unavailable || st.Code() == codes.DeadlineExceeded || st.Code() == codes.Canceled) {
			return sandboxremote.BoxInfo{}, fmt.Errorf("%w: %s", sandboxremote.ErrCreateUnknown, st.Message())
		}
		if st, ok := status.FromError(err); ok && st.Code() == codes.FailedPrecondition && strings.Contains(st.Message(), "image") {
			return sandboxremote.BoxInfo{}, fmt.Errorf("%w: %s", sandboxremote.ErrTemplateUnavailable, st.Message())
		}
		return sandboxremote.BoxInfo{}, mapErr(err)
	}
	return c.boxInfo(r), nil
}

// createRequest is the create the node sends. Exported to the test through
// the same function, so a test pins that it carries no driver config.
func (c *Client) createRequest(spec sandboxremote.BoxSpec) *pb.CreateSandboxRequest {
	labels := map[string]string{}
	for k, v := range spec.Labels {
		labels[k] = v
	}
	return &pb.CreateSandboxRequest{
		Name:   c.opts.BoxName,
		Labels: labels,
		// Random, like every request id this client sends (lane RC1): the
		// front replaces the node's create with the recorded spec under its
		// own deterministic id (openshellorg.BoxRequestUUID), which is what
		// makes a retried create at most once at the gateway.
		RequestId: osorg.RandomRequestUUID(),
		// Command and TTY are what the org compiled too (the in-box keeper,
		// TTY off); the front replaces the whole spec with the recorded one.
		Spec: &pb.SandboxSpec{Command: append([]string(nil), osorg.KeeperArgv...), Tty: false},
	}
}

// Get reads the box's state through the front.
func (c *Client) Get(ctx context.Context, id string) (sandboxremote.BoxInfo, error) {
	r, err := c.api.GetSandbox(ctx, &pb.GetSandboxRequest{Name: c.name(id)})
	if err != nil {
		return sandboxremote.BoxInfo{}, mapErr(err)
	}
	return c.boxInfo(r), nil
}

// ListByLabel finds the run's box. The front refuses ListSandboxes (row F7),
// so the run's own box is looked up by its name; any other label value has
// no box this client can see.
func (c *Client) ListByLabel(ctx context.Context, key, value string) ([]sandboxremote.BoxInfo, error) {
	if key != sandboxremote.LabelKey || value != c.opts.RunID {
		return nil, nil
	}
	info, err := c.Get(ctx, c.opts.BoxName)
	if errors.Is(err, sandboxremote.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return []sandboxremote.BoxInfo{info}, nil
}

// Delete deletes the box through the front with a teardown token (row F6:
// any other purpose is refused there).
func (c *Client) Delete(ctx context.Context, id string) error {
	ctx = sandboxremote.WithTokenPurpose(ctx, string(osorg.PurposeTeardown))
	_, err := c.api.DeleteSandbox(ctx, &pb.DeleteSandboxRequest{Name: c.name(id), RequestId: osorg.RandomRequestUUID()})
	return mapErr(err)
}

// WriteFiles is not a call this row has (the SDK's upload is a stub): the
// hosted core writes files as exec parts (Vendor.UploadViaExec).
func (c *Client) WriteFiles(context.Context, string, []sandboxremote.UploadFile) error {
	return fmt.Errorf("%w: the org-hosted row writes files through exec parts", sandboxremote.ErrNotSupported)
}

// ReadFile reads a box file through a one-shot exec, capped at max bytes.
func (c *Client) ReadFile(ctx context.Context, id, path string, max int64) ([]byte, error) {
	p, err := c.Exec(ctx, id, sandboxremote.ExecSpec{Argv: []string{"cat", "--", path}})
	if err != nil {
		return nil, err
	}
	defer p.Close()
	b, err := io.ReadAll(io.LimitReader(p, max+1))
	if err != nil {
		return nil, err
	}
	code, err := p.Wait(ctx)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("%w: %s (exit %d)", sandboxremote.ErrNotFound, path, code)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("openshellorg: %s is over %d bytes", path, max)
	}
	return b, nil
}

// Reattach: no reattach on this row (ReattachNone).
func (c *Client) Reattach(context.Context, string, string) (sandboxremote.Process, error) {
	return nil, sandboxremote.ErrNotSupported
}

func (c *Client) name(id string) string {
	if id == "" {
		return c.opts.BoxName
	}
	return id
}

// Exec starts a process in the box. A process with no streaming stdin and no
// PTY is a one-shot ExecSandbox (StdinData sent whole, at most
// MaxOneShotStdin); anything else is an ExecSandboxInteractive stream with
// the TTY as asked. A streaming stdin with the TTY off needs PacedStdin (the
// in-box wrapper's credit), else it is refused: no unpaced sender exists.
func (c *Client) Exec(ctx context.Context, id string, spec sandboxremote.ExecSpec) (sandboxremote.Process, error) {
	if len(spec.Argv) == 0 {
		return nil, errors.New("openshellorg: empty argv")
	}
	if spec.AsRoot {
		// The org's gateway runs every exec as the box user and offers no
		// root exec (the vendor row's NoRootExec): a root step is refused,
		// never run as the box user in its place (fix round 1, A3).
		return nil, ErrNoRootExec
	}
	if !spec.Stdin && !spec.PTY {
		if len(spec.StdinData) > osorg.MaxOneShotStdin {
			return nil, fmt.Errorf("openshellorg: a one-shot stdin of %d bytes is over %d; send it in parts", len(spec.StdinData), osorg.MaxOneShotStdin)
		}
		return c.oneShot(ctx, id, spec)
	}
	if len(spec.StdinData) > 0 {
		return nil, errors.New("openshellorg: StdinData is for a one-shot exec only")
	}
	if spec.Stdin && !spec.PTY && !spec.PacedStdin {
		return nil, errors.New("openshellorg: a streaming stdin with the TTY off must be paced (the in-box paced-stdin wrapper)")
	}
	return c.interactive(ctx, id, spec)
}

func execRequest(name string, spec sandboxremote.ExecSpec) *pb.ExecSandboxRequest {
	return &pb.ExecSandboxRequest{
		Sandbox: name, Command: append([]string(nil), spec.Argv...), Workdir: spec.Cwd,
		Environment: spec.Env, Tty: spec.PTY, Cols: uint32(spec.Cols), Rows: uint32(spec.Rows),
		NoLoginShell: true, RequestId: osorg.RandomRequestUUID(),
	}
}

// oneShot runs a server-streaming exec.
func (c *Client) oneShot(ctx context.Context, id string, spec sandboxremote.ExecSpec) (sandboxremote.Process, error) {
	sctx, cancel := context.WithCancel(ctx)
	req := execRequest(c.name(id), spec)
	req.Stdin = spec.StdinData
	st, err := c.api.ExecSandbox(sctx, req)
	if err != nil {
		cancel()
		return nil, mapErr(err)
	}
	p := newProcess(cancel, spec.Stderr, nil)
	go p.pump(func() (*pb.ExecSandboxEvent, error) { return st.Recv() })
	return p, nil
}

// interactive runs a bidi exec stream.
func (c *Client) interactive(ctx context.Context, id string, spec sandboxremote.ExecSpec) (sandboxremote.Process, error) {
	sctx, cancel := context.WithCancel(ctx)
	st, err := c.api.ExecSandboxInteractive(sctx)
	if err != nil {
		cancel()
		return nil, mapErr(err)
	}
	if err := st.Send(&pb.ExecSandboxInput{Payload: &pb.ExecSandboxInput_Start{Start: execRequest(c.name(id), spec)}}); err != nil {
		cancel()
		return nil, mapErr(err)
	}
	var credit *osorg.Credit
	if spec.PacedStdin && !spec.PTY {
		credit = osorg.NewCredit()
	}
	p := newProcess(cancel, spec.Stderr, credit)
	p.send = st
	p.paced = credit != nil
	p.lastSend = time.Now()
	go p.pump(func() (*pb.ExecSandboxEvent, error) { return st.Recv() })
	if every := c.heartbeat(); every > 0 {
		go p.heartbeat(sctx, every)
	}
	return p, nil
}

// heartbeat is the interactive stream's heartbeat period (Options.Heartbeat).
func (c *Client) heartbeat() time.Duration {
	if c.opts.Heartbeat == 0 {
		return osorg.StreamHeartbeat
	}
	return c.opts.Heartbeat
}

// HealthReport is the front's health answer (design 7.6 F1, probe rows R5 to
// R8).
type HealthReport struct {
	Serving        bool
	GatewayVersion string
	Sync           string
}

// Health asks the front's health service with the run token and reads the
// gateway version and the last sync state from the response trailers.
func (c *Client) Health(ctx context.Context) (HealthReport, error) {
	var tr metadata.MD
	r, err := grpc_health_v1.NewHealthClient(c.conn).Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: HealthService}, grpc.Trailer(&tr))
	if err != nil {
		return HealthReport{}, mapErr(err)
	}
	h := HealthReport{Serving: r.GetStatus() == grpc_health_v1.HealthCheckResponse_SERVING}
	if v := tr.Get(TrailerGatewayVersion); len(v) > 0 {
		h.GatewayVersion = v[0]
	}
	if v := tr.Get(TrailerSync); len(v) > 0 {
		h.Sync = v[0]
	}
	return h, nil
}

// ---- the process ------------------------------------------------------------

type sender interface {
	Send(*pb.ExecSandboxInput) error
	CloseSend() error
}

// process is one exec's stream: stdout through a pipe, stderr to the sink
// (credit lines taken out when paced), the exit code once it ends.
type process struct {
	cancel context.CancelFunc
	pr     *io.PipeReader
	pw     *io.PipeWriter
	stderr io.Writer
	filter *osorg.AckFilter
	credit *osorg.Credit
	send   sender
	paced  bool

	// writeMu orders Write calls (held across a paced wait for credit);
	// sendMu guards each single Send or CloseSend on the stream (a gRPC
	// stream takes one sender at a time), so the heartbeat never waits
	// behind a paced write's credit wait.
	writeMu  sync.Mutex
	sendMu   sync.Mutex
	sent     int64
	lastSend time.Time // sendMu: the last frame this side sent
	closed   bool      // sendMu: CloseSend ran

	done chan struct{}
	exit int
	err  error
}

func newProcess(cancel context.CancelFunc, stderr io.Writer, credit *osorg.Credit) *process {
	pr, pw := io.Pipe()
	p := &process{cancel: cancel, pr: pr, pw: pw, stderr: stderr, credit: credit, done: make(chan struct{}), exit: -1}
	if credit != nil {
		p.filter = osorg.NewAckFilter(credit.Set)
	}
	return p
}

// pump reads the stream's events until the exit or an error.
func (p *process) pump(recv func() (*pb.ExecSandboxEvent, error)) {
	defer close(p.done)
	readerGone := false
	defer func() {
		if p.credit != nil {
			p.credit.Close()
		}
	}()
	for {
		ev, err := recv()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				p.err = mapErr(err)
			}
			_ = p.pw.CloseWithError(io.EOF)
			return
		}
		switch e := ev.GetPayload().(type) {
		case *pb.ExecSandboxEvent_Stdout:
			// An empty chunk carries nothing (a pipe write of zero bytes
			// would still wait for a reader).
			if len(e.Stdout.GetData()) == 0 || readerGone {
				continue
			}
			if _, err := p.pw.Write(e.Stdout.GetData()); err != nil {
				// The reader was closed (Close or Kill, lane FX6, FX6-R1):
				// later stdout is dropped and the pump goes on to the
				// stream's exit or end, so the exit code is kept and the
				// pump never waits for a reader that is gone.
				readerGone = true
			}
		case *pb.ExecSandboxEvent_Stderr:
			data := e.Stderr.GetData()
			if p.filter != nil {
				data = p.filter.Feed(data)
			}
			if p.stderr != nil && len(data) > 0 {
				_, _ = p.stderr.Write(data)
			}
		case *pb.ExecSandboxEvent_Exit:
			p.exit = int(e.Exit.GetExitCode())
			_ = p.pw.Close()
			return
		}
	}
}

func (p *process) Read(b []byte) (int, error) { return p.pr.Read(b) }

// Write sends stdin in frames of at most FrameBytes, and when paced never
// more than WindowBytes ahead of the box's credit.
func (p *process) Write(b []byte) (int, error) {
	if p.send == nil {
		return 0, errors.New("openshellorg: this process has no streaming stdin")
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	n := 0
	for n < len(b) {
		k := min(len(b)-n, osorg.FrameBytes)
		if p.paced {
			if err := p.credit.WaitRoom(context.Background(), p.sent, int64(k), osorg.WindowBytes, osorg.StallLimit); err != nil {
				return n, err
			}
		}
		frame := append([]byte(nil), b[n:n+k]...)
		if err := p.sendFrame(&pb.ExecSandboxInput{Payload: &pb.ExecSandboxInput_Stdin{Stdin: frame}}); err != nil {
			return n, mapErr(err)
		}
		p.sent += int64(k)
		n += k
	}
	return n, nil
}

// errStdinClosed is a send after the stdin side was closed.
var errStdinClosed = errors.New("openshellorg: the stdin side is closed")

// sendFrame sends one frame on the stream and notes when.
func (p *process) sendFrame(m *pb.ExecSandboxInput) error {
	p.sendMu.Lock()
	defer p.sendMu.Unlock()
	if p.closed {
		return errStdinClosed
	}
	err := p.send.Send(m)
	p.lastSend = time.Now()
	return err
}

// heartbeat keeps the stdin side of an open interactive stream from going
// idle for longer than every (osorg.StreamHeartbeat, F-P6-3): when nothing
// was sent for that long it sends a zero-byte stdin frame, which the front
// drops. It stops when the stream ends, the stdin side is closed, or the
// stream's context ends (a Kill without a Close, with the pump blocked:
// FX4-A5). A send error is left to the pump, which reports the stream's end.
func (p *process) heartbeat(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every / 2)
	defer t.Stop()
	for {
		select {
		case <-p.done:
			return
		case <-ctx.Done():
			return
		case <-t.C:
		}
		p.sendMu.Lock()
		if p.closed {
			p.sendMu.Unlock()
			return
		}
		if time.Since(p.lastSend) >= every/2 {
			_ = p.send.Send(&pb.ExecSandboxInput{Payload: &pb.ExecSandboxInput_Stdin{Stdin: []byte{}}})
			p.lastSend = time.Now()
		}
		p.sendMu.Unlock()
	}
}

func (p *process) PID() string { return "" }

func (p *process) Resize(_ context.Context, rows, cols uint16) error {
	if p.send == nil {
		return sandboxremote.ErrNotSupported
	}
	return mapErr(p.sendFrame(&pb.ExecSandboxInput{Payload: &pb.ExecSandboxInput_Resize{Resize: &pb.ExecSandboxWindowResize{Cols: uint32(cols), Rows: uint32(rows)}}}))
}

// Wait returns the exact exit code once the process ends. A stream that
// ended without an exit is an error (a cut stream ends the in-box process).
func (p *process) Wait(ctx context.Context) (int, error) {
	select {
	case <-p.done:
	case <-ctx.Done():
		return -1, ctx.Err()
	}
	if p.exit >= 0 {
		return p.exit, nil
	}
	if p.err != nil {
		return -1, p.err
	}
	return -1, errors.New("openshellorg: the exec stream ended without an exit code")
}

// Kill cuts the stream: with the TTY off the in-box process ends about 5 s
// later (OB-079). Its stdout reader is closed too (lane FX6, FX6-R1): a
// pump blocked writing box output nobody reads is released, so it reaches
// the stream's end and never leaks.
func (p *process) Kill(context.Context) error {
	_ = p.pr.CloseWithError(io.ErrClosedPipe)
	p.cancel()
	return nil
}

// Close ends the stdin side and releases the stream and its stdout reader
// (lane FX6, FX6-R1: box output after the half-close that nobody
// read held the pump in its pipe write, so its exit was never read and
// the pump leaked).
func (p *process) Close() error {
	if p.send != nil {
		_ = p.closeSend()
	}
	_ = p.pr.CloseWithError(io.ErrClosedPipe)
	select {
	case <-p.done:
	default:
		p.cancel()
	}
	return nil
}

// CloseWrite ends the stdin side only (the box sees EOF).
func (p *process) CloseWrite() error {
	if p.send == nil {
		return nil
	}
	return p.closeSend()
}

// closeSend half-closes the stream once; the heartbeat stops with it.
func (p *process) closeSend() error {
	p.sendMu.Lock()
	defer p.sendMu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	return p.send.CloseSend()
}
